#include "state_wal.h"

#include <openssl/evp.h>

#include <array>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <limits>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

namespace xovm::cloud_material {
namespace {

constexpr std::array<std::byte, 4> kMagic = {
    std::byte{'X'}, std::byte{'W'}, std::byte{'A'}, std::byte{'L'}};
constexpr std::uint32_t kVersion = 1;
constexpr std::size_t kHeaderSize = 4 + 4 + 8 + 8 + 8 + 8;
constexpr std::size_t kChecksumSize = 32;
constexpr std::size_t kMinimumFrame = kHeaderSize + kChecksumSize;

void put32(std::vector<std::byte> &out, std::uint32_t value) {
    for (int shift = 24; shift >= 0; shift -= 8)
        out.push_back(static_cast<std::byte>((value >> shift) & 0xff));
}

void put64(std::vector<std::byte> &out, std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8)
        out.push_back(static_cast<std::byte>((value >> shift) & 0xff));
}

std::uint32_t get32(std::span<const std::byte> data, std::size_t &offset) {
    if (data.size() - offset < 4) throw BackendError{"wal_truncated"};
    std::uint32_t value = 0;
    for (int index = 0; index < 4; ++index)
        value = (value << 8) | std::to_integer<std::uint8_t>(data[offset++]);
    return value;
}

std::uint64_t get64(std::span<const std::byte> data, std::size_t &offset) {
    if (data.size() - offset < 8) throw BackendError{"wal_truncated"};
    std::uint64_t value = 0;
    for (int index = 0; index < 8; ++index)
        value = (value << 8) | std::to_integer<std::uint8_t>(data[offset++]);
    return value;
}

std::array<std::byte, 32> checksum(std::span<const std::byte> data) {
    std::array<std::byte, 32> result{};
    unsigned int size = 0;
    if (EVP_Digest(data.data(), data.size(), reinterpret_cast<unsigned char *>(result.data()),
                   &size, EVP_sha256(), nullptr) != 1 ||
        size != result.size())
        throw BackendError{"wal_checksum_failed"};
    return result;
}

bool equal(std::span<const std::byte> left, std::span<const std::byte> right) {
    return left.size() == right.size() &&
        std::equal(left.begin(), left.end(), right.begin());
}

std::vector<std::byte> frame(std::uint64_t sequence, const StateDelta &delta,
                             std::span<const std::byte> response) {
    if (delta.bytes.size() > kMaxWalPayload || response.size() > kMaxWalPayload ||
        delta.bytes.size() > kMaxWalPayload - response.size())
        throw BackendError{"wal_record_limit"};
    const auto payloadSize = delta.bytes.size() + response.size();
    if (payloadSize > UINT64_MAX - kHeaderSize - kChecksumSize)
        throw BackendError{"wal_record_limit"};
    const auto frameSize = static_cast<std::uint64_t>(kHeaderSize + kChecksumSize + payloadSize);
    std::vector<std::byte> result;
    result.reserve(static_cast<std::size_t>(frameSize));
    result.insert(result.end(), kMagic.begin(), kMagic.end());
    put32(result, kVersion);
    put64(result, frameSize);
    put64(result, sequence);
    put64(result, delta.bytes.size());
    put64(result, response.size());
    result.insert(result.end(), delta.bytes.begin(), delta.bytes.end());
    result.insert(result.end(), response.begin(), response.end());
    const auto digest = checksum(result);
    result.insert(result.end(), digest.begin(), digest.end());
    return result;
}

ssize_t defaultWrite(int fd, std::span<const std::byte> data) {
    return ::write(fd, data.data(), data.size());
}

int defaultSync(int fd) {
    return ::fsync(fd);
}

BackendError ioError(const char *code) {
    return BackendError{code};
}

std::filesystem::path normalizedPath(const std::filesystem::path &path) {
    std::error_code error;
    const auto absolute = std::filesystem::absolute(path, error);
    const auto lexical = (error ? path : absolute).lexically_normal();
    error.clear();
    const auto canonical = std::filesystem::weakly_canonical(lexical, error);
    return error ? lexical : canonical;
}

std::filesystem::path quarantinePath(const std::filesystem::path &path) {
    const auto normalized = normalizedPath(path);
    return normalized.parent_path() / (normalized.filename().string() + ".quarantine");
}

bool isQuarantined(const std::filesystem::path &path) {
    std::error_code error;
    return std::filesystem::exists(quarantinePath(path), error) || error;
}

class OwnedFd {
public:
    explicit OwnedFd(int fd) : fd_(fd) {}
    ~OwnedFd() { if (fd_ >= 0) ::close(fd_); }
    OwnedFd(const OwnedFd &) = delete;
    OwnedFd &operator=(const OwnedFd &) = delete;
    int get() const { return fd_; }
private:
    int fd_;
};

int openParentDirectory(const std::filesystem::path &path) {
    auto parent = normalizedPath(path).parent_path();
    if (parent.empty()) parent = ".";
    return ::open(parent.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
}

bool matchesPathIdentity(const std::filesystem::path &path, const struct stat &identity) {
    struct stat current{};
    return identity.st_nlink > 0 && ::stat(path.c_str(), &current) == 0 &&
        current.st_dev == identity.st_dev && current.st_ino == identity.st_ino;
}

bool syncParentDirect(const std::filesystem::path &path) {
    const int fd = openParentDirectory(path);
    const bool synced = fd >= 0 && ::fsync(fd) == 0;
    if (fd >= 0) ::close(fd);
    return synced;
}

bool writeAll(int fd, std::string_view text) {
    std::size_t offset = 0;
    while (offset < text.size()) {
        const auto count = ::write(fd, text.data() + offset, text.size() - offset);
        if (count <= 0) return false;
        offset += static_cast<std::size_t>(count);
    }
    return true;
}

bool beginQuarantine(const std::filesystem::path &path, std::uint64_t sequence,
                     off_t offset, const struct stat &identity) {
    const auto marker = quarantinePath(path);
    const int fd = ::open(marker.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0) return false;
    const auto text = std::to_string(sequence) + " " + std::to_string(offset) + " " +
        std::to_string(static_cast<std::uint64_t>(identity.st_dev)) + " " +
        std::to_string(static_cast<std::uint64_t>(identity.st_ino)) + "\n";
    const bool durable = writeAll(fd, text) && ::fsync(fd) == 0;
    ::close(fd);
    return durable && syncParentDirect(marker);
}

bool clearQuarantine(const std::filesystem::path &path) {
    const auto marker = quarantinePath(path);
    if (::unlink(marker.c_str()) != 0 && errno != ENOENT) return false;
    return syncParentDirect(marker);
}

} // namespace

StateWal::StateWal(std::filesystem::path path, IoHooks hooks,
                   std::uint64_t baseSequence, WalAppendMode appendMode)
    : path_(std::move(path)), hooks_(std::move(hooks)),
      base_sequence_(baseSequence), append_mode_(appendMode) {
    if (!hooks_.write) hooks_.write = defaultWrite;
    if (!hooks_.sync) hooks_.sync = defaultSync;
}

WalCommitResult StateWal::appendAndSync(std::uint64_t sequence, const StateDelta &delta,
                                       std::span<const std::byte> exactResponse) {
    try {
        if (sequence == 0) return ioError("wal_invalid_sequence");
        const auto path = normalizedPath(path_);
        if (isQuarantined(path)) return ioError("wal_quarantined");
        auto existing = recover();
        if (const auto *error = std::get_if<BackendError>(&existing)) return *error;
        const auto last = std::get<RecoveredState>(existing).last_sequence;
        if (last == UINT64_MAX || sequence != last + 1)
            return ioError(sequence <= last ? "wal_duplicate_sequence" : "wal_sequence_gap");
        auto encoded = frame(sequence, delta, exactResponse);

        bool created = true;
        int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_APPEND | O_CLOEXEC,
                        0600);
        if (fd < 0 && errno == EEXIST) {
            created = false;
            fd = ::open(path.c_str(), O_WRONLY | O_APPEND | O_CLOEXEC);
        }
        if (fd < 0) return ioError("wal_open_failed");
        struct stat before{};
        if (::fstat(fd, &before) != 0 || before.st_size < 0) {
            ::close(fd);
            return ioError("wal_stat_failed");
        }
        const auto currentSize = static_cast<std::uint64_t>(before.st_size);
        const auto limit = append_mode_ == WalAppendMode::maintenance
            ? kMaxWalSize : kMaxWalSize - kMaxWalFrame;
        if (currentSize > limit || encoded.size() > limit - currentSize) {
            ::close(fd);
            return ioError(append_mode_ == WalAppendMode::maintenance
                ? "wal_size_limit" : "wal_maintenance_required");
        }
        if (!beginQuarantine(path, sequence, before.st_size, before)) {
            ::close(fd);
            return ioError("wal_quarantine_failed");
        }

        const auto syncParent = [&] {
            const int directoryFd = openParentDirectory(path);
            const bool synced = directoryFd >= 0 && hooks_.sync(directoryFd) == 0;
            if (directoryFd >= 0) ::close(directoryFd);
            return synced;
        };
        const auto rollback = [&] {
            return matchesPathIdentity(path, before) &&
                ::ftruncate(fd, before.st_size) == 0 && hooks_.sync(fd) == 0 &&
                (!created || syncParent()) && matchesPathIdentity(path, before);
        };
        const auto finishRollback = [&](const char *code) -> WalCommitResult {
            const bool rolledBack = rollback();
            ::close(fd);
            if (!rolledBack) return ioError("wal_rollback_failed");
            if (!clearQuarantine(path)) return ioError("wal_quarantine_cleanup_failed");
            return ioError(code);
        };

        if (!matchesPathIdentity(path, before)) return finishRollback("wal_replaced");
        const auto written = hooks_.write(fd, encoded);
        if (written != static_cast<ssize_t>(encoded.size()))
            return finishRollback("wal_short_write");
        if (hooks_.sync(fd) != 0) return finishRollback("wal_sync_failed");
        if (created && !syncParent()) return finishRollback("wal_directory_sync_failed");
        if (!matchesPathIdentity(path, before)) return finishRollback("wal_replaced");
        ::close(fd);
        if (!clearQuarantine(path)) return ioError("wal_quarantine_cleanup_failed");
        return sequence;
    } catch (const BackendError &error) {
        return error;
    } catch (const std::bad_alloc &) {
        return ioError("allocation_failed");
    } catch (...) {
        return ioError("wal_write_failed");
    }
}

WalRecoveryResult StateWal::recover() {
    try {
        const auto path = normalizedPath(path_);
        if (isQuarantined(path)) return ioError("wal_quarantined");
        const int rawFd = ::open(path.c_str(), O_RDWR | O_CLOEXEC);
        if (rawFd < 0) {
            if (errno == ENOENT) {
                RecoveredState empty;
                empty.last_sequence = base_sequence_;
                return empty;
            }
            return ioError("wal_open_failed");
        }
        OwnedFd fd(rawFd);
        struct stat status{};
        if (::fstat(fd.get(), &status) != 0 || status.st_size < 0 ||
            static_cast<std::uint64_t>(status.st_size) > kMaxWalSize)
            return ioError("wal_size_limit");
        std::vector<std::byte> data(static_cast<std::size_t>(status.st_size));
        std::size_t readTotal = 0;
        while (readTotal < data.size()) {
            const auto count = ::read(fd.get(), data.data() + readTotal, data.size() - readTotal);
            if (count <= 0) return ioError("wal_read_failed");
            readTotal += static_cast<std::size_t>(count);
        }
        RecoveredState result;
        result.last_sequence = base_sequence_;
        const auto repairTail = [&](std::size_t size) {
            if (!matchesPathIdentity(path, status) ||
                !beginQuarantine(path, result.last_sequence + 1,
                                 static_cast<off_t>(size), status))
                return false;
            const bool repaired = ::ftruncate(fd.get(), static_cast<off_t>(size)) == 0 &&
                hooks_.sync(fd.get()) == 0;
            return repaired && clearQuarantine(path);
        };
        std::size_t offset = 0;
        while (offset < data.size()) {
            const auto frameStart = offset;
            if (data.size() - offset < kHeaderSize) {
                if (!repairTail(frameStart)) return ioError("wal_repair_failed");
                break;
            }
            if (!equal(std::span(data).subspan(offset, kMagic.size()), kMagic))
                return ioError("wal_bad_magic");
            offset += kMagic.size();
            const auto version = get32(data, offset);
            if (version != kVersion) return ioError("wal_unknown_version");
            const auto frameSize = get64(data, offset);
            const auto sequence = get64(data, offset);
            const auto deltaSize = get64(data, offset);
            const auto responseSize = get64(data, offset);
            if (frameSize < kMinimumFrame || frameSize > kMaxWalFrame ||
                deltaSize > kMaxWalPayload || responseSize > kMaxWalPayload ||
                deltaSize > kMaxWalPayload - responseSize ||
                frameSize != kHeaderSize + kChecksumSize + deltaSize + responseSize)
                return ioError("wal_invalid_frame");
            if (data.size() - frameStart < frameSize) {
                if (!repairTail(frameStart)) return ioError("wal_repair_failed");
                break;
            }
            const auto frameBytes = std::span(data).subspan(frameStart, frameSize);
            const auto checksumOffset = frameSize - kChecksumSize;
            const auto expected = checksum(frameBytes.subspan(0, checksumOffset));
            if (!equal(frameBytes.subspan(checksumOffset, kChecksumSize), expected))
                return ioError("wal_checksum_mismatch");
            offset = frameStart + frameSize;
            if (sequence == 0) return ioError("wal_invalid_sequence");
            if (sequence <= base_sequence_) continue;
            if (result.last_sequence == UINT64_MAX || sequence != result.last_sequence + 1)
                return ioError(sequence <= result.last_sequence
                    ? "wal_duplicate_sequence" : "wal_sequence_gap");
            WalRecord record;
            record.sequence = sequence;
            const auto payloadStart = kHeaderSize;
            record.delta.bytes.assign(frameBytes.begin() + payloadStart,
                                      frameBytes.begin() + payloadStart + deltaSize);
            record.response.assign(frameBytes.begin() + payloadStart + deltaSize,
                                   frameBytes.begin() + payloadStart + deltaSize + responseSize);
            result.records.push_back(std::move(record));
            result.last_sequence = sequence;
        }
        if (!matchesPathIdentity(path, status)) return ioError("wal_replaced");
        return result;
    } catch (const BackendError &error) {
        return error;
    } catch (const std::bad_alloc &) {
        return ioError("allocation_failed");
    } catch (...) {
        return ioError("wal_read_failed");
    }
}

} // namespace xovm::cloud_material
