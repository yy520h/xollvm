#include "state_wal.h"

#include <openssl/evp.h>

#include <array>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <limits>
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

int openForAppend(const std::filesystem::path &path) {
    return ::open(path.c_str(), O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
}

ssize_t defaultWrite(int fd, std::span<const std::byte> data) {
    return ::write(fd, data.data(), data.size());
}

int defaultSync(int fd) {
    return ::fdatasync(fd);
}

BackendError ioError(const char *code) {
    return BackendError{code};
}

} // namespace

StateWal::StateWal(std::filesystem::path path, IoHooks hooks, std::uint64_t baseSequence)
    : path_(std::move(path)), hooks_(std::move(hooks)), base_sequence_(baseSequence) {
    if (!hooks_.write) hooks_.write = defaultWrite;
    if (!hooks_.sync) hooks_.sync = defaultSync;
}

WalCommitResult StateWal::appendAndSync(std::uint64_t sequence, const StateDelta &delta,
                                       std::span<const std::byte> exactResponse) {
    try {
        if (sequence == 0) return ioError("wal_invalid_sequence");
        auto existing = recover();
        if (const auto *error = std::get_if<BackendError>(&existing)) return *error;
        const auto last = std::get<RecoveredState>(existing).last_sequence;
        if (last == UINT64_MAX || sequence != last + 1)
            return ioError(sequence <= last ? "wal_duplicate_sequence" : "wal_sequence_gap");
        auto encoded = frame(sequence, delta, exactResponse);
        struct stat before{};
        const int sizeFd = ::open(path_.c_str(), O_RDONLY | O_CLOEXEC);
        if (sizeFd >= 0) {
            const bool stated = ::fstat(sizeFd, &before) == 0;
            ::close(sizeFd);
            if (!stated) return ioError("wal_stat_failed");
        }
        const int fd = openForAppend(path_);
        if (fd < 0) return ioError("wal_open_failed");
        const auto written = hooks_.write(fd, encoded);
        const bool complete = written == static_cast<ssize_t>(encoded.size());
        const int syncResult = complete ? hooks_.sync(fd) : -1;
        const int closeResult = ::close(fd);
        (void)closeResult;
        if (!complete) return ioError("wal_short_write");
        if (syncResult != 0) {
            const int rollbackFd = ::open(path_.c_str(), O_WRONLY | O_CLOEXEC);
            if (rollbackFd >= 0) {
                ::ftruncate(rollbackFd, before.st_size);
                ::close(rollbackFd);
            }
            return ioError("wal_sync_failed");
        }
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
        const int fd = ::open(path_.c_str(), O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
            if (errno == ENOENT) {
                RecoveredState empty;
                empty.last_sequence = base_sequence_;
                return empty;
            }
            return ioError("wal_open_failed");
        }
        struct stat status{};
        if (::fstat(fd, &status) != 0 || status.st_size < 0 ||
            static_cast<std::uint64_t>(status.st_size) > 128 * 1024 * 1024) {
            ::close(fd);
            return ioError("wal_size_limit");
        }
        std::vector<std::byte> data(static_cast<std::size_t>(status.st_size));
        std::size_t readTotal = 0;
        while (readTotal < data.size()) {
            const auto count = ::read(fd, data.data() + readTotal, data.size() - readTotal);
            if (count <= 0) {
                ::close(fd);
                return ioError("wal_read_failed");
            }
            readTotal += static_cast<std::size_t>(count);
        }
        ::close(fd);
        RecoveredState result;
        result.last_sequence = base_sequence_;
        std::size_t offset = 0;
        while (offset < data.size()) {
            const auto frameStart = offset;
            if (data.size() - offset < kHeaderSize) {
                const int writeFd = ::open(path_.c_str(), O_WRONLY | O_CLOEXEC);
                if (writeFd >= 0) {
                    ::ftruncate(writeFd, static_cast<off_t>(frameStart));
                    ::close(writeFd);
                }
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
                const int writeFd = ::open(path_.c_str(), O_WRONLY | O_CLOEXEC);
                if (writeFd >= 0) {
                    ::ftruncate(writeFd, static_cast<off_t>(frameStart));
                    ::close(writeFd);
                }
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
