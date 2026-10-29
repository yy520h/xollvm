#include "checkpoint.h"

#include <openssl/evp.h>

#include <array>
#include <cerrno>
#include <fcntl.h>
#include <fstream>
#include <sys/stat.h>
#include <unistd.h>

namespace xovm::cloud_material {
namespace {

constexpr std::array<std::byte, 4> kMagic = {
    std::byte{'X'}, std::byte{'C'}, std::byte{'P'}, std::byte{'T'}};
constexpr std::uint32_t kVersion = 1;
constexpr std::size_t kHeaderSize = 4 + 4 + 8 + 8;
constexpr std::size_t kChecksumSize = 32;

void put32(std::vector<std::byte> &out, std::uint32_t value) {
    for (int shift = 24; shift >= 0; shift -= 8)
        out.push_back(static_cast<std::byte>((value >> shift) & 0xff));
}

void put64(std::vector<std::byte> &out, std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8)
        out.push_back(static_cast<std::byte>((value >> shift) & 0xff));
}

std::uint32_t get32(std::span<const std::byte> data, std::size_t &offset) {
    if (data.size() - offset < 4) throw BackendError{"checkpoint_truncated"};
    std::uint32_t value = 0;
    for (int index = 0; index < 4; ++index)
        value = (value << 8) | std::to_integer<std::uint8_t>(data[offset++]);
    return value;
}

std::uint64_t get64(std::span<const std::byte> data, std::size_t &offset) {
    if (data.size() - offset < 8) throw BackendError{"checkpoint_truncated"};
    std::uint64_t value = 0;
    for (int index = 0; index < 8; ++index)
        value = (value << 8) | std::to_integer<std::uint8_t>(data[offset++]);
    return value;
}

std::array<std::byte, 32> digest(std::span<const std::byte> data) {
    std::array<std::byte, 32> result{};
    unsigned int size = 0;
    if (EVP_Digest(data.data(), data.size(), reinterpret_cast<unsigned char *>(result.data()),
                   &size, EVP_sha256(), nullptr) != 1 || size != result.size())
        throw BackendError{"checkpoint_checksum_failed"};
    return result;
}

bool equal(std::span<const std::byte> left, std::span<const std::byte> right) {
    return left.size() == right.size() && std::equal(left.begin(), left.end(), right.begin());
}

bool syncDirectory(const std::filesystem::path &path) {
    const auto directory = path.parent_path().empty() ? std::filesystem::path(".")
                                                       : path.parent_path();
    const int directoryFd = ::open(directory.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (directoryFd < 0) return false;
    const bool synced = ::fsync(directoryFd) == 0;
    ::close(directoryFd);
    return synced;
}

ssize_t defaultWrite(int fd, std::span<const std::byte> data) {
    return ::write(fd, data.data(), data.size());
}

int defaultSync(int fd) {
    return ::fsync(fd);
}

int defaultRename(const char *from, const char *to) {
    return ::rename(from, to);
}

int defaultUnlink(const char *path) {
    return ::unlink(path);
}

int defaultDirectorySync(const char *path) {
    return syncDirectory(path) ? 0 : -1;
}

std::vector<std::byte> encode(const RecoveredState &state, std::uint64_t sequence) {
    if (sequence == 0 || state.last_sequence != sequence || state.records.empty() ||
        state.records.size() > 4096)
        throw BackendError{"checkpoint_invalid_state"};
    std::uint64_t previousSequence = 0;
    for (const auto &record : state.records) {
        if (record.sequence == 0 || record.sequence <= previousSequence ||
            record.delta.bytes.size() > kMaxWalPayload ||
            record.response.size() > kMaxWalPayload)
            throw BackendError{"checkpoint_record_limit"};
        previousSequence = record.sequence;
    }
    if (previousSequence != sequence) throw BackendError{"checkpoint_invalid_state"};

    const auto &latest = state.records.back();
    std::vector<std::byte> result;
    result.insert(result.end(), kMagic.begin(), kMagic.end());
    put32(result, kVersion);
    put64(result, sequence);
    put64(result, 1);
    put64(result, latest.sequence);
    put64(result, latest.delta.bytes.size());
    put64(result, latest.response.size());
    result.insert(result.end(), latest.delta.bytes.begin(), latest.delta.bytes.end());
    result.insert(result.end(), latest.response.begin(), latest.response.end());
    const auto checksumValue = digest(result);
    result.insert(result.end(), checksumValue.begin(), checksumValue.end());
    return result;
}

std::vector<std::byte> readFile(const std::filesystem::path &path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) throw BackendError{"checkpoint_open_failed"};
    file.seekg(0, std::ios::end);
    const auto size = file.tellg();
    if (size < 0 || static_cast<std::uint64_t>(size) > 128 * 1024 * 1024)
        throw BackendError{"checkpoint_size_limit"};
    file.seekg(0, std::ios::beg);
    std::vector<std::byte> data(static_cast<std::size_t>(size));
    if (!data.empty() && !file.read(reinterpret_cast<char *>(data.data()), data.size()))
        throw BackendError{"checkpoint_read_failed"};
    return data;
}

} // namespace

Checkpoint::Checkpoint(std::filesystem::path path, std::filesystem::path walPath,
                       IoHooks hooks)
    : path_(std::move(path)), wal_path_(std::move(walPath)), hooks_(std::move(hooks)) {
    if (!hooks_.write) hooks_.write = defaultWrite;
    if (!hooks_.sync) hooks_.sync = defaultSync;
    if (!hooks_.rename) hooks_.rename = defaultRename;
    if (!hooks_.unlink) hooks_.unlink = defaultUnlink;
    if (!hooks_.syncDirectory) hooks_.syncDirectory = defaultDirectorySync;
}

CheckpointResult Checkpoint::writeAtomic(const RecoveredState &state, std::uint64_t sequence) {
    try {
        auto encoded = encode(state, sequence);
        const auto temporary = path_.string() + ".tmp." + std::to_string(::getpid());
        const int fd = ::open(temporary.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
        if (fd < 0) return BackendError{"checkpoint_open_failed"};
        std::size_t writtenTotal = 0;
        while (writtenTotal < encoded.size()) {
            const auto written = hooks_.write(fd, std::span<const std::byte>(
                encoded.data() + writtenTotal, encoded.size() - writtenTotal));
            if (written <= 0) break;
            writtenTotal += static_cast<std::size_t>(written);
        }
        const bool complete = writtenTotal == encoded.size();
        const int synced = complete ? hooks_.sync(fd) : -1;
        ::close(fd);
        if (!complete) {
            hooks_.unlink(temporary.c_str());
            return BackendError{"checkpoint_short_write"};
        }
        if (synced != 0) {
            hooks_.unlink(temporary.c_str());
            return BackendError{"checkpoint_sync_failed"};
        }
        if (hooks_.rename(temporary.c_str(), path_.c_str()) != 0) {
            hooks_.unlink(temporary.c_str());
            return BackendError{"checkpoint_rename_failed"};
        }
        if (hooks_.syncDirectory(path_.c_str()) != 0)
            return BackendError{"checkpoint_directory_sync_failed"};
        if (hooks_.unlink(wal_path_.c_str()) != 0 && errno != ENOENT)
            return BackendError{"wal_retire_failed"};
        if (hooks_.syncDirectory(wal_path_.c_str()) != 0)
            return BackendError{"wal_retire_sync_failed"};
        return sequence;
    } catch (const BackendError &error) {
        return error;
    } catch (...) {
        return BackendError{"checkpoint_write_failed"};
    }
}

WalRecoveryResult Checkpoint::recover() const {
    try {
        if (!std::filesystem::exists(path_)) {
            StateWal wal(wal_path_);
            return wal.recover();
        }
        auto data = readFile(path_);
        if (data.size() < kHeaderSize + kChecksumSize ||
            !equal(std::span(data).first(kMagic.size()), kMagic))
            return BackendError{"checkpoint_invalid"};
        const auto expected = digest(std::span(data).first(data.size() - kChecksumSize));
        if (!equal(std::span(data).last(kChecksumSize), expected))
            return BackendError{"checkpoint_checksum_mismatch"};
        std::size_t offset = kMagic.size();
        if (get32(data, offset) != kVersion) return BackendError{"checkpoint_unknown_version"};
        const auto sequence = get64(data, offset);
        const auto count = get64(data, offset);
        if (!sequence || count > 4096) return BackendError{"checkpoint_invalid_state"};
        RecoveredState result;
        result.last_sequence = sequence;
        std::uint64_t previousSequence = 0;
        for (std::uint64_t index = 0; index < count; ++index) {
            WalRecord record;
            record.sequence = get64(data, offset);
            const auto deltaSize = get64(data, offset);
            const auto responseSize = get64(data, offset);
            if (!record.sequence || record.sequence <= previousSequence ||
                deltaSize > kMaxWalPayload || responseSize > kMaxWalPayload ||
                deltaSize > data.size() - offset || responseSize > data.size() - offset - deltaSize)
                return BackendError{"checkpoint_invalid_state"};
            record.delta.bytes.assign(data.begin() + offset, data.begin() + offset + deltaSize);
            offset += deltaSize;
            record.response.assign(data.begin() + offset, data.begin() + offset + responseSize);
            offset += responseSize;
            result.records.push_back(std::move(record));
            previousSequence = result.records.back().sequence;
        }
        if (offset != data.size() - kChecksumSize ||
            (!result.records.empty() && result.records.back().sequence != sequence))
            return BackendError{"checkpoint_invalid_state"};
        if (result.records.empty() || previousSequence != sequence) return BackendError{"checkpoint_invalid_state"};
        StateWal wal(wal_path_, {}, sequence);
        auto trailing = wal.recover();
        if (const auto *error = std::get_if<BackendError>(&trailing)) return *error;
        auto &walState = std::get<RecoveredState>(trailing);
        for (const auto &record : walState.records) {
            if (record.sequence <= sequence) continue;
            if (record.sequence != result.last_sequence + 1)
                return BackendError{"wal_sequence_gap"};
            result.records.push_back(record);
            result.last_sequence = record.sequence;
        }
        return result;
    } catch (const BackendError &error) {
        return error;
    } catch (...) {
        return BackendError{"checkpoint_read_failed"};
    }
}

} // namespace xovm::cloud_material
