#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "guardian_channel.h"

#include "dynamic_vm_window_provider.h"

#include <openssl/evp.h>
#include <openssl/kdf.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <limits>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

namespace xovm::material {
namespace {

constexpr std::array<uint8_t, 4> kMagic{'X', 'G', 'C', '2'};
constexpr uint8_t kProtocolVersion = 1;
constexpr size_t kHeaderSize = 18;
constexpr size_t kTagSize = 16;
constexpr size_t kMaxPayloadSize = 1024;
constexpr size_t kMaxPacketSize = kHeaderSize + kMaxPayloadSize + kTagSize;
#ifndef XOVM_GUARDIAN_TESTING
constexpr uint64_t kLeaseNs = 120000000000ULL;
#endif
constexpr uint64_t kRenewBeforeNs = 10000000000ULL;
constexpr int kSocketBufferSize = 4096;

enum class MessageType : uint8_t {
    Hello = 1,
    HelloAck = 2,
    HelloConfirm = 3,
    Challenge = 4,
    ChallengeResponse = 5,
    InstallGeneration = 6,
    InstallAck = 7,
    Shutdown = 8,
};

void appendU16(std::vector<uint8_t> &out, uint16_t value) {
    out.push_back(static_cast<uint8_t>(value >> 8));
    out.push_back(static_cast<uint8_t>(value));
}

void appendU32(std::vector<uint8_t> &out, uint32_t value) {
    for (int shift = 24; shift >= 0; shift -= 8)
        out.push_back(static_cast<uint8_t>(value >> shift));
}

void appendU64(std::vector<uint8_t> &out, uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8)
        out.push_back(static_cast<uint8_t>(value >> shift));
}

bool takeU16(const std::vector<uint8_t> &in, size_t &offset, uint16_t &value) {
    if (offset + 2 > in.size()) return false;
    value = static_cast<uint16_t>(in[offset]) << 8 |
            static_cast<uint16_t>(in[offset + 1]);
    offset += 2;
    return true;
}

bool takeU64(const std::vector<uint8_t> &in, size_t &offset, uint64_t &value) {
    if (offset + 8 > in.size()) return false;
    value = 0;
    for (size_t i = 0; i < 8; ++i) value = (value << 8) | in[offset + i];
    offset += 8;
    return true;
}

template <size_t N>
void appendArray(std::vector<uint8_t> &out, const std::array<uint8_t, N> &value) {
    out.insert(out.end(), value.begin(), value.end());
}

template <size_t N>
bool takeArray(const std::vector<uint8_t> &in, size_t &offset,
               std::array<uint8_t, N> &value) {
    if (offset + N > in.size()) return false;
    std::copy_n(in.begin() + static_cast<std::ptrdiff_t>(offset), N,
                value.begin());
    offset += N;
    return true;
}

std::optional<uint64_t> processStartTicks(pid_t pid) {
    std::ifstream stat("/proc/" + std::to_string(pid) + "/stat");
    std::string line;
    if (!stat || !std::getline(stat, line)) return std::nullopt;
    const size_t end_name = line.rfind(')');
    if (end_name == std::string::npos || end_name + 2 >= line.size())
        return std::nullopt;
    std::istringstream fields(line.substr(end_name + 2));
    std::string field;
    for (size_t index = 0; index <= 19; ++index) {
        if (!(fields >> field)) return std::nullopt;
    }
    try {
        size_t used = 0;
        const uint64_t ticks = std::stoull(field, &used);
        if (used != field.size() || ticks == 0) return std::nullopt;
        return ticks;
    } catch (...) {
        return std::nullopt;
    }
}

bool deriveKey(const std::array<uint8_t, 32> &boot_nonce,
               const std::vector<uint8_t> &info,
               std::array<uint8_t, 32> &key) {
    EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    const std::array<uint8_t, 24> salt{
        'x', 'o', 'v', 'm', '-', 'g', 'u', 'a', 'r', 'd', 'i', 'a', 'n', '-',
        'v', '2', '-', 'c', 'h', 'a', 'n', 'n', 'e', 'l'};
    size_t key_size = key.size();
    const bool ok = context && EVP_PKEY_derive_init(context) == 1 &&
                    EVP_PKEY_CTX_set_hkdf_md(context, EVP_sha256()) == 1 &&
                    EVP_PKEY_CTX_set1_hkdf_salt(context, salt.data(),
                                                salt.size()) == 1 &&
                    EVP_PKEY_CTX_set1_hkdf_key(context, boot_nonce.data(),
                                               boot_nonce.size()) == 1 &&
                    EVP_PKEY_CTX_add1_hkdf_info(context, info.data(),
                                                info.size()) == 1 &&
                    EVP_PKEY_derive(context, key.data(), &key_size) == 1 &&
                    key_size == key.size();
    EVP_PKEY_CTX_free(context);
    return ok;
}

std::array<uint8_t, 12> packetNonce(GuardianChannel::Role sender,
                                    uint64_t sequence) {
    std::array<uint8_t, 12> nonce{};
    nonce[0] = 'X';
    nonce[1] = 'G';
    nonce[2] = static_cast<uint8_t>(sender);
    nonce[3] = kProtocolVersion;
    for (size_t i = 0; i < 8; ++i)
        nonce[4 + i] = static_cast<uint8_t>(sequence >> (56 - i * 8));
    return nonce;
}

bool encryptPayload(const std::array<uint8_t, 32> &key,
                    const std::array<uint8_t, 12> &nonce,
                    const uint8_t *header, const std::vector<uint8_t> &plain,
                    uint8_t *cipher, uint8_t *tag) {
    EVP_CIPHER_CTX *context = EVP_CIPHER_CTX_new();
    int length = 0;
    int total = 0;
    const bool ok = context &&
        EVP_EncryptInit_ex(context, EVP_aes_256_gcm(), nullptr, nullptr,
                           nullptr) == 1 &&
        EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN, nonce.size(),
                            nullptr) == 1 &&
        EVP_EncryptInit_ex(context, nullptr, nullptr, key.data(),
                           nonce.data()) == 1 &&
        EVP_EncryptUpdate(context, nullptr, &length, header, kHeaderSize) == 1 &&
        EVP_EncryptUpdate(context, cipher, &length, plain.data(),
                          plain.size()) == 1 &&
        ((total = length), true) &&
        EVP_EncryptFinal_ex(context, cipher + total, &length) == 1 &&
        (total += length) == static_cast<int>(plain.size()) &&
        EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_GET_TAG, kTagSize, tag) == 1;
    EVP_CIPHER_CTX_free(context);
    return ok;
}

bool decryptPayload(const std::array<uint8_t, 32> &key,
                    const std::array<uint8_t, 12> &nonce,
                    const uint8_t *header, const uint8_t *cipher,
                    size_t cipher_size, const uint8_t *tag,
                    std::vector<uint8_t> &plain) {
    EVP_CIPHER_CTX *context = EVP_CIPHER_CTX_new();
    plain.assign(cipher_size, 0);
    int length = 0;
    int total = 0;
    const bool ok = context &&
        EVP_DecryptInit_ex(context, EVP_aes_256_gcm(), nullptr, nullptr,
                           nullptr) == 1 &&
        EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN, nonce.size(),
                            nullptr) == 1 &&
        EVP_DecryptInit_ex(context, nullptr, nullptr, key.data(),
                           nonce.data()) == 1 &&
        EVP_DecryptUpdate(context, nullptr, &length, header, kHeaderSize) == 1 &&
        EVP_DecryptUpdate(context, plain.data(), &length, cipher,
                          cipher_size) == 1 &&
        ((total = length), true) &&
        EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_TAG, kTagSize,
                            const_cast<uint8_t *>(tag)) == 1 &&
        EVP_DecryptFinal_ex(context, plain.data() + total, &length) == 1 &&
        (total += length) == static_cast<int>(cipher_size);
    EVP_CIPHER_CTX_free(context);
    if (!ok) {
        OPENSSL_cleanse(plain.data(), plain.size());
        plain.clear();
    }
    return ok;
}

} // namespace

struct GuardianChannelState {
    int fd = -1;
    GuardianChannel::Role role = GuardianChannel::Role::Guardian;
    pid_t owner_pid = -1;
    pid_t peer_pid = -1;
    dev_t socket_device = 0;
    ino_t socket_inode = 0;
    uid_t peer_uid = 0;
    gid_t peer_gid = 0;
    uint64_t local_start_ticks = 0;
    uint64_t peer_start_ticks = 0;
    std::array<uint8_t, 32> send_key{};
    std::array<uint8_t, 32> receive_key{};
    std::array<uint8_t, 32> launch_commitment{};
    std::array<uint8_t, 16> session_id{};
    DynamicHash state_digest{};
    uint64_t generation = 0;
    uint64_t current_window_id = 0;
    uint64_t last_challenge = 0;
    uint64_t send_sequence = 1;
    uint64_t receive_sequence = 1;
    std::atomic<bool> established{false};
    std::atomic<bool> poisoned{false};
    mutable std::mutex io_mutex;

    ~GuardianChannelState() {
        if (fd >= 0) ::close(fd);
        OPENSSL_cleanse(send_key.data(), send_key.size());
        OPENSSL_cleanse(receive_key.data(), receive_key.size());
    }

    void poison() {
        poisoned.store(true, std::memory_order_release);
        established.store(false, std::memory_order_release);
        if (fd >= 0) ::shutdown(fd, SHUT_RDWR);
    }

    bool rotateSessionKeys(uint64_t generation_value, uint64_t window_id,
                           uint64_t challenge, const DynamicHash &digest) {
        std::vector<uint8_t> binding;
        const std::array<uint8_t, 22> label{
            'x', 'o', 'v', 'm', '-', 'g', 'u', 'a', 'r', 'd', 'i', 'a', 'n', '-',
            's', 'e', 's', 's', 'i', 'o', 'n', '2'};
        binding.insert(binding.end(), label.begin(), label.end());
        appendArray(binding, session_id);
        appendU64(binding, generation_value);
        appendU64(binding, window_id);
        appendU64(binding, challenge);
        appendArray(binding, digest);
        const bool local_guardian = role == GuardianChannel::Role::Guardian;
        appendU64(binding, local_guardian ? local_start_ticks : peer_start_ticks);
        appendU64(binding, local_guardian ? peer_start_ticks : local_start_ticks);

        auto send_info = binding;
        send_info.push_back(static_cast<uint8_t>(role));
        auto receive_info = binding;
        receive_info.push_back(static_cast<uint8_t>(
            role == GuardianChannel::Role::Guardian
                ? GuardianChannel::Role::Worker
                : GuardianChannel::Role::Guardian));
        std::array<uint8_t, 32> next_send{};
        std::array<uint8_t, 32> next_receive{};
        const bool ok = deriveKey(send_key, send_info, next_send) &&
                        deriveKey(receive_key, receive_info, next_receive);
        if (ok) {
            OPENSSL_cleanse(send_key.data(), send_key.size());
            OPENSSL_cleanse(receive_key.data(), receive_key.size());
            send_key = next_send;
            receive_key = next_receive;
            OPENSSL_cleanse(launch_commitment.data(), launch_commitment.size());
        }
        OPENSSL_cleanse(next_send.data(), next_send.size());
        OPENSSL_cleanse(next_receive.data(), next_receive.size());
        if (!ok) poison();
        return ok;
    }

    bool descriptorIntact() const {
        struct stat status{};
        return fd >= 0 && ::fstat(fd, &status) == 0 && S_ISSOCK(status.st_mode) &&
               status.st_dev == socket_device && status.st_ino == socket_inode;
    }

    bool peerAlive() {
        if (owner_pid != ::getpid() || !descriptorIntact() ||
            poisoned.load(std::memory_order_acquire)) return false;
#ifdef POLLRDHUP
        constexpr short hangup_events = POLLHUP | POLLERR | POLLNVAL | POLLRDHUP;
#else
        constexpr short hangup_events = POLLHUP | POLLERR | POLLNVAL;
#endif
        pollfd descriptor{fd, static_cast<short>(POLLIN | hangup_events), 0};
        const int result = ::poll(&descriptor, 1, 0);
        if (result < 0 || (result > 0 && (descriptor.revents & hangup_events))) {
            poison();
            return false;
        }
        const auto ticks = processStartTicks(peer_pid);
        if (!ticks || *ticks != peer_start_ticks) {
            poison();
            return false;
        }
        return true;
    }

    bool sendPacket(MessageType type, const std::vector<uint8_t> &plain) {
        if (owner_pid != ::getpid() || plain.size() > kMaxPayloadSize ||
            !descriptorIntact() || poisoned.load(std::memory_order_acquire))
            return false;
        if (send_sequence == UINT64_MAX) {
            poison();
            return false;
        }
        const uint64_t sequence = send_sequence;
        std::array<uint8_t, kMaxPacketSize> packet{};
        std::copy(kMagic.begin(), kMagic.end(), packet.begin());
        packet[4] = kProtocolVersion;
        packet[5] = static_cast<uint8_t>(type);
        packet[6] = 0;
        packet[7] = 0;
        for (size_t i = 0; i < 8; ++i)
            packet[8 + i] = static_cast<uint8_t>(sequence >> (56 - i * 8));
        packet[16] = static_cast<uint8_t>(plain.size() >> 8);
        packet[17] = static_cast<uint8_t>(plain.size());
        const auto nonce = packetNonce(role, sequence);
        if (!encryptPayload(send_key, nonce, packet.data(), plain,
                            packet.data() + kHeaderSize,
                            packet.data() + kHeaderSize + plain.size())) {
            poison();
            return false;
        }
        const size_t packet_size = kHeaderSize + plain.size() + kTagSize;
        ssize_t sent;
        do {
            sent = ::send(fd, packet.data(), packet_size, MSG_NOSIGNAL);
        } while (sent < 0 && errno == EINTR);
        if (sent != static_cast<ssize_t>(packet_size)) {
            poison();
            return false;
        }
        ++send_sequence;
        return true;
    }

    bool receivePacket(MessageType expected_type, std::vector<uint8_t> &plain) {
        if (owner_pid != ::getpid() || !descriptorIntact() ||
            poisoned.load(std::memory_order_acquire)) return false;
        if (receive_sequence == UINT64_MAX) {
            poison();
            return false;
        }
        std::array<uint8_t, kMaxPacketSize + 1> packet{};
        std::array<uint8_t, CMSG_SPACE(sizeof(ucred))> control{};
        iovec vector{packet.data(), packet.size()};
        msghdr message{};
        message.msg_iov = &vector;
        message.msg_iovlen = 1;
        message.msg_control = control.data();
        message.msg_controllen = control.size();
        ssize_t received;
        do {
            received = ::recvmsg(fd, &message, MSG_CMSG_CLOEXEC);
        } while (received < 0 && errno == EINTR);
        if (received < static_cast<ssize_t>(kHeaderSize + kTagSize) ||
            (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC))) {
            poison();
            return false;
        }
        const ucred *credentials = nullptr;
        for (cmsghdr *header = CMSG_FIRSTHDR(&message); header;
             header = CMSG_NXTHDR(&message, header)) {
            if (header->cmsg_level == SOL_SOCKET &&
                header->cmsg_type == SCM_CREDENTIALS &&
                header->cmsg_len >= CMSG_LEN(sizeof(ucred))) {
                credentials = reinterpret_cast<const ucred *>(CMSG_DATA(header));
                break;
            }
        }
        if (!credentials || credentials->pid != peer_pid ||
            credentials->uid != peer_uid || credentials->gid != peer_gid ||
            !std::equal(kMagic.begin(), kMagic.end(), packet.begin()) ||
            packet[4] != kProtocolVersion ||
            packet[5] != static_cast<uint8_t>(expected_type) || packet[6] != 0 ||
            packet[7] != 0) {
            poison();
            return false;
        }
        uint64_t sequence = 0;
        for (size_t i = 0; i < 8; ++i) sequence = (sequence << 8) | packet[8 + i];
        const size_t plain_size = static_cast<size_t>(packet[16]) << 8 | packet[17];
        const size_t expected_size = kHeaderSize + plain_size + kTagSize;
        if (sequence != receive_sequence || plain_size > kMaxPayloadSize ||
            static_cast<size_t>(received) != expected_size) {
            poison();
            return false;
        }
        const GuardianChannel::Role sender =
            role == GuardianChannel::Role::Guardian
                ? GuardianChannel::Role::Worker
                : GuardianChannel::Role::Guardian;
        const auto nonce = packetNonce(sender, sequence);
        if (!decryptPayload(receive_key, nonce, packet.data(),
                            packet.data() + kHeaderSize, plain_size,
                            packet.data() + kHeaderSize + plain_size, plain)) {
            poison();
            return false;
        }
        const auto ticks = processStartTicks(peer_pid);
        if (!ticks || *ticks != peer_start_ticks) {
            poison();
            return false;
        }
        ++receive_sequence;
        return true;
    }
};

GuardianGeneration::~GuardianGeneration() {
    OPENSSL_cleanse(grant_key.data(), grant_key.size());
}

GuardianGeneration::GuardianGeneration(GuardianGeneration &&other) noexcept
    : request_id(other.request_id), sent_at_ns(other.sent_at_ns),
      artifact_hash(other.artifact_hash), grant(std::move(other.grant)),
      grant_key(other.grant_key) {
    OPENSSL_cleanse(other.grant_key.data(), other.grant_key.size());
}

GuardianGeneration &GuardianGeneration::operator=(GuardianGeneration &&other) noexcept {
    if (this != &other) {
        OPENSSL_cleanse(grant_key.data(), grant_key.size());
        request_id = other.request_id;
        sent_at_ns = other.sent_at_ns;
        artifact_hash = other.artifact_hash;
        grant = std::move(other.grant);
        grant_key = other.grant_key;
        OPENSSL_cleanse(other.grant_key.data(), other.grant_key.size());
    }
    return *this;
}

GuardianChannel::GuardianChannel(std::shared_ptr<GuardianChannelState> state)
    : state_(std::move(state)) {}

GuardianChannel::~GuardianChannel() { close(); }

GuardianChannel::GuardianChannel(GuardianChannel &&other) noexcept
    : state_(std::move(other.state_)) {}

GuardianChannel &GuardianChannel::operator=(GuardianChannel &&other) noexcept {
    if (this != &other) {
        close();
        state_ = std::move(other.state_);
    }
    return *this;
}

std::optional<GuardianChannel> GuardianChannel::adopt(
    int fd, Role role, const std::array<uint8_t, 32> &boot_nonce,
    const std::array<uint8_t, 16> &session_id, pid_t peer_pid) {
    if (fd < 0 || peer_pid <= 0 ||
        std::all_of(boot_nonce.begin(), boot_nonce.end(),
                    [](uint8_t byte) { return byte == 0; }) ||
        session_id == std::array<uint8_t, 16>{}) return std::nullopt;
    int socket_type = 0;
    socklen_t socket_type_size = sizeof(socket_type);
    sockaddr_storage local_address{};
    socklen_t local_address_size = sizeof(local_address);
    ucred peer{};
    socklen_t peer_size = sizeof(peer);
    if (::getsockopt(fd, SOL_SOCKET, SO_TYPE, &socket_type,
                     &socket_type_size) != 0 || socket_type != SOCK_SEQPACKET ||
        ::getsockname(fd, reinterpret_cast<sockaddr *>(&local_address),
                      &local_address_size) != 0 ||
        local_address.ss_family != AF_UNIX ||
        ::getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &peer, &peer_size) != 0 ||
        peer.uid != ::getuid() || peer.gid != ::getgid()) return std::nullopt;
    struct stat socket_status{};
    const int enabled = 1;
    const timeval timeout{2, 0};
    if (::fstat(fd, &socket_status) != 0 || !S_ISSOCK(socket_status.st_mode) ||
        ::setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &enabled, sizeof(enabled)) != 0 ||
        ::setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &kSocketBufferSize,
                     sizeof(kSocketBufferSize)) != 0 ||
        ::setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &kSocketBufferSize,
                     sizeof(kSocketBufferSize)) != 0 ||
        ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0 ||
        ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) != 0)
        return std::nullopt;
    const auto local_ticks = processStartTicks(::getpid());
    const auto peer_ticks = processStartTicks(peer_pid);
    if (!local_ticks || !peer_ticks) return std::nullopt;

    const bool local_guardian = role == Role::Guardian;
    const pid_t guardian_pid = local_guardian ? ::getpid() : peer_pid;
    const pid_t worker_pid = local_guardian ? peer_pid : ::getpid();
    const uint64_t guardian_ticks = local_guardian ? *local_ticks : *peer_ticks;
    const uint64_t worker_ticks = local_guardian ? *peer_ticks : *local_ticks;
    std::vector<uint8_t> binding;
    const std::array<uint8_t, 19> label{
        'x', 'o', 'v', 'm', '-', 'g', 'u', 'a', 'r', 'd', 'i', 'a', 'n', '-',
        'i', 'p', 'c', '-', '2'};
    binding.insert(binding.end(), label.begin(), label.end());
    appendArray(binding, session_id);
    appendU32(binding, static_cast<uint32_t>(guardian_pid));
    appendU64(binding, guardian_ticks);
    appendU32(binding, static_cast<uint32_t>(worker_pid));
    appendU64(binding, worker_ticks);
    auto guardian_info = binding;
    guardian_info.push_back(static_cast<uint8_t>(Role::Guardian));
    auto worker_info = binding;
    worker_info.push_back(static_cast<uint8_t>(Role::Worker));
    std::array<uint8_t, 32> guardian_key{};
    std::array<uint8_t, 32> worker_key{};
    auto commitment_info = binding;
    const std::array<uint8_t, 10> commitment_label{
        'c', 'o', 'm', 'm', 'i', 't', 'm', 'e', 'n', 't'};
    commitment_info.insert(commitment_info.end(), commitment_label.begin(),
                           commitment_label.end());
    std::array<uint8_t, 32> launch_commitment{};
    if (!deriveKey(boot_nonce, guardian_info, guardian_key) ||
        !deriveKey(boot_nonce, worker_info, worker_key) ||
        !deriveKey(boot_nonce, commitment_info, launch_commitment)) {
        OPENSSL_cleanse(guardian_key.data(), guardian_key.size());
        OPENSSL_cleanse(worker_key.data(), worker_key.size());
        OPENSSL_cleanse(launch_commitment.data(), launch_commitment.size());
        return std::nullopt;
    }

    auto state = std::make_shared<GuardianChannelState>();
    state->fd = fd;
    state->role = role;
    state->owner_pid = ::getpid();
    state->peer_pid = peer_pid;
    state->socket_device = socket_status.st_dev;
    state->socket_inode = socket_status.st_ino;
    state->peer_uid = peer.uid;
    state->peer_gid = peer.gid;
    state->local_start_ticks = *local_ticks;
    state->peer_start_ticks = *peer_ticks;
    state->session_id = session_id;
    state->launch_commitment = launch_commitment;
    state->send_key = local_guardian ? guardian_key : worker_key;
    state->receive_key = local_guardian ? worker_key : guardian_key;
    OPENSSL_cleanse(guardian_key.data(), guardian_key.size());
    OPENSSL_cleanse(worker_key.data(), worker_key.size());
    return GuardianChannel(std::move(state));
}

bool GuardianChannel::guardianHandshake(const GuardianChannelHello &hello,
                                        uint64_t current_window_id) {
    if (!state_ || state_->role != Role::Guardian ||
        hello.format_version != kDynamicVmFormatVersion ||
        hello.generation == 0 || hello.challenge_counter == 0 ||
        hello.session_id != state_->session_id ||
        hello.previous_state_digest == DynamicHash{} || current_window_id == 0)
        return false;
    std::lock_guard lock(state_->io_mutex);
    std::vector<uint8_t> packet;
    if (!state_->receivePacket(MessageType::Hello, packet)) return false;
    size_t offset = 0;
    uint16_t format_version = 0;
    std::array<uint8_t, 32> launch_commitment{};
    std::array<uint8_t, 16> session_id{};
    uint64_t generation = 0;
    uint64_t challenge_counter = 0;
    DynamicHash digest{};
    uint64_t worker_identity = 0;
    if (!takeU16(packet, offset, format_version) ||
        !takeArray(packet, offset, launch_commitment) ||
        !takeArray(packet, offset, session_id) ||
        !takeU64(packet, offset, generation) ||
        !takeU64(packet, offset, challenge_counter) ||
        !takeArray(packet, offset, digest) ||
        !takeU64(packet, offset, worker_identity) || offset != packet.size() ||
        format_version != hello.format_version ||
        launch_commitment != state_->launch_commitment ||
        session_id != hello.session_id ||
        generation != hello.generation ||
        challenge_counter != hello.challenge_counter ||
        digest != hello.previous_state_digest ||
        worker_identity != state_->peer_start_ticks) {
        state_->poison();
        return false;
    }
    std::vector<uint8_t> response;
    appendU64(response, challenge_counter);
    appendU64(response, state_->local_start_ticks);
    appendU64(response, generation);
    appendU64(response, current_window_id);
    appendArray(response, digest);
    if (!state_->sendPacket(MessageType::HelloAck, response) ||
        !state_->receivePacket(MessageType::HelloConfirm, packet)) return false;
    offset = 0;
    uint64_t confirmed_challenge = 0;
    uint64_t confirmed_guardian = 0;
    uint64_t confirmed_worker = 0;
    if (!takeU64(packet, offset, confirmed_challenge) ||
        !takeU64(packet, offset, confirmed_guardian) ||
        !takeU64(packet, offset, confirmed_worker) || offset != packet.size() ||
        confirmed_challenge != challenge_counter ||
        confirmed_guardian != state_->local_start_ticks ||
        confirmed_worker != state_->peer_start_ticks) {
        state_->poison();
        return false;
    }
    state_->generation = generation;
    state_->current_window_id = current_window_id;
    state_->state_digest = digest;
    state_->last_challenge = challenge_counter;
    if (!state_->rotateSessionKeys(
            generation, current_window_id, challenge_counter, digest))
        return false;
    state_->established.store(true, std::memory_order_release);
    return true;
}

bool GuardianChannel::workerHandshake(const GuardianChannelHello &hello,
                                      uint64_t current_window_id) {
    if (!state_ || state_->role != Role::Worker ||
        hello.format_version != kDynamicVmFormatVersion ||
        hello.generation == 0 || hello.challenge_counter == 0 ||
        hello.session_id != state_->session_id ||
        hello.previous_state_digest == DynamicHash{} || current_window_id == 0)
        return false;
    std::lock_guard lock(state_->io_mutex);
    std::vector<uint8_t> request;
    appendU16(request, hello.format_version);
    appendArray(request, state_->launch_commitment);
    appendArray(request, hello.session_id);
    appendU64(request, hello.generation);
    appendU64(request, hello.challenge_counter);
    appendArray(request, hello.previous_state_digest);
    appendU64(request, state_->local_start_ticks);
    if (!state_->sendPacket(MessageType::Hello, request)) return false;
    std::vector<uint8_t> response;
    if (!state_->receivePacket(MessageType::HelloAck, response)) return false;
    size_t offset = 0;
    uint64_t challenge_counter = 0;
    uint64_t guardian_identity = 0;
    uint64_t generation = 0;
    uint64_t window_id = 0;
    DynamicHash digest{};
    if (!takeU64(response, offset, challenge_counter) ||
        !takeU64(response, offset, guardian_identity) ||
        !takeU64(response, offset, generation) ||
        !takeU64(response, offset, window_id) ||
        !takeArray(response, offset, digest) || offset != response.size() ||
        challenge_counter != hello.challenge_counter ||
        guardian_identity != state_->peer_start_ticks ||
        generation != hello.generation || window_id != current_window_id ||
        digest != hello.previous_state_digest) {
        state_->poison();
        return false;
    }
    std::vector<uint8_t> confirmation;
    appendU64(confirmation, challenge_counter);
    appendU64(confirmation, guardian_identity);
    appendU64(confirmation, state_->local_start_ticks);
    if (!state_->sendPacket(MessageType::HelloConfirm, confirmation)) return false;
    state_->generation = generation;
    state_->current_window_id = window_id;
    state_->state_digest = digest;
    state_->last_challenge = challenge_counter;
    if (!state_->rotateSessionKeys(
            generation, window_id, challenge_counter, digest))
        return false;
    state_->established.store(true, std::memory_order_release);
    return true;
}

bool GuardianChannel::challenge(uint64_t challenge_counter,
                                uint64_t generation) {
    if (!state_) return false;
    std::lock_guard lock(state_->io_mutex);
    if (state_->role != Role::Guardian || !established() ||
        generation != state_->generation ||
        challenge_counter <= state_->last_challenge) return false;
    std::vector<uint8_t> request;
    appendU64(request, challenge_counter);
    appendU64(request, generation);
    appendU64(request, state_->local_start_ticks);
    if (!state_->sendPacket(MessageType::Challenge, request)) return false;
    std::vector<uint8_t> response;
    if (!state_->receivePacket(MessageType::ChallengeResponse, response))
        return false;
    size_t offset = 0;
    uint64_t response_counter = 0;
    uint64_t process_identity = 0;
    uint64_t response_generation = 0;
    uint64_t window_id = 0;
    DynamicHash digest{};
    if (!takeU64(response, offset, response_counter) ||
        !takeU64(response, offset, process_identity) ||
        !takeU64(response, offset, response_generation) ||
        !takeU64(response, offset, window_id) ||
        !takeArray(response, offset, digest) || offset != response.size() ||
        response_counter != challenge_counter ||
        process_identity != state_->peer_start_ticks ||
        response_generation != generation ||
        window_id != state_->current_window_id || digest != state_->state_digest) {
        state_->poison();
        return false;
    }
    state_->last_challenge = challenge_counter;
    return state_->rotateSessionKeys(
        state_->generation, state_->current_window_id,
        challenge_counter, state_->state_digest);
}

bool GuardianChannel::serveChallenge() {
    if (!state_ || state_->role != Role::Worker || !established()) return false;
    std::lock_guard lock(state_->io_mutex);
    std::vector<uint8_t> request;
    if (!state_->receivePacket(MessageType::Challenge, request)) return false;
    size_t offset = 0;
    uint64_t challenge_counter = 0;
    uint64_t generation = 0;
    uint64_t guardian_identity = 0;
    if (!takeU64(request, offset, challenge_counter) ||
        !takeU64(request, offset, generation) ||
        !takeU64(request, offset, guardian_identity) || offset != request.size() ||
        challenge_counter <= state_->last_challenge ||
        generation != state_->generation ||
        guardian_identity != state_->peer_start_ticks) {
        state_->poison();
        return false;
    }
    std::vector<uint8_t> response;
    appendU64(response, challenge_counter);
    appendU64(response, state_->local_start_ticks);
    appendU64(response, state_->generation);
    appendU64(response, state_->current_window_id);
    appendArray(response, state_->state_digest);
    if (!state_->sendPacket(MessageType::ChallengeResponse, response)) return false;
    state_->last_challenge = challenge_counter;
    return state_->rotateSessionKeys(
        state_->generation, state_->current_window_id,
        challenge_counter, state_->state_digest);
}

bool GuardianChannel::installGeneration(GuardianGeneration generation) {
    const auto encoded_grant = encodeWindowGrant(generation.grant);
    if (!state_) return false;
    std::lock_guard lock(state_->io_mutex);
    if (state_->role != Role::Guardian || !established() ||
        generation.request_id == std::array<uint8_t, 16>{} ||
        generation.sent_at_ns == 0 || encoded_grant.empty() ||
        generation.artifact_hash == DynamicHash{} ||
        generation.grant.session_id != state_->session_id ||
        state_->generation == UINT64_MAX ||
        generation.grant.generation != state_->generation + 1 ||
        generation.grant.window_id != 1 ||
        generation.grant.previous_state_hash != state_->state_digest ||
        generation.grant_key == std::array<uint8_t, 32>{}) return false;
    std::vector<uint8_t> request;
    appendArray(request, generation.request_id);
    appendU64(request, generation.sent_at_ns);
    appendArray(request, generation.artifact_hash);
    appendU16(request, static_cast<uint16_t>(encoded_grant.size()));
    request.insert(request.end(), encoded_grant.begin(), encoded_grant.end());
    appendArray(request, generation.grant_key);
    appendU64(request, state_->local_start_ticks);
    const bool sent = state_->sendPacket(MessageType::InstallGeneration, request);
    OPENSSL_cleanse(request.data(), request.size());
    if (!sent) return false;
    std::vector<uint8_t> response;
    if (!state_->receivePacket(MessageType::InstallAck, response)) return false;
    size_t offset = 0;
    std::array<uint8_t, 16> request_id{};
    uint64_t installed_generation = 0;
    uint64_t window_id = 0;
    DynamicHash artifact_hash{};
    DynamicHash state_digest{};
    uint64_t worker_identity = 0;
    if (!takeArray(response, offset, request_id) ||
        !takeU64(response, offset, installed_generation) ||
        !takeU64(response, offset, window_id) ||
        !takeArray(response, offset, artifact_hash) ||
        !takeArray(response, offset, state_digest) ||
        !takeU64(response, offset, worker_identity) || offset != response.size() ||
        request_id != generation.request_id ||
        installed_generation != generation.grant.generation ||
        window_id != generation.grant.window_id ||
        artifact_hash != generation.artifact_hash ||
        state_digest != generation.grant.next_state_hash ||
        worker_identity != state_->peer_start_ticks) {
        state_->poison();
        return false;
    }
    state_->generation = generation.grant.generation;
    state_->current_window_id = generation.grant.window_id;
    state_->state_digest = generation.grant.next_state_hash;
    return state_->rotateSessionKeys(
        state_->generation, state_->current_window_id,
        state_->last_challenge, state_->state_digest);
}

std::optional<GuardianGeneration> GuardianChannel::receiveGeneration() {
    if (!state_ || state_->role != Role::Worker || !established())
        return std::nullopt;
    std::lock_guard lock(state_->io_mutex);
    std::vector<uint8_t> request;
    if (!state_->receivePacket(MessageType::InstallGeneration, request))
        return std::nullopt;
    GuardianGeneration generation;
    size_t offset = 0;
    uint16_t grant_size = 0;
    uint64_t guardian_identity = 0;
    bool parsed = takeArray(request, offset, generation.request_id) &&
                  takeU64(request, offset, generation.sent_at_ns) &&
                  takeArray(request, offset, generation.artifact_hash) &&
                  takeU16(request, offset, grant_size) &&
                  grant_size != 0 && offset + grant_size <= request.size();
    std::vector<uint8_t> encoded_grant;
    if (parsed) {
        encoded_grant.assign(request.begin() + static_cast<std::ptrdiff_t>(offset),
                             request.begin() + static_cast<std::ptrdiff_t>(offset + grant_size));
        offset += grant_size;
        const auto decoded = decodeWindowGrant(encoded_grant);
        if (decoded) generation.grant = *decoded;
        else parsed = false;
    }
    parsed = parsed && takeArray(request, offset, generation.grant_key) &&
             takeU64(request, offset, guardian_identity) && offset == request.size();
    OPENSSL_cleanse(request.data(), request.size());
    if (!parsed || generation.request_id == std::array<uint8_t, 16>{} ||
        generation.sent_at_ns == 0 || generation.artifact_hash == DynamicHash{} ||
        generation.grant.session_id != state_->session_id ||
        state_->generation == UINT64_MAX ||
        generation.grant.generation != state_->generation + 1 ||
        generation.grant.window_id != 1 ||
        generation.grant.previous_state_hash != state_->state_digest ||
        generation.grant_key == std::array<uint8_t, 32>{} ||
        guardian_identity != state_->peer_start_ticks ||
        encodeWindowGrant(generation.grant) != encoded_grant) {
        state_->poison();
        return std::nullopt;
    }
    auto material = decryptWindowMaterial(generation.grant, generation.grant_key);
    if (!material) {
        state_->poison();
        return std::nullopt;
    }
    OPENSSL_cleanse(&*material, sizeof(*material));
    std::vector<uint8_t> response;
    appendArray(response, generation.request_id);
    appendU64(response, generation.grant.generation);
    appendU64(response, generation.grant.window_id);
    appendArray(response, generation.artifact_hash);
    appendArray(response, generation.grant.next_state_hash);
    appendU64(response, state_->local_start_ticks);
    if (!state_->sendPacket(MessageType::InstallAck, response)) {
        return std::nullopt;
    }
    state_->generation = generation.grant.generation;
    state_->current_window_id = generation.grant.window_id;
    state_->state_digest = generation.grant.next_state_hash;
    if (!state_->rotateSessionKeys(
            state_->generation, state_->current_window_id,
            state_->last_challenge, state_->state_digest))
        return std::nullopt;
    return generation;
}

bool GuardianChannel::shutdown() {
    if (!state_ || state_->role != Role::Guardian || !established()) return false;
    std::lock_guard lock(state_->io_mutex);
    std::vector<uint8_t> payload;
    appendU64(payload, state_->generation);
    appendU64(payload, state_->local_start_ticks);
    const bool sent = state_->sendPacket(MessageType::Shutdown, payload);
    state_->established.store(false, std::memory_order_release);
    return sent;
}

bool GuardianChannel::receiveShutdown() {
    if (!state_ || state_->role != Role::Worker || !established()) return false;
    std::lock_guard lock(state_->io_mutex);
    std::vector<uint8_t> payload;
    if (!state_->receivePacket(MessageType::Shutdown, payload)) return false;
    size_t offset = 0;
    uint64_t generation = 0;
    uint64_t guardian_identity = 0;
    if (!takeU64(payload, offset, generation) ||
        !takeU64(payload, offset, guardian_identity) || offset != payload.size() ||
        generation != state_->generation ||
        guardian_identity != state_->peer_start_ticks) {
        state_->poison();
        return false;
    }
    state_->established.store(false, std::memory_order_release);
    return true;
}

bool GuardianChannel::established() const {
    return state_ && state_->established.load(std::memory_order_acquire) &&
           state_->peerAlive();
}

bool GuardianChannel::poisoned() const {
    return !state_ || state_->poisoned.load(std::memory_order_acquire);
}

GuardianChannel::Role GuardianChannel::role() const {
    return state_ ? state_->role : Role::Guardian;
}

pid_t GuardianChannel::peerPid() const { return state_ ? state_->peer_pid : -1; }

uint64_t GuardianChannel::processIdentity() const {
    return state_ ? state_->peer_start_ticks : 0;
}

void GuardianChannel::close() {
    if (state_) {
        state_->poison();
        state_.reset();
    }
}

std::shared_ptr<GuardianChannelState> GuardianChannel::livenessState() const {
    return state_;
}

uint64_t LeasePin::generation() const {
    return *this ? generation_->number : 0;
}

uint64_t LeasePin::deadlineNs() const {
    return *this ? generation_->deadline_ns : 0;
}

LeasePin::operator bool() const {
    return generation_ && owner_pid_ == ::getpid();
}

#ifdef XOVM_GUARDIAN_TESTING
LeaseState::LeaseState(uint64_t lease_ns)
    : lease_ns_(lease_ns), owner_pid_(::getpid()) {}

LeaseState::LeaseState(uint64_t lease_ns, const GuardianChannel &channel)
    : lease_ns_(lease_ns), owner_pid_(::getpid()),
      channel_(channel.livenessState()), channel_bound_(true) {}
#else
LeaseState::LeaseState(const GuardianChannel &channel)
    : lease_ns_(kLeaseNs), owner_pid_(::getpid()),
      channel_(channel.livenessState()), channel_bound_(true) {}
#endif

bool LeaseState::channelAlive() const {
    if (owner_pid_ != ::getpid()) return false;
    if (!channel_bound_) return true;
    const auto channel = channel_.lock();
    return channel && channel->established.load(std::memory_order_acquire) &&
           channel->peerAlive();
}

std::optional<LeasePin> LeaseState::acquire(uint64_t sent_ns,
                                            uint64_t generation,
                                            uint64_t now_ns,
                                            uint64_t grant_expires_at_ns) {
    std::lock_guard lock(mutex_);
    if (!lease_ns_ || generation == 0 || sent_ns > UINT64_MAX - lease_ns_ ||
        !channelAlive()) return std::nullopt;
    if (highest_generation_ == UINT64_MAX ||
        (highest_generation_ != 0 &&
         (generation != highest_generation_ + 1 || sent_ns < renew_at_ns_)))
        return std::nullopt;
    const uint64_t lease_deadline = sent_ns + lease_ns_;
    const uint64_t deadline = std::min(lease_deadline, grant_expires_at_ns);
    if (deadline <= sent_ns || (now_ns != 0 && now_ns >= deadline))
        return std::nullopt;
    current_ = std::make_shared<const LeasePin::Generation>(
        LeasePin::Generation{generation, deadline});
    highest_generation_ = generation;
    renew_at_ns_ = lease_ns_ > kRenewBeforeNs
        ? lease_deadline - kRenewBeforeNs
        : sent_ns;
    renewal_due_ = false;
    renewal_failed_ = false;
    return LeasePin(current_, owner_pid_);
}

bool LeaseState::renewIfDue(uint64_t now_ns) {
    std::lock_guard lock(mutex_);
    if (!current_ || now_ns < renew_at_ns_ || now_ns >= current_->deadline_ns ||
        !channelAlive()) return false;
    renewal_due_ = true;
    return true;
}

void LeaseState::markRenewalFailed() {
    std::lock_guard lock(mutex_);
    renewal_failed_ = true;
}

std::optional<LeasePin> LeaseState::pin(uint64_t now_ns) const {
    std::lock_guard lock(mutex_);
    if (!current_ || now_ns >= current_->deadline_ns || !channelAlive())
        return std::nullopt;
    return LeasePin(current_, owner_pid_);
}

uint64_t LeaseState::deadlineNs() const {
    std::lock_guard lock(mutex_);
    return current_ ? current_->deadline_ns : 0;
}

uint64_t LeaseState::renewAtNs() const {
    std::lock_guard lock(mutex_);
    return renew_at_ns_;
}

bool LeaseState::needsRenewal() const {
    std::lock_guard lock(mutex_);
    return renewal_due_;
}

} // namespace xovm::material
