#ifndef XOVM_CLOUD_MATERIAL_BACKEND_RAW_SESSION_H
#define XOVM_CLOUD_MATERIAL_BACKEND_RAW_SESSION_H

#include "../cloud_material/raw_protocol.h"

#include <array>
#include <cstdint>
#include <functional>
#include <span>
#include <string>
#include <variant>
#include <vector>

namespace xovm::cloud_material {

struct RawSessionError {
    std::string code;
};

struct RawSessionConfig {
    std::function<std::variant<std::vector<uint8_t>, RawSessionError>(size_t)> random_bytes;
    std::function<std::variant<std::array<uint8_t, 64>, RawSessionError>(
        std::span<const uint8_t>)> sign;
    std::function<std::variant<uint64_t, RawSessionError>()> trusted_now;
    uint64_t counter = 0;
    uint32_t key_version = 1;
    uint64_t expires_at_ms = 0;
};

class AuthenticatedRawContext final {
public:
    ~AuthenticatedRawContext();
    AuthenticatedRawContext(const AuthenticatedRawContext &) = delete;
    AuthenticatedRawContext &operator=(const AuthenticatedRawContext &) = delete;

    // RawHello values are transcript-bound client claims, not authenticated principals.
    // Dispatchers must still authorize them against the active snapshot and policy.
    const std::string &softwareId() const { return software_id_; }
    const std::string &buildId() const { return build_id_; }
    const std::array<uint8_t, 16> &sessionId() const { return session_id_; }
    uint32_t keyVersion() const { return key_version_; }
    uint64_t expiresAtMs() const { return expires_at_ms_; }
    const std::array<uint8_t, 32> &transcriptHash() const { return transcript_hash_; }
    const std::array<uint8_t, 32> &initialStateCommitment() const {
        return initial_state_commitment_;
    }

    std::variant<std::array<uint8_t, 32>, RawSessionError> deriveGrantKey(
        std::span<const uint8_t, 32> request_commitment) const;

private:
    friend class RawSession;

    AuthenticatedRawContext() = default;
    AuthenticatedRawContext(AuthenticatedRawContext &&other) noexcept;
    AuthenticatedRawContext &operator=(AuthenticatedRawContext &&other) noexcept;
    void clearSecrets() noexcept;

    std::string software_id_;
    std::string build_id_;
    std::array<uint8_t, 16> session_id_{};
    uint32_t key_version_ = 0;
    uint64_t expires_at_ms_ = 0;
    std::array<uint8_t, 32> transcript_hash_{};
    std::array<uint8_t, 32> initial_state_commitment_{};
    std::array<uint8_t, 32> grant_key_root_{};
};

class RawSession {
public:
    ~RawSession();
    RawSession(const RawSession &) = delete;
    RawSession &operator=(const RawSession &) = delete;
    RawSession(RawSession &&other) noexcept;
    RawSession &operator=(RawSession &&other) noexcept;

    static std::variant<RawSession, RawSessionError> accept(
        const xovm::material::RawHello &hello, const RawSessionConfig &config);

    const xovm::material::RawServerHello &serverHello() const { return server_hello_; }
    const xovm::material::RawSessionTranscript &transcript() const { return transcript_; }
    const AuthenticatedRawContext &authenticatedContext() const { return authenticated_context_; }

    std::variant<std::vector<uint8_t>, RawSessionError> encrypt(
        xovm::material::RawFrameHeader header, std::span<const uint8_t> plaintext);
    std::variant<std::vector<uint8_t>, RawSessionError> decrypt(
        const xovm::material::RawFrameHeader &header, std::span<const uint8_t> ciphertext,
        std::span<const uint8_t, 16> tag);
    std::variant<std::monostate, RawSessionError> checkFresh() const;

private:
    RawSession() = default;
    void clearSecrets() noexcept;

    xovm::material::RawServerHello server_hello_;
    xovm::material::RawSessionTranscript transcript_;
    xovm::material::RawSessionKeys keys_;
    std::array<uint8_t, 32> transcript_hash_{};
    AuthenticatedRawContext authenticated_context_;
    std::function<std::variant<uint64_t, RawSessionError>()> trusted_now_;
    uint64_t send_sequence_ = 0;
    uint64_t receive_sequence_ = 0;
};

} // namespace xovm::cloud_material

#endif
