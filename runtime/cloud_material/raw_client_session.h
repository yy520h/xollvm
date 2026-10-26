#ifndef XOVM_RAW_CLIENT_SESSION_H
#define XOVM_RAW_CLIENT_SESSION_H

#include "raw_protocol.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <span>
#include <string>
#include <variant>
#include <vector>

namespace xovm::cloud_material {

struct RawClientSessionError {
    std::string code;
};

struct RawClientSessionConfig {
    xovm::material::RawHello hello;
    std::array<uint8_t, 32> server_signing_public_key{};
    std::function<std::variant<std::vector<uint8_t>, RawClientSessionError>(size_t)> random_bytes;
};

class RawClientSession {
public:
    ~RawClientSession();
    RawClientSession(const RawClientSession &) = delete;
    RawClientSession &operator=(const RawClientSession &) = delete;
    RawClientSession(RawClientSession &&other) noexcept;
    RawClientSession &operator=(RawClientSession &&other) noexcept;

    static std::variant<RawClientSession, RawClientSessionError> create(
        const RawClientSessionConfig &config);

    const xovm::material::RawHello &hello() const { return hello_; }
    const std::array<uint8_t, 16> &sessionId() const { return server_hello_.session_id; }
    uint32_t keyVersion() const { return server_hello_.key_version; }
    const std::array<uint8_t, 32> &initialStateCommitment() const {
        return initial_state_commitment_;
    }
    std::variant<std::array<uint8_t, 32>, RawClientSessionError> deriveGrantKey(
        std::span<const uint8_t, 32> request_commitment) const;
    bool acceptServerHello(const xovm::material::RawServerHello &server_hello);
    bool established() const { return established_; }

    std::variant<std::vector<uint8_t>, RawClientSessionError> encrypt(
        xovm::material::RawFrameHeader header, std::span<const uint8_t> plaintext);
    std::variant<std::vector<uint8_t>, RawClientSessionError> decrypt(
        const xovm::material::RawFrameHeader &header, std::span<const uint8_t> ciphertext,
        std::span<const uint8_t, 16> tag);

private:
    RawClientSession() = default;
    void clearSecrets() noexcept;

    xovm::material::RawHello hello_;
    std::array<uint8_t, 32> private_key_{};
    std::array<uint8_t, 32> server_signing_public_key_{};
    xovm::material::RawServerHello server_hello_;
    xovm::material::RawSessionTranscript transcript_;
    xovm::material::RawSessionKeys keys_{};
    std::array<uint8_t, 32> transcript_hash_{};
    std::array<uint8_t, 32> initial_state_commitment_{};
    uint64_t send_sequence_ = 0;
    uint64_t receive_sequence_ = 0;
    bool established_ = false;
};

} // namespace xovm::cloud_material

#endif
