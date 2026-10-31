#ifndef XOVM_MATERIAL_PROTOCOL_H
#define XOVM_MATERIAL_PROTOCOL_H

#include "material_package.h"
#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <variant>
#include <vector>

namespace xovm::material {

struct ProtocolAccess;
class PendingRequest;
class VerifiedPackage;

inline constexpr size_t kMaxMaterialResponse = 16 * 1024 * 1024;

struct ProtocolError {
    std::string code;
};

struct InstalledTrust {
    std::string software_id;
    std::string root_key_id;
    std::array<uint8_t, 32> root_public_key;
    uint64_t trusted_lower_ms;
    uint64_t trusted_upper_ms;
};

class VerifiedTrustBundle {
public:
    VerifiedTrustBundle(VerifiedTrustBundle &&) noexcept = default;
    VerifiedTrustBundle &operator=(VerifiedTrustBundle &&) noexcept = default;
    VerifiedTrustBundle(const VerifiedTrustBundle &) = delete;
    VerifiedTrustBundle &operator=(const VerifiedTrustBundle &) = delete;

private:
    struct SigningKey {
        std::string key_id;
        std::array<uint8_t, 32> public_key{};
        uint64_t not_before_ms = 0;
        uint64_t signing_until_ms = 0;
        uint64_t not_after_ms = 0;
        std::string status;
    };
    struct Token {};
    VerifiedTrustBundle(Token, std::vector<SigningKey> keys, uint64_t trustEpoch,
                        std::array<uint8_t, 32> counterEpoch,
                        uint64_t issuedAtMs, uint64_t validUntilMs);

    std::vector<SigningKey> keys_;
    uint64_t trust_epoch_ = 0;
    std::array<uint8_t, 32> counter_epoch_{};
    uint64_t valid_until_ms_ = 0;

    friend struct ProtocolAccess;
};

using TrustBundleResult = std::variant<VerifiedTrustBundle, ProtocolError>;
TrustBundleResult verifyTrustBundle(std::span<const uint8_t> bytes,
                                    const InstalledTrust &installed);

struct ExpectedMaterial {
    std::string software_id;
    std::string build_id;
    std::string final_artifact_hash;
    std::string session_id;
    std::string counter_epoch;
    std::string region_id;
    std::string engine_abi_hash;
    std::string mode;
};

class PendingRequest {
public:
    PendingRequest(std::vector<uint8_t> canonicalRequest,
                   std::array<uint8_t, 32> clientPrivateKey,
                   VerifiedTrustBundle trustBundle, ExpectedMaterial expected,
                   uint64_t sentBootNs, uint64_t receivedBootNs);
    PendingRequest(PendingRequest &&) = delete;
    PendingRequest &operator=(PendingRequest &&) = delete;
    PendingRequest(const PendingRequest &) = delete;
    PendingRequest &operator=(const PendingRequest &) = delete;
    ~PendingRequest();

private:
    std::vector<uint8_t> request_bytes_;
    std::array<uint8_t, 32> client_private_key_{};
    VerifiedTrustBundle trust_bundle_;
    ExpectedMaterial expected_;
    uint64_t sent_boot_ns_ = 0;
    uint64_t received_boot_ns_ = 0;
    bool consumed_ = false;

    friend struct ProtocolAccess;
};

class VerifiedPackage {
public:
    VerifiedPackage(VerifiedPackage &&) noexcept = default;
    VerifiedPackage &operator=(VerifiedPackage &&) noexcept = default;
    VerifiedPackage(const VerifiedPackage &) = delete;
    VerifiedPackage &operator=(const VerifiedPackage &) = delete;
    const ParsedPackage &package() const { return package_; }
    uint64_t sentBootNs() const { return sent_boot_ns_; }
    uint64_t receivedBootNs() const { return received_boot_ns_; }
    ~VerifiedPackage();

private:
    struct Token {};
    explicit VerifiedPackage(Token, ParsedPackage package, uint64_t sentBootNs,
                             uint64_t receivedBootNs)
        : package_(std::move(package)), sent_boot_ns_(sentBootNs),
          received_boot_ns_(receivedBootNs) {}
    ParsedPackage package_;
    uint64_t sent_boot_ns_ = 0;
    uint64_t received_boot_ns_ = 0;

    friend struct ProtocolAccess;
};

using AuthenticationResult = std::variant<VerifiedPackage, ProtocolError>;
AuthenticationResult authenticateResponse(std::span<const uint8_t> response,
                                           PendingRequest &pending);

} // namespace xovm::material
#endif
