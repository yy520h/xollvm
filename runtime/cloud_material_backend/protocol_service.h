#ifndef XOVM_CLOUD_MATERIAL_BACKEND_PROTOCOL_SERVICE_H
#define XOVM_CLOUD_MATERIAL_BACKEND_PROTOCOL_SERVICE_H

#include "auth_policy.h"
#include "session_state.h"
#include "http_contract.h"
#include "response_crypto.h"

namespace xovm::cloud_material {

using Bytes = std::vector<std::byte>;

class ProtocolService {
public:
    using Issue = std::function<std::variant<Bytes, BackendError>(
        const Request &, const AnonymousGrant &, SessionState::Transaction &)>;
    using TrustedNow = std::function<std::variant<std::uint64_t, BackendError>()>;
    using RandomBytes = std::function<std::variant<Bytes, BackendError>(std::size_t)>;
    struct ControlAuthorization {
        std::string counter_epoch;
        std::uint64_t auth_valid_until_ms = 0;
        std::uint32_t control_valid_for_ms = 0;
    };
    using AuthorizeControl = std::function<std::variant<ControlAuthorization, BackendError>(
        const Request &, const RequestFacts &, std::uint64_t)>;
    struct IssuedPayload {
        nlohmann::json payload;
        nlohmann::json binding;
        std::string session_id;
        std::string counter_epoch;
        std::uint64_t counter = 0;
        std::uint64_t session_valid_until_ms = 0;
    };
    using BuildPayload = std::function<std::variant<IssuedPayload, BackendError>(
        const Request &, const RequestFacts &, const BuildSnapshot &, SessionState::Transaction &)>;
    struct Providers {
        RelayAuthenticator *relay_authenticator = nullptr;
        AnonymousPolicy *anonymous_policy = nullptr;
        SnapshotManager *snapshots = nullptr;
        SessionState *state = nullptr;
        TrustedNow trusted_now;
        RandomBytes random_bytes;
        AuthorizeControl authorize_control;
        SigningMetadata signing;
        SignEd25519 sign;
        Issue issue;
        BuildPayload build_payload;
    };

    ProtocolService() = default;
    explicit ProtocolService(Providers providers) : providers_(std::move(providers)) {}
    std::variant<Bytes, BackendError> handle(
        std::span<const std::byte> requestBytes, const std::string &relayCredential);

    std::variant<Bytes, BackendError> handle(
        const Request &request, const AnonymousGrant &grant, SnapshotManager &snapshots,
        SessionState &state, std::uint64_t trustedNow, const Issue &issue,
        SnapshotManager::SnapshotHandle snapshot = {});
    std::variant<std::monostate, BackendError> authorizeMode(
        const RequestFacts &facts) const;

private:
    Providers providers_;
};

} // namespace xovm::cloud_material

#endif
