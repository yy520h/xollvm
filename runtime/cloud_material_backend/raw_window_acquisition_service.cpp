#include "raw_window_acquisition_service.h"

#include "../cloud_material/dynamic_vm_window_provider.h"

#include <algorithm>
#include <array>
#include <exception>
#include <limits>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <span>
#include <stdexcept>
#include <string_view>

namespace xovm::cloud_material {
namespace {

using xovm::material::DynamicHash;
using xovm::material::WindowAcquireRequest;

constexpr std::string_view kRequestDigestDomain =
    "xovm/raw-window-acquire/request/v3";
constexpr std::string_view kNextStateDomain =
    "xovm/raw-window-acquire/next-state/v3";

class SensitiveIssueInput final {
public:
    ~SensitiveIssueInput() {
        OPENSSL_cleanse(value.session_secret.data(), value.session_secret.size());
        if (!value.material.empty())
            OPENSSL_cleanse(value.material.data(), value.material.size());
        value.material.clear();
    }

    SensitiveIssueInput(const SensitiveIssueInput &) = delete;
    SensitiveIssueInput &operator=(const SensitiveIssueInput &) = delete;
    SensitiveIssueInput() = default;

    xovm::material::WindowIssueInput value;
};

class SensitiveProvision final {
public:
    explicit SensitiveProvision(xovm::material::WindowMaterialProvisionV3 provision)
        : value(std::move(provision)) {}
    ~SensitiveProvision() { xovm::material::secureClear(value); }

    SensitiveProvision(const SensitiveProvision &) = delete;
    SensitiveProvision &operator=(const SensitiveProvision &) = delete;

    xovm::material::WindowMaterialProvisionV3 value;
};

std::string hex(std::span<const std::uint8_t> bytes) {
    constexpr char digits[] = "0123456789abcdef";
    std::string result;
    result.reserve(bytes.size() * 2);
    for (const auto byte : bytes) {
        result.push_back(digits[byte >> 4]);
        result.push_back(digits[byte & 15]);
    }
    return result;
}

void append64(std::vector<std::uint8_t> &output, std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8)
        output.push_back(static_cast<std::uint8_t>(value >> shift));
}

void appendFramed(std::vector<std::uint8_t> &output,
                  std::span<const std::uint8_t> value) {
    const auto size = static_cast<std::uint32_t>(value.size());
    output.push_back(static_cast<std::uint8_t>(size >> 24));
    output.push_back(static_cast<std::uint8_t>(size >> 16));
    output.push_back(static_cast<std::uint8_t>(size >> 8));
    output.push_back(static_cast<std::uint8_t>(size));
    output.insert(output.end(), value.begin(), value.end());
}

std::variant<DynamicHash, BackendError> sha256(
    std::string_view domain, std::span<const std::uint8_t> canonical) {
    std::vector<std::uint8_t> framed;
    framed.reserve(domain.size() + sizeof(std::uint32_t) + canonical.size());
    framed.insert(framed.end(), domain.begin(), domain.end());
    appendFramed(framed, canonical);
    DynamicHash digest{};
    unsigned int size = 0;
    const bool ok = EVP_Digest(framed.data(), framed.size(), digest.data(), &size,
                               EVP_sha256(), nullptr) == 1 &&
                    size == digest.size();
    OPENSSL_cleanse(framed.data(), framed.size());
    if (!ok) return BackendError{"key_unavailable"};
    return digest;
}

std::variant<DynamicHash, BackendError> nextState(
    const WindowAcquireRequest &request,
    const std::array<std::uint8_t, 16> &sessionId,
    const DynamicHash &requestDigest) {
    std::vector<std::uint8_t> canonical;
    canonical.reserve(request.previous_state_hash.size() + sessionId.size() +
                      sizeof(request.generation) + sizeof(request.window_id) +
                      request.region_id.size() + requestDigest.size());
    canonical.insert(canonical.end(), request.previous_state_hash.begin(),
                     request.previous_state_hash.end());
    canonical.insert(canonical.end(), sessionId.begin(), sessionId.end());
    append64(canonical, request.generation);
    append64(canonical, request.window_id);
    canonical.insert(canonical.end(), request.region_id.begin(),
                     request.region_id.end());
    canonical.insert(canonical.end(), requestDigest.begin(), requestDigest.end());
    return sha256(kNextStateDomain, canonical);
}

BackendError normalizeStateError(const BackendError &error) {
    static constexpr std::array<std::string_view, 11> allowed{
        "request_conflict", "request_retired", "session_closed", "unauthorized",
        "window_chain_mismatch", "window_invalid", "state_capacity",
        "counter_exhausted", "commit_failed", "build_unavailable",
        "authority_unavailable"};
    if (std::find(allowed.begin(), allowed.end(), error.code) != allowed.end())
        return error;
    return BackendError{"authority_unavailable"};
}

BackendError normalizeBuilderError(const BackendError &error) {
    static constexpr std::array<std::string_view, 3> allowed{
        "build_unavailable", "authority_unavailable", "key_unavailable"};
    if (std::find(allowed.begin(), allowed.end(), error.code) != allowed.end())
        return error;
    return BackendError{"authority_unavailable"};
}

bool allZero(std::span<const std::uint8_t> bytes) {
    return std::all_of(bytes.begin(), bytes.end(),
                       [](const auto byte) { return byte == 0; });
}

bool sameSelectorGraph(
    const xovm::material::DynamicVmWindowSelectorV3 &left,
    const xovm::material::DynamicVmWindowSelectorV3 &right) {
    return left.format_version == right.format_version &&
           left.execution_schema_version == right.execution_schema_version &&
           left.profile == right.profile && left.abi_id == right.abi_id &&
           left.abi_hash == right.abi_hash &&
           left.graph_commitment == right.graph_commitment;
}

bool validProvisionChain(
    const xovm::material::WindowMaterialProvisionV3 &provision) {
    if (!sameSelectorGraph(provision.selector, provision.entry_selector))
        return false;
    if (provision.selector.status ==
        xovm::material::ContinuationNodeStatusV2::Return)
        return !provision.next_selector.has_value();
    if (!provision.next_selector ||
        !xovm::material::validateDynamicVmWindowSelectorV3(
            *provision.next_selector) ||
        !sameSelectorGraph(provision.selector, *provision.next_selector))
        return false;
    return provision.selector.next_node_id ==
           provision.next_selector->node_id;
}

std::variant<std::string, BackendError> selectorCommitment(
    const xovm::material::DynamicVmWindowSelectorV3 &selector) {
    const auto encoded = xovm::material::encodeDynamicVmWindowSelectorV3(selector);
    if (encoded.size() != xovm::material::kDynamicVmWindowSelectorV3EncodedSize)
        return BackendError{"authority_unavailable"};
    auto digest = sha256("xovm/raw-window-acquire/selector/v3", encoded);
    if (const auto *error = std::get_if<BackendError>(&digest)) return *error;
    return hex(std::get<DynamicHash>(digest));
}

} // namespace

std::variant<std::vector<std::uint8_t>, BackendError>
RawWindowAcquisitionService::acquire(
    const AuthenticatedRawContext &context,
    const xovm::material::WindowAcquireRequest &request) {
    try {
        if (!providers_.snapshots || !providers_.anonymous_policy ||
            !providers_.sessions || !providers_.trusted_now ||
            !providers_.build_material || providers_.rate_budget == 0 ||
            providers_.window_ttl_ms == 0 ||
            providers_.window_ttl_ms > kMaximumWindowTtlMs)
            return BackendError{"authority_unavailable"};

        const auto canonicalRequest = xovm::material::encodeWindowAcquireRequest(request);
        if (canonicalRequest.size() != xovm::material::kWindowAcquireRequestEncodedSize)
            return BackendError{"invalid_request"};

        auto nowResult = providers_.trusted_now();
        if (const auto *error = std::get_if<BackendError>(&nowResult))
            return normalizeBuilderError(*error);
        const auto now = std::get<std::uint64_t>(nowResult);

        const auto buildId = hex(request.build_id);
        const auto regionId = hex(request.region_id);
        const auto artifactHash = hex(request.artifact_hash);
        const auto sessionId = hex(context.sessionId());
        const auto requestId = hex(request.request_id);
        if (request.format_version !=
                xovm::material::kDynamicVmSelectiveFormatVersionV3 ||
            !xovm::material::validateDynamicVmWindowSelectorV3(request.selector) ||
            allZero(request.artifact_hash) || context.buildId() != buildId ||
            context.softwareId().empty() || allZero(context.sessionId()))
            return BackendError{"unauthorized"};
        auto digestResult = sha256(kRequestDigestDomain, canonicalRequest);
        if (const auto *error = std::get_if<BackendError>(&digestResult)) return *error;
        const auto requestDigest = std::get<DynamicHash>(digestResult);

        RequestFacts facts;
        facts.request_id = requestId;
        facts.request_digest = hex(requestDigest);
        facts.software_id = context.softwareId();
        facts.build_id = buildId;
        facts.region_id = regionId;
        facts.mode = "lease";
        facts.type = "material.issue";

        if (auto cached = providers_.sessions->lookupRawWindowRequest(
                sessionId, facts.software_id, facts.build_id, facts.region_id,
                facts.request_id, facts.request_digest, now)) {
            if (const auto *error = std::get_if<BackendError>(&*cached))
                return normalizeStateError(*error);
            const auto &response = std::get<StateResult>(*cached).response;
            std::vector<std::uint8_t> exact;
            exact.reserve(response.size());
            for (const auto byte : response)
                exact.push_back(std::to_integer<std::uint8_t>(byte));
            return exact;
        }
        if (context.expiresAtMs() <= now)
            return BackendError{"session_closed"};
        if (now > std::numeric_limits<std::uint64_t>::max() -
                      providers_.window_ttl_ms)
            return BackendError{"authority_unavailable"};

        auto snapshot = providers_.snapshots->acquire();
        if (!snapshot || !providers_.snapshots->ready())
            return BackendError{"authority_unavailable"};
        const auto *build = snapshot->find(buildId);
        if (!build || build->registration.build_id != buildId ||
            build->registration.software_id != context.softwareId() ||
            build->registration.verifier_sidecars.find(regionId) ==
                build->registration.verifier_sidecars.end())
            return BackendError{"build_unavailable"};
        facts.final_artifact_hash = build->final_artifact_hash;
        if (artifactHash != facts.final_artifact_hash)
            return BackendError{"build_unavailable"};

        auto reservationResult = providers_.anonymous_policy->reserve(
            *snapshot, facts, now, providers_.rate_budget);
        if (const auto *error = std::get_if<BackendError>(&reservationResult))
            return normalizeStateError(*error);
        auto reservation = std::get<AnonymousPolicy::Reservation>(
            std::move(reservationResult));
        const auto &grant = reservation.grant();
        if (grant.buildId() != facts.build_id ||
            grant.requestDigest() != facts.request_digest ||
            grant.validUntilMs() <= now ||
            !grant.scopes().contains("material.issue"))
            return BackendError{"unauthorized"};

        const auto expiresAt = std::min(
            {context.expiresAtMs(), grant.validUntilMs(),
             now + providers_.window_ttl_ms});
        if (expiresAt <= now) return BackendError{"unauthorized"};

        auto issuance = providers_.snapshots->beginIssuance(snapshot, buildId);
        if (!issuance) return BackendError{"build_unavailable"};

        auto transactNowResult = providers_.trusted_now();
        if (const auto *error = std::get_if<BackendError>(&transactNowResult))
            return normalizeBuilderError(*error);
        const auto transactNow = std::get<std::uint64_t>(transactNowResult);
        if (transactNow < now || transactNow >= expiresAt)
            return BackendError{"authority_unavailable"};

        BackendError callbackError{"authority_unavailable"};
        bool callbackFailed = false;
        auto stateResult = providers_.sessions->transact(
            facts, grant, transactNow, [&](SessionState::Transaction &transaction) {
                const auto selectorResult = selectorCommitment(request.selector);
                if (const auto *error = std::get_if<BackendError>(&selectorResult)) {
                    callbackError = *error;
                    callbackFailed = true;
                    throw std::runtime_error("raw_window_callback_failed");
                }
                WindowPreflightInput preflight;
                preflight.session_id = sessionId;
                preflight.region_id = regionId;
                preflight.generation = request.generation;
                preflight.window_id = request.window_id;
                preflight.previous_state = hex(request.previous_state_hash);
                preflight.selector_commitment = std::get<std::string>(selectorResult);
                preflight.expires_at_ms = expiresAt;
                const auto grantExpiry =
                    transaction.preflightWindow(std::move(preflight));
                if (transactNow >= grantExpiry) {
                    callbackError = BackendError{"window_chain_mismatch"};
                    callbackFailed = true;
                    throw std::runtime_error("raw_window_callback_failed");
                }

                auto materialResult = providers_.build_material(request);
                if (const auto *error = std::get_if<BackendError>(&materialResult)) {
                    callbackError = normalizeBuilderError(*error);
                    callbackFailed = true;
                    throw std::runtime_error("raw_window_callback_failed");
                }
                SensitiveProvision provision(
                    std::get<xovm::material::WindowMaterialProvisionV3>(
                        std::move(materialResult)));
                if (provision.value.artifact_hash != request.artifact_hash ||
                    provision.value.selector != request.selector ||
                    !xovm::material::validateDynamicVmWindowSelectorV3(
                        provision.value.selector) ||
                    !xovm::material::validateDynamicVmWindowSelectorV3(
                        provision.value.entry_selector) ||
                    allZero(provision.value.material.window) ||
                    !validProvisionChain(provision.value)) {
                    callbackError = BackendError{"authority_unavailable"};
                    callbackFailed = true;
                    throw std::runtime_error("raw_window_callback_failed");
                }

                auto commitNowResult = providers_.trusted_now();
                if (const auto *error = std::get_if<BackendError>(&commitNowResult)) {
                    callbackError = normalizeBuilderError(*error);
                    callbackFailed = true;
                    throw std::runtime_error("raw_window_callback_failed");
                }
                const auto commitNow = std::get<std::uint64_t>(commitNowResult);
                if (commitNow < transactNow || commitNow >= grantExpiry) {
                    callbackError = BackendError{"authority_unavailable"};
                    callbackFailed = true;
                    throw std::runtime_error("raw_window_callback_failed");
                }

                auto nextResult = nextState(
                    request, context.sessionId(), requestDigest);
                if (const auto *error = std::get_if<BackendError>(&nextResult)) {
                    callbackError = *error;
                    callbackFailed = true;
                    throw std::runtime_error("raw_window_callback_failed");
                }
                const auto next = std::get<DynamicHash>(nextResult);
                if (allZero(next)) {
                    callbackError = BackendError{"key_unavailable"};
                    callbackFailed = true;
                    throw std::runtime_error("raw_window_callback_failed");
                }

                auto keyResult = context.deriveGrantKey(requestDigest);
                if (const auto *error = std::get_if<RawSessionError>(&keyResult)) {
                    (void)error;
                    callbackError = BackendError{"key_unavailable"};
                    callbackFailed = true;
                    throw std::runtime_error("raw_window_callback_failed");
                }
                auto &grantKey = std::get<std::array<std::uint8_t, 32>>(keyResult);

                SensitiveIssueInput input;
                input.value.build_id = request.build_id;
                input.value.region_id = request.region_id;
                input.value.artifact_hash = request.artifact_hash;
                input.value.selector = request.selector;
                input.value.session_id = context.sessionId();
                input.value.session_secret = grantKey;
                OPENSSL_cleanse(grantKey.data(), grantKey.size());
                input.value.generation = request.generation;
                input.value.window_id = request.window_id;
                input.value.previous_state_hash = request.previous_state_hash;
                input.value.next_state_hash = next;
                input.value.now_ms = commitNow;
                input.value.expires_at_ms = grantExpiry;
                input.value.key_version = context.keyVersion();
                static_assert(sizeof(provision.value.material) ==
                              xovm::material::kWindowMaterialSize);
                const auto materialBytes = std::span<const std::uint8_t>(
                    reinterpret_cast<const std::uint8_t *>(
                        &provision.value.material),
                    sizeof(provision.value.material));
                input.value.material.assign(materialBytes.begin(), materialBytes.end());

                auto windowGrant = xovm::material::issueWindowGrant(input.value);
                if (!windowGrant) {
                    callbackError = BackendError{"key_unavailable"};
                    callbackFailed = true;
                    throw std::runtime_error("raw_window_callback_failed");
                }
                auto encoded = xovm::material::encodeWindowGrant(*windowGrant);
                if (encoded.empty()) {
                    callbackError = BackendError{"key_unavailable"};
                    callbackFailed = true;
                    throw std::runtime_error("raw_window_callback_failed");
                }

                WindowFinalizeInput finalize;
                finalize.next_state = hex(next);
                finalize.selector_is_entry =
                    provision.value.selector == provision.value.entry_selector;
                if (provision.value.next_selector) {
                    const auto successor =
                        selectorCommitment(*provision.value.next_selector);
                    if (const auto *error = std::get_if<BackendError>(&successor)) {
                        callbackError = *error;
                        callbackFailed = true;
                        throw std::runtime_error("raw_window_callback_failed");
                    }
                    finalize.next_selector_commitment =
                        std::get<std::string>(successor);
                }
                finalize.encoded_response.reserve(encoded.size());
                for (const auto byte : encoded)
                    finalize.encoded_response.push_back(static_cast<std::byte>(byte));
                return transaction.finalizeWindow(std::move(finalize));
            });
        if (const auto *error = std::get_if<BackendError>(&stateResult)) {
            if (callbackFailed) return callbackError;
            return normalizeStateError(*error);
        }
        if (!reservation.commit()) std::terminate();
        issuance.finishCommit();

        const auto &committed = std::get<StateResult>(stateResult).response;
        std::vector<std::uint8_t> exact;
        exact.reserve(committed.size());
        for (const auto byte : committed)
            exact.push_back(std::to_integer<std::uint8_t>(byte));
        return exact;
    } catch (...) {
        return BackendError{"authority_unavailable"};
    }
}

} // namespace xovm::cloud_material
