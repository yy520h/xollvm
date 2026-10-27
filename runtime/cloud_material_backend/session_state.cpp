#include "session_state.h"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <limits>
#include <string_view>
#include <unordered_set>

namespace xovm::cloud_material {

namespace {
using Json = nlohmann::json;

constexpr std::size_t kMaxSessions = 4096;
constexpr std::size_t kMaxReplies = 4096;
constexpr std::size_t kMaxRawRegistrations = 4096;
constexpr std::size_t kMaxClaims = 32768;
constexpr std::size_t kMaxGenerations = 16384;
constexpr std::size_t kMaxIdentityBytes = 1024;
constexpr std::size_t kMaxChainStateBytes = 256;
constexpr std::size_t kMaxWindowResponseBytes = 512 * 1024;
constexpr std::size_t kMaxRetainedBytes = 8 * 1024 * 1024;
constexpr std::string_view kRawTransportKind = "raw";

bool boundedString(const std::string &value, std::size_t maximum, bool allowEmpty = false) {
    return (allowEmpty || !value.empty()) && value.size() <= maximum;
}

bool canonicalHex(const std::string &value, std::size_t size, bool rejectZero = true) {
    if (value.size() != size || !std::all_of(value.begin(), value.end(), [](char character) {
            return (character >= '0' && character <= '9') ||
                   (character >= 'a' && character <= 'f');
        }))
        return false;
    return !rejectZero || std::any_of(value.begin(), value.end(),
        [](char character) { return character != '0'; });
}

bool canonicalIdentity(const std::string &value) {
    return !value.empty() && value.size() <= 64 &&
        ((value.front() >= 'A' && value.front() <= 'Z') ||
         (value.front() >= 'a' && value.front() <= 'z') ||
         (value.front() >= '0' && value.front() <= '9')) &&
        std::all_of(value.begin(), value.end(), [](char character) {
            return (character >= 'A' && character <= 'Z') ||
                   (character >= 'a' && character <= 'z') ||
                   (character >= '0' && character <= '9') || character == '.' ||
                   character == '_' || character == '-';
        });
}

bool canonicalRawFacts(const RequestFacts &facts) {
    return facts.type == "session.open" && facts.region_id.empty() && facts.mode.empty() &&
        canonicalIdentity(facts.software_id) && canonicalHex(facts.build_id, 64) &&
        canonicalHex(facts.final_artifact_hash, 64) &&
        canonicalHex(facts.request_id, 32) && canonicalHex(facts.request_digest, 64);
}

StateOutcome stateError(std::string code) {
    StateOutcome result;
    result.emplace<BackendError>();
    std::get<BackendError>(result).code = std::move(code);
    return result;
}

bool addRetained(std::size_t &total, std::size_t bytes) {
    if (bytes > kMaxRetainedBytes || total > kMaxRetainedBytes - bytes) return false;
    total += bytes;
    return true;
}

Json bytesJson(std::span<const std::byte> bytes) {
    Json result = Json::array();
    for (const auto byte : bytes) result.push_back(std::to_integer<std::uint8_t>(byte));
    return result;
}

std::vector<std::byte> bytesFromJson(const Json &value) {
    if (!value.is_array() || value.size() > kMaxWalPayload) throw std::runtime_error("wal_state_invalid");
    std::vector<std::byte> result;
    result.reserve(value.size());
    for (const auto &item : value) {
        if (!item.is_number_unsigned() || item.get<unsigned>() > 255)
            throw std::runtime_error("wal_state_invalid");
        result.push_back(static_cast<std::byte>(item.get<unsigned>()));
    }
    return result;
}

std::string makeRequestKey(const RequestFacts &facts) {
    return facts.software_id + ":" + facts.build_id + ":" +
        facts.final_artifact_hash + ":" + facts.request_id;
}
}

SessionState::SessionState(StateWal *wal) : wal_(wal) {}

SessionState::Transaction::Transaction(SessionState &state, const RequestFacts &facts,
                                       const std::string &subjectId, std::uint64_t now)
    : state_(state), facts_(facts), subject_id_(subjectId), now_(now) {}

StateResult SessionState::Transaction::allocate(const std::string &sessionId,
                                                const std::string &regionId,
                                                const std::string &clientNonce,
                                                const std::string &clientEphemeralKey) {
    const auto scope = facts_.build_id + ":" + sessionId + ":" + regionId;
    const auto session = state_.sessions_.find(sessionId);
    if (session == state_.sessions_.end() || session->second.closed ||
        session->second.valid_until_ms <= now_)
        throw std::runtime_error("session_closed");
    if (session->second.build_id != facts_.build_id ||
        session->second.software_id != facts_.software_id ||
        session->second.artifact_hash != facts_.final_artifact_hash ||
        session->second.subject_id != subject_id_)
        throw std::runtime_error("unauthorized");
    for (const auto &[label, value] : std::vector<std::pair<std::string, std::string>>{
             {"client_nonce", clientNonce}, {"client_key", clientEphemeralKey}}) {
        const auto key = label + ":" + scope + ":" + value;
        if (state_.claims_.contains(key)) throw std::runtime_error("replay_detected");
        state_.claims_[key] = facts_.request_digest;
    }
    auto &generation = state_.generations_[scope];
    if (generation == UINT64_MAX || state_.next_counter_ == UINT64_MAX)
        throw std::runtime_error("counter_exhausted");
    ++generation;
    StateResult result;
    result.generation = generation;
    result.counter = state_.next_counter_++;
    result.response = std::move(response_);
    result.session_id = sessionId;
    result.counter_epoch = session->second.counter_epoch;
    result.valid_until_ms = session->second.valid_until_ms;
    changed_ = true;
    return result;
}

StateResult SessionState::Transaction::claimServer(const std::string &serverNonce,
                                                   const std::string &serverEphemeralKey) {
    for (const auto &[label, value] : std::vector<std::pair<std::string, std::string>>{
             {"server_nonce", serverNonce}, {"server_key", serverEphemeralKey}}) {
        const auto key = label + ":" + facts_.build_id + ":" + value;
        if (state_.claims_.contains(key)) throw std::runtime_error("invalid_key");
        state_.claims_[key] = facts_.request_digest;
    }
    return {};
}

void SessionState::Transaction::preflightWindow(WindowPreflightInput input) {
    if (window_preflight_) throw std::runtime_error("window_invalid");
    if (!boundedString(input.session_id, kMaxIdentityBytes) ||
        !boundedString(input.region_id, kMaxIdentityBytes) ||
        !boundedString(input.previous_state, kMaxChainStateBytes) ||
        input.generation == 0 || input.window_id == 0 || input.expires_at_ms <= now_)
        throw std::runtime_error("window_invalid");

    const auto session = state_.sessions_.find(input.session_id);
    if (session == state_.sessions_.end() || session->second.closed ||
        session->second.valid_until_ms <= now_ || input.expires_at_ms > session->second.valid_until_ms)
        throw std::runtime_error("session_closed");
    if (session->second.build_id != facts_.build_id ||
        session->second.software_id != facts_.software_id ||
        session->second.artifact_hash != facts_.final_artifact_hash ||
        session->second.subject_id != subject_id_ || input.region_id != facts_.region_id)
        throw std::runtime_error("unauthorized");

    const auto current = state_.windows_.find(input.session_id);
    if (current == state_.windows_.end()) {
        // Generation intentionally stays fixed for this slice. Raw registrations
        // durably anchor genesis; legacy registrations remain externally anchored.
        if (input.window_id != 1 ||
            (!session->second.initial_state_commitment.empty() &&
             input.previous_state != session->second.initial_state_commitment))
            throw std::runtime_error("window_chain_mismatch");
        if (state_.windows_.size() >= kMaxSessions) throw std::runtime_error("state_capacity");
    } else {
        const auto &record = current->second;
        if (record.region_id != input.region_id || record.generation != input.generation ||
            record.expires_at_ms <= now_ || record.window_id == UINT64_MAX ||
            input.window_id != record.window_id + 1 || input.previous_state != record.state)
            throw std::runtime_error("window_chain_mismatch");
    }
    window_preflight_ = std::move(input);
}

StateResult SessionState::Transaction::finalizeWindow(WindowFinalizeInput input) {
    if (!window_preflight_) throw std::runtime_error("window_invalid");
    if (!boundedString(input.next_state, kMaxChainStateBytes) ||
        input.encoded_response.empty() || input.encoded_response.size() > kMaxWindowResponseBytes)
        throw std::runtime_error("window_invalid");

    auto preflight = std::move(*window_preflight_);
    auto current = state_.windows_.find(preflight.session_id);
    if (current == state_.windows_.end()) {
        state_.windows_.emplace(preflight.session_id, WindowRecord{
            preflight.region_id, preflight.generation, preflight.window_id,
            std::move(input.next_state), preflight.expires_at_ms});
    } else {
        current->second.window_id = preflight.window_id;
        current->second.state = std::move(input.next_state);
        current->second.expires_at_ms = preflight.expires_at_ms;
    }
    window_preflight_.reset();
    response_ = std::move(input.encoded_response);
    return StateResult{.generation = preflight.generation,
                       .session_id = std::move(preflight.session_id),
                       .valid_until_ms = preflight.expires_at_ms};
}

StateResult SessionState::Transaction::openSession(
    const std::string &sessionId, const std::string &counterEpoch,
    std::uint64_t validUntilMs, const std::string &serverNonce,
    const std::string &serverEphemeralKey, const std::string &clientNonce,
    const std::string &clientEphemeralKey) {
    if (validUntilMs <= now_ || state_.sessions_.contains(sessionId))
        throw std::runtime_error("session_closed");
    claimServer(serverNonce, serverEphemeralKey);
    const auto nonceKey = "client_nonce:" + facts_.build_id + ":" + clientNonce;
    const auto keyKey = "client_key:" + facts_.build_id + ":" + clientEphemeralKey;
    if (state_.claims_.contains(nonceKey) || state_.claims_.contains(keyKey))
        throw std::runtime_error("replay_detected");
    state_.claims_[nonceKey] = facts_.request_digest;
    state_.claims_[keyKey] = facts_.request_digest;
    state_.sessions_.emplace(sessionId, SessionState::SessionRecord{
        .build_id = facts_.build_id,
        .subject_id = subject_id_,
        .software_id = facts_.software_id,
        .artifact_hash = facts_.final_artifact_hash,
        .counter_epoch = counterEpoch,
        .valid_until_ms = validUntilMs});
    if (state_.next_counter_ == UINT64_MAX) throw std::runtime_error("counter_exhausted");
    return StateResult{.counter = state_.next_counter_++, .session_id = sessionId,
                       .counter_epoch = counterEpoch, .valid_until_ms = validUntilMs};
}

StateResult SessionState::Transaction::closeSession(
    const std::string &sessionId, const std::string &counterEpoch, std::uint64_t now,
    const std::string &serverNonce,
    const std::string &serverEphemeralKey, const std::string &clientNonce,
    const std::string &clientEphemeralKey) {
    auto session = state_.sessions_.find(sessionId);
    if (session == state_.sessions_.end() || session->second.closed ||
        session->second.valid_until_ms <= now || session->second.build_id != facts_.build_id ||
        session->second.software_id != facts_.software_id ||
        session->second.artifact_hash != facts_.final_artifact_hash ||
        session->second.subject_id != subject_id_ ||
        session->second.counter_epoch != counterEpoch)
        throw std::runtime_error("session_closed");
    claimServer(serverNonce, serverEphemeralKey);
    const auto nonceKey = "client_nonce:" + facts_.build_id + ":" + clientNonce;
    const auto keyKey = "client_key:" + facts_.build_id + ":" + clientEphemeralKey;
    if (state_.claims_.contains(nonceKey) || state_.claims_.contains(keyKey))
        throw std::runtime_error("replay_detected");
    state_.claims_[nonceKey] = facts_.request_digest;
    state_.claims_[keyKey] = facts_.request_digest;
    session->second.closed = true;
    session->second.valid_until_ms = now;
    state_.windows_.erase(sessionId);
    if (state_.next_counter_ == UINT64_MAX) throw std::runtime_error("counter_exhausted");
    return StateResult{.counter = state_.next_counter_++, .session_id = sessionId,
                       .counter_epoch = session->second.counter_epoch,
                       .valid_until_ms = now, .closed = true};
}

StateResult SessionState::Transaction::controlSession(
    const std::string &sessionId, const std::string &counterEpoch, std::uint64_t now,
    std::uint64_t validUntilMs, bool close,
    const std::string &serverNonce, const std::string &serverEphemeralKey,
    const std::string &clientNonce, const std::string &clientEphemeralKey) {
    if (close) return closeSession(sessionId, counterEpoch, now, serverNonce, serverEphemeralKey,
                                   clientNonce, clientEphemeralKey);
    auto session = state_.sessions_.find(sessionId);
    if (session == state_.sessions_.end() || session->second.closed ||
        session->second.valid_until_ms <= now || validUntilMs <= now ||
        session->second.build_id != facts_.build_id ||
        session->second.software_id != facts_.software_id ||
        session->second.artifact_hash != facts_.final_artifact_hash ||
        session->second.subject_id != subject_id_ ||
        session->second.counter_epoch != counterEpoch)
        throw std::runtime_error("session_closed");
    claimServer(serverNonce, serverEphemeralKey);
    const auto key = "client_nonce:" + facts_.build_id + ":" + clientNonce;
    const auto ephemeral = "client_key:" + facts_.build_id + ":" + clientEphemeralKey;
    if (state_.claims_.contains(key) || state_.claims_.contains(ephemeral))
        throw std::runtime_error("replay_detected");
    state_.claims_[key] = facts_.request_digest;
    state_.claims_[ephemeral] = facts_.request_digest;
    session->second.valid_until_ms = validUntilMs;
    if (state_.next_counter_ == UINT64_MAX) throw std::runtime_error("counter_exhausted");
    return StateResult{.counter = state_.next_counter_++, .session_id = sessionId,
                       .counter_epoch = session->second.counter_epoch,
                       .valid_until_ms = validUntilMs};
}

StateOutcome SessionState::transact(const RequestFacts &facts, const AnonymousGrant &grant,
                                    std::uint64_t trustedNow,
                                    const std::function<StateResult(Transaction &)> &callback) {
    if (grant.subject_id_.empty() || grant.build_id_ != facts.build_id ||
        grant.request_digest_ != facts.request_digest || grant.valid_until_ms_ <= trustedNow ||
        (facts.type == "material.issue" && !grant.scopes_.contains("material.issue")) ||
        ((facts.type == "session.open" || facts.type == "session.renew" ||
          facts.type == "session.close") && !grant.scopes_.contains("session.control")))
        return StateOutcome{BackendError{"unauthorized"}};
    std::lock_guard lock(mutex_);
    const auto requestKey = makeRequestKey(facts);
    if (const auto raw = raw_registrations_.find(requestKey);
        raw != raw_registrations_.end()) {
        if (raw->second.request_digest != facts.request_digest)
            return stateError("request_conflict");
        if (raw->second.subject_id != grant.subject_id_ ||
            raw->second.build_id != facts.build_id ||
            raw->second.software_id != facts.software_id ||
            raw->second.artifact_hash != facts.final_artifact_hash)
            return stateError("unauthorized");
        return stateError("replay_detected");
    }
    if (auto cached = replies_.find(requestKey); cached != replies_.end()) {
        const auto claim = claims_.find("request:" + requestKey);
        if (claim == claims_.end() || claim->second != facts.request_digest)
            return stateError("request_conflict");
        const auto &record = cached->second;
        if (record.subject_id != grant.subject_id_ || record.build_id != facts.build_id ||
            record.software_id != facts.software_id ||
            record.artifact_hash != facts.final_artifact_hash ||
            record.region_id != facts.region_id || record.request_type != facts.type)
            return stateError("unauthorized");
        if (!record.result.session_id.empty()) {
            const auto session = sessions_.find(record.result.session_id);
            if (session == sessions_.end() || session->second.build_id != facts.build_id ||
                session->second.software_id != facts.software_id ||
                session->second.artifact_hash != facts.final_artifact_hash ||
                session->second.subject_id != grant.subject_id_ ||
                (!record.result.counter_epoch.empty() &&
                 session->second.counter_epoch != record.result.counter_epoch))
                return stateError("unauthorized");
            const bool exactCloseRetry = record.result.closed &&
                record.request_type == "session.close" && session->second.closed;
            if (!exactCloseRetry &&
                (session->second.closed || session->second.valid_until_ms <= trustedNow ||
                 (record.result.valid_until_ms != 0 &&
                  record.result.valid_until_ms <= trustedNow)))
                return stateError("session_closed");
        }
        return record.result;
    }
    try {
        SessionState draft;
        draft.replies_ = replies_;
        draft.claims_ = claims_;
        draft.raw_registrations_ = raw_registrations_;
        draft.generations_ = generations_;
        draft.sessions_ = sessions_;
        draft.windows_ = windows_;
        draft.next_counter_ = next_counter_;
        draft.retained_bytes_ = retained_bytes_;
        draft.wal_ = nullptr;
        draft.next_sequence_ = next_sequence_;
        Transaction transaction(draft, facts, grant.subject_id_, trustedNow);
        auto result = callback(transaction);
        if (transaction.window_preflight_) throw std::runtime_error("window_invalid");
        result.response = std::move(transaction.response_);
        draft.replies_[requestKey] = ReplyRecord{result, grant.subject_id_, facts.build_id,
            facts.software_id, facts.final_artifact_hash, facts.region_id, facts.type};
        draft.claims_["request:" + requestKey] = facts.request_digest;
        if (!draft.refreshRetainedBytes()) return BackendError{"state_capacity"};
        if (wal_) {
            if (next_sequence_ == UINT64_MAX) return BackendError{"counter_exhausted"};
            StateDelta delta{draft.serialize()};
            const auto committed = wal_->appendAndSync(next_sequence_, delta, result.response);
            if (const auto *error = std::get_if<BackendError>(&committed)) return *error;
            ++draft.next_sequence_;
        }
        replies_.swap(draft.replies_);
        claims_.swap(draft.claims_);
        raw_registrations_.swap(draft.raw_registrations_);
        generations_.swap(draft.generations_);
        sessions_.swap(draft.sessions_);
        windows_.swap(draft.windows_);
        next_counter_ = draft.next_counter_;
        retained_bytes_ = draft.retained_bytes_;
        next_sequence_ = draft.next_sequence_;
        return result;
    } catch (const std::exception &error) {
        return stateError(error.what());
    } catch (...) {
        return stateError("state_failed");
    }
}

RawSessionRegistrationOutcome SessionState::registerRawSession(
    const RequestFacts &facts, const AnonymousGrant &grant,
    std::uint64_t trustedNow, const RawSessionRegistrationInput &input,
    const BuildRawSessionMetadata &buildMetadata) {
    if (!canonicalRawFacts(facts) ||
        !boundedString(grant.subjectId(), kMaxIdentityBytes) ||
        grant.buildId() != facts.build_id || grant.requestDigest() != facts.request_digest ||
        grant.validUntilMs() <= trustedNow ||
        !grant.scopes().contains("session.control"))
        return BackendError{"unauthorized"};
    if (!canonicalHex(input.client_nonce, 64) ||
        !canonicalHex(input.client_ephemeral_key, 64))
        return BackendError{"invalid_key"};
    if (!buildMetadata) return BackendError{"state_failed"};

    std::lock_guard lock(mutex_);
    const auto requestKey = makeRequestKey(facts);
    if (const auto previous = raw_registrations_.find(requestKey);
        previous != raw_registrations_.end()) {
        if (previous->second.request_digest != facts.request_digest)
            return BackendError{"request_conflict"};
        if (previous->second.subject_id != grant.subject_id_ ||
            previous->second.build_id != facts.build_id ||
            previous->second.software_id != facts.software_id ||
            previous->second.artifact_hash != facts.final_artifact_hash)
            return BackendError{"unauthorized"};
        return BackendError{"replay_detected"};
    }
    if (raw_registrations_.size() >= kMaxRawRegistrations ||
        sessions_.size() >= kMaxSessions || claims_.size() > kMaxClaims - 4)
        return BackendError{"state_capacity"};
    if (replies_.contains(requestKey)) {
        const auto claim = claims_.find("request:" + requestKey);
        return BackendError{claim != claims_.end() && claim->second != facts.request_digest
            ? "request_conflict" : "replay_detected"};
    }
    const auto clientNonceClaim = "client_nonce:" + facts.build_id + ":" + input.client_nonce;
    const auto clientKeyClaim = "client_key:" + facts.build_id + ":" + input.client_ephemeral_key;
    if (claims_.contains(clientNonceClaim) || claims_.contains(clientKeyClaim))
        return BackendError{"replay_detected"};
    if (next_counter_ == UINT64_MAX) return BackendError{"counter_exhausted"};
    constexpr std::size_t metadataBytes = 32 + 64 + sizeof(std::uint32_t) +
        sizeof(std::uint64_t) + sizeof(bool);
    const auto registrationBytes = requestKey.size() + facts.request_digest.size() +
        grant.subjectId().size() + facts.build_id.size() + facts.software_id.size() +
        facts.final_artifact_hash.size() + 32 + sizeof(std::uint64_t) + 4 * 64;
    const auto sessionBytes = metadataBytes + facts.build_id.size() + grant.subjectId().size() +
        facts.software_id.size() + facts.final_artifact_hash.size() + kRawTransportKind.size();
    constexpr std::size_t serverClaimKeys =
        sizeof("server_nonce:") - 1 + 64 + 1 + 64 +
        sizeof("server_key:") - 1 + 64 + 1 + 64;
    const auto claimBytes = clientNonceClaim.size() + clientKeyClaim.size() +
        serverClaimKeys + 4 * facts.request_digest.size();
    if (retained_bytes_ > kMaxRetainedBytes ||
        registrationBytes > kMaxRetainedBytes - retained_bytes_ ||
        sessionBytes > kMaxRetainedBytes - retained_bytes_ - registrationBytes ||
        claimBytes > kMaxRetainedBytes - retained_bytes_ - registrationBytes - sessionBytes)
        return BackendError{"state_capacity"};

    try {
        const auto counter = next_counter_;
        auto metadataResult = buildMetadata(counter);
        if (const auto *error = std::get_if<BackendError>(&metadataResult)) return *error;
        auto metadata = std::get<RawSessionMetadata>(std::move(metadataResult));
        if (!canonicalHex(metadata.session_id, 32) ||
            !canonicalHex(metadata.server_nonce, 64) ||
            !canonicalHex(metadata.server_ephemeral_key, 64) ||
            !canonicalHex(metadata.initial_state_commitment, 64) ||
            metadata.key_version == 0 || metadata.valid_until_ms <= trustedNow ||
            metadata.valid_until_ms > grant.validUntilMs())
            return BackendError{"invalid_key"};
        if (const auto existing = sessions_.find(metadata.session_id);
            existing != sessions_.end()) {
            if (existing->second.subject_id != grant.subject_id_ ||
                existing->second.build_id != facts.build_id ||
                existing->second.software_id != facts.software_id ||
                existing->second.artifact_hash != facts.final_artifact_hash)
                return BackendError{"unauthorized"};
            return BackendError{"request_conflict"};
        }
        const auto serverNonceClaim =
            "server_nonce:" + facts.build_id + ":" + metadata.server_nonce;
        const auto serverKeyClaim =
            "server_key:" + facts.build_id + ":" + metadata.server_ephemeral_key;
        if (claims_.contains(serverNonceClaim) || claims_.contains(serverKeyClaim))
            return BackendError{"invalid_key"};

        SessionState draft;
        draft.replies_ = replies_;
        draft.claims_ = claims_;
        draft.raw_registrations_ = raw_registrations_;
        draft.generations_ = generations_;
        draft.sessions_ = sessions_;
        draft.windows_ = windows_;
        draft.next_counter_ = counter + 1;
        draft.retained_bytes_ = retained_bytes_;
        draft.next_sequence_ = next_sequence_;
        draft.claims_.emplace(clientNonceClaim, facts.request_digest);
        draft.claims_.emplace(clientKeyClaim, facts.request_digest);
        draft.claims_.emplace(serverNonceClaim, facts.request_digest);
        draft.claims_.emplace(serverKeyClaim, facts.request_digest);
        draft.raw_registrations_.emplace(requestKey, RawRegistrationRecord{
            .request_digest = facts.request_digest,
            .subject_id = grant.subject_id_,
            .build_id = facts.build_id,
            .software_id = facts.software_id,
            .artifact_hash = facts.final_artifact_hash,
            .session_id = metadata.session_id,
            .counter = counter,
            .client_nonce = input.client_nonce,
            .client_ephemeral_key = input.client_ephemeral_key,
            .server_nonce = metadata.server_nonce,
            .server_ephemeral_key = metadata.server_ephemeral_key});
        draft.sessions_.emplace(metadata.session_id, SessionRecord{
            .build_id = facts.build_id,
            .subject_id = grant.subject_id_,
            .software_id = facts.software_id,
            .artifact_hash = facts.final_artifact_hash,
            .transport_kind = std::string(kRawTransportKind),
            .initial_state_commitment = metadata.initial_state_commitment,
            .key_version = metadata.key_version,
            .valid_until_ms = metadata.valid_until_ms});
        if (!draft.refreshRetainedBytes()) return BackendError{"state_capacity"};
        if (wal_) {
            if (next_sequence_ == UINT64_MAX) return BackendError{"counter_exhausted"};
            StateDelta delta{draft.serialize()};
            const auto committed = wal_->appendAndSync(next_sequence_, delta, {});
            if (const auto *error = std::get_if<BackendError>(&committed)) return *error;
            ++draft.next_sequence_;
        }

        claims_.swap(draft.claims_);
        raw_registrations_.swap(draft.raw_registrations_);
        sessions_.swap(draft.sessions_);
        next_counter_ = draft.next_counter_;
        retained_bytes_ = draft.retained_bytes_;
        next_sequence_ = draft.next_sequence_;
        return RawSessionRegistrationResult{counter, std::move(metadata)};
    } catch (const std::exception &error) {
        return BackendError{error.what()};
    } catch (...) {
        return BackendError{"state_failed"};
    }
}

bool SessionState::refreshRetainedBytes() {
    if (replies_.size() > kMaxReplies || raw_registrations_.size() > kMaxRawRegistrations ||
        claims_.size() > kMaxClaims || generations_.size() > kMaxGenerations ||
        sessions_.size() > kMaxSessions || windows_.size() > kMaxSessions)
        return false;
    std::size_t total = sizeof(next_counter_);
    const auto add = [&](std::size_t bytes) { return addRetained(total, bytes); };
    for (const auto &[key, reply] : replies_) {
        const auto &result = reply.result;
        if (!add(key.size()) || !add(sizeof(result.generation)) ||
            !add(sizeof(result.counter)) || !add(result.response.size()) ||
            !add(result.session_id.size()) || !add(result.counter_epoch.size()) ||
            !add(sizeof(result.valid_until_ms)) || !add(sizeof(result.closed)) ||
            !add(reply.subject_id.size()) || !add(reply.build_id.size()) ||
            !add(reply.software_id.size()) || !add(reply.artifact_hash.size()) ||
            !add(reply.region_id.size()) || !add(reply.request_type.size()))
            return false;
    }
    for (const auto &[key, value] : claims_)
        if (!add(key.size()) || !add(value.size())) return false;
    for (const auto &[key, registration] : raw_registrations_) {
        if (!add(key.size()) || !add(registration.request_digest.size()) ||
            !add(registration.subject_id.size()) || !add(registration.build_id.size()) ||
            !add(registration.software_id.size()) || !add(registration.artifact_hash.size()) ||
            !add(registration.session_id.size()) || !add(sizeof(registration.counter)) ||
            !add(registration.client_nonce.size()) ||
            !add(registration.client_ephemeral_key.size()) ||
            !add(registration.server_nonce.size()) ||
            !add(registration.server_ephemeral_key.size()))
            return false;
    }
    for (const auto &[key, value] : generations_)
        if (!add(key.size()) || !add(sizeof(value))) return false;
    for (const auto &[key, session] : sessions_) {
        if (!add(key.size()) || !add(session.build_id.size()) ||
            !add(session.subject_id.size()) || !add(session.software_id.size()) ||
            !add(session.artifact_hash.size()) || !add(session.counter_epoch.size()) ||
            !add(session.transport_kind.size()) ||
            !add(session.initial_state_commitment.size()) ||
            !add(sizeof(session.key_version)) || !add(sizeof(session.valid_until_ms)) ||
            !add(sizeof(session.closed)))
            return false;
    }
    for (const auto &[key, window] : windows_) {
        if (!add(key.size()) || !add(window.region_id.size()) ||
            !add(sizeof(window.generation)) || !add(sizeof(window.window_id)) ||
            !add(window.state.size()) || !add(sizeof(window.expires_at_ms)))
            return false;
    }
    retained_bytes_ = total;
    return true;
}

std::vector<std::byte> SessionState::serialize() const {
    Json value{{"next_counter", next_counter_}, {"retained_bytes", retained_bytes_}};
    value["replies"] = Json::object();
    for (const auto &[key, reply] : replies_) {
        const auto &result = reply.result;
        value["replies"][key] = {{"generation", result.generation}, {"counter", result.counter},
            {"response", bytesJson(result.response)}, {"session_id", result.session_id},
            {"counter_epoch", result.counter_epoch}, {"valid_until_ms", result.valid_until_ms},
            {"closed", result.closed}, {"subject_id", reply.subject_id},
            {"build_id", reply.build_id}, {"software_id", reply.software_id},
            {"artifact_hash", reply.artifact_hash}, {"region_id", reply.region_id},
            {"request_type", reply.request_type}};
    }
    value["claims"] = claims_;
    value["raw_registrations"] = Json::object();
    for (const auto &[key, registration] : raw_registrations_) {
        value["raw_registrations"][key] = {
            {"request_digest", registration.request_digest},
            {"subject_id", registration.subject_id},
            {"build_id", registration.build_id},
            {"software_id", registration.software_id},
            {"artifact_hash", registration.artifact_hash},
            {"session_id", registration.session_id},
            {"counter", registration.counter},
            {"client_nonce", registration.client_nonce},
            {"client_ephemeral_key", registration.client_ephemeral_key},
            {"server_nonce", registration.server_nonce},
            {"server_ephemeral_key", registration.server_ephemeral_key}};
    }
    value["generations"] = generations_;
    value["sessions"] = Json::object();
    for (const auto &[key, session] : sessions_) {
        value["sessions"][key] = {{"build_id", session.build_id}, {"subject_id", session.subject_id},
            {"software_id", session.software_id}, {"artifact_hash", session.artifact_hash},
            {"counter_epoch", session.counter_epoch},
            {"transport_kind", session.transport_kind},
            {"initial_state_commitment", session.initial_state_commitment},
            {"key_version", session.key_version}, {"valid_until_ms", session.valid_until_ms},
            {"closed", session.closed}};
    }
    value["windows"] = Json::object();
    for (const auto &[key, window] : windows_) {
        value["windows"][key] = {{"region_id", window.region_id},
            {"generation", window.generation}, {"window_id", window.window_id},
            {"state", window.state}, {"expires_at_ms", window.expires_at_ms}};
    }
    const auto text = value.dump();
    std::vector<std::byte> result;
    result.reserve(text.size());
    for (const auto byte : text) result.push_back(static_cast<std::byte>(byte));
    return result;
}

std::variant<std::monostate, BackendError> SessionState::applySerialized(
    std::span<const std::byte> bytes) {
    try {
        const std::string text(reinterpret_cast<const char *>(bytes.data()), bytes.size());
        const auto value = Json::parse(text);
        if (!value.is_object() || !value.contains("replies") || !value.contains("claims") ||
            !value.contains("generations") || !value.contains("sessions"))
            return BackendError{"wal_state_invalid"};
        const auto &replyValue = value.at("replies");
        const auto &claimValue = value.at("claims");
        const auto &generationValue = value.at("generations");
        const auto &sessionValue = value.at("sessions");
        if (!replyValue.is_object() || !claimValue.is_object() ||
            !generationValue.is_object() || !sessionValue.is_object())
            return BackendError{"wal_state_invalid"};
        const Json *rawRegistrationValue = nullptr;
        if (value.contains("raw_registrations")) {
            rawRegistrationValue = &value.at("raw_registrations");
            if (!rawRegistrationValue->is_object()) return BackendError{"wal_state_invalid"};
        }
        if (replyValue.size() > kMaxReplies || claimValue.size() > kMaxClaims ||
            (rawRegistrationValue && rawRegistrationValue->size() > kMaxRawRegistrations) ||
            generationValue.size() > kMaxGenerations || sessionValue.size() > kMaxSessions)
            return BackendError{"state_capacity"};

        std::unordered_map<std::string, ReplyRecord> replies;
        for (const auto &[key, item] : replyValue.items()) {
            if (!boundedString(key, kMaxIdentityBytes)) return BackendError{"wal_state_invalid"};
            ReplyRecord reply;
            reply.result = StateResult{item.at("generation").get<std::uint64_t>(),
                item.at("counter").get<std::uint64_t>(), bytesFromJson(item.at("response")),
                item.at("session_id").get<std::string>(), item.at("counter_epoch").get<std::string>(),
                item.at("valid_until_ms").get<std::uint64_t>(), item.at("closed").get<bool>()};
            reply.subject_id = item.at("subject_id").get<std::string>();
            reply.build_id = item.at("build_id").get<std::string>();
            reply.software_id = item.at("software_id").get<std::string>();
            reply.artifact_hash = item.at("artifact_hash").get<std::string>();
            reply.region_id = item.at("region_id").get<std::string>();
            reply.request_type = item.at("request_type").get<std::string>();
            if (!boundedString(reply.result.session_id, kMaxIdentityBytes, true) ||
                !boundedString(reply.result.counter_epoch, kMaxIdentityBytes, true) ||
                !boundedString(reply.subject_id, kMaxIdentityBytes) ||
                !boundedString(reply.build_id, kMaxIdentityBytes) ||
                !boundedString(reply.software_id, kMaxIdentityBytes) ||
                !boundedString(reply.artifact_hash, kMaxIdentityBytes) ||
                !boundedString(reply.region_id, kMaxIdentityBytes, true) ||
                !boundedString(reply.request_type, kMaxIdentityBytes))
                return BackendError{"wal_state_invalid"};
            replies.emplace(key, std::move(reply));
        }
        std::unordered_map<std::string, std::string> claims;
        for (const auto &[key, item] : claimValue.items()) {
            const auto claim = item.get<std::string>();
            if (!boundedString(key, 4 * kMaxIdentityBytes) ||
                !boundedString(claim, kMaxIdentityBytes, true))
                return BackendError{"wal_state_invalid"};
            claims.emplace(key, claim);
        }
        std::unordered_map<std::string, RawRegistrationRecord> rawRegistrations;
        if (rawRegistrationValue) {
            for (const auto &[key, item] : rawRegistrationValue->items()) {
                // Older raw records did not retain enough public information to
                // prove their session and nonce/key claim bindings. Fail closed.
                if (!item.is_object() || item.size() != 11)
                    return BackendError{"wal_state_invalid"};
                RawRegistrationRecord registration{
                    .request_digest = item.at("request_digest").get<std::string>(),
                    .subject_id = item.at("subject_id").get<std::string>(),
                    .build_id = item.at("build_id").get<std::string>(),
                    .software_id = item.at("software_id").get<std::string>(),
                    .artifact_hash = item.at("artifact_hash").get<std::string>(),
                    .session_id = item.at("session_id").get<std::string>(),
                    .counter = item.at("counter").get<std::uint64_t>(),
                    .client_nonce = item.at("client_nonce").get<std::string>(),
                    .client_ephemeral_key =
                        item.at("client_ephemeral_key").get<std::string>(),
                    .server_nonce = item.at("server_nonce").get<std::string>(),
                    .server_ephemeral_key =
                        item.at("server_ephemeral_key").get<std::string>()};
                const auto expectedKey = registration.software_id + ":" +
                    registration.build_id + ":" + registration.artifact_hash + ":";
                if (!boundedString(key, kMaxIdentityBytes) ||
                    !canonicalHex(registration.request_digest, 64) ||
                    !boundedString(registration.subject_id, kMaxIdentityBytes) ||
                    !canonicalHex(registration.build_id, 64) ||
                    !canonicalIdentity(registration.software_id) ||
                    !canonicalHex(registration.artifact_hash, 64) ||
                    !canonicalHex(registration.session_id, 32) || registration.counter == 0 ||
                    !canonicalHex(registration.client_nonce, 64) ||
                    !canonicalHex(registration.client_ephemeral_key, 64) ||
                    !canonicalHex(registration.server_nonce, 64) ||
                    !canonicalHex(registration.server_ephemeral_key, 64) ||
                    !key.starts_with(expectedKey) ||
                    !canonicalHex(key.substr(expectedKey.size()), 32) ||
                    !rawRegistrations.emplace(key, std::move(registration)).second)
                    return BackendError{"wal_state_invalid"};
            }
        }
        std::unordered_map<std::string, std::uint64_t> generations;
        for (const auto &[key, item] : generationValue.items()) {
            if (!boundedString(key, 4 * kMaxIdentityBytes)) return BackendError{"wal_state_invalid"};
            generations.emplace(key, item.get<std::uint64_t>());
        }
        std::unordered_map<std::string, SessionRecord> sessions;
        for (const auto &[key, item] : sessionValue.items()) {
            SessionRecord session;
            session.build_id = item.at("build_id").get<std::string>();
            session.subject_id = item.at("subject_id").get<std::string>();
            session.software_id = item.at("software_id").get<std::string>();
            session.artifact_hash = item.at("artifact_hash").get<std::string>();
            session.counter_epoch = item.at("counter_epoch").get<std::string>();
            if (item.contains("transport_kind"))
                session.transport_kind = item.at("transport_kind").get<std::string>();
            if (item.contains("initial_state_commitment"))
                session.initial_state_commitment =
                    item.at("initial_state_commitment").get<std::string>();
            if (item.contains("key_version"))
                session.key_version = item.at("key_version").get<std::uint32_t>();
            session.valid_until_ms = item.at("valid_until_ms").get<std::uint64_t>();
            session.closed = item.at("closed").get<bool>();
            const bool raw = session.transport_kind == kRawTransportKind;
            if (!boundedString(key, kMaxIdentityBytes) ||
                !boundedString(session.build_id, kMaxIdentityBytes) ||
                !boundedString(session.subject_id, kMaxIdentityBytes) ||
                !boundedString(session.software_id, kMaxIdentityBytes) ||
                !boundedString(session.artifact_hash, kMaxIdentityBytes) ||
                !boundedString(session.counter_epoch, kMaxIdentityBytes, true) ||
                (!session.transport_kind.empty() && !raw) ||
                (raw && (!canonicalHex(key, 32) || !canonicalHex(session.build_id, 64) ||
                         !canonicalIdentity(session.software_id) ||
                         !canonicalHex(session.artifact_hash, 64) ||
                         !session.counter_epoch.empty() ||
                         !canonicalHex(session.initial_state_commitment, 64) ||
                         session.key_version == 0)) ||
                (!raw && (!session.initial_state_commitment.empty() ||
                          session.key_version != 0)) ||
                !sessions.emplace(key, std::move(session)).second)
                return BackendError{"wal_state_invalid"};
        }
        std::unordered_map<std::string, WindowRecord> windows;
        if (value.contains("windows")) {
            const auto &windowValue = value.at("windows");
            if (!windowValue.is_object() || windowValue.size() > kMaxSessions)
                return BackendError{"state_capacity"};
            for (const auto &[key, item] : windowValue.items()) {
                WindowRecord window{item.at("region_id").get<std::string>(),
                    item.at("generation").get<std::uint64_t>(),
                    item.at("window_id").get<std::uint64_t>(),
                    item.at("state").get<std::string>(),
                    item.at("expires_at_ms").get<std::uint64_t>()};
                const auto session = sessions.find(key);
                if (!boundedString(key, kMaxIdentityBytes) || session == sessions.end() ||
                    session->second.closed || !boundedString(window.region_id, kMaxIdentityBytes) ||
                    window.generation == 0 || window.window_id == 0 ||
                    !boundedString(window.state, kMaxChainStateBytes) ||
                    window.expires_at_ms > session->second.valid_until_ms)
                    return BackendError{"wal_state_invalid"};
                windows.emplace(key, std::move(window));
            }
        }
        std::unordered_set<std::string> registeredRawSessions;
        std::uint64_t maximumCounter = 0;
        for (const auto &[key, reply] : replies) {
            (void)key;
            maximumCounter = std::max(maximumCounter, reply.result.counter);
        }
        for (const auto &[key, generation] : generations) {
            (void)key;
            if (generation == UINT64_MAX) return BackendError{"wal_state_invalid"};
        }
        for (const auto &[key, window] : windows) {
            (void)key;
            if (window.window_id == UINT64_MAX) return BackendError{"wal_state_invalid"};
        }
        for (const auto &[requestKey, registration] : rawRegistrations) {
            const auto session = sessions.find(registration.session_id);
            if (session == sessions.end() ||
                session->second.transport_kind != kRawTransportKind ||
                session->second.build_id != registration.build_id ||
                session->second.subject_id != registration.subject_id ||
                session->second.software_id != registration.software_id ||
                session->second.artifact_hash != registration.artifact_hash ||
                !registeredRawSessions.emplace(registration.session_id).second)
                return BackendError{"wal_state_invalid"};
            const auto claimMatches = [&](std::string_view label,
                                          const std::string &publicValue) {
                const auto claim = claims.find(std::string(label) + ":" +
                    registration.build_id + ":" + publicValue);
                return claim != claims.end() && claim->second == registration.request_digest;
            };
            if (!claimMatches("client_nonce", registration.client_nonce) ||
                !claimMatches("client_key", registration.client_ephemeral_key) ||
                !claimMatches("server_nonce", registration.server_nonce) ||
                !claimMatches("server_key", registration.server_ephemeral_key))
                return BackendError{"wal_state_invalid"};
            maximumCounter = std::max(maximumCounter, registration.counter);
            (void)requestKey;
        }
        for (const auto &[sessionId, session] : sessions) {
            if (session.transport_kind == kRawTransportKind &&
                !registeredRawSessions.contains(sessionId))
                return BackendError{"wal_state_invalid"};
        }
        const auto nextCounter = value.at("next_counter").get<std::uint64_t>();
        if (nextCounter == 0 || nextCounter == UINT64_MAX ||
            nextCounter <= maximumCounter)
            return BackendError{"wal_state_invalid"};
        SessionState parsed;
        parsed.replies_ = std::move(replies);
        parsed.claims_ = std::move(claims);
        parsed.raw_registrations_ = std::move(rawRegistrations);
        parsed.generations_ = std::move(generations);
        parsed.sessions_ = std::move(sessions);
        parsed.windows_ = std::move(windows);
        parsed.next_counter_ = nextCounter;
        if (!parsed.refreshRetainedBytes()) return BackendError{"state_capacity"};

        replies_.swap(parsed.replies_);
        claims_.swap(parsed.claims_);
        raw_registrations_.swap(parsed.raw_registrations_);
        generations_.swap(parsed.generations_);
        sessions_.swap(parsed.sessions_);
        windows_.swap(parsed.windows_);
        next_counter_ = parsed.next_counter_;
        retained_bytes_ = parsed.retained_bytes_;
        return std::monostate{};
    } catch (...) {
        return BackendError{"wal_state_invalid"};
    }
}

std::variant<std::monostate, BackendError> SessionState::restore(
    const RecoveredState &recovered) {
    std::lock_guard lock(mutex_);
    if (recovered.records.empty()) {
        // An empty WAL can be based only at the initial sequence. A nonzero
        // high-water without a snapshot is not enough state to restore safely.
        if (recovered.last_sequence != 0) return BackendError{"wal_state_invalid"};
        next_sequence_ = 1;
        return std::monostate{};
    }
    if (recovered.last_sequence == UINT64_MAX ||
        recovered.records.back().sequence != recovered.last_sequence)
        return BackendError{"wal_state_invalid"};

    // Parse into a detached instance so every scalar and collection, including
    // the sequence high-water, is published atomically only after validation.
    SessionState parsed;
    auto result = parsed.applySerialized(recovered.records.back().delta.bytes);
    if (std::holds_alternative<BackendError>(result)) return result;
    parsed.next_sequence_ = recovered.last_sequence + 1;

    replies_.swap(parsed.replies_);
    claims_.swap(parsed.claims_);
    raw_registrations_.swap(parsed.raw_registrations_);
    generations_.swap(parsed.generations_);
    sessions_.swap(parsed.sessions_);
    windows_.swap(parsed.windows_);
    next_counter_ = parsed.next_counter_;
    retained_bytes_ = parsed.retained_bytes_;
    next_sequence_ = parsed.next_sequence_;
    return std::monostate{};
}

} // namespace xovm::cloud_material
