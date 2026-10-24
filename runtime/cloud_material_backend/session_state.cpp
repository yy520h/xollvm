#include "session_state.h"

#include <nlohmann/json.hpp>

namespace xovm::cloud_material {

namespace {
using Json = nlohmann::json;

StateOutcome stateError(std::string code) {
    StateOutcome result;
    result.emplace<BackendError>();
    std::get<BackendError>(result).code = std::move(code);
    return result;
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
                                       std::uint64_t now)
    : state_(state), facts_(facts), now_(now) {}

StateResult SessionState::Transaction::allocate(const std::string &sessionId,
                                                const std::string &regionId,
                                                const std::string &clientNonce,
                                                const std::string &clientEphemeralKey) {
    const auto scope = facts_.build_id + ":" + sessionId + ":" + regionId;
    const auto requestKey = makeRequestKey(facts_);
    const auto cached = state_.replies_.find(requestKey);
    if (cached != state_.replies_.end()) {
        if (state_.claims_["request:" + requestKey] != facts_.request_digest)
            throw std::runtime_error("request_conflict");
        return cached->second;
    }
    if (auto session = state_.sessions_.find(sessionId); session != state_.sessions_.end()) {
        if (session->second.closed || session->second.valid_until_ms <= now_)
            throw std::runtime_error("session_closed");
        if (session->second.build_id != facts_.build_id ||
            session->second.software_id != facts_.software_id ||
            session->second.artifact_hash != facts_.final_artifact_hash)
            throw std::runtime_error("unauthorized");
    } else {
        throw std::runtime_error("session_closed");
    }
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
    state_.replies_[requestKey] = result;
    state_.claims_["request:" + requestKey] = facts_.request_digest;
    state_.retained_bytes_ += facts_.request_digest.size() + clientNonce.size() +
                              clientEphemeralKey.size() + requestKey.size();
    if (state_.replies_.size() > 4096 || state_.claims_.size() > 32768 ||
        state_.retained_bytes_ > 8 * 1024 * 1024)
        throw std::runtime_error("state_capacity");
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
        facts_.build_id, "anonymous:" + facts_.build_id, facts_.software_id,
        facts_.final_artifact_hash, counterEpoch, validUntilMs, false});
    state_.retained_bytes_ += sessionId.size() + counterEpoch.size();
    if (state_.sessions_.size() > 4096 || state_.retained_bytes_ > 8 * 1024 * 1024)
        throw std::runtime_error("state_capacity");
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
    const auto requestKey = makeRequestKey(facts_);
    if (state_.replies_.contains(requestKey)) return state_.replies_.at(requestKey);
    if (close) return closeSession(sessionId, counterEpoch, now, serverNonce, serverEphemeralKey,
                                   clientNonce, clientEphemeralKey);
    auto session = state_.sessions_.find(sessionId);
    if (session == state_.sessions_.end() || session->second.closed ||
        session->second.valid_until_ms <= now || validUntilMs <= now ||
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
    if (auto cached = replies_.find(requestKey); cached != replies_.end()) {
        const auto claim = claims_.find("request:" + requestKey);
        if (claim == claims_.end() || claim->second != facts.request_digest)
        return stateError("request_conflict");
        return cached->second;
    }
    try {
        SessionState draft;
        draft.replies_ = replies_;
        draft.claims_ = claims_;
        draft.generations_ = generations_;
        draft.sessions_ = sessions_;
        draft.next_counter_ = next_counter_;
        draft.retained_bytes_ = retained_bytes_;
        draft.wal_ = nullptr;
        draft.next_sequence_ = next_sequence_;
        Transaction transaction(draft, facts, trustedNow);
        auto result = callback(transaction);
        result.response = std::move(transaction.response_);
        draft.replies_[requestKey] = result;
        draft.claims_["request:" + requestKey] = facts.request_digest;
        if (wal_) {
            StateDelta delta{draft.serialize()};
            const auto committed = wal_->appendAndSync(next_sequence_, delta, result.response);
            if (const auto *error = std::get_if<BackendError>(&committed)) return *error;
            ++draft.next_sequence_;
        }
        replies_.swap(draft.replies_);
        claims_.swap(draft.claims_);
        generations_.swap(draft.generations_);
        sessions_.swap(draft.sessions_);
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

std::vector<std::byte> SessionState::serialize() const {
    Json value{{"next_counter", next_counter_}, {"retained_bytes", retained_bytes_}};
    value["replies"] = Json::object();
    for (const auto &[key, result] : replies_) {
        value["replies"][key] = {{"generation", result.generation}, {"counter", result.counter},
            {"response", bytesJson(result.response)}, {"session_id", result.session_id},
            {"counter_epoch", result.counter_epoch}, {"valid_until_ms", result.valid_until_ms},
            {"closed", result.closed}};
    }
    value["claims"] = claims_;
    value["generations"] = generations_;
    value["sessions"] = Json::object();
    for (const auto &[key, session] : sessions_) {
        value["sessions"][key] = {{"build_id", session.build_id}, {"subject_id", session.subject_id},
            {"software_id", session.software_id}, {"artifact_hash", session.artifact_hash},
            {"counter_epoch", session.counter_epoch}, {"valid_until_ms", session.valid_until_ms},
            {"closed", session.closed}};
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
        std::unordered_map<std::string, StateResult> replies;
        for (const auto &[key, item] : value.at("replies").items()) {
            replies.emplace(key, StateResult{
                item.at("generation").get<std::uint64_t>(), item.at("counter").get<std::uint64_t>(),
                bytesFromJson(item.at("response")), item.at("session_id").get<std::string>(),
                item.at("counter_epoch").get<std::string>(), item.at("valid_until_ms").get<std::uint64_t>(),
                item.at("closed").get<bool>()});
        }
        std::unordered_map<std::string, std::string> claims =
            value.at("claims").get<std::unordered_map<std::string, std::string>>();
        std::unordered_map<std::string, std::uint64_t> generations =
            value.at("generations").get<std::unordered_map<std::string, std::uint64_t>>();
        std::unordered_map<std::string, SessionRecord> sessions;
        for (const auto &[key, item] : value.at("sessions").items()) {
            sessions.emplace(key, SessionRecord{item.at("build_id").get<std::string>(),
                item.at("subject_id").get<std::string>(), item.at("software_id").get<std::string>(),
                item.at("artifact_hash").get<std::string>(), item.at("counter_epoch").get<std::string>(),
                item.at("valid_until_ms").get<std::uint64_t>(), item.at("closed").get<bool>()});
        }
        if (replies.size() > 4096 || claims.size() > 32768 || sessions.size() > 4096)
            return BackendError{"state_capacity"};
        replies_ = std::move(replies);
        claims_ = std::move(claims);
        generations_ = std::move(generations);
        sessions_ = std::move(sessions);
        next_counter_ = value.at("next_counter").get<std::uint64_t>();
        retained_bytes_ = value.value("retained_bytes", std::size_t{0});
        return std::monostate{};
    } catch (...) {
        return BackendError{"wal_state_invalid"};
    }
}

std::variant<std::monostate, BackendError> SessionState::restore(
    const RecoveredState &recovered) {
    std::lock_guard lock(mutex_);
    if (recovered.records.empty()) {
        next_sequence_ = 1;
        return std::monostate{};
    }
    auto result = applySerialized(recovered.records.back().delta.bytes);
    if (std::holds_alternative<BackendError>(result)) return result;
    next_sequence_ = recovered.last_sequence + 1;
    return std::monostate{};
}

} // namespace xovm::cloud_material
