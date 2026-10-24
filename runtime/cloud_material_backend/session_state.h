#ifndef XOVM_CLOUD_MATERIAL_BACKEND_SESSION_STATE_H
#define XOVM_CLOUD_MATERIAL_BACKEND_SESSION_STATE_H

#include "auth_policy.h"
#include "state_wal.h"

#include <functional>
#include <mutex>
#include <unordered_map>

namespace xovm::cloud_material {

struct StateResult {
    std::uint64_t generation = 0;
    std::uint64_t counter = 0;
    std::vector<std::byte> response;
    std::string session_id;
    std::string counter_epoch;
    std::uint64_t valid_until_ms = 0;
    bool closed = false;
    bool operator==(const StateResult &) const = default;
};

using StateOutcome = std::variant<StateResult, BackendError>;

class SessionState {
public:
    explicit SessionState(StateWal *wal = nullptr);
    using StateOutcome = xovm::cloud_material::StateOutcome;
    class Transaction {
    public:
        StateResult allocate(const std::string &sessionId, const std::string &regionId,
                             const std::string &clientNonce,
                             const std::string &clientEphemeralKey);
        StateResult openSession(const std::string &sessionId, const std::string &counterEpoch,
                                std::uint64_t validUntilMs, const std::string &serverNonce,
                                const std::string &serverEphemeralKey,
                                const std::string &clientNonce,
                                const std::string &clientEphemeralKey);
        StateResult closeSession(const std::string &sessionId, const std::string &counterEpoch,
                                  std::uint64_t now,
                                  const std::string &serverNonce,
                                  const std::string &serverEphemeralKey,
                                  const std::string &clientNonce,
                                  const std::string &clientEphemeralKey);
        StateResult controlSession(const std::string &sessionId, const std::string &counterEpoch,
                                   std::uint64_t now,
                                   std::uint64_t validUntilMs, bool close,
                                   const std::string &serverNonce,
                                   const std::string &serverEphemeralKey,
                                   const std::string &clientNonce,
                                   const std::string &clientEphemeralKey);
        StateResult claimServer(const std::string &serverNonce,
                                const std::string &serverEphemeralKey);
        void setResponse(std::vector<std::byte> response) { response_ = std::move(response); }
    private:
        friend class SessionState;
        Transaction(SessionState &state, const RequestFacts &facts, std::uint64_t now);
        SessionState &state_;
        const RequestFacts &facts_;
        std::uint64_t now_;
        bool changed_ = false;
        std::vector<std::byte> response_;
    };

    StateOutcome transact(const RequestFacts &facts, const AnonymousGrant &grant,
                          std::uint64_t trustedNow,
                          const std::function<StateResult(Transaction &)> &callback);
    std::variant<std::monostate, BackendError> restore(const RecoveredState &recovered);

private:
    std::vector<std::byte> serialize() const;
    std::variant<std::monostate, BackendError> applySerialized(
        std::span<const std::byte> bytes);

    std::mutex mutex_;
    std::unordered_map<std::string, StateResult> replies_;
    std::unordered_map<std::string, std::string> claims_;
    std::unordered_map<std::string, std::uint64_t> generations_;
    struct SessionRecord {
        std::string build_id;
        std::string subject_id;
        std::string software_id;
        std::string artifact_hash;
        std::string counter_epoch;
        std::uint64_t valid_until_ms = 0;
        bool closed = false;
    };
    std::unordered_map<std::string, SessionRecord> sessions_;
    std::uint64_t next_counter_ = 1;
    std::size_t retained_bytes_ = 0;
    StateWal *wal_ = nullptr;
    std::uint64_t next_sequence_ = 1;
};

} // namespace xovm::cloud_material

#endif
