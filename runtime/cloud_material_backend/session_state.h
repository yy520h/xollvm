#ifndef XOVM_CLOUD_MATERIAL_BACKEND_SESSION_STATE_H
#define XOVM_CLOUD_MATERIAL_BACKEND_SESSION_STATE_H

#include "auth_policy.h"
#include "state_wal.h"

#include <functional>
#include <mutex>
#include <optional>
#include <unordered_map>

namespace xovm::cloud_material {

struct StateResult {
    std::uint64_t generation = 0;
    std::uint64_t window_id = 0;
    std::uint64_t counter = 0;
    std::vector<std::byte> response;
    std::string session_id;
    std::string counter_epoch;
    std::uint64_t valid_until_ms = 0;
    bool closed = false;
    bool operator==(const StateResult &) const = default;
};

using StateOutcome = std::variant<StateResult, BackendError>;

// The raw/protocol layer owns parsing and cryptographic generation of these
// values. Preflight performs all session/chain checks before expensive material
// work. Finalize supplies only the newly generated public commitment/response.
struct WindowPreflightInput {
    std::string session_id;
    std::string region_id;
    std::uint64_t generation = 0;
    std::uint64_t window_id = 0;
    std::string previous_state;
    std::uint64_t expires_at_ms = 0;
    // Set by preflight. Callers supply only expires_at_ms, which is the current
    // policy/session/window bound. Raw generation timing is independently fixed
    // to the server epoch plus 120 seconds and never slides.
    std::uint64_t generation_deadline_ms = 0;
};

struct WindowFinalizeInput {
    std::string next_state;
    std::vector<std::byte> encoded_response;
};

// All values are canonical lowercase hex except software/build identity carried
// by RequestFacts. Private keys, derived keys, and encoded hello bytes never
// cross this state boundary.
struct RawSessionRegistrationInput {
    std::string client_nonce;
    std::string client_ephemeral_key;
};

struct RawSessionMetadata {
    std::string session_id;
    std::string server_nonce;
    std::string server_ephemeral_key;
    std::string initial_state_commitment;
    std::uint32_t key_version = 0;
    std::uint64_t valid_until_ms = 0;
    bool operator==(const RawSessionMetadata &) const = default;
};

struct RawSessionRegistrationResult {
    std::uint64_t counter = 0;
    RawSessionMetadata session;
    bool operator==(const RawSessionRegistrationResult &) const = default;
};

using RawSessionRegistrationOutcome =
    std::variant<RawSessionRegistrationResult, BackendError>;
using BuildRawSessionMetadata = std::function<
    std::variant<RawSessionMetadata, BackendError>(std::uint64_t counter)>;

struct ReclamationResult {
    std::size_t records_retired = 0;
    std::size_t response_bytes_reclaimed = 0;
    bool more_work = false;
    bool operator==(const ReclamationResult &) const = default;
};

using ReclamationOutcome = std::variant<ReclamationResult, BackendError>;

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
        std::uint64_t preflightWindow(WindowPreflightInput input);
        StateResult finalizeWindow(WindowFinalizeInput input);
        void setResponse(std::vector<std::byte> response) { response_ = std::move(response); }
    private:
        friend class SessionState;
        Transaction(SessionState &state, const RequestFacts &facts,
                    const std::string &subjectId, std::uint64_t now);
        SessionState &state_;
        const RequestFacts &facts_;
        const std::string &subject_id_;
        std::uint64_t now_;
        bool changed_ = false;
        std::optional<WindowPreflightInput> window_preflight_;
        std::optional<StateResult> committed_result_;
        std::vector<std::byte> response_;
    };

    StateOutcome transact(const RequestFacts &facts, const AnonymousGrant &grant,
                          std::uint64_t trustedNow,
                          const std::function<StateResult(Transaction &)> &callback);
    RawSessionRegistrationOutcome registerRawSession(
        const RequestFacts &facts, const AnonymousGrant &grant,
        std::uint64_t trustedNow, const RawSessionRegistrationInput &input,
        const BuildRawSessionMetadata &buildMetadata);
    std::optional<StateOutcome> lookupRawWindowRequest(
        const std::string &sessionId, const std::string &softwareId,
        const std::string &buildId, const std::string &regionId,
        const std::string &requestId, const std::string &requestDigest,
        std::uint64_t trustedNow);
    ReclamationOutcome reclaimExpiredResponses(std::uint64_t trustedNow);
    std::variant<std::monostate, BackendError> restore(const RecoveredState &recovered);

private:
    std::vector<std::byte> serialize() const;
    std::variant<std::monostate, BackendError> applySerialized(
        std::span<const std::byte> bytes);
    bool refreshRetainedBytes();

    struct ReplyRecord {
        StateResult result;
        std::string request_digest;
        std::string subject_id;
        std::string build_id;
        std::string software_id;
        std::string artifact_hash;
        std::string region_id;
        std::string request_type;
        std::uint64_t retire_at_ms = 0;
        bool retired = false;
        bool legacy_window_identity = false;
    };
    std::mutex mutex_;
    std::unordered_map<std::string, ReplyRecord> replies_;
    std::unordered_map<std::string, std::string> claims_;
    // Fresh raw registration stores only its identity-bound request fence. It
    // never stores or serves a replayable hello response.
    struct RawRegistrationRecord {
        std::string request_digest;
        std::string subject_id;
        std::string build_id;
        std::string software_id;
        std::string artifact_hash;
        // Public registration bindings needed to fail closed when restoring the
        // session and its replay claims. No private/derived key or hello bytes.
        std::string session_id;
        std::uint64_t counter = 0;
        std::string client_nonce;
        std::string client_ephemeral_key;
        std::string server_nonce;
        std::string server_ephemeral_key;
    };
    std::unordered_map<std::string, RawRegistrationRecord> raw_registrations_;
    std::unordered_map<std::string, std::uint64_t> generations_;
    struct SessionRecord {
        std::string build_id;
        std::string subject_id;
        std::string software_id;
        std::string artifact_hash;
        std::string counter_epoch;
        std::string transport_kind;
        std::string initial_state_commitment;
        std::uint32_t key_version = 0;
        std::uint64_t valid_until_ms = 0;
        bool closed = false;
        bool raw_chain_started = false;
    };
    std::unordered_map<std::string, SessionRecord> sessions_;
    struct WindowRecord {
        std::string region_id;
        std::uint64_t generation = 0;
        std::uint64_t window_id = 0;
        std::string state;
        std::uint64_t epoch_at_ms = 0;
        std::uint64_t deadline_ms = 0;
        bool legacy_timing = false;
    };
    std::unordered_map<std::string, WindowRecord> windows_;
    std::uint64_t next_counter_ = 1;
    std::size_t retained_bytes_ = 0;
    StateWal *wal_ = nullptr;
    std::uint64_t next_sequence_ = 1;
};

} // namespace xovm::cloud_material

#endif
