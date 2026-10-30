#include "state_maintenance.h"

namespace xovm::cloud_material {
namespace {

std::variant<std::monostate, BackendError> validate(
    const RecoveredState &recovered) {
    SessionState state;
    return state.restore(recovered);
}

} // namespace

StateMaintenanceOutcome runOfflineStateMaintenance(
    const std::filesystem::path &stateDir,
    const TrustedNow &trustedNow,
    const ProcessLock &lock) {
    if (stateDir.empty() || !trustedNow)
        return BackendError{"maintenance_unavailable"};
    std::error_code pathError;
    if (!std::filesystem::equivalent(
            lock.path().parent_path(), stateDir, pathError) || pathError)
        return BackendError{"maintenance_lock_mismatch"};

    const auto walPath = stateDir / "state.wal";
    Checkpoint checkpoint(stateDir / "checkpoint.bin", walPath);
    auto recovered = checkpoint.recover();
    if (const auto *error = std::get_if<BackendError>(&recovered)) return *error;
    auto initial = std::get<RecoveredState>(std::move(recovered));
    auto restored = validate(initial);
    if (const auto *error = std::get_if<BackendError>(&restored)) return *error;

    auto now = trustedNow();
    if (const auto *error = std::get_if<BackendError>(&now)) return *error;

    ReclamationResult reclamation;
    {
        StateWal wal(walPath, {}, initial.last_sequence,
                     WalAppendMode::maintenance);
        SessionState state(&wal);
        restored = state.restore(initial);
        if (const auto *error = std::get_if<BackendError>(&restored))
            return *error;
        auto result = state.reclaimExpiredResponses(
            std::get<std::uint64_t>(now));
        if (const auto *error = std::get_if<BackendError>(&result)) return *error;
        reclamation = std::get<ReclamationResult>(std::move(result));
    }

    recovered = checkpoint.recover();
    if (const auto *error = std::get_if<BackendError>(&recovered)) return *error;
    auto latest = std::get<RecoveredState>(std::move(recovered));
    restored = validate(latest);
    if (const auto *error = std::get_if<BackendError>(&restored)) return *error;

    std::error_code existsError;
    const bool walExists = std::filesystem::exists(walPath, existsError);
    if (existsError) return BackendError{"maintenance_state_unavailable"};
    if (latest.last_sequence != 0 &&
        (reclamation.records_retired != 0 || walExists)) {
        auto compacted = checkpoint.writeAtomic(latest, latest.last_sequence);
        if (const auto *error = std::get_if<BackendError>(&compacted))
            return *error;
    }

    return StateMaintenanceResult{
        .records_retired = reclamation.records_retired,
        .response_bytes_reclaimed = reclamation.response_bytes_reclaimed,
        .replies_compacted = reclamation.replies_compacted,
        .raw_registrations_compacted = reclamation.raw_registrations_compacted,
        .sessions_compacted = reclamation.sessions_compacted,
        .claims_compacted = reclamation.claims_compacted,
        .sequence = latest.last_sequence,
        .more_work = reclamation.more_work,
    };
}

} // namespace xovm::cloud_material
