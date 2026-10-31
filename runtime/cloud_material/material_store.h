#ifndef XOVM_MATERIAL_STORE_H
#define XOVM_MATERIAL_STORE_H

#include "material_protocol.h"
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <utility>

namespace xovm::material {

struct RequestTiming {
    uint64_t sent_boot_ns = 0;
    uint64_t received_boot_ns = 0;
};

enum class StoreError {
    None,
    InvalidTiming,
    Expired,
    GenerationRejected,
    SessionMismatch,
    RegionMismatch,
    Shutdown,
    ForkedProcess,
};

struct GenerationState;

class PinnedMaterial {
public:
    PinnedMaterial() = default;
    PinnedMaterial(PinnedMaterial &&) noexcept = default;
    PinnedMaterial &operator=(PinnedMaterial &&) noexcept = default;
    PinnedMaterial(const PinnedMaterial &) = delete;
    PinnedMaterial &operator=(const PinnedMaterial &) = delete;
    ~PinnedMaterial() = default;

    explicit operator bool() const;
    const ParsedPackage *package() const;
    uint64_t deadlineNs() const;
    uint64_t renewAtNs() const;
    bool hasDeadline() const;
    void release();

private:
    explicit PinnedMaterial(std::shared_ptr<const GenerationState> state, int ownerPid)
        : state_(std::move(state)), owner_pid_(ownerPid) {}

    std::shared_ptr<const GenerationState> state_;
    int owner_pid_ = 0;
    friend class MaterialStore;
};

struct AcquireResult {
    PinnedMaterial material;
    StoreError error = StoreError::None;
};

class MaterialStore {
public:
    MaterialStore();
    MaterialStore(const MaterialStore &) = delete;
    MaterialStore &operator=(const MaterialStore &) = delete;

    StoreError publish(VerifiedPackage package, RequestTiming timing);
    AcquireResult acquire(const std::string &regionId, uint64_t nowBootNs);
    void shutdown();
    bool isOwnerProcess() const;

private:
    struct RegionState {
        std::string session_id;
        uint64_t generation = 0;
        std::shared_ptr<const GenerationState> current;
    };

    int owner_pid_ = 0;
    bool running_ = true;
    mutable std::mutex mutex_;
    std::unordered_map<std::string, RegionState> regions_;
};

uint64_t bootTimeNs();

#ifdef XOVM_MATERIAL_STORE_TESTING
using ZeroizeObserver = void (*)(bool bytecodeCleared, bool mapCleared);
void setMaterialZeroizeObserverForTest(ZeroizeObserver observer);
#endif

} // namespace xovm::material
#endif
