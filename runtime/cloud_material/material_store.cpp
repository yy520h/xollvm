#include "material_store.h"

#include <openssl/crypto.h>
#include <algorithm>
#include <atomic>
#include <limits>
#include <unistd.h>

namespace xovm::material {
namespace {
constexpr uint64_t kNsPerMs = 1000000;
constexpr uint64_t kTenSecondsNs = 10000000000ULL;

#ifdef XOVM_MATERIAL_STORE_TESTING
std::atomic<ZeroizeObserver> ZeroizeProbe{nullptr};
#endif

bool checkedAdd(uint64_t left, uint64_t right, uint64_t &result) {
    if (left > std::numeric_limits<uint64_t>::max() - right) return false;
    result = left + right;
    return true;
}
} // namespace

struct GenerationState {
    ParsedPackage package;
    uint64_t deadline_ns = 0;
    uint64_t renew_at_ns = 0;
    bool has_deadline = false;

    ~GenerationState() {
        OPENSSL_cleanse(package.bytecode.data(), package.bytecode.size());
        OPENSSL_cleanse(package.decode_map.data(),
                        package.decode_map.size() * sizeof(package.decode_map[0]));
#ifdef XOVM_MATERIAL_STORE_TESTING
        if (auto observer = ZeroizeProbe.load(std::memory_order_acquire)) {
            const bool bytecodeCleared = std::all_of(package.bytecode.begin(), package.bytecode.end(),
                [](uint8_t value) { return value == 0; });
            const bool mapCleared = std::all_of(package.decode_map.begin(), package.decode_map.end(),
                [](uint16_t value) { return value == 0; });
            observer(bytecodeCleared, mapCleared);
        }
#endif
    }
};

MaterialStore::MaterialStore() : owner_pid_(getpid()) {}

bool MaterialStore::isOwnerProcess() const {
    return owner_pid_ == getpid();
}

StoreError MaterialStore::publish(VerifiedPackage verified, RequestTiming timing) {
    if (!isOwnerProcess()) return StoreError::ForkedProcess;
    if (timing.received_boot_ns < timing.sent_boot_ns ||
        timing.sent_boot_ns != verified.sentBootNs() ||
        timing.received_boot_ns != verified.receivedBootNs()) return StoreError::InvalidTiming;

    const auto &source = verified.package();
    auto candidate = std::make_shared<GenerationState>();
    candidate->package = source;
    if (source.binding.mode == "lease") {
        if (!source.binding.lease_ms || source.binding.lease_ms > 120000)
            return StoreError::InvalidTiming;
        const uint64_t leaseNs = static_cast<uint64_t>(source.binding.lease_ms) * kNsPerMs;
        if (!checkedAdd(timing.sent_boot_ns, leaseNs, candidate->deadline_ns))
            return StoreError::InvalidTiming;
        const uint64_t renewOffset = leaseNs > kTenSecondsNs ? leaseNs - kTenSecondsNs : 0;
        if (!checkedAdd(timing.sent_boot_ns, renewOffset, candidate->renew_at_ns))
            return StoreError::InvalidTiming;
        if (timing.received_boot_ns >= candidate->deadline_ns) return StoreError::Expired;
        candidate->has_deadline = true;
    } else if (source.binding.mode != "session" || source.binding.lease_ms != 0) {
        return StoreError::InvalidTiming;
    }

    std::shared_ptr<const GenerationState> retired;
    {
        std::lock_guard lock(mutex_);
        if (!running_) return StoreError::Shutdown;
        auto region = regions_.find(source.binding.region_id);
        if (region != regions_.end()) {
            if (region->second.session_id != source.binding.session_id)
                return StoreError::SessionMismatch;
            if (source.binding.generation <= region->second.generation)
                return StoreError::GenerationRejected;
            retired = std::move(region->second.current);
            region->second.generation = source.binding.generation;
            region->second.current = std::move(candidate);
        } else {
            regions_.emplace(source.binding.region_id, RegionState{
                source.binding.session_id, source.binding.generation, std::move(candidate)});
        }
    }
    retired.reset();
    return StoreError::None;
}

AcquireResult MaterialStore::acquire(const std::string &regionId, uint64_t nowBootNs) {
    if (!isOwnerProcess()) return {{}, StoreError::ForkedProcess};
    std::shared_ptr<const GenerationState> expired;
    std::lock_guard lock(mutex_);
    if (!running_) return {{}, StoreError::Shutdown};
    auto found = regions_.find(regionId);
    if (found == regions_.end()) return {{}, StoreError::RegionMismatch};
    const auto &state = found->second.current;
    if (!state) return {{}, StoreError::Expired};
    if (state->has_deadline && nowBootNs >= state->deadline_ns) {
        expired = std::move(found->second.current);
        return {{}, StoreError::Expired};
    }
    return {PinnedMaterial(state, owner_pid_), StoreError::None};
}

void MaterialStore::shutdown() {
    if (!isOwnerProcess()) return;
    std::unordered_map<std::string, RegionState> retired;
    {
        std::lock_guard lock(mutex_);
        running_ = false;
        retired.swap(regions_);
    }
    retired.clear();
}

PinnedMaterial::operator bool() const {
    return state_ && owner_pid_ == getpid();
}

const ParsedPackage *PinnedMaterial::package() const {
    return *this ? &state_->package : nullptr;
}

uint64_t PinnedMaterial::deadlineNs() const {
    return *this ? state_->deadline_ns : 0;
}

uint64_t PinnedMaterial::renewAtNs() const {
    return *this ? state_->renew_at_ns : 0;
}

bool PinnedMaterial::hasDeadline() const {
    return *this && state_->has_deadline;
}

void PinnedMaterial::release() {
    state_.reset();
    owner_pid_ = 0;
}

#ifdef XOVM_MATERIAL_STORE_TESTING
void setMaterialZeroizeObserverForTest(ZeroizeObserver observer) {
    ZeroizeProbe.store(observer, std::memory_order_release);
}
#endif

} // namespace xovm::material
