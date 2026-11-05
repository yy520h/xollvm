#include "integrity_state.h"

#include <openssl/sha.h>

namespace xovm::material {

std::optional<DynamicHash> IntegrityState::commit(const WindowGrant &grant,
                                                  const DynamicHash &next_state,
                                                  uint64_t window_id,
                                                  uint64_t continuation) const {
    const std::array<uint8_t, 32> empty{};
    return commit(grant, next_state, window_id, continuation, empty);
}

std::optional<DynamicHash> IntegrityState::commit(const WindowGrant &grant,
                                                  const DynamicHash &next_state,
                                                  uint64_t window_id,
                                                  uint64_t continuation,
                                                  std::span<const uint8_t, 32> integrity_material) const {
    if (grant.previous_state_hash != state_ || grant.window_id != window_id ||
        grant.next_state_hash != next_state || next_state == DynamicHash{})
        return std::nullopt;
    std::vector<uint8_t> input;
    constexpr char label[] = "XOVM/dynamic/integrity";
    input.insert(input.end(), label, label + sizeof(label) - 1);
    input.insert(input.end(), state_.begin(), state_.end());
    input.insert(input.end(), grant.build_id.begin(), grant.build_id.end());
    input.insert(input.end(), grant.region_id.begin(), grant.region_id.end());
    input.insert(input.end(), grant.artifact_hash.begin(), grant.artifact_hash.end());
    const auto selector = encodeDynamicVmWindowSelectorV3(grant.selector);
    if (selector.size() != kDynamicVmWindowSelectorV3EncodedSize)
        return std::nullopt;
    input.insert(input.end(), selector.begin(), selector.end());
    input.insert(input.end(), grant.session_id.begin(), grant.session_id.end());
    for (int shift = 56; shift >= 0; shift -= 8)
        input.push_back(static_cast<uint8_t>(grant.generation >> shift));
    for (int shift = 56; shift >= 0; shift -= 8)
        input.push_back(static_cast<uint8_t>(window_id >> shift));
    for (int shift = 56; shift >= 0; shift -= 8)
        input.push_back(static_cast<uint8_t>(continuation >> shift));
    input.insert(input.end(), next_state.begin(), next_state.end());
    input.insert(input.end(), grant.next_state_hash.begin(), grant.next_state_hash.end());
    input.insert(input.end(), integrity_material.begin(), integrity_material.end());
    DynamicHash result{};
    SHA256(input.data(), input.size(), result.data());
    return result;
}

bool IntegrityState::advance(const WindowGrant &grant, const DynamicHash &next_state,
                             uint64_t window_id, uint64_t continuation) {
    auto committed = commit(grant, next_state, window_id, continuation);
    if (!committed) return false;
    state_ = next_state;
    return true;
}

bool IntegrityState::advance(const WindowGrant &grant, const DynamicHash &next_state,
                             uint64_t window_id, uint64_t continuation,
                             std::span<const uint8_t, 32> integrity_material) {
    auto committed = commit(grant, next_state, window_id, continuation, integrity_material);
    if (!committed) return false;
    state_ = next_state;
    return true;
}

} // namespace xovm::material
