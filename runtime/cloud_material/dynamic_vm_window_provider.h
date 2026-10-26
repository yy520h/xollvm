#ifndef XOVM_DYNAMIC_VM_WINDOW_PROVIDER_H
#define XOVM_DYNAMIC_VM_WINDOW_PROVIDER_H

#include "dynamic_vm_schema.h"

#include <optional>
#include <span>

namespace xovm::material {

// Trusted provider-only input. Unlike WindowAcquireRequest, this contains secret
// and server-derived values and must never be accepted as a wire representation.
struct WindowIssueInput {
    DynamicHash build_id{};
    DynamicHash region_id{};
    std::array<uint8_t, 16> session_id{};
    std::array<uint8_t, 32> session_secret{};
    uint64_t generation = 0;
    uint64_t window_id = 0;
    DynamicHash previous_state_hash{};
    DynamicHash next_state_hash{};
    uint64_t now_ms = 0;
    uint64_t expires_at_ms = 0;
    uint32_t key_version = 0;
    std::vector<uint8_t> material;
};

// Temporary source-compatibility alias for existing trusted provider callers.
// Wire-facing code must use WindowAcquireRequest.
using WindowRequest = WindowIssueInput;

std::optional<WindowGrant> issueWindowGrant(const WindowIssueInput &input);
std::optional<WindowMaterial> decryptWindowMaterial(
    const WindowGrant &grant, std::span<const uint8_t, 32> session_secret);

} // namespace xovm::material

#endif
