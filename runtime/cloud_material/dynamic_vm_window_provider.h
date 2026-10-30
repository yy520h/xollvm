#ifndef XOVM_DYNAMIC_VM_WINDOW_PROVIDER_H
#define XOVM_DYNAMIC_VM_WINDOW_PROVIDER_H

#include "dynamic_vm_schema.h"

#include <optional>
#include <span>

namespace xovm::material {

// Trusted provider output. The capability is stored only in material.window;
// selector identities are public and are persisted as commitments by the backend.
struct WindowMaterialProvisionV3 {
    DynamicHash artifact_hash{};
    DynamicVmWindowSelectorV3 selector{};
    WindowMaterial material{};
    // Public graph identities returned from the provider's private registration.
    // The service never trusts a request-side entry/successor assertion.
    DynamicVmWindowSelectorV3 entry_selector{};
    std::optional<DynamicVmWindowSelectorV3> next_selector;
};

void secureClear(WindowMaterialProvisionV3 &provision);

// Trusted provider-only input. Unlike WindowAcquireRequest, this contains secret
// and server-derived values and must never be accepted as a wire representation.
struct WindowIssueInput {
    DynamicHash build_id{};
    DynamicHash region_id{};
    DynamicHash artifact_hash{};
    DynamicVmWindowSelectorV3 selector{};
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
