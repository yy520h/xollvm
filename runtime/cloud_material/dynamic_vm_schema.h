#ifndef XOVM_DYNAMIC_VM_SCHEMA_H
#define XOVM_DYNAMIC_VM_SCHEMA_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace xovm::material {

inline constexpr uint16_t kDynamicVmFormatVersion = 2;
inline constexpr size_t kDynamicVmHashSize = 32;
inline constexpr size_t kWindowAcquireRequestEncodedSize = 130;
inline constexpr size_t kWindowMaterialSize = 192;
inline constexpr size_t kEncryptedWindowMaterialSize = 220;
inline constexpr size_t kDynamicVmMaxWindowMaterial = 256 * 1024;
inline constexpr size_t kDynamicVmMaxDescriptor = 64 * 1024;

using DynamicHash = std::array<uint8_t, kDynamicVmHashSize>;

struct EncryptedVmArtifact {
    uint16_t format_version = kDynamicVmFormatVersion;
    DynamicHash build_id{};
    DynamicHash region_id{};
    DynamicHash artifact_hash{};
    std::vector<uint8_t> encrypted_bytecode_blocks;
    std::vector<uint8_t> encrypted_handler_shards;
    std::vector<uint8_t> continuation_descriptors;
    std::vector<uint8_t> relocation_descriptors;
};

// Canonical wire claim sent by a client when acquiring its next material window.
struct WindowAcquireRequest {
    uint16_t format_version = kDynamicVmFormatVersion;
    std::array<uint8_t, 16> request_id{};
    DynamicHash build_id{};
    DynamicHash region_id{};
    uint64_t generation = 0;
    uint64_t window_id = 0;
    DynamicHash previous_state_hash{};

    bool operator==(const WindowAcquireRequest &) const = default;
};

struct WindowGrant {
    uint16_t format_version = kDynamicVmFormatVersion;
    DynamicHash build_id{};
    DynamicHash region_id{};
    std::array<uint8_t, 16> session_id{};
    uint64_t generation = 0;
    uint64_t window_id = 0;
    DynamicHash previous_state_hash{};
    DynamicHash next_state_hash{};
    uint64_t issued_at_ms = 0;
    uint64_t expires_at_ms = 0;
    uint32_t key_version = 0;
    std::vector<uint8_t> encrypted_window_material;
};

struct ContinuationWindow {
    DynamicHash state_hash{};
    uint64_t window_id = 0;
    std::vector<uint8_t> authenticated_bytes;
};

struct HandlerShardDescriptor {
    uint32_t shard_id = 0;
    uint32_t code_size = 0;
    uint32_t relocation_count = 0;
    DynamicHash commitment{};

    bool operator==(const HandlerShardDescriptor &) const = default;
};

struct HandlerShardPayload {
    HandlerShardDescriptor descriptor;
    std::vector<uint8_t> code;
};

struct GuardianChannelHello {
    uint16_t format_version = kDynamicVmFormatVersion;
    std::array<uint8_t, 32> boot_nonce{};
    std::array<uint8_t, 16> session_id{};
    uint64_t generation = 0;
    uint64_t challenge_counter = 0;
    DynamicHash previous_state_digest{};
};

struct WindowBinding {
    DynamicHash build_id{};
    DynamicHash region_id{};
    std::array<uint8_t, 16> session_id{};
    uint64_t generation = 0;
    uint64_t window_id = 0;
    DynamicHash previous_state_hash{};
    uint64_t now_ms = 0;
};

struct WindowMaterial {
    std::array<uint8_t, 32> window{};
    std::array<uint8_t, 32> permutation{};
    std::array<uint8_t, 32> decode{};
    std::array<uint8_t, 32> chaff{};
    std::array<uint8_t, 32> integrity{};
    std::array<uint8_t, 32> jit{};
};

static_assert(sizeof(WindowMaterial) == kWindowMaterialSize);

std::vector<uint8_t> encodeEncryptedVmArtifact(const EncryptedVmArtifact &artifact);
std::optional<EncryptedVmArtifact> decodeEncryptedVmArtifact(std::span<const uint8_t> encoded);
std::vector<uint8_t> encodeWindowAcquireRequest(const WindowAcquireRequest &request);
std::optional<WindowAcquireRequest> decodeWindowAcquireRequest(
    std::span<const uint8_t> encoded);
std::vector<uint8_t> encodeHandlerShardDescriptor(const HandlerShardDescriptor &descriptor);
std::optional<HandlerShardDescriptor> decodeHandlerShardDescriptor(
    std::span<const uint8_t> encoded);
std::vector<uint8_t> encodeHandlerShardPayload(const HandlerShardDescriptor &descriptor,
                                               std::span<const uint8_t> code);
std::optional<HandlerShardPayload> decodeHandlerShardPayload(
    std::span<const uint8_t> encoded);
std::vector<uint8_t> encodeWindowGrant(const WindowGrant &grant);
std::optional<WindowGrant> decodeWindowGrant(std::span<const uint8_t> encoded);
bool validateWindowBinding(const WindowGrant &grant, const WindowBinding &binding);
bool advanceContinuation(const DynamicHash &current_state,
                         const WindowGrant &grant,
                         DynamicHash &next_state);

WindowMaterial deriveWindowMaterial(std::span<const uint8_t, 32> session_secret,
                                    const WindowGrant &grant);

void secureClear(std::vector<uint8_t> &bytes);
void secureClear(WindowMaterial &material);

} // namespace xovm::material

#endif
