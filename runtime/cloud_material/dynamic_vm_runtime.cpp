#include "dynamic_vm_runtime.h"

#include "continuation_executor.h"
#include "dynamic_vm_shard.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>
#include <vector>

namespace xovm::material {
namespace {

bool zeroHash(const DynamicHash &hash) {
    return std::all_of(hash.begin(), hash.end(), [](uint8_t value) { return value == 0; });
}

#if defined(XOVM_DYNAMIC_VM_TESTING)

void secureClearBytes(std::span<uint8_t> bytes) {
    volatile uint8_t *cursor = bytes.data();
    for (size_t index = 0; index < bytes.size(); ++index)
        cursor[index] = 0;
}

struct EphemeralArtifactKey {
    std::array<uint8_t, 32> bytes{};
    void clear() { secureClearBytes(bytes); }
    ~EphemeralArtifactKey() { clear(); }
};

struct DecryptedArtifactGuard {
    std::optional<DecryptedVmArtifact> &artifact;
    ~DecryptedArtifactGuard() {
        if (artifact) secureClear(*artifact);
    }
};

struct HandlerCodeGuard {
    std::optional<HandlerShardPayload> &payload;
    ~HandlerCodeGuard() {
        if (payload) secureClear(payload->code);
    }
};

struct RegisterGuard {
    std::vector<uint32_t> &registers;
    ~RegisterGuard() {
        secureClearBytes(std::span<uint8_t>(
            reinterpret_cast<uint8_t *>(registers.data()),
            registers.size() * sizeof(uint32_t)));
    }
};

uint32_t readLittleEndianU32(std::span<const uint8_t> bytes) {
    return static_cast<uint32_t>(bytes[0]) |
           (static_cast<uint32_t>(bytes[1]) << 8) |
           (static_cast<uint32_t>(bytes[2]) << 16) |
           (static_cast<uint32_t>(bytes[3]) << 24);
}

bool validateNodeTemplate(const DynamicVmExecutionAbiV2 &abi,
                          const ContinuationNodeV2 &node,
                          std::span<const uint8_t> bytecode,
                          std::span<const uint8_t> handler_code) {
    const auto block = bytecode.subspan(node.bytecode_offset, node.bytecode_size);
    const auto shard = handler_code.subspan(node.shard_offset, node.shard_size);
    const uint32_t next_ip = node.bytecode_offset + node.bytecode_size;

    if (node.semantic == ContinuationNodeSemanticV2::LoadI32) {
        const size_t immediate_offset = abi.loadi32_immediate_offset;
        if (immediate_offset + sizeof(uint32_t) > block.size()) return false;
        return validateAarch64LoadImmediateShard(
            shard, node.register_index,
            readLittleEndianU32(block.subspan(immediate_offset, sizeof(uint32_t))),
            next_ip);
    }
    if (node.semantic == ContinuationNodeSemanticV2::ReturnI32)
        return validateAarch64ReturnIntShard(
            shard, node.register_index, next_ip);
    return false;
}

#endif

} // namespace

ConsumedDynamicVmWindow::ConsumedDynamicVmWindow(ConsumedDynamicVmWindow &&other) noexcept
    : build_id_(other.build_id_), region_id_(other.region_id_),
      artifact_hash_(other.artifact_hash_), generation_(other.generation_),
      window_id_(other.window_id_), expires_at_ms_(other.expires_at_ms_),
      material_(other.material_), live_(other.live_) {
    other.clear();
}

ConsumedDynamicVmWindow &ConsumedDynamicVmWindow::operator=(
    ConsumedDynamicVmWindow &&other) noexcept {
    if (this != &other) {
        clear();
        build_id_ = other.build_id_;
        region_id_ = other.region_id_;
        artifact_hash_ = other.artifact_hash_;
        generation_ = other.generation_;
        window_id_ = other.window_id_;
        expires_at_ms_ = other.expires_at_ms_;
        material_ = other.material_;
        live_ = other.live_;
        other.clear();
    }
    return *this;
}

ConsumedDynamicVmWindow::~ConsumedDynamicVmWindow() {
    clear();
}

void ConsumedDynamicVmWindow::clear() {
    secureClear(material_);
    build_id_.fill(0);
    region_id_.fill(0);
    artifact_hash_.fill(0);
    generation_ = 0;
    window_id_ = 0;
    expires_at_ms_ = 0;
    live_ = false;
}

DynamicVmWindowConsumer::DynamicVmWindowConsumer(
    DynamicVmWindowConsumer &&other) noexcept
    : build_id_(other.build_id_), region_id_(other.region_id_),
      artifact_hash_(other.artifact_hash_), session_id_(other.session_id_),
      state_hash_(other.state_hash_), generation_(other.generation_),
      window_id_(other.window_id_),
      integrity_commitment_(other.integrity_commitment_),
      integrity_(std::move(other.integrity_)) {
    other.invalidate();
}

DynamicVmWindowConsumer &DynamicVmWindowConsumer::operator=(
    DynamicVmWindowConsumer &&other) noexcept {
    if (this != &other) {
        invalidate();
        build_id_ = other.build_id_;
        region_id_ = other.region_id_;
        artifact_hash_ = other.artifact_hash_;
        session_id_ = other.session_id_;
        state_hash_ = other.state_hash_;
        generation_ = other.generation_;
        window_id_ = other.window_id_;
        integrity_commitment_ = other.integrity_commitment_;
        integrity_ = std::move(other.integrity_);
        other.invalidate();
    }
    return *this;
}

void DynamicVmWindowConsumer::invalidate() {
    build_id_.fill(0);
    region_id_.fill(0);
    artifact_hash_.fill(0);
    session_id_.fill(0);
    state_hash_.fill(0);
    generation_ = 0;
    window_id_ = 0;
    integrity_commitment_.fill(0);
    integrity_.reset();
}

std::optional<DynamicVmWindowConsumer> DynamicVmWindowConsumer::create(
    const EncryptedVmArtifact &artifact,
    const DynamicHash &build_id,
    const DynamicHash &region_id,
    const DynamicHash &expected_artifact_hash,
    const std::array<uint8_t, 16> &session_id,
    const DynamicHash &initial_state,
    uint64_t generation) {
    if (!validateEncryptedVmArtifactMetadata(artifact, build_id, region_id,
                                             expected_artifact_hash) ||
        zeroHash(initial_state) || generation == 0)
        return std::nullopt;
    return DynamicVmWindowConsumer(build_id, region_id, artifact.artifact_hash,
                                   session_id, initial_state, generation);
}

#if defined(XOVM_DYNAMIC_VM_TESTING)
std::optional<DynamicVmExecutionResult> executeDynamicVmArtifactForTesting(
    const EncryptedVmArtifact &artifact,
    ConsumedDynamicVmWindow &&window,
    uint64_t now_ms,
    uint32_t initial_ip) {
    const bool live = window.live_;
    const DynamicHash build_id = window.build_id_;
    const DynamicHash region_id = window.region_id_;
    const DynamicHash artifact_hash = window.artifact_hash_;
    const uint64_t expires_at_ms = window.expires_at_ms_;
    const uint8_t decode_salt = window.material_.decode[0];
    EphemeralArtifactKey artifact_key{window.material_.window};
    window.clear();
    if (!live || now_ms >= expires_at_ms ||
        artifact.build_id != build_id || artifact.region_id != region_id ||
        artifact.artifact_hash != artifact_hash ||
        !validateEncryptedVmArtifactMetadata(
            artifact, build_id, region_id, artifact_hash))
        return std::nullopt;

    auto decrypted = decryptEncryptedVmArtifact(
        artifact, artifact_key.bytes, build_id, region_id, artifact_hash);
    artifact_key.clear();
    DecryptedArtifactGuard decrypted_guard{decrypted};
    if (!decrypted || decrypted->continuation_descriptors.size() <
                          kDynamicVmExecutionAbiV2EncodedSize)
        return std::nullopt;

    const std::span<const uint8_t> descriptors =
        decrypted->continuation_descriptors;
    auto abi = decodeDynamicVmExecutionAbiV2(
        descriptors.first(kDynamicVmExecutionAbiV2EncodedSize));
    auto graph = decodeContinuationGraphV2(
        descriptors.subspan(kDynamicVmExecutionAbiV2EncodedSize));
    auto payload = decodeHandlerShardPayload(decrypted->handler_shards);
    HandlerCodeGuard payload_guard{payload};
    if (!abi || !graph || !payload || abi->decode_salt != decode_salt ||
        !decrypted->relocation_descriptors.empty() || graph->nodes.empty() ||
        graph->nodes.size() > kDynamicVmMaxContinuationNodesV2 ||
        payload->descriptor.shard_id != graph->nodes.front().shard_id ||
        payload->descriptor.code_size != payload->code.size() ||
        payload->descriptor.relocation_count != 0 ||
        payload->descriptor.commitment != hashAarch64ShardCode(payload->code) ||
        validateContinuationGraphV2(*abi, *graph, decrypted->bytecode,
                                    payload->code) !=
            DynamicVmSchemaStatusV2::Valid)
        return std::nullopt;

    for (const auto &node : graph->nodes) {
        if (!validateNodeTemplate(*abi, node, decrypted->bytecode,
                                  payload->code))
            return std::nullopt;
    }

    auto cursor = ContinuationCursorV2::create(*abi, *graph);
    if (!cursor || !cursor->current() ||
        initial_ip != cursor->current()->bytecode_offset)
        return std::nullopt;

#if !defined(__aarch64__) || defined(XOVM_DYNAMIC_VM_TEST_NON_AARCH64)
    return std::nullopt;
#else
    std::vector<uint32_t> registers(abi->i32_register_count, 0);
    RegisterGuard register_guard{registers};
    uint32_t return_value = 0;
    XovmDynamicVmExecutionContext context{
        XOVM_DYNAMIC_VM_EXECUTION_CONTEXT_VERSION,
        XOVM_DYNAMIC_VM_EXECUTION_CONTEXT_SIZE,
        registers.data(),
        static_cast<uint32_t>(registers.size()),
        &return_value,
        initial_ip,
        decrypted->bytecode.data(),
        static_cast<uint32_t>(decrypted->bytecode.size()),
        nullptr,
    };

    uint32_t final_status = XOVM_SHARD_ABORT;
    size_t traversed = 0;
    while (!cursor->complete()) {
        const ContinuationNodeV2 *node = cursor->current();
        if (!node || traversed >= graph->nodes.size()) return std::nullopt;
        const auto shard = std::span<const uint8_t>(payload->code).subspan(
            node->shard_offset, node->shard_size);
        auto buffer = JitHandlerBuffer::allocate(shard.size());
        if (!buffer) return std::nullopt;
        if (!buffer->loadAndSeal(shard, {})) {
            (void)buffer->close();
            return std::nullopt;
        }

        auto entry = reinterpret_cast<DynamicVmShardEntry>(buffer->address());
        const uint32_t observed_status = entry(&context);
        const bool closed = buffer->close();
        if (!closed) return std::nullopt;

        const uint32_t expected_status =
            node->status == ContinuationNodeStatusV2::Continue
                ? XOVM_SHARD_CONTINUE
                : XOVM_SHARD_RETURN;
        const uint32_t expected_ip = node->bytecode_offset + node->bytecode_size;
        if (observed_status != expected_status ||
            context.instruction_pointer != expected_ip)
            return std::nullopt;

        ContinuationCompletionV2 completion{
            node->node_id, node->status, node->next_node_id,
            node->transition_tail_commitment};
        if (!cursor->advance(completion)) return std::nullopt;
        final_status = observed_status;
        ++traversed;
    }

    if (traversed == 0 || traversed != graph->nodes.size() || traversed > 2 ||
        final_status != XOVM_SHARD_RETURN)
        return std::nullopt;
    return DynamicVmExecutionResult{
        final_status, context.instruction_pointer, return_value};
#endif
}
#endif

std::optional<ConsumedDynamicVmWindow> DynamicVmWindowConsumer::consume(
    const WindowGrant &grant,
    std::span<const uint8_t, 32> session_secret,
    uint64_t now_ms, uint64_t continuation) {
    if (grant.format_version != kDynamicVmFormatVersion || grant.build_id != build_id_ ||
        grant.region_id != region_id_ || grant.session_id != session_id_ ||
        grant.generation != generation_ || grant.window_id != window_id_ + 1 ||
        grant.previous_state_hash != state_hash_ || grant.issued_at_ms > now_ms ||
        now_ms >= grant.expires_at_ms || zeroHash(grant.next_state_hash))
        return std::nullopt;
    auto material = decryptWindowMaterial(grant, session_secret);
    if (!material) return std::nullopt;
    IntegrityState state = integrity_ ? *integrity_ : IntegrityState(state_hash_);
    auto commitment = state.commit(grant, grant.next_state_hash, grant.window_id,
                                   continuation, material->integrity);
    if (!commitment || !state.advance(grant, grant.next_state_hash, grant.window_id,
                                      continuation, material->integrity)) {
        secureClear(*material);
        return std::nullopt;
    }
    state_hash_ = grant.next_state_hash;
    generation_ = grant.generation;
    window_id_ = grant.window_id;
    integrity_commitment_ = *commitment;
    integrity_ = std::make_unique<IntegrityState>(state);
    ConsumedDynamicVmWindow consumed(build_id_, region_id_, artifact_hash_,
                                     generation_, window_id_, grant.expires_at_ms,
                                     *material);
    secureClear(*material);
    return consumed;
}

} // namespace xovm::material
