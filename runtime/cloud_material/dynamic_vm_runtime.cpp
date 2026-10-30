#include "dynamic_vm_runtime.h"

#include "dynamic_vm_shard.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <openssl/crypto.h>
#include <span>
#include <utility>

namespace xovm::material {
namespace {

bool zeroHash(const DynamicHash &hash) {
    return std::all_of(hash.begin(), hash.end(),
                       [](uint8_t value) { return value == 0; });
}

std::optional<std::pair<DynamicVmExecutionAbiV2, ContinuationGraphV2>>
parseExecutionContract(const EncryptedVmArtifact &artifact) {
    if (artifact.continuation_descriptors.size() <=
        kDynamicVmExecutionAbiV2EncodedSize)
        return std::nullopt;
    auto abi = decodeDynamicVmExecutionAbiV2(
        std::span<const uint8_t>(artifact.continuation_descriptors)
            .first(kDynamicVmExecutionAbiV2EncodedSize));
    auto graph = decodeContinuationGraphV2(
        std::span<const uint8_t>(artifact.continuation_descriptors)
            .subspan(kDynamicVmExecutionAbiV2EncodedSize));
    if (!abi || !graph ||
        validateContinuationGraphV2(*abi, *graph) !=
            DynamicVmSchemaStatusV2::Valid)
        return std::nullopt;
    return std::pair{std::move(*abi), std::move(*graph)};
}

#if defined(XOVM_DYNAMIC_VM_TESTING)

uint32_t readLittleEndianU32(std::span<const uint8_t> bytes) {
    return static_cast<uint32_t>(bytes[0]) |
           static_cast<uint32_t>(bytes[1]) << 8 |
           static_cast<uint32_t>(bytes[2]) << 16 |
           static_cast<uint32_t>(bytes[3]) << 24;
}

bool validateNodeTemplate(const DynamicVmExecutionAbiV2 &abi,
                          const ContinuationNodeV2 &node,
                          std::span<const uint8_t> bytecode,
                          std::span<const uint8_t> handler_code) {
    if (bytecode.size() != node.bytecode_size ||
        handler_code.size() != node.shard_size)
        return false;
    const uint32_t next_ip = node.bytecode_offset + node.bytecode_size;
    if (node.semantic == ContinuationNodeSemanticV2::LoadI32) {
        const size_t immediate_offset = abi.loadi32_immediate_offset;
        if (immediate_offset > bytecode.size() ||
            sizeof(uint32_t) > bytecode.size() - immediate_offset)
            return false;
        return validateAarch64LoadImmediateShard(
            handler_code, node.register_index,
            readLittleEndianU32(bytecode.subspan(immediate_offset,
                                                 sizeof(uint32_t))),
            next_ip);
    }
    if (node.semantic == ContinuationNodeSemanticV2::ReturnI32)
        return validateAarch64ReturnIntShard(handler_code, node.register_index,
                                             next_ip);
    return false;
}

void clearRegisters(std::vector<uint32_t> &registers) {
    if (!registers.empty())
        OPENSSL_cleanse(registers.data(), registers.size() * sizeof(uint32_t));
    registers.clear();
    registers.shrink_to_fit();
}

#endif

} // namespace

ConsumedDynamicVmWindow::ConsumedDynamicVmWindow(
    ConsumedDynamicVmWindow &&other) noexcept
    : build_id_(other.build_id_), region_id_(other.region_id_),
      artifact_hash_(other.artifact_hash_), grant_(std::move(other.grant_)),
      material_(other.material_), integrity_commitment_(other.integrity_commitment_),
      continuation_(other.continuation_), pending_token_(other.pending_token_),
      pending_control_(std::move(other.pending_control_)), live_(other.live_) {
    other.clear(false);
}

ConsumedDynamicVmWindow &ConsumedDynamicVmWindow::operator=(
    ConsumedDynamicVmWindow &&other) noexcept {
    if (this != &other) {
        clear();
        build_id_ = other.build_id_;
        region_id_ = other.region_id_;
        artifact_hash_ = other.artifact_hash_;
        grant_ = std::move(other.grant_);
        material_ = other.material_;
        integrity_commitment_ = other.integrity_commitment_;
        continuation_ = other.continuation_;
        pending_token_ = other.pending_token_;
        pending_control_ = std::move(other.pending_control_);
        live_ = other.live_;
        other.clear(false);
    }
    return *this;
}

ConsumedDynamicVmWindow::~ConsumedDynamicVmWindow() {
    clear();
}

void ConsumedDynamicVmWindow::clear(bool abandon) {
    if (abandon && live_ && pending_control_ &&
        pending_control_->token.load(std::memory_order_acquire) == pending_token_)
        pending_control_->abandoned.store(true, std::memory_order_release);
    secureClear(material_);
    secureClear(grant_.encrypted_window_material);
    build_id_.fill(0);
    region_id_.fill(0);
    artifact_hash_.fill(0);
    grant_ = {};
    integrity_commitment_.fill(0);
    continuation_ = 0;
    pending_token_ = 0;
    pending_control_.reset();
    live_ = false;
}

DynamicVmWindowConsumer::DynamicVmWindowConsumer(
    DynamicVmWindowConsumer &&other) noexcept
    : build_id_(other.build_id_), region_id_(other.region_id_),
      artifact_hash_(other.artifact_hash_), session_id_(other.session_id_),
      state_hash_(other.state_hash_), generation_(other.generation_),
      window_id_(other.window_id_),
      integrity_commitment_(other.integrity_commitment_),
      integrity_(std::move(other.integrity_)), abi_(other.abi_),
      graph_(std::move(other.graph_)), expected_selector_(other.expected_selector_),
      pending_token_(other.pending_token_),
      pending_control_(std::move(other.pending_control_)), pending_(other.pending_),
      poisoned_(other.poisoned_) {
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
        abi_ = other.abi_;
        graph_ = std::move(other.graph_);
        expected_selector_ = other.expected_selector_;
        pending_token_ = other.pending_token_;
        pending_control_ = std::move(other.pending_control_);
        pending_ = other.pending_;
        poisoned_ = other.poisoned_;
        other.invalidate();
    }
    return *this;
}

void DynamicVmWindowConsumer::invalidate() {
    if (pending_ && pending_control_)
        pending_control_->abandoned.store(true, std::memory_order_release);
    build_id_.fill(0);
    region_id_.fill(0);
    artifact_hash_.fill(0);
    session_id_.fill(0);
    state_hash_.fill(0);
    generation_ = 0;
    window_id_ = 0;
    integrity_commitment_.fill(0);
    integrity_.reset();
    abi_ = {};
    graph_ = {};
    expected_selector_ = {};
    pending_token_ = 0;
    pending_control_.reset();
    pending_ = false;
    poisoned_ = true;
}

std::optional<DynamicVmWindowConsumer> DynamicVmWindowConsumer::create(
    const EncryptedVmArtifact &artifact, const DynamicHash &build_id,
    const DynamicHash &region_id, const DynamicHash &expected_artifact_hash,
    const std::array<uint8_t, 16> &session_id,
    const DynamicHash &initial_state, uint64_t generation) {
    if (!validateEncryptedVmArtifactMetadata(artifact, build_id, region_id,
                                             expected_artifact_hash) ||
        zeroHash(initial_state) || generation == 0)
        return std::nullopt;
    auto contract = parseExecutionContract(artifact);
    if (!contract || contract->second.nodes.empty()) return std::nullopt;
    auto entry = dynamicVmWindowSelectorV3(
        contract->first, contract->second.descriptor,
        contract->second.nodes.front());
    if (!entry || contract->second.descriptor.entry_node_id != entry->node_id)
        return std::nullopt;
    return DynamicVmWindowConsumer(
        build_id, region_id, artifact.artifact_hash, session_id, initial_state,
        generation, std::move(contract->first), std::move(contract->second),
        *entry);
}

std::optional<DynamicVmWindowSelectorV3>
DynamicVmWindowConsumer::successor(
    const DynamicVmWindowSelectorV3 &selector) const {
    const auto current = std::find_if(
        graph_.nodes.begin(), graph_.nodes.end(),
        [&](const ContinuationNodeV2 &node) { return node.node_id == selector.node_id; });
    if (current == graph_.nodes.end() || current->status == ContinuationNodeStatusV2::Return)
        return std::nullopt;
    const auto next = std::find_if(
        graph_.nodes.begin(), graph_.nodes.end(), [&](const ContinuationNodeV2 &node) {
            return node.node_id == current->next_node_id;
        });
    if (next == graph_.nodes.end()) return std::nullopt;
    return dynamicVmWindowSelectorV3(abi_, graph_.descriptor, *next);
}

std::optional<ConsumedDynamicVmWindow> DynamicVmWindowConsumer::consume(
    const WindowGrant &grant, std::span<const uint8_t, 32> session_secret,
    uint64_t now_ms, uint64_t continuation) {
    return consumeValidated(grant, session_secret, now_ms, continuation, false);
}

std::optional<ConsumedDynamicVmWindow>
DynamicVmWindowConsumer::installReplacement(
    const WindowGrant &grant, std::span<const uint8_t, 32> session_secret,
    uint64_t now_ms, uint64_t continuation) {
    return consumeValidated(grant, session_secret, now_ms, continuation, true);
}

std::optional<ConsumedDynamicVmWindow>
DynamicVmWindowConsumer::consumeValidated(
    const WindowGrant &grant, std::span<const uint8_t, 32> session_secret,
    uint64_t now_ms, uint64_t continuation, bool replacement) {
    if (pending_ && pending_control_ &&
        pending_control_->abandoned.load(std::memory_order_acquire)) {
        pending_ = false;
        poisoned_ = true;
    }
    if (poisoned_ || pending_) return std::nullopt;
    const auto entry_selector = dynamicVmWindowSelectorV3(
        abi_, graph_.descriptor, graph_.nodes.front());
    const bool generation_valid = replacement
        ? generation_ != UINT64_MAX && grant.generation == generation_ + 1 &&
              grant.window_id == 1 && entry_selector &&
              grant.selector == *entry_selector
        : grant.generation == generation_ && window_id_ != UINT64_MAX &&
              grant.window_id == window_id_ + 1 &&
              grant.selector == expected_selector_;
    if (grant.format_version != kDynamicVmSelectiveFormatVersionV3 ||
        grant.build_id != build_id_ || grant.region_id != region_id_ ||
        grant.artifact_hash != artifact_hash_ ||
        grant.session_id != session_id_ ||
        !generation_valid || grant.previous_state_hash != state_hash_ ||
        grant.issued_at_ms > now_ms || now_ms >= grant.expires_at_ms ||
        zeroHash(grant.next_state_hash))
        return std::nullopt;
    auto material = decryptWindowMaterial(grant, session_secret);
    if (!material) return std::nullopt;
    IntegrityState state = integrity_ ? *integrity_ : IntegrityState(state_hash_);
    auto commitment = state.commit(grant, grant.next_state_hash, grant.window_id,
                                   continuation, material->integrity);
    if (!commitment) {
        secureClear(*material);
        return std::nullopt;
    }
    if (pending_token_ == UINT64_MAX) {
        secureClear(*material);
        poisoned_ = true;
        return std::nullopt;
    }
    ++pending_token_;
    pending_control_ = std::make_shared<DynamicVmPendingControl>();
    pending_control_->token.store(pending_token_, std::memory_order_release);
    pending_ = true;
    ConsumedDynamicVmWindow consumed(
        build_id_, region_id_, artifact_hash_, grant, *material, *commitment,
        continuation, pending_token_, pending_control_);
    secureClear(*material);
    return consumed;
}

bool DynamicVmWindowConsumer::commitPending(
    const ConsumedDynamicVmWindow &window) {
    if (poisoned_ || !pending_ || !window.live_ ||
        !pending_control_ || pending_control_->abandoned.load(std::memory_order_acquire) ||
        window.pending_control_ != pending_control_ ||
        window.pending_token_ != pending_token_ ||
        window.grant_.previous_state_hash != state_hash_)
        return false;
    IntegrityState state = integrity_ ? *integrity_ : IntegrityState(state_hash_);
    if (!state.advance(window.grant_, window.grant_.next_state_hash,
                       window.grant_.window_id, window.continuation_,
                       window.material_.integrity))
        return false;
    state_hash_ = window.grant_.next_state_hash;
    generation_ = window.grant_.generation;
    window_id_ = window.grant_.window_id;
    integrity_commitment_ = window.integrity_commitment_;
    integrity_ = std::make_unique<IntegrityState>(state);
    const auto next = successor(window.grant_.selector);
    expected_selector_ = next ? *next : DynamicVmWindowSelectorV3{};
    pending_ = false;
    pending_control_.reset();
    return true;
}

void DynamicVmWindowConsumer::rejectPending(uint64_t token) {
    if (pending_ && token == pending_token_) {
        pending_ = false;
        pending_control_.reset();
        poisoned_ = true;
    }
}

#if defined(XOVM_DYNAMIC_VM_TESTING)

DynamicVmExecutionStateForTesting::DynamicVmExecutionStateForTesting(
    DynamicVmExecutionStateForTesting &&other) noexcept
    : artifact_hash_(other.artifact_hash_), abi_hash_(other.abi_hash_),
      expected_node_id_(other.expected_node_id_),
      instruction_pointer_(other.instruction_pointer_),
      return_value_(other.return_value_), registers_(std::move(other.registers_)),
      started_(other.started_), complete_(other.complete_) {
    other.clear();
}

DynamicVmExecutionStateForTesting &
DynamicVmExecutionStateForTesting::operator=(
    DynamicVmExecutionStateForTesting &&other) noexcept {
    if (this != &other) {
        clear();
        artifact_hash_ = other.artifact_hash_;
        abi_hash_ = other.abi_hash_;
        expected_node_id_ = other.expected_node_id_;
        instruction_pointer_ = other.instruction_pointer_;
        return_value_ = other.return_value_;
        registers_ = std::move(other.registers_);
        started_ = other.started_;
        complete_ = other.complete_;
        other.clear();
    }
    return *this;
}

DynamicVmExecutionStateForTesting::~DynamicVmExecutionStateForTesting() {
    clear();
}

void DynamicVmExecutionStateForTesting::clear() {
    clearRegisters(registers_);
    artifact_hash_.fill(0);
    abi_hash_.fill(0);
    expected_node_id_ = 0;
    instruction_pointer_ = 0;
    return_value_ = 0;
    started_ = false;
    complete_ = false;
}

std::optional<DynamicVmExecutionResult> executeDynamicVmWindowForTesting(
    const EncryptedVmArtifact &artifact, DynamicVmWindowConsumer &consumer,
    ConsumedDynamicVmWindow &&window, DynamicVmExecutionStateForTesting &state,
    uint64_t now_ms) {
    const uint64_t token = window.pending_token_;
    const bool live = window.live_;
    const auto grant = window.grant_;
    auto capability = window.material_.window;
    const uint8_t decode_salt = window.material_.decode[0];
    const DynamicHash build_id = window.build_id_;
    const DynamicHash region_id = window.region_id_;
    const DynamicHash artifact_hash = window.artifact_hash_;
    if (!live || state.complete_ || now_ms >= grant.expires_at_ms ||
        artifact.build_id != build_id || artifact.region_id != region_id ||
        artifact.artifact_hash != artifact_hash) {
        consumer.rejectPending(token);
        window.clear();
        return std::nullopt;
    }
    auto decrypted = decryptSelectiveDynamicVmNodeV3(
        artifact, grant.selector, capability, build_id, region_id, artifact_hash);
    OPENSSL_cleanse(capability.data(), capability.size());
    window.material_.window.fill(0);
    if (!decrypted || decrypted->abi().decode_salt != decode_salt ||
        decrypted->node().node_id != grant.selector.node_id ||
        !validateNodeTemplate(decrypted->abi(), decrypted->node(),
                              decrypted->bytecodeBlock(),
                              decrypted->handlerShard())) {
        consumer.rejectPending(token);
        window.clear();
        return std::nullopt;
    }
    const auto abi_hash = hashDynamicVmExecutionAbiV2(decrypted->abi());
    if (!abi_hash) {
        consumer.rejectPending(token);
        window.clear();
        return std::nullopt;
    }
    if (!state.started_) {
        if (decrypted->node().node_id !=
            decrypted->descriptor().entry_node_id) {
            consumer.rejectPending(token);
            window.clear();
            return std::nullopt;
        }
        state.artifact_hash_ = artifact_hash;
        state.abi_hash_ = *abi_hash;
        state.expected_node_id_ = decrypted->node().node_id;
        state.instruction_pointer_ = decrypted->node().bytecode_offset;
        state.registers_.assign(decrypted->abi().i32_register_count, 0);
        state.started_ = true;
    }
    if (state.artifact_hash_ != artifact_hash || state.abi_hash_ != *abi_hash ||
        state.expected_node_id_ != decrypted->node().node_id ||
        state.instruction_pointer_ != decrypted->node().bytecode_offset ||
        state.registers_.size() != decrypted->abi().i32_register_count) {
        consumer.rejectPending(token);
        window.clear();
        state.clear();
        return std::nullopt;
    }

#if !defined(__aarch64__) || defined(XOVM_DYNAMIC_VM_TEST_NON_AARCH64)
    consumer.rejectPending(token);
    window.clear();
    state.clear();
    return std::nullopt;
#else
    XovmDynamicVmExecutionContext context{
        XOVM_DYNAMIC_VM_EXECUTION_CONTEXT_VERSION,
        XOVM_DYNAMIC_VM_EXECUTION_CONTEXT_SIZE,
        state.registers_.data(),
        static_cast<uint32_t>(state.registers_.size()),
        &state.return_value_,
        state.instruction_pointer_,
        decrypted->bytecodeBlock().data(),
        static_cast<uint32_t>(decrypted->bytecodeBlock().size()),
        nullptr,
    };
    auto buffer = JitHandlerBuffer::allocate(decrypted->handlerShard().size());
    if (!buffer || !buffer->loadAndSeal(decrypted->handlerShard(), {})) {
        if (buffer) (void)buffer->close();
        consumer.rejectPending(token);
        window.clear();
        state.clear();
        return std::nullopt;
    }
    auto entry = reinterpret_cast<DynamicVmShardEntry>(buffer->address());
    const uint32_t observed_status = entry(&context);
    const bool closed = buffer->close();
    const uint32_t expected_status =
        decrypted->node().status == ContinuationNodeStatusV2::Continue
            ? XOVM_SHARD_CONTINUE
            : XOVM_SHARD_RETURN;
    const uint32_t expected_ip = decrypted->node().bytecode_offset +
                                 decrypted->node().bytecode_size;
    if (!closed || observed_status != expected_status ||
        context.instruction_pointer != expected_ip ||
        (decrypted->node().status == ContinuationNodeStatusV2::Continue &&
         decrypted->node().next_node_id == 0) ||
        (decrypted->node().status == ContinuationNodeStatusV2::Return &&
         decrypted->node().next_node_id != 0)) {
        consumer.rejectPending(token);
        window.clear();
        state.clear();
        return std::nullopt;
    }
    state.instruction_pointer_ = context.instruction_pointer;
    state.expected_node_id_ = decrypted->node().next_node_id;
    state.complete_ = decrypted->node().status == ContinuationNodeStatusV2::Return;
    if (!consumer.commitPending(window)) {
        consumer.rejectPending(token);
        window.clear();
        state.clear();
        return std::nullopt;
    }
    window.clear();
    const DynamicVmExecutionResult result{
        observed_status, state.instruction_pointer_, state.return_value_,
        state.complete_};
    if (state.complete_) {
        const uint32_t returned = state.return_value_;
        const uint32_t ip = state.instruction_pointer_;
        state.clear();
        state.complete_ = true;
        state.return_value_ = returned;
        state.instruction_pointer_ = ip;
    }
    return result;
#endif
}

#endif

} // namespace xovm::material
