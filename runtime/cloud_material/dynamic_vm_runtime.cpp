#include "dynamic_vm_runtime.h"
#include "dynamic_vm_shard.h"

#include <openssl/evp.h>
#include <algorithm>
#include <cstring>

namespace xovm::material {
namespace {

bool zeroHash(const DynamicHash &hash) {
    return std::all_of(hash.begin(), hash.end(), [](uint8_t value) { return value == 0; });
}

uint32_t runDynamicShard(DynamicVmShardContext *context) {
    if (!context || !context->bytecode || !context->regs || !context->ret_storage ||
        !context->program.supported || context->reg_count == 0 ||
        context->ip >= context->bytecode_size)
        return XOVM_SHARD_ABORT;
    const uint8_t *Bytecode = context->bytecode;
    const size_t IP = context->ip;
    if (Bytecode[IP] == context->program.load_opcode) {
        if (IP + context->program.load_size > context->bytecode_size ||
            Bytecode[IP + context->program.load_destination_offset] >= context->reg_count)
            return XOVM_SHARD_ABORT;
        const size_t ImmediateOffset = IP + context->program.load_immediate_offset;
        uint32_t Immediate = static_cast<uint32_t>(Bytecode[ImmediateOffset]) |
            (static_cast<uint32_t>(Bytecode[ImmediateOffset + 1]) << 8) |
            (static_cast<uint32_t>(Bytecode[ImmediateOffset + 2]) << 16) |
            (static_cast<uint32_t>(Bytecode[ImmediateOffset + 3]) << 24);
        context->regs[Bytecode[IP + context->program.load_destination_offset]] = Immediate;
        context->ip += context->program.load_size;
        return XOVM_SHARD_CONTINUE;
    }
    if (Bytecode[IP] == context->program.ret_opcode) {
        if (IP + context->program.ret_size > context->bytecode_size ||
            Bytecode[IP + context->program.ret_source_offset] >= context->reg_count)
            return XOVM_SHARD_ABORT;
        *context->ret_storage = context->regs[Bytecode[IP + context->program.ret_source_offset]];
        context->ip += context->program.ret_size;
        return XOVM_SHARD_RETURN;
    }
    return XOVM_SHARD_ABORT;
}

} // namespace

std::optional<DynamicVmWindowConsumer> DynamicVmWindowConsumer::create(
    const EncryptedVmArtifact &artifact,
    const DynamicHash &build_id,
    const DynamicHash &region_id,
    const std::array<uint8_t, 16> &session_id,
    const DynamicHash &initial_state) {
    std::vector<uint8_t> commitment = artifact.encrypted_bytecode_blocks;
    commitment.insert(commitment.end(), artifact.encrypted_handler_shards.begin(),
                      artifact.encrypted_handler_shards.end());
    commitment.insert(commitment.end(), artifact.continuation_descriptors.begin(),
                      artifact.continuation_descriptors.end());
    commitment.insert(commitment.end(), artifact.relocation_descriptors.begin(),
                      artifact.relocation_descriptors.end());
    DynamicHash artifact_hash{};
    EVP_Digest(commitment.data(), commitment.size(), artifact_hash.data(), nullptr,
               EVP_sha256(), nullptr);
    if (artifact.format_version != kDynamicVmFormatVersion || artifact.build_id != build_id ||
        artifact.region_id != region_id || artifact_hash != artifact.artifact_hash ||
        zeroHash(initial_state))
        return std::nullopt;
    return DynamicVmWindowConsumer(build_id, region_id, session_id, initial_state);
}

std::optional<DynamicVmExecutionResult> executeDynamicVmArtifact(
    const EncryptedVmArtifact &artifact,
    std::span<const uint8_t, 32> artifact_key,
    const DynamicHash &build_id, const DynamicHash &region_id,
    uint32_t initial_ip) {
    auto Decrypted = decryptEncryptedVmArtifact(artifact, artifact_key, build_id, region_id);
    if (!Decrypted) return std::nullopt;
    auto Payload = decodeHandlerShardPayload(Decrypted->handler_shards);
    if (!Payload || !validateAarch64Shard(Payload->code)) {
        secureClear(*Decrypted);
        return std::nullopt;
    }
    auto Buffer = JitHandlerBuffer::allocate(Payload->code.size());
    if (!Buffer || !Buffer->loadAndSeal(Payload->code, Decrypted->relocation_descriptors)) {
        secureClear(*Decrypted);
        return std::nullopt;
    }
    uint32_t Registers[2] = {};
    uint32_t ReturnValue = 0;
    DynamicVmShardContext Context{Registers, 2, &ReturnValue, initial_ip, runDynamicShard,
        Decrypted->bytecode.data(), static_cast<uint32_t>(Decrypted->bytecode.size()), {}};
    if (!Decrypted->continuation_descriptors.empty()) {
        auto Descriptor = decodeProgramDescriptor(Decrypted->continuation_descriptors);
        if (!Descriptor) {
            secureClear(*Decrypted);
            return std::nullopt;
        }
        Context.program = *Descriptor;
    }
    auto Entry = reinterpret_cast<DynamicVmShardEntry>(Buffer->address());
    uint32_t Status = XOVM_SHARD_CONTINUE;
    for (size_t Steps = 0; Status == XOVM_SHARD_CONTINUE && Steps < 256; ++Steps)
        Status = Entry(&Context);
    if (Status == XOVM_SHARD_CONTINUE) Status = XOVM_SHARD_ABORT;
    DynamicVmExecutionResult Result{Status, Context.ip, ReturnValue};
    secureClear(*Decrypted);
    return Result;
}

std::optional<WindowMaterial> DynamicVmWindowConsumer::consume(
    const WindowGrant &grant,
    std::span<const uint8_t, 32> session_secret,
    uint64_t now_ms, uint64_t continuation) {
    if (grant.format_version != kDynamicVmFormatVersion || grant.build_id != build_id_ ||
        grant.region_id != region_id_ || grant.session_id != session_id_ ||
        grant.generation != generation_ + 1 || grant.window_id != window_id_ + 1 ||
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
    return material;
}

} // namespace xovm::material
