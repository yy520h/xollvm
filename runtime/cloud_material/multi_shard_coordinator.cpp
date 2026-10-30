#include "multi_shard_coordinator.h"

#include <algorithm>

namespace xovm::material {

std::optional<MultiShardCoordinator> MultiShardCoordinator::create(
    std::vector<ShardExecutionContext> contexts) {
    if (contexts.empty())
        return std::nullopt;

    // Validate all shard IDs are unique
    std::vector<uint32_t> shard_ids;
    for (const auto &ctx : contexts)
        shard_ids.push_back(ctx.shard_id);
    std::sort(shard_ids.begin(), shard_ids.end());
    if (std::adjacent_find(shard_ids.begin(), shard_ids.end()) != shard_ids.end())
        return std::nullopt;  // Duplicate shard IDs

    // Validate shard sequence is contiguous
    for (size_t i = 0; i < contexts.size(); ++i) {
        if (contexts[i].shard_sequence != i)
            return std::nullopt;
    }

    // Validate operand flow between consecutive shards
    for (size_t i = 0; i + 1 < contexts.size(); ++i) {
        if (!validateOperandFlow(contexts[i], contexts[i + 1]))
            return std::nullopt;
        if (!validateShardAbiCompatibility(contexts[i], contexts[i + 1]))
            return std::nullopt;
    }

    return MultiShardCoordinator(std::move(contexts));
}

bool MultiShardCoordinator::canExecute(uint32_t shard_id) const {
    if (current_index_ >= contexts_.size())
        return false;
    return contexts_[current_index_].shard_id == shard_id;
}

bool MultiShardCoordinator::advanceShard(uint32_t shard_id,
                                         const DynamicHash &execution_result) {
    if (!canExecute(shard_id))
        return false;

    const auto &current_ctx = contexts_[current_index_];
    
    // Verify execution result matches expected shard commitment
    if (execution_result != current_ctx.shard_commitment)
        return false;

    executed_shards_.push_back(shard_id);
    ++current_index_;
    return true;
}

const ShardExecutionContext *MultiShardCoordinator::current() const {
    if (current_index_ >= contexts_.size())
        return nullptr;
    return &contexts_[current_index_];
}

bool MultiShardCoordinator::complete() const {
    return current_index_ >= contexts_.size();
}

std::vector<uint32_t> MultiShardCoordinator::expectedSequence() const {
    std::vector<uint32_t> sequence;
    for (const auto &ctx : contexts_)
        sequence.push_back(ctx.shard_id);
    return sequence;
}

bool validateShardAbiCompatibility(
    const ShardExecutionContext &from_shard,
    const ShardExecutionContext &to_shard) {
    // Both shards must have valid ABI hashes
    if (from_shard.abi_variant_hash == DynamicHash{} ||
        to_shard.abi_variant_hash == DynamicHash{})
        return false;

    // Output operands of 'from' must not exceed input operands of 'to'
    // (actual operand mapping verified separately)
    if (from_shard.output_operand_count > to_shard.input_operand_count)
        return false;

    return true;
}

bool validateOperandFlow(const ShardExecutionContext &from_shard,
                        const ShardExecutionContext &to_shard) {
    // Validate operand count compatibility
    // Output of one shard feeds into input of next
    
    // Current validation: output count must match input count
    // Future: more sophisticated operand mapping verification
    if (from_shard.output_operand_count != to_shard.input_operand_count)
        return false;

    return true;
}

}  // namespace xovm::material
