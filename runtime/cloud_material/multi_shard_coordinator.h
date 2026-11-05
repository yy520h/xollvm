#ifndef XOVM_MULTI_SHARD_COORDINATOR_H
#define XOVM_MULTI_SHARD_COORDINATOR_H

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

#include "dynamic_vm_schema.h"

namespace xovm::material {

// Multi-shard execution coordinator
// Manages execution flow across multiple handler shards with identity verification
struct ShardExecutionContext {
    uint32_t shard_id = 0;
    uint32_t shard_sequence = 0;           // Execution order within continuation
    uint32_t entry_point = 0;              // Entry instruction offset
    uint32_t exit_point = 0;               // Exit instruction offset
    DynamicHash shard_commitment{};        // Expected shard identity
    DynamicHash abi_variant_hash{};        // ABI variant specification
    uint16_t input_operand_count = 0;      // Number of input operands
    uint16_t output_operand_count = 0;     // Number of output operands
};

// Shard sequence validator
class MultiShardCoordinator {
public:
    // Initialize coordinator with shard contexts
    static std::optional<MultiShardCoordinator> create(
        std::vector<ShardExecutionContext> contexts);

    // Verify shard can execute at current position
    bool canExecute(uint32_t shard_id) const;

    // Validate shard execution results and advance to next shard
    bool advanceShard(uint32_t shard_id, const DynamicHash &execution_result);

    // Get current shard context
    const ShardExecutionContext *current() const;

    // Check if all shards have executed
    bool complete() const;

    // Get expected shard sequence order
    std::vector<uint32_t> expectedSequence() const;

private:
    explicit MultiShardCoordinator(std::vector<ShardExecutionContext> contexts)
        : contexts_(std::move(contexts)), current_index_(0) {}

    std::vector<ShardExecutionContext> contexts_;
    size_t current_index_ = 0;
    std::vector<uint32_t> executed_shards_;
};

// Validates ABI compatibility between shards
bool validateShardAbiCompatibility(
    const ShardExecutionContext &from_shard,
    const ShardExecutionContext &to_shard);

// Verifies shard output operands match next shard input operands
bool validateOperandFlow(const ShardExecutionContext &from_shard,
                        const ShardExecutionContext &to_shard);

} // namespace xovm::material

#endif
