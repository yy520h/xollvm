#ifndef XOVM_CONTINUATION_EXECUTOR_H
#define XOVM_CONTINUATION_EXECUTOR_H

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

#include "dynamic_vm_schema.h"

namespace xovm::material {

// Operand specification for continuation tail execution
// Defines input/output register operands and immediate values
struct ContinuationTailOperand {
    uint32_t operand_id = 0;
    uint8_t operand_type = 0;  // INPUT=0, OUTPUT=1, IMMEDIATE=2
    uint32_t register_index = 0;
    uint32_t immediate_value = 0;
    uint16_t operand_size = 0;  // bytes
    uint8_t flags = 0;           // condition flags, shift amounts, etc.
};

// Tail ABI specification - defines the interface between handler shards
struct ContinuationTailAbi {
    uint32_t tail_id = 0;
    uint32_t operand_count = 0;
    std::vector<ContinuationTailOperand> operands;
    uint32_t exception_handler_node_id = 0;  // node to execute on exception
    uint32_t exit_handler_node_id = 0;       // node to execute on normal exit
    uint32_t reserved = 0;
};

// The execution result that is presented back to the authenticated graph cursor.
// All fields must agree with the descriptor for the current node.
struct ContinuationCompletionV2 {
    uint32_t node_id = 0;
    ContinuationNodeStatusV2 status = ContinuationNodeStatusV2::Continue;
    uint32_t next_node_id = 0;
    DynamicHash transition_tail_commitment{};
};

// A bounded cursor over an immutable copy of a structurally validated graph.
// Execution is deliberately outside this type: callers inspect current(), perform
// the described operation, then authenticate the observed completion with advance().
class ContinuationCursorV2 {
public:
    static std::optional<ContinuationCursorV2> create(
        const DynamicVmExecutionAbiV2 &abi,
        const ContinuationGraphV2 &graph);

    const ContinuationNodeV2 *current() const;
    bool advance(const ContinuationCompletionV2 &completion);
    bool complete() const;

    // Operand boundary validation - checks that operands are within limits
    bool validateOperandBoundary(const ContinuationTailOperand &operand) const;

    // Multi-shard identity validation
    bool validateShardIdentity(uint32_t shard_id, const DynamicHash &shard_commitment) const;

private:
    static constexpr size_t kNoSuccessor = static_cast<size_t>(-1);

    ContinuationCursorV2(ContinuationGraphV2 graph,
                         std::vector<size_t> successor_indices);

    ContinuationGraphV2 graph_;
    std::vector<size_t> successor_indices_;
    size_t current_index_ = 0;
    size_t advances_remaining_ = 0;
    bool complete_ = false;
};

} // namespace xovm::material

#endif
