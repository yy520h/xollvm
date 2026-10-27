#include "continuation_executor.h"

#include <unordered_map>
#include <utility>

namespace xovm::material {

std::optional<ContinuationCursorV2> ContinuationCursorV2::create(
    const DynamicVmExecutionAbiV2 &abi,
    const ContinuationGraphV2 &graph) {
    // Validate the exact snapshot retained by the cursor before exposing even
    // its entry descriptor.
    ContinuationGraphV2 validated_graph = graph;
    if (validateContinuationGraphV2(abi, validated_graph) !=
        DynamicVmSchemaStatusV2::Valid)
        return std::nullopt;

    std::unordered_map<uint32_t, size_t> indices;
    indices.reserve(validated_graph.nodes.size());
    for (size_t index = 0; index < validated_graph.nodes.size(); ++index)
        indices.emplace(validated_graph.nodes[index].node_id, index);

    std::vector<size_t> successor_indices;
    successor_indices.reserve(validated_graph.nodes.size());
    for (const auto &node : validated_graph.nodes) {
        if (node.status == ContinuationNodeStatusV2::Return) {
            if (node.next_node_id != 0) return std::nullopt;
            successor_indices.push_back(kNoSuccessor);
            continue;
        }
        const auto successor = indices.find(node.next_node_id);
        if (node.next_node_id == 0 || successor == indices.end())
            return std::nullopt;
        successor_indices.push_back(successor->second);
    }

    return ContinuationCursorV2(std::move(validated_graph),
                                std::move(successor_indices));
}

ContinuationCursorV2::ContinuationCursorV2(
    ContinuationGraphV2 graph, std::vector<size_t> successor_indices)
    : graph_(std::move(graph)),
      successor_indices_(std::move(successor_indices)),
      advances_remaining_(graph_.nodes.size()) {}

const ContinuationNodeV2 *ContinuationCursorV2::current() const {
    if (complete_ || current_index_ >= graph_.nodes.size()) return nullptr;
    return &graph_.nodes[current_index_];
}

bool ContinuationCursorV2::advance(
    const ContinuationCompletionV2 &completion) {
    const auto *node = current();
    if (!node || advances_remaining_ == 0 ||
        completion.node_id != node->node_id ||
        completion.status != node->status ||
        completion.next_node_id != node->next_node_id ||
        completion.transition_tail_commitment !=
            node->transition_tail_commitment)
        return false;

    const size_t successor_index = successor_indices_[current_index_];
    if (node->status == ContinuationNodeStatusV2::Return) {
        if (successor_index != kNoSuccessor) return false;
        complete_ = true;
        --advances_remaining_;
        return true;
    }

    if (successor_index == kNoSuccessor ||
        successor_index >= graph_.nodes.size())
        return false;
    current_index_ = successor_index;
    --advances_remaining_;
    return true;
}

bool ContinuationCursorV2::complete() const {
    return complete_;
}

} // namespace xovm::material
