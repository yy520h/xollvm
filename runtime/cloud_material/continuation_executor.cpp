#include "continuation_executor.h"

#include <unordered_map>

namespace xovm::material {

bool ContinuationExecutor::runWindow(const std::vector<ContinuationNode> &nodes,
                                      uint64_t first_id) const {
    if (!first_id || nodes.empty()) return false;
    std::unordered_map<uint64_t, const ContinuationNode *> local;
    for (const auto &node : nodes) {
        if (!node.id || !node.execute || !local.emplace(node.id, &node).second) return false;
    }
    uint64_t current = first_id;
    size_t steps = 0;
    while (current) {
        if (++steps > nodes.size()) return false;
        const auto found = local.find(current);
        if (found == local.end() || !found->second->execute(current)) return false;
        current = found->second->next_id;
    }
    return true;
}

bool ContinuationExecutor::runWindow(const ContinuationWindow &window,
                                     const WindowGrant &grant,
                                     WindowBinding &binding,
                                     const std::vector<ContinuationNode> &nodes,
                                     uint64_t first_id) const {
    if (window.window_id != grant.window_id || window.state_hash != grant.previous_state_hash ||
        window.authenticated_bytes.empty() || !validateWindowBinding(grant, binding))
        return false;
    if (!runWindow(nodes, first_id)) return false;
    DynamicHash next_state{};
    if (!advanceContinuation(window.state_hash, grant, next_state)) return false;
    binding.previous_state_hash = next_state;
    return true;
}

} // namespace xovm::material
