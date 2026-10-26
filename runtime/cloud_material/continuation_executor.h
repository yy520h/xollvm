#ifndef XOVM_CONTINUATION_EXECUTOR_H
#define XOVM_CONTINUATION_EXECUTOR_H

#include <cstdint>
#include <functional>
#include <vector>

#include "dynamic_vm_schema.h"

namespace xovm::material {

struct ContinuationNode {
    uint64_t id = 0;
    uint64_t next_id = 0;
    std::function<bool(uint64_t)> execute;
};

class ContinuationExecutor {
public:
    bool runWindow(const std::vector<ContinuationNode> &nodes, uint64_t first_id) const;
    bool runWindow(const ContinuationWindow &window, const WindowGrant &grant,
                   WindowBinding &binding, const std::vector<ContinuationNode> &nodes,
                   uint64_t first_id) const;
};

} // namespace xovm::material

#endif
