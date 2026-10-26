#ifndef XOVM_INTEGRITY_STATE_H
#define XOVM_INTEGRITY_STATE_H

#include "dynamic_vm_schema.h"

#include <optional>
#include <span>

namespace xovm::material {

class IntegrityState {
public:
    explicit IntegrityState(DynamicHash state) : state_(state) {}

    std::optional<DynamicHash> commit(const WindowGrant &grant,
                                      const DynamicHash &next_state,
                                      uint64_t window_id,
                                      uint64_t continuation) const;
    std::optional<DynamicHash> commit(const WindowGrant &grant,
                                      const DynamicHash &next_state,
                                      uint64_t window_id,
                                      uint64_t continuation,
                                      std::span<const uint8_t, 32> integrity_material) const;
    bool advance(const WindowGrant &grant, const DynamicHash &next_state,
                 uint64_t window_id, uint64_t continuation);
    bool advance(const WindowGrant &grant, const DynamicHash &next_state,
                 uint64_t window_id, uint64_t continuation,
                 std::span<const uint8_t, 32> integrity_material);
    const DynamicHash &value() const { return state_; }

private:
    DynamicHash state_{};
};

} // namespace xovm::material

#endif
