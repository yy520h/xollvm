#ifndef XOVM_DYNAMIC_VM_SHARD_H
#define XOVM_DYNAMIC_VM_SHARD_H

#include "dynamic_vm_schema.h"
#include "material_abi.h"

#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace xovm::material {

using DynamicVmShardEntry = uint32_t (*)(XovmDynamicVmExecutionContext *);

inline constexpr uint32_t XOVM_SHARD_CONTINUE = 0;
inline constexpr uint32_t XOVM_SHARD_RETURN = 1;
inline constexpr uint32_t XOVM_SHARD_ABORT = 2;

std::optional<std::vector<uint8_t>> buildAarch64LoadImmediateShard(
    uint32_t destination, uint32_t immediate, uint32_t next_ip);
std::optional<std::vector<uint8_t>> buildAarch64ReturnIntShard(
    uint32_t source, uint32_t next_ip);
std::optional<std::vector<uint8_t>> buildAarch64LoadAndReturnIntShard(
    uint32_t destination, uint32_t immediate, uint32_t source, uint32_t next_ip);

enum class Aarch64ShardTemplate : uint8_t {
    LoadImmediate,
    ReturnInt,
    LoadAndReturnInt,
};

struct Aarch64ShardTemplateParameters {
    uint32_t destination = 0;
    uint32_t immediate = 0;
    uint32_t source = 0;
    uint32_t next_ip = 0;
};

// Exact expected-template validator. Only operands used by expected_template
// participate; all are range-checked before canonical bytes are generated.
bool validateAarch64ShardTemplate(
    std::span<const uint8_t> code,
    Aarch64ShardTemplate expected_template,
    const Aarch64ShardTemplateParameters &parameters);

// Named convenience validators. Each accepts only the bytes emitted for the
// named operation and supplied operands; instruction-class membership alone is
// never sufficient.
bool validateAarch64LoadImmediateShard(std::span<const uint8_t> code,
                                       uint32_t destination,
                                       uint32_t immediate,
                                       uint32_t next_ip);
bool validateAarch64ReturnIntShard(std::span<const uint8_t> code,
                                   uint32_t source,
                                   uint32_t next_ip);
bool validateAarch64LoadAndReturnIntShard(std::span<const uint8_t> code,
                                          uint32_t destination,
                                          uint32_t immediate,
                                          uint32_t source,
                                          uint32_t next_ip);

// Compatibility recognizer for artifact readers that do not yet carry the
// expected template parameters. It accepts one complete canonical shard or the
// exact two-node LOADI-to-RET_INT v2 payload; it never accepts an arbitrary
// sequence of otherwise allowed AArch64 instructions.
bool validateAarch64Shard(std::span<const uint8_t> code);
DynamicHash hashAarch64ShardCode(std::span<const uint8_t> code);

} // namespace xovm::material

#endif
