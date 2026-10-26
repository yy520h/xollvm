#ifndef XOVM_DYNAMIC_VM_SHARD_H
#define XOVM_DYNAMIC_VM_SHARD_H

#include "dynamic_vm_schema.h"

#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace xovm::material {

struct DynamicVmShardContext {
    uint32_t *regs = nullptr;
    uint32_t reg_count = 0;
    uint32_t *ret_storage = nullptr;
    uint32_t ip = 0;
    uint32_t (*callback)(DynamicVmShardContext *) = nullptr;
    const uint8_t *bytecode = nullptr;
    uint32_t bytecode_size = 0;
    struct ProgramDescriptor {
        uint8_t load_opcode = 0;
        uint8_t ret_opcode = 0x0d;
        uint8_t load_destination_offset = 1;
        uint8_t load_immediate_offset = 2;
        uint8_t ret_source_offset = 1;
        uint16_t load_size = 6;
        uint16_t ret_size = 2;
        bool supported = false;
    } program;
};

using DynamicVmShardEntry = uint32_t (*)(DynamicVmShardContext *);

inline constexpr uint32_t XOVM_SHARD_CONTINUE = 0;
inline constexpr uint32_t XOVM_SHARD_RETURN = 1;
inline constexpr uint32_t XOVM_SHARD_ABORT = 2;

std::optional<std::vector<uint8_t>> buildAarch64LoadImmediateShard(
    uint32_t destination, uint32_t immediate, uint32_t next_ip);
std::optional<std::vector<uint8_t>> buildAarch64ReturnIntShard(
    uint32_t source, uint32_t next_ip);
std::optional<std::vector<uint8_t>> buildAarch64LoadAndReturnIntShard(
    uint32_t destination, uint32_t immediate, uint32_t source, uint32_t next_ip);
std::optional<std::vector<uint8_t>> buildAarch64BridgeShard();
bool validateAarch64Shard(std::span<const uint8_t> code);
DynamicHash hashAarch64ShardCode(std::span<const uint8_t> code);
std::vector<uint8_t> encodeProgramDescriptor(
    const DynamicVmShardContext::ProgramDescriptor &descriptor);
std::optional<DynamicVmShardContext::ProgramDescriptor> decodeProgramDescriptor(
    std::span<const uint8_t> encoded);

} // namespace xovm::material

#endif
