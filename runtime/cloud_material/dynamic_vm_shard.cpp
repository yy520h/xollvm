#include "dynamic_vm_shard.h"

#include <cstddef>
#include <openssl/evp.h>

namespace xovm::material {
namespace {

constexpr uint32_t kRet = 0xD65F03C0;
constexpr uint32_t kBrX16 = 0xD61F0200;

void putInstruction(std::vector<uint8_t> &code, uint32_t instruction) {
    code.push_back(static_cast<uint8_t>(instruction));
    code.push_back(static_cast<uint8_t>(instruction >> 8));
    code.push_back(static_cast<uint8_t>(instruction >> 16));
    code.push_back(static_cast<uint8_t>(instruction >> 24));
}

uint32_t loadRegister(uint32_t destination, uint32_t source, uint32_t byte_offset) {
    return 0xB9400000u | ((byte_offset / 4) << 10) | (source << 5) | destination;
}

uint32_t storeRegister(uint32_t source, uint32_t destination, uint32_t byte_offset) {
    return 0xB9000000u | ((byte_offset / 4) << 10) | (destination << 5) | source;
}

uint32_t loadPointer(uint32_t destination, uint32_t source, uint32_t byte_offset) {
    return 0xF9400000u | ((byte_offset / 8) << 10) | (source << 5) | destination;
}

void putImmediate(std::vector<uint8_t> &code, uint32_t destination, uint32_t value) {
    putInstruction(code, 0x52800000u | ((value & 0xffffu) << 5) | destination);
    const uint32_t high = value >> 16;
    if (high)
        putInstruction(code, 0x72800000u | (1u << 21) | ((high & 0xffffu) << 5) |
            destination);
}

void putAdvance(std::vector<uint8_t> &code, uint32_t next_ip) {
    putImmediate(code, 3, next_ip);
    putInstruction(code, storeRegister(3, 0, offsetof(DynamicVmShardContext, ip)));
}

std::optional<std::vector<uint8_t>> beginShard(uint32_t next_ip) {
#if !defined(__aarch64__)
    (void)next_ip;
    return std::nullopt;
#else
    if (next_ip > 0xfffu) return std::nullopt;
    return std::vector<uint8_t>{};
#endif
}

} // namespace

std::optional<std::vector<uint8_t>> buildAarch64LoadImmediateShard(
    uint32_t destination, uint32_t immediate, uint32_t next_ip) {
    if (destination > 31) return std::nullopt;
    auto code = beginShard(next_ip);
    if (!code) return std::nullopt;
    putInstruction(*code, loadPointer(1, 0, offsetof(DynamicVmShardContext, regs)));
    putImmediate(*code, 2, immediate);
    putInstruction(*code, storeRegister(2, 1, destination * sizeof(uint32_t)));
    putAdvance(*code, next_ip);
    putImmediate(*code, 0, XOVM_SHARD_CONTINUE);
    putInstruction(*code, kRet);
    return code;
}

std::optional<std::vector<uint8_t>> buildAarch64ReturnIntShard(
    uint32_t source, uint32_t next_ip) {
    if (source > 31) return std::nullopt;
    auto code = beginShard(next_ip);
    if (!code) return std::nullopt;
    putInstruction(*code, loadPointer(1, 0, offsetof(DynamicVmShardContext, regs)));
    putInstruction(*code, loadPointer(2, 0, offsetof(DynamicVmShardContext, ret_storage)));
    putInstruction(*code, loadRegister(3, 1, source * sizeof(uint32_t)));
    putInstruction(*code, storeRegister(3, 2, 0));
    putAdvance(*code, next_ip);
    putImmediate(*code, 0, XOVM_SHARD_RETURN);
    putInstruction(*code, kRet);
    return code;
}

std::optional<std::vector<uint8_t>> buildAarch64LoadAndReturnIntShard(
    uint32_t destination, uint32_t immediate, uint32_t source, uint32_t next_ip) {
    if (destination > 31 || source > 31) return std::nullopt;
    auto code = beginShard(next_ip);
    if (!code) return std::nullopt;
    putInstruction(*code, loadPointer(1, 0, offsetof(DynamicVmShardContext, regs)));
    putImmediate(*code, 2, immediate);
    putInstruction(*code, storeRegister(2, 1, destination * sizeof(uint32_t)));
    putInstruction(*code, loadPointer(2, 0, offsetof(DynamicVmShardContext, ret_storage)));
    putInstruction(*code, loadRegister(3, 1, source * sizeof(uint32_t)));
    putInstruction(*code, storeRegister(3, 2, 0));
    putAdvance(*code, next_ip);
    putImmediate(*code, 0, XOVM_SHARD_RETURN);
    putInstruction(*code, kRet);
    return code;
}

std::optional<std::vector<uint8_t>> buildAarch64BridgeShard() {
#if !defined(__aarch64__)
    return std::nullopt;
#else
    std::vector<uint8_t> code;
    putInstruction(code, loadPointer(16, 0,
        offsetof(DynamicVmShardContext, callback)));
    // Tail-call the authenticated callback so the caller's link register is
    // preserved without making the shard carry a stack frame.
    putInstruction(code, kBrX16);
    return code;
#endif
}

bool validateAarch64Shard(std::span<const uint8_t> code) {
    if (code.empty() || code.size() % 4 != 0 || code.size() > 4096)
        return false;
    for (size_t Offset = 0; Offset < code.size(); Offset += 4) {
        uint32_t Instruction = static_cast<uint32_t>(code[Offset]) |
            (static_cast<uint32_t>(code[Offset + 1]) << 8) |
            (static_cast<uint32_t>(code[Offset + 2]) << 16) |
            (static_cast<uint32_t>(code[Offset + 3]) << 24);
        const bool IsRet = Instruction == kRet;
        const bool IsBridge = Instruction == kBrX16;
        const bool IsLoadPointer = (Instruction & 0xFFC00000u) == 0xF9400000u;
        const bool IsLoadStore = (Instruction & 0xFFC00000u) == 0xB9400000u ||
            (Instruction & 0xFFC00000u) == 0xB9000000u;
        const bool IsMoveWide = (Instruction & 0x7F800000u) == 0x52800000u ||
            (Instruction & 0x7F800000u) == 0x72800000u;
        if (!IsRet && !IsBridge && !IsLoadPointer && !IsLoadStore && !IsMoveWide)
            return false;
    }
    uint32_t Last = static_cast<uint32_t>(code[code.size() - 4]) |
        (static_cast<uint32_t>(code[code.size() - 3]) << 8) |
        (static_cast<uint32_t>(code[code.size() - 2]) << 16) |
        (static_cast<uint32_t>(code[code.size() - 1]) << 24);
    return Last == kRet || Last == kBrX16;
}

DynamicHash hashAarch64ShardCode(std::span<const uint8_t> code) {
    DynamicHash Result{};
    EVP_Digest(code.data(), code.size(), Result.data(), nullptr, EVP_sha256(), nullptr);
    return Result;
}

std::vector<uint8_t> encodeProgramDescriptor(
    const DynamicVmShardContext::ProgramDescriptor &Descriptor) {
    if (!Descriptor.load_size || !Descriptor.ret_size ||
        Descriptor.load_destination_offset >= Descriptor.load_size ||
        Descriptor.load_immediate_offset + 4 > Descriptor.load_size ||
        Descriptor.ret_source_offset >= Descriptor.ret_size)
        return {};
    return {'X', 'O', 'V', 'M', 'C', 'N', 'T', 1,
        static_cast<uint8_t>(Descriptor.supported ? 1 : 0), Descriptor.load_opcode,
        Descriptor.ret_opcode, Descriptor.load_destination_offset,
        Descriptor.load_immediate_offset, Descriptor.ret_source_offset,
        static_cast<uint8_t>(Descriptor.load_size >> 8),
        static_cast<uint8_t>(Descriptor.load_size),
        static_cast<uint8_t>(Descriptor.ret_size >> 8),
        static_cast<uint8_t>(Descriptor.ret_size)};
}

std::optional<DynamicVmShardContext::ProgramDescriptor> decodeProgramDescriptor(
    std::span<const uint8_t> Encoded) {
    const std::array<uint8_t, 7> Magic = {'X', 'O', 'V', 'M', 'C', 'N', 'T'};
    if (Encoded.size() != 18 || !std::equal(Encoded.begin(), Encoded.begin() + 7,
        Magic.begin()) ||
        Encoded[7] != 1)
        return std::nullopt;
    DynamicVmShardContext::ProgramDescriptor Descriptor;
    if (Encoded[8] > 1) return std::nullopt;
    Descriptor.supported = Encoded[8] != 0;
    Descriptor.load_opcode = Encoded[9];
    Descriptor.ret_opcode = Encoded[10];
    Descriptor.load_destination_offset = Encoded[11];
    Descriptor.load_immediate_offset = Encoded[12];
    Descriptor.ret_source_offset = Encoded[13];
    Descriptor.load_size = static_cast<uint16_t>(Encoded[14] << 8 | Encoded[15]);
    Descriptor.ret_size = static_cast<uint16_t>(Encoded[16] << 8 | Encoded[17]);
    if (!Descriptor.supported) return Descriptor;
    if (encodeProgramDescriptor(Descriptor).size() != Encoded.size()) return std::nullopt;
    return Descriptor;
}

} // namespace xovm::material
