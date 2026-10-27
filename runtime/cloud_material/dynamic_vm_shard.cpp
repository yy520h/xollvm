#include "dynamic_vm_shard.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <openssl/evp.h>

namespace xovm::material {
namespace {

constexpr uint32_t kRet = 0xD65F03C0;
constexpr uint32_t kMoveWideImmediateMask = 0x001FFFE0u;
constexpr uint32_t kLoadStoreImmediateMask = 0x003FFC00u;
constexpr uint32_t kMaxVmRegister = kDynamicVmMaxI32RegistersV2 - 1;

void putInstruction(std::vector<uint8_t> &code, uint32_t instruction) {
    code.push_back(static_cast<uint8_t>(instruction));
    code.push_back(static_cast<uint8_t>(instruction >> 8));
    code.push_back(static_cast<uint8_t>(instruction >> 16));
    code.push_back(static_cast<uint8_t>(instruction >> 24));
}

uint32_t instructionAt(std::span<const uint8_t> code, size_t index) {
    const size_t offset = index * 4;
    return static_cast<uint32_t>(code[offset]) |
        (static_cast<uint32_t>(code[offset + 1]) << 8) |
        (static_cast<uint32_t>(code[offset + 2]) << 16) |
        (static_cast<uint32_t>(code[offset + 3]) << 24);
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
        putInstruction(code, 0x72800000u | (1u << 21) |
            ((high & 0xffffu) << 5) | destination);
}

void putAdvance(std::vector<uint8_t> &code, uint32_t next_ip) {
    putImmediate(code, 3, next_ip);
    putInstruction(code, storeRegister(3, 0,
        offsetof(XovmDynamicVmExecutionContext, instruction_pointer)));
}

bool validRegister(uint32_t index) {
    return index <= kMaxVmRegister;
}

std::optional<std::vector<uint8_t>> emitLoadImmediate(
    uint32_t destination, uint32_t immediate, uint32_t next_ip) {
    if (!validRegister(destination)) return std::nullopt;
    std::vector<uint8_t> code;
    putInstruction(code, loadPointer(1, 0,
        offsetof(XovmDynamicVmExecutionContext, registers)));
    putImmediate(code, 2, immediate);
    putInstruction(code, storeRegister(2, 1, destination * sizeof(uint32_t)));
    putAdvance(code, next_ip);
    putImmediate(code, 0, XOVM_SHARD_CONTINUE);
    putInstruction(code, kRet);
    return code;
}

std::optional<std::vector<uint8_t>> emitReturnInt(uint32_t source, uint32_t next_ip) {
    if (!validRegister(source)) return std::nullopt;
    std::vector<uint8_t> code;
    putInstruction(code, loadPointer(1, 0,
        offsetof(XovmDynamicVmExecutionContext, registers)));
    putInstruction(code, loadPointer(2, 0,
        offsetof(XovmDynamicVmExecutionContext, return_storage)));
    putInstruction(code, loadRegister(3, 1, source * sizeof(uint32_t)));
    putInstruction(code, storeRegister(3, 2, 0));
    putAdvance(code, next_ip);
    putImmediate(code, 0, XOVM_SHARD_RETURN);
    putInstruction(code, kRet);
    return code;
}

std::optional<std::vector<uint8_t>> emitLoadAndReturnInt(
    uint32_t destination, uint32_t immediate, uint32_t source, uint32_t next_ip) {
    if (!validRegister(destination) || !validRegister(source))
        return std::nullopt;
    std::vector<uint8_t> code;
    putInstruction(code, loadPointer(1, 0,
        offsetof(XovmDynamicVmExecutionContext, registers)));
    putImmediate(code, 2, immediate);
    putInstruction(code, storeRegister(2, 1, destination * sizeof(uint32_t)));
    putInstruction(code, loadPointer(2, 0,
        offsetof(XovmDynamicVmExecutionContext, return_storage)));
    putInstruction(code, loadRegister(3, 1, source * sizeof(uint32_t)));
    putInstruction(code, storeRegister(3, 2, 0));
    putAdvance(code, next_ip);
    putImmediate(code, 0, XOVM_SHARD_RETURN);
    putInstruction(code, kRet);
    return code;
}

bool equalExpected(std::span<const uint8_t> code,
                   const std::optional<std::vector<uint8_t>> &expected) {
    return expected && code.size() == expected->size() &&
        std::equal(code.begin(), code.end(), expected->begin());
}

std::optional<uint32_t> decodeMoveImmediate(uint32_t instruction,
                                            uint32_t destination,
                                            bool high_half) {
    const uint32_t base = high_half ? 0x72A00000u : 0x52800000u;
    if ((instruction & ~kMoveWideImmediateMask) != (base | destination))
        return std::nullopt;
    return (instruction >> 5) & 0xffffu;
}

struct DecodedImmediate {
    uint32_t value;
    size_t next_instruction;
};

std::optional<DecodedImmediate> decodeCanonicalImmediate(
    std::span<const uint8_t> code, size_t instruction_index,
    uint32_t destination) {
    if ((instruction_index + 1) * 4 > code.size()) return std::nullopt;
    const auto low = decodeMoveImmediate(
        instructionAt(code, instruction_index), destination, false);
    if (!low) return std::nullopt;
    DecodedImmediate decoded{*low, instruction_index + 1};
    if ((decoded.next_instruction + 1) * 4 <= code.size()) {
        const auto high = decodeMoveImmediate(
            instructionAt(code, decoded.next_instruction), destination, true);
        if (high) {
            if (*high == 0) return std::nullopt;
            decoded.value |= *high << 16;
            ++decoded.next_instruction;
        }
    }
    return decoded;
}

std::optional<uint32_t> decodeVmRegisterOffset(uint32_t instruction,
                                               uint32_t fixed_bits) {
    if ((instruction & ~kLoadStoreImmediateMask) != fixed_bits)
        return std::nullopt;
    const uint32_t index = (instruction >> 10) & 0xfffu;
    if (!validRegister(index)) return std::nullopt;
    return index;
}

bool recognizeLoadImmediate(std::span<const uint8_t> code) {
    if (code.size() < 28 || code.size() > 36 || code.size() % 4 != 0)
        return false;
    const auto immediate = decodeCanonicalImmediate(code, 1, 2);
    if (!immediate) return false;
    const size_t store_index = immediate->next_instruction;
    if ((store_index + 1) * 4 > code.size()) return false;
    const auto destination = decodeVmRegisterOffset(
        instructionAt(code, store_index), 0xB9000022u);
    const auto next_ip = decodeCanonicalImmediate(code, store_index + 1, 3);
    if (!destination || !next_ip ||
        code.size() != (next_ip->next_instruction + 3) * 4)
        return false;
    return validateAarch64LoadImmediateShard(
        code, *destination, immediate->value, next_ip->value);
}

bool recognizeReturnInt(std::span<const uint8_t> code) {
    if (code.size() != 32 && code.size() != 36) return false;
    const auto source = decodeVmRegisterOffset(instructionAt(code, 2), 0xB9400023u);
    const auto next_ip = decodeCanonicalImmediate(code, 4, 3);
    if (!source || !next_ip ||
        code.size() != (next_ip->next_instruction + 3) * 4)
        return false;
    return validateAarch64ReturnIntShard(code, *source, next_ip->value);
}

bool recognizeLoadAndReturnInt(std::span<const uint8_t> code) {
    if (code.size() < 40 || code.size() > 48 || code.size() % 4 != 0)
        return false;
    const auto immediate = decodeCanonicalImmediate(code, 1, 2);
    if (!immediate) return false;
    const size_t store_index = immediate->next_instruction;
    if ((store_index + 5) * 4 > code.size()) return false;
    const auto destination = decodeVmRegisterOffset(
        instructionAt(code, store_index), 0xB9000022u);
    const auto source = decodeVmRegisterOffset(
        instructionAt(code, store_index + 2), 0xB9400023u);
    const auto next_ip = decodeCanonicalImmediate(code, store_index + 4, 3);
    if (!destination || !source || !next_ip ||
        code.size() != (next_ip->next_instruction + 3) * 4)
        return false;
    return validateAarch64LoadAndReturnIntShard(
        code, *destination, immediate->value, *source, next_ip->value);
}

bool recognizeCanonicalLoadReturnProgram(std::span<const uint8_t> code) {
    if (code.size() != 60 && code.size() != 64) return false;
    const size_t load_size = code.size() - 32;
    const auto load = code.first(load_size);
    const auto ret = code.subspan(load_size);
    if (!recognizeLoadImmediate(load) || !recognizeReturnInt(ret)) return false;

    const size_t load_store_index = load_size == 32 ? 3 : 2;
    const auto destination = decodeVmRegisterOffset(
        instructionAt(load, load_store_index), 0xB9000022u);
    const auto load_next_ip = decodeMoveImmediate(
        instructionAt(load, load_store_index + 1), 3, false);
    const auto source = decodeVmRegisterOffset(instructionAt(ret, 2), 0xB9400023u);
    const auto return_next_ip = decodeMoveImmediate(instructionAt(ret, 4), 3, false);
    return destination && source && load_next_ip && return_next_ip &&
        *destination == *source &&
        *load_next_ip == kDynamicVmLoadI32InstructionSizeV2 &&
        *return_next_ip == kDynamicVmLoadI32InstructionSizeV2 +
                               kDynamicVmReturnI32InstructionSizeV2;
}

} // namespace

std::optional<std::vector<uint8_t>> buildAarch64LoadImmediateShard(
    uint32_t destination, uint32_t immediate, uint32_t next_ip) {
#if !defined(__aarch64__) || defined(XOVM_DYNAMIC_VM_TEST_NON_AARCH64)
    (void)destination;
    (void)immediate;
    (void)next_ip;
    return std::nullopt;
#else
    return emitLoadImmediate(destination, immediate, next_ip);
#endif
}

std::optional<std::vector<uint8_t>> buildAarch64ReturnIntShard(
    uint32_t source, uint32_t next_ip) {
#if !defined(__aarch64__) || defined(XOVM_DYNAMIC_VM_TEST_NON_AARCH64)
    (void)source;
    (void)next_ip;
    return std::nullopt;
#else
    return emitReturnInt(source, next_ip);
#endif
}

std::optional<std::vector<uint8_t>> buildAarch64LoadAndReturnIntShard(
    uint32_t destination, uint32_t immediate, uint32_t source, uint32_t next_ip) {
#if !defined(__aarch64__) || defined(XOVM_DYNAMIC_VM_TEST_NON_AARCH64)
    (void)destination;
    (void)immediate;
    (void)source;
    (void)next_ip;
    return std::nullopt;
#else
    return emitLoadAndReturnInt(destination, immediate, source, next_ip);
#endif
}

bool validateAarch64ShardTemplate(
    std::span<const uint8_t> code,
    Aarch64ShardTemplate expected_template,
    const Aarch64ShardTemplateParameters &parameters) {
    switch (expected_template) {
    case Aarch64ShardTemplate::LoadImmediate:
        return equalExpected(code, emitLoadImmediate(
            parameters.destination, parameters.immediate, parameters.next_ip));
    case Aarch64ShardTemplate::ReturnInt:
        return equalExpected(code, emitReturnInt(parameters.source, parameters.next_ip));
    case Aarch64ShardTemplate::LoadAndReturnInt:
        return equalExpected(code, emitLoadAndReturnInt(
            parameters.destination, parameters.immediate,
            parameters.source, parameters.next_ip));
    }
    return false;
}

bool validateAarch64LoadImmediateShard(std::span<const uint8_t> code,
                                       uint32_t destination,
                                       uint32_t immediate,
                                       uint32_t next_ip) {
    return validateAarch64ShardTemplate(code, Aarch64ShardTemplate::LoadImmediate,
        {destination, immediate, 0, next_ip});
}

bool validateAarch64ReturnIntShard(std::span<const uint8_t> code,
                                   uint32_t source,
                                   uint32_t next_ip) {
    return validateAarch64ShardTemplate(code, Aarch64ShardTemplate::ReturnInt,
        {0, 0, source, next_ip});
}

bool validateAarch64LoadAndReturnIntShard(std::span<const uint8_t> code,
                                          uint32_t destination,
                                          uint32_t immediate,
                                          uint32_t source,
                                          uint32_t next_ip) {
    return validateAarch64ShardTemplate(
        code, Aarch64ShardTemplate::LoadAndReturnInt,
        {destination, immediate, source, next_ip});
}

bool validateAarch64Shard(std::span<const uint8_t> code) {
    return recognizeLoadImmediate(code) || recognizeReturnInt(code) ||
        recognizeLoadAndReturnInt(code) || recognizeCanonicalLoadReturnProgram(code);
}

DynamicHash hashAarch64ShardCode(std::span<const uint8_t> code) {
    DynamicHash result{};
    EVP_Digest(code.data(), code.size(), result.data(), nullptr, EVP_sha256(), nullptr);
    return result;
}

} // namespace xovm::material
