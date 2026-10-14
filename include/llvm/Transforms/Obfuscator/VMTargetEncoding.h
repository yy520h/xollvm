#pragma once
#include <cstdint>
#include "llvm/ADT/ArrayRef.h"
#include "llvm/IR/IRBuilder.h"

namespace llvm {
// 按 LE 序列化；header 后是固定宽度 slot record，不依赖主机 packing。
namespace VMTargetFormat {
constexpr uint64_t Magic = 0x315447544d564f58ULL; // XOVMTGT1
constexpr unsigned Version = 1, HeaderSize = 32, RecordSize = 32;
constexpr unsigned StateOffset = 12, CountOffset = 16, RoleOffset = 20;
constexpr unsigned KeyOffset = 8, AddOffset = 16, RotateOffset = 24, KindOffset = 28;
constexpr unsigned HandlerRole = 1, EngineRole = 2;
inline uint64_t rotl(uint64_t V, unsigned R) { return (V << R) | (V >> (64 - R)); }
inline uint64_t rotr(uint64_t V, unsigned R) { return (V >> R) | (V << (64 - R)); }
inline uint64_t encode(uint64_t Delta, uint64_t Key, uint64_t Add, unsigned Rotate) {
	return rotl((Delta ^ Key) + Add, Rotate);
}
inline uint64_t decode(uint64_t Word, uint64_t Key, uint64_t Add, unsigned Rotate) {
	return (rotr(Word, Rotate) - Add) ^ Key;
}
}
GlobalVariable* buildVMTargetDescriptor(Module& M, ArrayRef<Constant*> Targets,
	ArrayRef<bool> Encoded, unsigned Role, uint64_t Seed, const Twine& Name);
Value* emitVMTargetRecord(IRBuilder<>& B, Value* Descriptor, Value* Index);
Value* emitVMTargetLoad(IRBuilder<>& B, Value* Table, Value* SlotIndex,
	Value* Descriptor, const Twine& Name);
} // namespace llvm
