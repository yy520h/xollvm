#pragma once

#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/ValueHandle.h"

namespace llvm {

// 上下文中的值全部属于同一引擎，不能引用调用方 VMImpl 的临时成员。
struct VMByteDecodeContext {
	Value* BC = nullptr;
	Value* Salt = nullptr;
	Value* LazyCtx = nullptr;
	WeakTrackingVH Keystream;
	bool EncBytecode = false;
	bool StrongBC = false;
	bool LazyDecrypt = false;
	bool CacheEnabled = false;
	bool KeyIsPointer = false;
	unsigned KeyOffset = 0;
	unsigned NonceOffset = 176;
	unsigned WindowOffset = 184;
	unsigned CachedBlockOffset = 200;
};

Value* emitVMByteLoad(IRBuilder<>& B, const VMByteDecodeContext& C,
	Value* Index, const Twine& Name);

} // namespace llvm
