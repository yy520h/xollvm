#include "llvm/Transforms/Obfuscator/VMTargetEncoding.h"
#include "llvm/Transforms/Obfuscator/Rng.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/Module.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

using namespace llvm;

GlobalVariable* llvm::buildVMTargetDescriptor(Module& M, ArrayRef<Constant*> Targets,
	ArrayRef<bool> Encoded, unsigned Role, uint64_t Seed, const Twine& Name) {
	assert(Targets.size() == Encoded.size());
	auto& C = M.getContext();
	auto* I32 = Type::getInt32Ty(C); auto* I64 = Type::getInt64Ty(C);
	auto* RT = StructType::get(C, {PointerType::getUnqual(C), I64, I64, I32, I32});
	SmallVector<Constant*, 128> Records;
	for (unsigned i = 0; i < Targets.size(); ++i) {
		uint64_t S = obf::mix64(Seed ^ obf::fnv1a64("vm.target.v1") ^ (uint64_t(Role) << 32) ^ i);
		uint64_t K = obf::mix64(S), A = obf::mix64(S ^ 0xc67178f21a864fd3ULL);
		unsigned R = 1 + obf::mix64(S ^ 0x61937be8ULL) % 63;
		Records.push_back(ConstantStruct::get(RT, {Targets[i], ConstantInt::get(I64, K),
			ConstantInt::get(I64, A), ConstantInt::get(I32, R), ConstantInt::get(I32, Encoded[i])}));
	}
	auto* AT = ArrayType::get(RT, Records.size());
	auto* DT = StructType::get(C, {I64, I32, I32, I32, I32, I64, AT});
	auto* Init = ConstantStruct::get(DT, {ConstantInt::get(I64, VMTargetFormat::Magic),
		ConstantInt::get(I32, VMTargetFormat::Version), ConstantInt::get(I32, 0),
		ConstantInt::get(I32, Targets.size()), ConstantInt::get(I32, Role), ConstantInt::get(I64, 0),
		ConstantArray::get(AT, Records)});
	// 链接后改写状态和载荷，不能把 pending 常量折叠成无条件 trap。
	auto* G = new GlobalVariable(M, DT, false, GlobalValue::PrivateLinkage, Init, Name);
	G->setSection(".obf.vm.targets"); G->setAlignment(Align(8));
	appendToCompilerUsed(M, {G});
	return G;
}

Value* llvm::emitVMTargetRecord(IRBuilder<>& B, Value* Descriptor, Value* Index) {
	Value* I = B.CreateZExtOrTrunc(Index, B.getInt64Ty());
	Value* Off = B.CreateAdd(B.getInt64(VMTargetFormat::HeaderSize), B.CreateMul(I, B.getInt64(VMTargetFormat::RecordSize)));
	return B.CreateGEP(B.getInt8Ty(), Descriptor, Off, "vm.target.record");
}

Value* llvm::emitVMTargetLoad(IRBuilder<>& B, Value* Table, Value* SlotIndex,
	Value* Descriptor, const Twine& Name) {
	(void)Table;
	auto* F = B.GetInsertBlock()->getParent();
	auto Load = [&](Type* Ty, Value* P, unsigned Off) {
		auto* L = B.CreateLoad(Ty, B.CreateGEP(B.getInt8Ty(), P, B.getInt64(Off)));
		L->setVolatile(true); return L;
	};
	Value* State = Load(B.getInt32Ty(), Descriptor, VMTargetFormat::StateOffset);
	Value* Count = Load(B.getInt32Ty(), Descriptor, VMTargetFormat::CountOffset);
	Value* Good = B.CreateAnd(B.CreateICmpEQ(State, B.getInt32(1)),
		B.CreateICmpULT(B.CreateZExtOrTrunc(SlotIndex, B.getInt64Ty()), B.CreateZExt(Count, B.getInt64Ty())));
	auto* Valid = BasicBlock::Create(B.getContext(), "vm.target.valid", F);
	auto* Invalid = BasicBlock::Create(B.getContext(), "vm.target.pending", F);
	B.CreateCondBr(Good, Valid, Invalid);
	IRBuilder<> Trap(Invalid); Trap.CreateCall(Intrinsic::getOrInsertDeclaration(F->getParent(), Intrinsic::trap)); Trap.CreateUnreachable();
	B.SetInsertPoint(Valid);
	Value* Rec = emitVMTargetRecord(B, Descriptor, SlotIndex);
	Value* E = Load(B.getInt64Ty(), Rec, 0);
	Value* K = Load(B.getInt64Ty(), Rec, VMTargetFormat::KeyOffset);
	Value* A = Load(B.getInt64Ty(), Rec, VMTargetFormat::AddOffset);
	Value* R = B.CreateZExt(Load(B.getInt32Ty(), Rec, VMTargetFormat::RotateOffset), B.getInt64Ty());
	Value* Kind = Load(B.getInt32Ty(), Rec, VMTargetFormat::KindOffset);
	Value* ParamsOK = B.CreateAnd(B.CreateICmpEQ(Kind, B.getInt32(1)),
		B.CreateAnd(B.CreateICmpUGT(R, B.getInt64(0)), B.CreateICmpULT(R, B.getInt64(64))));
	auto* Decode = BasicBlock::Create(B.getContext(), "vm.target.decode", F);
	B.CreateCondBr(ParamsOK, Decode, Invalid); B.SetInsertPoint(Decode);
	Value* Rot = B.CreateOr(B.CreateLShr(E, R), B.CreateShl(E, B.CreateSub(B.getInt64(64), R)));
	Value* D = B.CreateXor(B.CreateSub(Rot, A), K);
	return B.CreateIntToPtr(B.CreateAdd(B.CreatePtrToInt(Rec, B.getInt64Ty()), D), B.getPtrTy(), Name);
}
