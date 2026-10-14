#include "llvm/Transforms/Obfuscator/VMWhiteBoxAES.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/SHA256.h"
#include "llvm/ADT/StringExtras.h"

using namespace llvm;

GlobalVariable* llvm::emitVMWhiteBoxInstance(Module& M, const VMWhiteBoxTables& T) {
	assert(T.Bytes.size() == VMWhiteBoxTables::Size);
	auto Digest = SHA256::hash(T.Bytes);
	std::string Name = "__vm_whitebox." + toHex(ArrayRef<uint8_t>(Digest.data(), 16), true);
	if (auto* G = M.getGlobalVariable(Name, true)) return G;
	auto* Init = ConstantDataArray::get(M.getContext(), T.Bytes);
	auto* G = new GlobalVariable(M, Init->getType(), true, GlobalValue::PrivateLinkage, Init, Name);
	G->setUnnamedAddr(GlobalValue::UnnamedAddr::Global); G->setAlignment(Align(16));
	return G;
}

Function* llvm::getVMWhiteBoxBlockFunction(Module& M) {
	if (auto* F = M.getFunction("__vm_whitebox_block")) return F;
	auto& C = M.getContext(); auto* P = PointerType::getUnqual(C);
	auto* F = Function::Create(FunctionType::get(Type::getVoidTy(C), {P, P, P}, false),
		GlobalValue::PrivateLinkage, "__vm_whitebox_block", M);
	F->addFnAttr(Attribute::NoUnwind); F->addFnAttr(Attribute::NoInline);
	IRBuilder<> B(BasicBlock::Create(C, "entry", F));
	auto* State = B.CreateAlloca(ArrayType::get(B.getInt8Ty(), 16));
	auto* Next = B.CreateAlloca(ArrayType::get(B.getInt8Ty(), 16));
	B.CreateMemCpy(State, Align(1), F->getArg(1), Align(1), 16);
	auto* Entry = B.GetInsertBlock();
	auto* Loop = BasicBlock::Create(C, "round", F); auto* Done = BasicBlock::Create(C, "last", F);
	B.CreateBr(Loop); B.SetInsertPoint(Loop);
	auto* Round = B.CreatePHI(B.getInt64Ty(), 2); Round->addIncoming(B.getInt64(0), Entry);
	auto Read = [&](Value* Base, Value* Index) { return B.CreateZExt(B.CreateLoad(B.getInt8Ty(), B.CreateGEP(B.getInt8Ty(), Base, Index)), B.getInt64Ty()); };
	for (unsigned c = 0; c < 4; ++c) {
		Value* V[4][4];
		for (unsigned row = 0; row < 4; ++row) {
			Value* X = Read(State, B.getInt64(((c + row) % 4) * 4 + row));
			Value* Off = B.CreateAdd(B.CreateMul(Round, B.getInt64(VMWhiteBoxTables::RoundBytes)),
				B.CreateAdd(B.getInt64((c * 4 + row) * 1024), B.CreateMul(X, B.getInt64(4))));
			for (unsigned out = 0; out < 4; ++out) V[row][out] = Read(F->getArg(0), B.CreateAdd(Off, B.getInt64(out)));
		}
		for (unsigned out = 0; out < 4; ++out) {
			Value* Byte = B.getInt64(0);
			for (unsigned n = 0; n < 2; ++n) {
				Value* Base = B.CreateAdd(B.CreateMul(Round, B.getInt64(VMWhiteBoxTables::XorRoundBytes)),
					B.getInt64(VMWhiteBoxTables::XorOffset + ((c * 4 + out) * 6 + n * 3) * 256));
				auto Xor = [&](unsigned Stage, Value* A, Value* V) {
					return Read(F->getArg(0), B.CreateAdd(Base, B.CreateAdd(B.getInt64(Stage * 256), B.CreateOr(B.CreateShl(A, 4), V))));
				};
				auto Nibble = [&](unsigned Row) { return B.CreateAnd(B.CreateLShr(V[Row][out], n * 4), B.getInt64(15)); };
				Value* A = Xor(0, Nibble(0), Nibble(1)); Value* D = Xor(1, Nibble(2), Nibble(3));
				Byte = B.CreateOr(Byte, B.CreateShl(Xor(2, A, D), n * 4));
			}
			B.CreateStore(B.CreateTrunc(Byte, B.getInt8Ty()), B.CreateGEP(B.getInt8Ty(), Next, B.getInt64(c * 4 + out)));
		}
	}
	B.CreateMemCpy(State, Align(1), Next, Align(1), 16);
	Value* Inc = B.CreateAdd(Round, B.getInt64(1)); Round->addIncoming(Inc, Loop);
	B.CreateCondBr(B.CreateICmpULT(Inc, B.getInt64(9)), Loop, Done); B.SetInsertPoint(Done);
	for (unsigned p = 0; p < 16; ++p) {
		Value* X = Read(State, B.getInt64((((p / 4) + p % 4) % 4) * 4 + p % 4));
		Value* V = Read(F->getArg(0), B.CreateAdd(B.getInt64(VMWhiteBoxTables::LastOffset + p * 256), X));
		B.CreateStore(B.CreateTrunc(V, B.getInt8Ty()), B.CreateGEP(B.getInt8Ty(), F->getArg(2), B.getInt64(p)));
	}
	B.CreateRetVoid(); return F;
}

Function* llvm::getVMWhiteBoxCTRFunction(Module& M) {
	if (auto* F = M.getFunction("__vm_whitebox_ctr_block")) return F;
	auto& C = M.getContext(); auto* P = PointerType::getUnqual(C);
	auto* F = Function::Create(FunctionType::get(Type::getVoidTy(C), {P, P, Type::getInt32Ty(C), P}, false),
		GlobalValue::PrivateLinkage, "__vm_whitebox_ctr_block", M);
	F->addFnAttr(Attribute::NoUnwind);
	IRBuilder<> B(BasicBlock::Create(C, "entry", F));
	auto* Counter = B.CreateAlloca(ArrayType::get(B.getInt8Ty(), 16));
	B.CreateMemCpy(Counter, Align(1), F->getArg(1), Align(1), 8);
	Value* Block = B.CreateZExt(F->getArg(2), B.getInt64Ty());
	for (unsigned i = 0; i < 8; ++i)
		B.CreateStore(B.CreateTrunc(B.CreateLShr(Block, (7 - i) * 8), B.getInt8Ty()), B.CreateGEP(B.getInt8Ty(), Counter, B.getInt64(8 + i)));
	B.CreateCall(getVMWhiteBoxBlockFunction(M), {F->getArg(0), Counter, F->getArg(3)});
	B.CreateRetVoid(); return F;
}
