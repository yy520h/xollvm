#include "llvm/Transforms/Obfuscator/VMPass_Decode.h"
#include "llvm/IR/Module.h"

using namespace llvm;

static Function* cachedByteFunction(Module& M, const VMByteDecodeContext& C) {
	std::string Name = std::string("__vm_lazy_fetch.") + (C.KeyIsPointer ? "whitebox" : "aes");
	if (auto* F = M.getFunction(Name)) return F;
	auto& Context = M.getContext();
	auto* F = Function::Create(FunctionType::get(Type::getInt8Ty(Context),
		{PointerType::getUnqual(Context), Type::getInt32Ty(Context)}, false), GlobalValue::PrivateLinkage, Name, M);
	F->addFnAttr(Attribute::NoUnwind);
	IRBuilder<> B(BasicBlock::Create(Context, "entry", F));
	Value* CT = F->getArg(0), *Index = F->getArg(1);
	Value* Block = B.CreateLShr(Index, 4);
	Value* Cache = B.CreateGEP(B.getInt8Ty(), CT, B.getInt64(C.CachedBlockOffset));
	Value* Window = B.CreateGEP(B.getInt8Ty(), CT, B.getInt64(C.WindowOffset));
	auto* Miss = BasicBlock::Create(Context, "cache.miss", F); auto* Hit = BasicBlock::Create(Context, "cache.hit", F);
	B.CreateCondBr(B.CreateICmpEQ(B.CreateLoad(B.getInt32Ty(), Cache), Block), Hit, Miss);
	B.SetInsertPoint(Miss);
	Value* Key = B.CreateGEP(B.getInt8Ty(), CT, B.getInt64(C.KeyOffset));
	if (C.KeyIsPointer) Key = B.CreateLoad(B.getPtrTy(), Key);
	Value* Nonce = B.CreateGEP(B.getInt8Ty(), CT, B.getInt64(C.NonceOffset));
	B.CreateCall(cast<Function>(C.Keystream), {Key, Nonce, Block, Window});
	B.CreateStore(Block, Cache); B.CreateBr(Hit); B.SetInsertPoint(Hit);
	Value* Off = B.CreateZExt(B.CreateAnd(Index, 15), B.getInt64Ty());
	B.CreateRet(B.CreateLoad(B.getInt8Ty(), B.CreateGEP(B.getInt8Ty(), Window, Off)));
	return F;
}

Value* llvm::emitVMByteLoad(IRBuilder<>& B, const VMByteDecodeContext& C,
	Value* Index, const Twine& N) {
	Value* Ptr = B.CreateGEP(B.getInt8Ty(), C.BC,
		B.CreateSExt(Index, B.getInt64Ty(), N + ".ip64"), N + ".p");
	Value* Raw = B.CreateLoad(B.getInt8Ty(), Ptr, N);
	if (!C.EncBytecode) return Raw;
	if (C.LazyDecrypt) {
		assert(C.LazyCtx && C.Keystream && "missing lazy decode context");
		if (C.CacheEnabled) {
			Raw = B.CreateXor(Raw, B.CreateCall(cachedByteFunction(*B.GetInsertBlock()->getModule(), C), {C.LazyCtx, Index}), N + ".aesx");
		} else {
		Value* RK = B.CreateGEP(B.getInt8Ty(), C.LazyCtx, B.getInt64(C.KeyOffset), N + ".lz.rk");
		Value* NC = B.CreateGEP(B.getInt8Ty(), C.LazyCtx, B.getInt64(C.NonceOffset), N + ".lz.nc");
		Value* Win = B.CreateGEP(B.getInt8Ty(), C.LazyCtx, B.getInt64(C.WindowOffset), N + ".lz.win");
		B.CreateCall(cast<Function>(C.Keystream), { RK, NC, B.CreateLShr(Index, B.getInt32(4)), Win });
		Value* Off = B.CreateZExt(B.CreateAnd(Index, B.getInt32(15)), B.getInt64Ty());
		Value* KS = B.CreateLoad(B.getInt8Ty(), B.CreateGEP(B.getInt8Ty(), Win, Off));
		Raw = B.CreateXor(Raw, KS, N + ".aesx");
		}
	}
	auto* Salt = B.CreateLoad(B.getInt32Ty(), C.Salt, N + ".s");
	Salt->setVolatile(true);
	Value* Key;
	if (C.StrongBC) {
		Key = B.CreateXor(Salt, B.CreateMul(Index, B.getInt32(0x9E3779B1u)), N + ".k0");
		Key = B.CreateXor(Key, B.CreateLShr(Key, B.getInt32(15)), N + ".k1");
		Key = B.CreateMul(Key, B.getInt32(0x85EBCA77u), N + ".k2");
		Key = B.CreateXor(Key, B.CreateLShr(Key, B.getInt32(13)), N + ".k3");
	} else {
		Key = B.CreateXor(Salt, Index, N + ".kx");
	}
	return B.CreateXor(Raw, B.CreateTrunc(Key, B.getInt8Ty(), N + ".k8"), N + ".dec");
}
