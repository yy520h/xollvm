#include "llvm/Transforms/Obfuscator/AntiDebug.h"

#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/Transforms/Obfuscator/FunctionObfContextAnalysis.h"
#include "llvm/Transforms/Obfuscator/ObfuscationAnnotationAnalysis.h"
#include "llvm/Transforms/Obfuscator/ObfuscationConfig.h"
#include "llvm/Transforms/Obfuscator/Utils.h"
#include "llvm/Transforms/Obfuscator/VMPass_Plan.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

using namespace llvm;

static bool supportsProcAntiDebug(const Module& M) {
	Triple T(M.getTargetTriple());
	return T.isOSLinux() || T.isAndroid();
}

namespace {

struct AntiDebugSymbols {
	FunctionCallee Open;
	FunctionCallee Read;
	FunctionCallee Close;
	FunctionCallee Ptrace;
	FunctionCallee Clock;
	FunctionCallee PthreadCreate;
	FunctionCallee Sleep;
};

Value* emitTracerPid(IRBuilder<>& B, const AntiDebugSymbols& S);
Value* emitTracerPid(IRBuilder<>& B, const AntiDebugSymbols& S, AllocaInst* Buffer);
Value* emitMaps(IRBuilder<>& B, const AntiDebugSymbols& S);
Value* emitTiming(IRBuilder<>& B, AntiDebugSymbols& S, uint64_t Threshold);

AntiDebugSymbols getSymbols(Module& M, const AntiDebugConfig& Cfg) {
	LLVMContext& C = M.getContext();
	Type* Ptr = PointerType::getUnqual(C);
	Type* I32 = Type::getInt32Ty(C);
	Type* I64 = Type::getInt64Ty(C);
	Type* Timespec = StructType::get(C, {I64, I64});
	AntiDebugSymbols S;
	if (Cfg.tracerPid || Cfg.maps) {
		S.Open = M.getOrInsertFunction("open", FunctionType::get(I32, {Ptr, I32}, false));
		S.Read = M.getOrInsertFunction("read", FunctionType::get(I64, {I32, Ptr, I64}, false));
		S.Close = M.getOrInsertFunction("close", FunctionType::get(I32, {I32}, false));
	}
	if (Cfg.ptrace)
		S.Ptrace = M.getOrInsertFunction("ptrace", FunctionType::get(I64, {I64, I64, Ptr, Ptr}, false));
	if (Cfg.timing)
		S.Clock = M.getOrInsertFunction("clock_gettime", FunctionType::get(I32, {I32, PointerType::getUnqual(Timespec)}, false));
	if (Cfg.dynamic) {
		S.PthreadCreate = M.getOrInsertFunction("pthread_create",
			FunctionType::get(I32, {Ptr, Ptr, Ptr, Ptr}, false));
		S.Sleep = M.getOrInsertFunction("usleep", FunctionType::get(I32, {I32}, false));
	}
	return S;
}

GlobalVariable* getOrCreateMonitorState(Module& M, const AntiDebugConfig& Cfg) {
	if (auto* Existing = M.getGlobalVariable("__obf_antidebug_monitor_state", true))
		return Existing;
	LLVMContext& C = M.getContext();
	Type* I32 = Type::getInt32Ty(C);
	ArrayType* StateTy = ArrayType::get(I32, 4);
	Constant* Init = ConstantArray::get(StateTy, {
		ConstantInt::get(I32, 0), ConstantInt::get(I32, 0),
		ConstantInt::get(I32, 0), ConstantInt::get(I32, Cfg.intervalMs * 1000u)});
	return new GlobalVariable(M, StateTy, false, GlobalValue::InternalLinkage,
		Init, "__obf_antidebug_monitor_state");
}

Function* getOrCreateMonitor(Module& M, AntiDebugConfig& Cfg,
	GlobalVariable* State, GlobalVariable* Response, AntiDebugSymbols& S) {
	if (auto* Existing = M.getFunction("__obf_antidebug_monitor")) return Existing;
	LLVMContext& C = M.getContext();
	Type* Ptr = PointerType::getUnqual(C);
	FunctionType* FT = FunctionType::get(Ptr, {Ptr}, false);
	Function* Fn = Function::Create(FT, GlobalValue::InternalLinkage,
		"__obf_antidebug_monitor", &M);
	BasicBlock* Entry = BasicBlock::Create(C, "obf.ad.monitor.entry", Fn);
	BasicBlock* Loop = BasicBlock::Create(C, "obf.ad.monitor.loop", Fn);
	BasicBlock* Exit = BasicBlock::Create(C, "obf.ad.monitor.exit", Fn);
	IRBuilder<> B(Entry);
	AllocaInst* Buffer = B.CreateAlloca(Type::getInt8Ty(C), B.getInt64(4096), "obf.ad.monitor.buf");
	B.CreateBr(Loop);
	B.SetInsertPoint(Loop);
	Value* StopPtr = B.CreateGEP(State->getValueType(), State, {B.getInt32(0), B.getInt32(0)});
	auto* StopLoad = B.CreateLoad(Type::getInt32Ty(C), StopPtr, "obf.ad.stop");
	StopLoad->setAtomic(AtomicOrdering::Monotonic);
	Value* Stop = StopLoad;
	Value* Done = B.CreateICmpNE(Stop, B.getInt32(0), "obf.ad.done");
	BasicBlock* Check = BasicBlock::Create(C, "obf.ad.monitor.check", Fn);
	B.CreateCondBr(Done, Exit, Check);
	B.SetInsertPoint(Check);
	Value* Detected = B.getFalse();
	if (Cfg.tracerPid)
		Detected = B.CreateOr(Detected, emitTracerPid(B, S, Buffer), "obf.ad.monitor.any");
	if (Cfg.maps)
		Detected = B.CreateOr(Detected, emitMaps(B, S), "obf.ad.monitor.any");
	if (Cfg.timing)
		Detected = B.CreateOr(Detected, emitTiming(B, S, Cfg.thresholdNs), "obf.ad.monitor.any");
	Value* ResponsePtr = B.CreateGEP(State->getValueType(), State,
		{B.getInt32(0), B.getInt32(1)});
	cast<StoreInst>(B.CreateStore(B.CreateSelect(Detected, B.getInt32(1), B.getInt32(0)), ResponsePtr))
		->setAtomic(AtomicOrdering::Monotonic);
	cast<StoreInst>(B.CreateStore(B.CreateSelect(Detected, B.getInt32(1), B.getInt32(0)), Response))
		->setAtomic(AtomicOrdering::Monotonic);
	Value* IntervalPtr = B.CreateGEP(State->getValueType(), State,
		{B.getInt32(0), B.getInt32(3)});
	B.CreateCall(S.Sleep, {B.CreateLoad(Type::getInt32Ty(C), IntervalPtr)});
	B.CreateBr(Loop);
	B.SetInsertPoint(Exit);
	B.CreateRet(ConstantPointerNull::get(cast<PointerType>(Ptr)));
	return Fn;
}

void createMonitorCtor(Module& M, GlobalVariable* State, Function* Monitor,
	AntiDebugSymbols& S) {
	if (M.getFunction("__obf_antidebug_monitor_ctor")) return;
	LLVMContext& C = M.getContext();
	Type* I32 = Type::getInt32Ty(C);
	Type* Ptr = PointerType::getUnqual(C);
	Function* Ctor = Function::Create(FunctionType::get(Type::getVoidTy(C), false),
		GlobalValue::InternalLinkage, "__obf_antidebug_monitor_ctor", &M);
	BasicBlock* Entry = BasicBlock::Create(C, "obf.ad.ctor.entry", Ctor);
	IRBuilder<> B(Entry);
	Value* StartedPtr = B.CreateGEP(State->getValueType(), State,
		{B.getInt32(0), B.getInt32(2)});
	auto* StartedLoad = B.CreateLoad(I32, StartedPtr);
	StartedLoad->setAtomic(AtomicOrdering::Monotonic);
	Value* Started = StartedLoad;
	BasicBlock* Start = BasicBlock::Create(C, "obf.ad.ctor.start", Ctor);
	BasicBlock* Exit = BasicBlock::Create(C, "obf.ad.ctor.exit", Ctor);
	B.CreateCondBr(B.CreateICmpEQ(Started, B.getInt32(0)), Start, Exit);
	B.SetInsertPoint(Start);
	cast<StoreInst>(B.CreateStore(B.getInt32(1), StartedPtr))->setAtomic(AtomicOrdering::Monotonic);
	AllocaInst* Thread = B.CreateAlloca(Type::getInt64Ty(C), nullptr, "obf.ad.thread");
	B.CreateCall(S.PthreadCreate, {Thread,
		ConstantPointerNull::get(cast<PointerType>(Ptr)), Monitor, State});
	B.CreateBr(Exit);
	B.SetInsertPoint(Exit);
	B.CreateRetVoid();
	appendToGlobalCtors(M, Ctor, 65535, nullptr);
}

Value* hasToken(IRBuilder<>& B, Value* Buffer, Value* Length, StringRef Token) {
	Module* M = B.GetInsertBlock()->getModule();
	LLVMContext& C = M->getContext();
	Type* Ptr = PointerType::getUnqual(C);
	FunctionCallee Strstr = M->getOrInsertFunction("strstr",
		FunctionType::get(Ptr, {Ptr, Ptr}, false));
	Value* Needle = B.CreateGlobalString(Token, "obf.ad.token");
	Value* SafeLength = B.CreateSelect(B.CreateICmpUGT(Length, B.getInt64(4094)),
		B.getInt64(4094), Length, "obf.ad.len");
	Value* End = B.CreateGEP(Type::getInt8Ty(C), Buffer, SafeLength, "obf.ad.end");
	B.CreateStore(B.getInt8(0), End);
	return B.CreateICmpNE(B.CreateCall(Strstr, {Buffer, Needle}),
		ConstantPointerNull::get(cast<PointerType>(Ptr)), "obf.ad.hit");
}

Value* emitTracerPid(IRBuilder<>& B, const AntiDebugSymbols& S) {
	Module* M = B.GetInsertBlock()->getModule();
	LLVMContext& C = M->getContext();
	AllocaInst* Buffer = B.CreateAlloca(Type::getInt8Ty(C), B.getInt64(4096), "obf.ad.buf");
	return emitTracerPid(B, S, Buffer);
}

Value* emitTracerPid(IRBuilder<>& B, const AntiDebugSymbols& S, AllocaInst* Buffer) {
	Value* Path = B.CreateGlobalString("/proc/self/status", "obf.ad.status");
	Value* FD = B.CreateCall(S.Open, {Path, B.getInt32(0)}, "obf.ad.fd");
	Value* N = B.CreateCall(S.Read, {FD, Buffer, B.getInt64(4095)}, "obf.ad.n");
	B.CreateCall(S.Close, {FD});
	Value* Valid = B.CreateICmpSGT(N, B.getInt64(0));
	Value* Hit = hasToken(B, Buffer, N, "TracerPid: 1");
	return B.CreateAnd(Valid, Hit, "obf.ad.tracer");
}

Value* emitMaps(IRBuilder<>& B, const AntiDebugSymbols& S) {
	Module* M = B.GetInsertBlock()->getModule();
	LLVMContext& C = M->getContext();
	Value* Path = B.CreateGlobalString("/proc/self/maps", "obf.ad.maps");
	Value* FD = B.CreateCall(S.Open, {Path, B.getInt32(0)}, "obf.ad.maps.fd");
	AllocaInst* Buffer = B.CreateAlloca(Type::getInt8Ty(C), B.getInt64(4096), "obf.ad.maps.buf");
	Value* N = B.CreateCall(S.Read, {FD, Buffer, B.getInt64(4095)}, "obf.ad.maps.n");
	B.CreateCall(S.Close, {FD});
	Value* Valid = B.CreateICmpSGT(N, B.getInt64(0));
	Value* Hit = hasToken(B, Buffer, N, "gdb");
	return B.CreateAnd(Valid, Hit, "obf.ad.maps.hit");
}

Value* emitTiming(IRBuilder<>& B, AntiDebugSymbols& S, uint64_t Threshold) {
	Module* M = B.GetInsertBlock()->getModule();
	LLVMContext& C = M->getContext();
	Type* Timespec = StructType::get(C, {Type::getInt64Ty(C), Type::getInt64Ty(C)});
	AllocaInst* A = B.CreateAlloca(Timespec, nullptr, "obf.ad.t0");
	AllocaInst* Z = B.CreateAlloca(Timespec, nullptr, "obf.ad.t1");
	B.CreateCall(S.Clock, {B.getInt32(1), A});
	AllocaInst* Sink = B.CreateAlloca(Type::getInt64Ty(C), nullptr, "obf.ad.sink");
	B.CreateStore(B.CreateLoad(Type::getInt64Ty(C), Sink), Sink)->setVolatile(true);
	B.CreateCall(S.Clock, {B.getInt32(1), Z});
	Value* Asec = B.CreateStructGEP(Timespec, A, 0);
	Value* Ansec = B.CreateStructGEP(Timespec, A, 1);
	Value* Zsec = B.CreateStructGEP(Timespec, Z, 0);
	Value* Znsec = B.CreateStructGEP(Timespec, Z, 1);
	Value* Delta = B.CreateAdd(
		B.CreateMul(B.CreateSub(B.CreateLoad(Type::getInt64Ty(C), Zsec), B.CreateLoad(Type::getInt64Ty(C), Asec)), B.getInt64(1000000000)),
		B.CreateSub(B.CreateLoad(Type::getInt64Ty(C), Znsec), B.CreateLoad(Type::getInt64Ty(C), Ansec)), "obf.ad.delta");
	return B.CreateICmpUGT(Delta, B.getInt64(Threshold), "obf.ad.timing");
}

} // namespace

GlobalVariable* llvm::getOrCreateAntiDebugResponse(Module& M) {
	LLVMContext& C = M.getContext();
	if (auto* Existing = M.getGlobalVariable("__obf_antidebug_response", true))
		return Existing;
	return new GlobalVariable(M, Type::getInt32Ty(C), false,
		GlobalValue::InternalLinkage, ConstantInt::get(Type::getInt32Ty(C), 0),
		"__obf_antidebug_response");
}

PreservedAnalyses AntiDebugPass::run(Function& F, FunctionAnalysisManager& AM) {
	if (F.isDeclaration()) return PreservedAnalyses::all();
	const ObfuscationConfig& OC = getObfConfig(F, AM);
	auto PC = OC.getPassConfig("antidebug");
	if (!PC.has_value()) return PreservedAnalyses::all();
	AntiDebugConfig Cfg = AntiDebugConfig::fromPassConfig(*PC);
	std::string Reason;
	if (!Cfg.enabled || !Cfg.validate(&Reason)) return PreservedAnalyses::all();
	Module& M = *F.getParent();
	if (!supportsProcAntiDebug(M) && (Cfg.tracerPid || Cfg.ptrace || Cfg.maps || Cfg.dynamic)) {
		auto& FOC = *AM.getResult<FunctionObfContextAnalysis>(F);
		obf::recordObfPassSkip(FOC, "antidebug", "target platform lacks Linux proc/pthread ABI");
		return PreservedAnalyses::all();
	}
	// VM 的暂存副本已经冻结；入口保护必须等正式 wrapper 提交后再插入。
	if (VMPlanCoordinator::active() && F.getMetadata("obf.vm.caller")) {
		F.setMetadata("obf.antidebug.deferred", MDNode::get(M.getContext(), {}));
		return PreservedAnalyses::all();
	}
	return applyAntiDebug(F, Cfg) ? PreservedAnalyses::none() : PreservedAnalyses::all();
}

bool llvm::applyAntiDebug(Function& F, AntiDebugConfig Cfg) {
	if (F.isDeclaration() || !Cfg.enabled || !Cfg.validate()) return false;
	Module& M = *F.getParent();
	if (!supportsProcAntiDebug(M) && (Cfg.tracerPid || Cfg.ptrace || Cfg.maps || Cfg.dynamic))
		return false;
	AntiDebugSymbols S = getSymbols(M, Cfg);
	if (Cfg.dynamic) {
		GlobalVariable* State = getOrCreateMonitorState(M, Cfg);
		GlobalVariable* Response = getOrCreateAntiDebugResponse(M);
		Function* Monitor = getOrCreateMonitor(M, Cfg, State, Response, S);
		createMonitorCtor(M, State, Monitor, S);
	}
	GlobalVariable* Response = getOrCreateAntiDebugResponse(M);
	BasicBlock* Entry = &F.getEntryBlock();
	IRBuilder<> B(&*Entry->getFirstInsertionPt());
	Value* Detected = B.getFalse();
	if (Cfg.tracerPid) Detected = B.CreateOr(Detected, emitTracerPid(B, S), "obf.ad.any");
	if (Cfg.maps) Detected = B.CreateOr(Detected, emitMaps(B, S), "obf.ad.any");
	if (Cfg.ptrace) {
		Value* Result = B.CreateCall(S.Ptrace, {B.getInt64(0), B.getInt64(0), ConstantPointerNull::get(cast<PointerType>(B.getInt8Ty()->getPointerTo())), ConstantPointerNull::get(cast<PointerType>(B.getInt8Ty()->getPointerTo()))}, "obf.ad.ptrace");
		Detected = B.CreateOr(Detected, B.CreateICmpSLT(Result, B.getInt64(0)), "obf.ad.any");
	}
	if (Cfg.timing) Detected = B.CreateOr(Detected, emitTiming(B, S, Cfg.thresholdNs), "obf.ad.any");
	B.CreateStore(B.CreateSelect(Detected, B.getInt32(1), B.getInt32(0)), Response)->setVolatile(true);
	if (!Cfg.responseCorrupt) return true;
	BasicBlock* Body = Entry->splitBasicBlock(B.GetInsertPoint(), "obf.ad.body");
	Entry->getTerminator()->eraseFromParent();
	IRBuilder<> Guard(Entry);
	Value* Flag = Guard.CreateLoad(Type::getInt32Ty(M.getContext()), Response, "obf.ad.response");
	cast<LoadInst>(Flag)->setVolatile(true);
	BasicBlock* Fail = BasicBlock::Create(M.getContext(), "obf.ad.fail", &F, Body);
	Guard.CreateCondBr(Guard.CreateICmpNE(Flag, Guard.getInt32(0)), Fail, Body);
	IRBuilder<> FailBuilder(Fail);
	Type* RT = F.getReturnType();
	if (RT->isVoidTy()) FailBuilder.CreateRetVoid();
	else if (RT->isPointerTy()) FailBuilder.CreateRet(ConstantPointerNull::get(cast<PointerType>(RT)));
	else if (RT->isIntegerTy()) FailBuilder.CreateRet(ConstantInt::get(RT, 0));
	else if (RT->isFloatingPointTy()) FailBuilder.CreateRet(ConstantFP::get(RT, 0.0));
	else FailBuilder.CreateUnreachable();
	return true;
}
