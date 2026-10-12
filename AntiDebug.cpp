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

std::string configSuffix(const AntiDebugConfig& Cfg) {
	return "." + std::to_string(Cfg.tracerPid || Cfg.ptrace) +
		std::to_string(Cfg.maps) + std::to_string(Cfg.timing) +
		std::to_string(Cfg.dynamic) + "." + std::to_string(Cfg.dynamic ? Cfg.intervalMs : 0) +
		"." + std::to_string(Cfg.timing ? Cfg.thresholdNs : 0);
}

struct AntiDebugSymbols {
	FunctionCallee Open;
	FunctionCallee Read;
	FunctionCallee Close;
	FunctionCallee Clock;
	FunctionCallee PthreadCreate;
	FunctionCallee PthreadJoin;
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
	if (Cfg.tracerPid || Cfg.ptrace || Cfg.maps) {
		S.Open = M.getOrInsertFunction("open", FunctionType::get(I32, {Ptr, I32}, false));
		S.Read = M.getOrInsertFunction("read", FunctionType::get(I64, {I32, Ptr, I64}, false));
		S.Close = M.getOrInsertFunction("close", FunctionType::get(I32, {I32}, false));
	}
	if (Cfg.timing)
		S.Clock = M.getOrInsertFunction("clock_gettime", FunctionType::get(I32, {I32, PointerType::getUnqual(Timespec)}, false));
	if (Cfg.dynamic) {
		S.PthreadCreate = M.getOrInsertFunction("pthread_create",
			FunctionType::get(I32, {Ptr, Ptr, Ptr, Ptr}, false));
		S.PthreadJoin = M.getOrInsertFunction("pthread_join",
			FunctionType::get(I32, {M.getDataLayout().getIntPtrType(C), Ptr}, false));
		S.Sleep = M.getOrInsertFunction("usleep", FunctionType::get(I32, {I32}, false));
	}
	return S;
}

GlobalVariable* getOrCreateMonitorState(Module& M, const AntiDebugConfig& Cfg) {
	std::string Name = "__obf_antidebug_monitor_state" + configSuffix(Cfg);
	if (auto* Existing = M.getGlobalVariable(Name, true))
		return Existing;
	LLVMContext& C = M.getContext();
	Type* I32 = Type::getInt32Ty(C);
	ArrayType* StateTy = ArrayType::get(I32, 4);
	Constant* Init = ConstantArray::get(StateTy, {
		ConstantInt::get(I32, 0), ConstantInt::get(I32, 0),
		ConstantInt::get(I32, 0), ConstantInt::get(I32, Cfg.intervalMs)});
	return new GlobalVariable(M, StateTy, false, GlobalValue::InternalLinkage,
		Init, Name);
}

Function* getOrCreateMonitor(Module& M, AntiDebugConfig& Cfg,
	GlobalVariable* State, GlobalVariable* Response, AntiDebugSymbols& S) {
	std::string Name = "__obf_antidebug_monitor" + configSuffix(Cfg);
	if (auto* Existing = M.getFunction(Name)) return Existing;
	LLVMContext& C = M.getContext();
	Type* Ptr = PointerType::getUnqual(C);
	FunctionType* FT = FunctionType::get(Ptr, {Ptr}, false);
	Function* Fn = Function::Create(FT, GlobalValue::InternalLinkage,
		Name, &M);
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
	if (Cfg.tracerPid || Cfg.ptrace)
		Detected = B.CreateOr(Detected, emitTracerPid(B, S, Buffer), "obf.ad.monitor.any");
	if (Cfg.maps)
		Detected = B.CreateOr(Detected, emitMaps(B, S), "obf.ad.monitor.any");
	if (Cfg.timing)
		Detected = B.CreateOr(Detected, emitTiming(B, S, Cfg.thresholdNs), "obf.ad.monitor.any");
	B.CreateAtomicRMW(AtomicRMWInst::Or, Response,
		B.CreateZExt(Detected, B.getInt32Ty()), MaybeAlign(4), AtomicOrdering::Monotonic);
	Value* IntervalPtr = B.CreateGEP(State->getValueType(), State,
		{B.getInt32(0), B.getInt32(3)});
	Value* Interval = B.CreateLoad(B.getInt32Ty(), IntervalPtr);
	BasicBlock* Wait = BasicBlock::Create(C, "obf.ad.monitor.wait", Fn);
	BasicBlock* Sleep = BasicBlock::Create(C, "obf.ad.monitor.sleep", Fn);
	B.CreateBr(Wait);
	B.SetInsertPoint(Wait);
	PHINode* Remaining = B.CreatePHI(B.getInt32Ty(), 2, "remaining.ms");
	Remaining->addIncoming(Interval, Check);
	auto* WaitingStop = B.CreateLoad(B.getInt32Ty(), StopPtr);
	WaitingStop->setAtomic(AtomicOrdering::Monotonic);
	B.CreateCondBr(B.CreateICmpNE(WaitingStop, B.getInt32(0)), Exit, Sleep);
	B.SetInsertPoint(Sleep);
	// 分段休眠使正常退出不受用户配置的长轮询间隔阻塞。
	Value* Chunk = B.CreateSelect(B.CreateICmpUGT(Remaining, B.getInt32(10)),
		B.getInt32(10), Remaining);
	B.CreateCall(S.Sleep, {B.CreateMul(Chunk, B.getInt32(1000))});
	Value* Rest = B.CreateSub(Remaining, Chunk);
	Remaining->addIncoming(Rest, Sleep);
	B.CreateCondBr(B.CreateICmpEQ(Rest, B.getInt32(0)), Loop, Wait);
	B.SetInsertPoint(Exit);
	B.CreateRet(ConstantPointerNull::get(cast<PointerType>(Ptr)));
	return Fn;
}

void createMonitorCtor(Module& M, GlobalVariable* State, Function* Monitor,
	GlobalVariable* Response, AntiDebugSymbols& S) {
	std::string Name = Monitor->getName().str() + "_ctor";
	if (M.getFunction(Name)) return;
	LLVMContext& C = M.getContext();
	Type* I32 = Type::getInt32Ty(C);
	Type* Ptr = PointerType::getUnqual(C);
	Function* Ctor = Function::Create(FunctionType::get(Type::getVoidTy(C), false),
		GlobalValue::InternalLinkage, Name, &M);
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
	Type* ThreadTy = M.getDataLayout().getIntPtrType(C);
	auto* Thread = new GlobalVariable(M, ThreadTy, false, GlobalValue::InternalLinkage,
		ConstantInt::get(ThreadTy, 0), Monitor->getName() + ".thread");
	Value* Rc = B.CreateCall(S.PthreadCreate, {Thread,
		ConstantPointerNull::get(cast<PointerType>(Ptr)), Monitor, State});
	Value* Ok = B.CreateICmpEQ(Rc, B.getInt32(0));
	cast<StoreInst>(B.CreateStore(B.CreateZExt(Ok, I32), StartedPtr))->setAtomic(AtomicOrdering::Monotonic);
	// 监控启动失败不能悄悄降级为成功状态。
	B.CreateAtomicRMW(AtomicRMWInst::Or, Response, B.CreateZExt(B.CreateNot(Ok), I32),
		MaybeAlign(4), AtomicOrdering::Monotonic);
	B.CreateBr(Exit);
	B.SetInsertPoint(Exit);
	B.CreateRetVoid();
	appendToGlobalCtors(M, Ctor, 65535, nullptr);
	Function* Dtor = Function::Create(FunctionType::get(B.getVoidTy(), false),
		GlobalValue::InternalLinkage, Monitor->getName() + "_dtor", &M);
	BasicBlock* Stop = BasicBlock::Create(C, "stop", Dtor);
	BasicBlock* Join = BasicBlock::Create(C, "join", Dtor);
	BasicBlock* Done = BasicBlock::Create(C, "done", Dtor);
	B.SetInsertPoint(Stop);
	StartedPtr = B.CreateGEP(State->getValueType(), State, {B.getInt32(0), B.getInt32(2)});
	Value* StopPtr = B.CreateGEP(State->getValueType(), State, {B.getInt32(0), B.getInt32(0)});
	cast<StoreInst>(B.CreateStore(B.getInt32(1), StopPtr))->setAtomic(AtomicOrdering::Monotonic);
	auto* HasThread = B.CreateLoad(I32, StartedPtr);
	HasThread->setAtomic(AtomicOrdering::Monotonic);
	B.CreateCondBr(B.CreateICmpNE(HasThread, B.getInt32(0)), Join, Done);
	B.SetInsertPoint(Join);
	B.CreateCall(S.PthreadJoin, {B.CreateLoad(ThreadTy, Thread),
		ConstantPointerNull::get(cast<PointerType>(Ptr))});
	cast<StoreInst>(B.CreateStore(B.getInt32(0), StartedPtr))->setAtomic(AtomicOrdering::Monotonic);
	B.CreateBr(Done);
	B.SetInsertPoint(Done);
	B.CreateRetVoid();
	appendToGlobalDtors(M, Dtor, 65535, nullptr);
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

Function* getOrCreateTracerParser(Module& M) {
	if (auto* Existing = M.getFunction("__obf_antidebug_parse_tracer")) return Existing;
	LLVMContext& C = M.getContext();
	Function* Fn = Function::Create(FunctionType::get(Type::getInt1Ty(C),
		{PointerType::getUnqual(C), Type::getInt64Ty(C)}, false),
		GlobalValue::InternalLinkage, "__obf_antidebug_parse_tracer", &M);
	Value* Buffer = Fn->getArg(0);
	Value* Length = Fn->getArg(1);
	auto Block = [&](const char* Name) { return BasicBlock::Create(C, Name, Fn); };
	BasicBlock* Entry = Block("entry");
	BasicBlock* Line = Block("line");
	BasicBlock* Prefix = Block("prefix");
	BasicBlock* Skip = Block("skip");
	BasicBlock* Advance = Block("advance");
	BasicBlock* Space = Block("space");
	BasicBlock* SpaceChar = Block("space.char");
	BasicBlock* SpaceNext = Block("space.next");
	BasicBlock* Digits = Block("digits");
	BasicBlock* DigitChar = Block("digit.char");
	BasicBlock* DigitNext = Block("digit.next");
	BasicBlock* End = Block("end");
	BasicBlock* Miss = Block("miss");
	IRBuilder<> P(Entry);
	P.CreateBr(Line);
	P.SetInsertPoint(Line);
	PHINode* Pos = P.CreatePHI(P.getInt64Ty(), 2, "pos");
	Pos->addIncoming(P.getInt64(0), Entry);
	// 每次只从行首匹配，且先检查长度；不依赖缓冲区终止符。
	P.CreateCondBr(P.CreateICmpUGE(P.CreateSub(Length, Pos), P.getInt64(10)), Prefix, Miss);
	P.SetInsertPoint(Prefix);
	Value* Match = P.getTrue();
	StringRef Field = "TracerPid:";
	for (unsigned I = 0; I < Field.size(); ++I) {
		Value* Ch = P.CreateLoad(P.getInt8Ty(), P.CreateGEP(P.getInt8Ty(), Buffer,
			P.CreateAdd(Pos, P.getInt64(I))));
		Match = P.CreateAnd(Match, P.CreateICmpEQ(Ch, P.getInt8(Field[I])));
	}
	Value* FieldEnd = P.CreateAdd(Pos, P.getInt64(Field.size()));
	P.CreateCondBr(Match, Space, Skip);
	P.SetInsertPoint(Skip);
	PHINode* Scan = P.CreatePHI(P.getInt64Ty(), 2, "scan");
	Scan->addIncoming(Pos, Prefix);
	P.CreateCondBr(P.CreateICmpULT(Scan, Length), Advance, Miss);
	P.SetInsertPoint(Advance);
	Value* Ch = P.CreateLoad(P.getInt8Ty(), P.CreateGEP(P.getInt8Ty(), Buffer, Scan));
	Value* Next = P.CreateAdd(Scan, P.getInt64(1));
	P.CreateCondBr(P.CreateICmpEQ(Ch, P.getInt8('\n')), Line, Skip);
	Scan->addIncoming(Next, Advance);
	Pos->addIncoming(Next, Advance);
	P.SetInsertPoint(Space);
	PHINode* Cursor = P.CreatePHI(P.getInt64Ty(), 2, "cursor");
	Cursor->addIncoming(FieldEnd, Prefix);
	P.CreateCondBr(P.CreateICmpULT(Cursor, Length), SpaceChar, Miss);
	P.SetInsertPoint(SpaceChar);
	Ch = P.CreateLoad(P.getInt8Ty(), P.CreateGEP(P.getInt8Ty(), Buffer, Cursor));
	Value* White = P.CreateOr(P.CreateICmpEQ(Ch, P.getInt8(' ')),
		P.CreateICmpEQ(Ch, P.getInt8('\t')));
	P.CreateCondBr(White, SpaceNext, Digits);
	P.SetInsertPoint(SpaceNext);
	Next = P.CreateAdd(Cursor, P.getInt64(1));
	P.CreateBr(Space);
	Cursor->addIncoming(Next, SpaceNext);
	P.SetInsertPoint(Digits);
	PHINode* DigitPos = P.CreatePHI(P.getInt64Ty(), 2, "digit.pos");
	PHINode* Nonzero = P.CreatePHI(P.getInt1Ty(), 2, "nonzero");
	DigitPos->addIncoming(Cursor, SpaceChar);
	Nonzero->addIncoming(P.getFalse(), SpaceChar);
	P.CreateCondBr(P.CreateICmpULT(DigitPos, Length), DigitChar, End);
	P.SetInsertPoint(DigitChar);
	Ch = P.CreateLoad(P.getInt8Ty(), P.CreateGEP(P.getInt8Ty(), Buffer, DigitPos));
	Value* IsDigit = P.CreateAnd(P.CreateICmpUGE(Ch, P.getInt8('0')),
		P.CreateICmpULE(Ch, P.getInt8('9')));
	P.CreateCondBr(IsDigit, DigitNext, End);
	P.SetInsertPoint(DigitNext);
	Next = P.CreateAdd(DigitPos, P.getInt64(1));
	Value* HasNonzero = P.CreateOr(Nonzero, P.CreateICmpNE(Ch, P.getInt8('0')));
	P.CreateBr(Digits);
	DigitPos->addIncoming(Next, DigitNext);
	Nonzero->addIncoming(HasNonzero, DigitNext);
	P.SetInsertPoint(End);
	P.CreateRet(Nonzero);
	P.SetInsertPoint(Miss);
	P.CreateRet(P.getFalse());
	return Fn;
}

Value* emitTracerPid(IRBuilder<>& B, const AntiDebugSymbols& S, AllocaInst* Buffer) {
	Value* Path = B.CreateGlobalString("/proc/self/status", "obf.ad.status");
	Value* FD = B.CreateCall(S.Open, {Path, B.getInt32(0)}, "obf.ad.fd");
	Value* N = B.CreateCall(S.Read, {FD, Buffer, B.getInt64(4095)}, "obf.ad.n");
	B.CreateCall(S.Close, {FD});
	// 读取失败按空输入处理，读取长度必须限制在实际缓冲区内。
	Value* Positive = B.CreateSelect(B.CreateICmpSGT(N, B.getInt64(0)), N, B.getInt64(0));
	Value* Length = B.CreateSelect(B.CreateICmpUGT(Positive, B.getInt64(4095)),
		B.getInt64(4095), Positive);
	return B.CreateCall(getOrCreateTracerParser(*B.GetInsertBlock()->getModule()),
		{Buffer, Length}, "obf.ad.tracer");
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

GlobalVariable* llvm::getOrCreateAntiDebugResponse(Module& M, const AntiDebugConfig& Cfg) {
	LLVMContext& C = M.getContext();
	std::string Name = "__obf_antidebug_response" + configSuffix(Cfg);
	if (auto* Existing = M.getGlobalVariable(Name, true))
		return Existing;
	return new GlobalVariable(M, Type::getInt32Ty(C), false,
		GlobalValue::InternalLinkage, ConstantInt::get(Type::getInt32Ty(C), 0),
		Name);
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
	GlobalVariable* Response = getOrCreateAntiDebugResponse(M, Cfg);
	if (Cfg.dynamic) {
		GlobalVariable* State = getOrCreateMonitorState(M, Cfg);
		Function* Monitor = getOrCreateMonitor(M, Cfg, State, Response, S);
		createMonitorCtor(M, State, Monitor, Response, S);
	}
	BasicBlock* Entry = &F.getEntryBlock();
	IRBuilder<> B(&*Entry->getFirstInsertionPt());
	Value* Detected = B.getFalse();
	// ptrace 配置兼容为只读 tracer 检测，不改变父子进程的跟踪/信号关系。
	if (Cfg.tracerPid || Cfg.ptrace)
		Detected = B.CreateOr(Detected, emitTracerPid(B, S), "obf.ad.any");
	if (Cfg.maps) Detected = B.CreateOr(Detected, emitMaps(B, S), "obf.ad.any");
	if (Cfg.timing) Detected = B.CreateOr(Detected, emitTiming(B, S, Cfg.thresholdNs), "obf.ad.any");
	B.CreateAtomicRMW(AtomicRMWInst::Or, Response, B.CreateZExt(Detected, B.getInt32Ty()),
		MaybeAlign(4), AtomicOrdering::Monotonic);
	if (!Cfg.responseCorrupt) return true;
	BasicBlock* Body = Entry->splitBasicBlock(B.GetInsertPoint(), "obf.ad.body");
	Entry->getTerminator()->eraseFromParent();
	IRBuilder<> Guard(Entry);
	Value* Flag = Guard.CreateLoad(Type::getInt32Ty(M.getContext()), Response, "obf.ad.response");
	cast<LoadInst>(Flag)->setAtomic(AtomicOrdering::Monotonic);
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
