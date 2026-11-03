#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/ADT/Twine.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Alignment.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/Local.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

#include "llvm/Transforms/Obfuscator/VMPass_Impl.h"
#include "llvm/Transforms/Obfuscator/VMPass_ISA.h"
#include "llvm/Transforms/Obfuscator/VMPass_Emitter.h"
#include "llvm/Transforms/Obfuscator/ObfuscationOptions.h"
#include "llvm/Transforms/Obfuscator/Utils.h"
#include "llvm/Transforms/Obfuscator/Rng.h"
#include "llvm/Transforms/Obfuscator/VMTargetEncoding.h"
#include "llvm/Transforms/Obfuscator/VMWhiteBoxAES.h"

#include <functional>
using namespace llvm;

#define DEBUG_TYPE "vm"



void VMImpl::buildHandlerTable() {
	// table is [OP_COUNT*K + 1 x ptr] (+ OP_COUNT more when encDispatch is
	// on).  Slots [P*K .. P*K+K-1] hold the K variant BlockAddress entries
	// for physical opcode P (M1: intra-function handler-variant dispatch --
	// all K variant bodies are reachable per opcode; vm.fetch selects one at
	// runtime from (ip, salt)).  Slot [OP_COUNT*K] holds the engine function
	// pointer — the wrapper loads it and makes an indirect call, breaking
	// static call-site xref analysis.
	//
	// NOTE: The pointer is stored unmasked here because LLVM 21 does not
	// support xor(ptrtoint) in constant-expression global initialisers.
	// The handler table already contains many blockaddress(@__vm_engine,...)
	// entries so one more raw ptr adds no new information for the analyst.
	// (constant blinding) will obfuscate the wrapper's runtime
	// load path so the connection is not trivially visible in the wrapper.
	// In shared engine mode, OpcBB[] lives in vm_engine.
	VMEngine::SharedState* SS =
		SharedEngineMode ? VMEngine::getSharedState(M, EngineId) : nullptr;
	Function* BAFn = SharedEngineMode ? SS->EngineFn : &F;
	unsigned K = SharedEngineMode ? SS->NumVariants : NumVariants;
	bool ED = SharedEngineMode ? SS->EncDispatch : EncDispatch;
	// M3: decoy slot count for this engine (0 = off / nestedVM, mirrors K).
	unsigned Nd = SharedEngineMode ? SS->NumDecoys : NumDecoys;

	// P2: table size grows to hold the encrypted dispatch map (dmap) when
	// encDispatch is on. M1: base size grows from OP_COUNT+1 to OP_COUNT*K+1.
	// M3: Nd more slots appended past the dmap (or past the engine-ptr slot
	// when encDispatch is off) for decoy blockaddresses. At K==1, Nd==0 this
	// is byte-identical to pre-M1 (TableSize == OP_COUNT+1).
	unsigned TableSize = OP_COUNT * K + 1u + (ED ? OP_COUNT : 0u) + Nd;
	SmallVector<Constant*, 128> Es;
	Es.resize(TableSize, nullptr);

	// P2: secondary Fisher-Yates permutation of handler table slots (P-space).
	// Identity when encDispatch is off (dormant, no RNG consumption).
	uint8_t DispPerm[OP_COUNT];
	for (unsigned i = 0; i < OP_COUNT; ++i) DispPerm[i] = (uint8_t)i;
	if (ED) {
		auto DR = R.fork("vm.disp.perm");
		for (unsigned i = OP_COUNT - 1; i > 0; --i) {
			unsigned j = DR.range(i + 1);
			uint8_t t = DispPerm[i]; DispPerm[i] = DispPerm[j]; DispPerm[j] = t;
		}
	}

	for (unsigned L = 0; L < OP_COUNT; ++L) {
		unsigned P = (unsigned)OpMap.encode((VMOp)L);
		assert(P < OP_COUNT && "opcode map out of range");
		unsigned PermP = DispPerm[P];               // identity when ED off
		for (unsigned v = 0; v < K; ++v) {
			BasicBlock* HB = SharedEngineMode ? SS->OpcBB[L][v] : OpcBB[L][v];
			if (!HB) HB = SharedEngineMode ? SS->Invalid : InvalidBB;
			assert(HB && "missing opcode handler variant and invalid block");
			Es[PermP * K + v] = BlockAddress::get(BAFn, HB);
		}
	}
	for (unsigned i = 0; i < OP_COUNT * K; ++i)
		assert(Es[i] && "unfilled handler table slot");

	// engine pointer in slot [OP_COUNT*K]
	{
		Function* EngFn = M.getFunction(VMEngine::vmEngineName(EngineId));
		assert(EngFn && "vm_engine must exist before building handler table");
		Es[OP_COUNT * K] = EngFn;
	}

	// P2: encrypted dispatch map (dmap) occupies slots
	// [OP_COUNT*K+1 .. OP_COUNT*K+OP_COUNT]. dmap[P] = DispPerm[P] XOR
	// SaltConst (semantics UNCHANGED from pre-M1 -- still indexed per-P;
	// vm.fetch multiplies the decoded value by K after decrypt), stored as
	// an inttoptr constant expr (LLVM allows ConstantExpr::getIntToPtr in
	// global initializers; ptrtoint recovers the integer at runtime).
	if (ED) {
		for (unsigned P = 0; P < OP_COUNT; ++P) {
			uint64_t enc = (uint64_t)((uint32_t)DispPerm[P] ^ SaltConst);
			Es[OP_COUNT * K + 1 + P] =
				ConstantExpr::getIntToPtr(ConstantInt::get(I64Ty, enc), PtrTy);
		}
	}

	// M3: decoy blockaddresses occupy the tail Nd slots, past the dmap (or
	// past the engine-ptr slot when encDispatch is off). Never referenced by
	// vm.fetch/emitThreadedTail (P is clamped mod OP_COUNT before indexing),
	// so these slots exist purely for a static lifter to trip over.
	{
		unsigned DecoyBase = OP_COUNT * K + 1u + (ED ? OP_COUNT : 0u);
		BasicBlock* const* DBB = SharedEngineMode ? SS->DecoyBB.data() : DecoyBB.data();
		for (unsigned i = 0; i < Nd; ++i) {
			assert(DBB[i] && "missing decoy handler block");
			Es[DecoyBase + i] = BlockAddress::get(BAFn, DBB[i]);
		}
	}

	for (unsigned i = 0; i < TableSize; ++i)
		assert(Es[i] && "unfilled handler table slot (incl. dmap/decoys)");
	if (Cfg.encodedTargets) {
		SmallVector<bool, 128> Encode(TableSize, true);
		Encode[OP_COUNT * K] = false;
		for (unsigned P = 0; ED && P < OP_COUNT; ++P) Encode[OP_COUNT * K + 1 + P] = false;
		Constant* Eng = Es[OP_COUNT * K];
		Es[OP_COUNT * K] = ConstantPointerNull::get(cast<PointerType>(PtrTy));
		GVHandlers = buildVMTargetDescriptor(M, Es, Encode, VMTargetFormat::HandlerRole,
			R.fork("vm.targets.handler").u64(), F.getName() + ".vm.targets");
		GVEngineTarget = buildVMTargetDescriptor(M, {Eng}, {true}, VMTargetFormat::EngineRole,
			R.fork("vm.targets.engine").u64(), F.getName() + ".vm.engine.target");
		return;
	}

	auto* ATy = ArrayType::get(PtrTy, TableSize);
	GVHandlers = new GlobalVariable(M, ATy, true, GlobalValue::PrivateLinkage,
		ConstantArray::get(ATy, Es), (F.getName() + ".vm.ophandlers").str());
	GVHandlers->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
}


// buildDispatch 
// vm.dispatch: bounds-check IP  vm.fetch: fetch opcode  decrypt  indirectbr

void VMImpl::buildDispatch() {
	if (ThreadedDispatch) {
		// No central vm.dispatch/vm.fetch pair: ExitBB and every OpcBB
		// placeholder were already created before buildOpcodeHandlers() ran
		// (see populateVMEngine), so every handler's own inlined tail
		// (nextInsn -> emitThreadedTail) could reference the full successor
		// set as it was built. All that remains is wiring vm.entry to fetch
		// the first instruction, same as any other handler's back-edge.
		if (Entry && !llvm::obf::hasTerminatorCompat(Entry)) {
			IRBuilder<> EB(Entry);
			nextInsn(EB);
		}
		return;
	}

	// ExitBB is new; Dispatch is the shell already created in run()
	ExitBB = BasicBlock::Create(Ctx, "vm.exit", HFn);
	auto* FetchBB = BasicBlock::Create(Ctx, "vm.fetch", HFn);

	new UnreachableInst(Ctx, ExitBB);

	//  vm.dispatch: bounds check 
	{
		IRBuilder<> B(Dispatch);
		auto* IP = B.CreateLoad(I32Ty, VMIP, "vm.ip.d"); IP->setVolatile(true);
		Value* BCLen = EffBCLen ? EffBCLen
			: (Value*)B.getInt32((uint32_t)E.BC.size());
		Value* OOB = B.CreateICmpUGE(IP, BCLen, "vm.oob");
		B.CreateCondBr(OOB, ExitBB, FetchBB);
	}

	//  vm.fetch: load opcode, decrypt, dispatch 
	{
		IRBuilder<> B(FetchBB);
		auto* IP = B.CreateLoad(I32Ty, VMIP, "vm.ip.f"); IP->setVolatile(true);
		Value* Raw = loadBC(B, IP, 0, "vm.raw");

		// loadBC() already decrypts when EncBytecode=1
		Value* OpB = Raw;

		// keyedDispatch: un-XOR the per-IP opcode key applied by
		// BytecodeEmitter::bop() at write time, before mapping the byte to a
		// permuted opcode index.
		if (KeyedDispatch) {
			auto* SaltL = B.CreateLoad(I32Ty, EffSalt, "vm.opk.salt"); SaltL->setVolatile(true);
			OpB = B.CreateXor(OpB, opKeyByteIR(B, SaltL, IP, "vm.opk"), "vm.opd");
		}

		// Advance IP past opcode byte
		B.CreateStore(B.CreateAdd(IP, B.getInt32(1), "vm.ip1"), VMIP)->setVolatile(true);

		// Demand-mode opcode-domain check: the decoded opcode byte must be a
		// valid handler index [0,OP_COUNT). No modulo clamp -- an out-of-domain
		// opcode (corrupted/forged bytecode) branches to the trap block and
		// faults instead of being folded back into a valid handler. The table
		// lookup lives in vm.lookup, AFTER this branch.
		Value* OIdx = B.CreateZExt(OpB, I32Ty, "vm.oidx");
		Value* Invalid = B.CreateICmpUGE(OIdx, B.getInt32(OP_COUNT), "vm.op.invalid");
		BasicBlock* LookupBB = BasicBlock::Create(Ctx, "vm.lookup", HFn);
		B.CreateCondBr(Invalid, InvalidBB, LookupBB);

		//  vm.lookup: table lookup + indirect dispatch
		IRBuilder<> LB(LookupBB);
		// The opcode byte is already in [0,OP_COUNT) -- use it verbatim as the
		// P-space index (no URem).
		Value* P = OIdx;

		// P2: route through the encrypted dispatch map (dmap) when encDispatch
		// is on. dmap lives at handlers[OP_COUNT*K+1 + P] (M1: base table grew
		// to OP_COUNT*K slots); decrypt with the runtime salt to recover the
		// permuted P-space slot (semantics unchanged -- runtime multiplies by
		// NumVariants below, after decode).
		Value* FinalSlot;
		if (EncDispatch) {
			Value* DmIdx  = LB.CreateAdd(P,
				LB.getInt32(OP_COUNT * NumVariants + 1), "vm.dm.i");
			Value* DmPtr = Cfg.encodedTargets ? emitVMTargetRecord(LB, EffHandlers, DmIdx) : LB.CreateGEP(PtrTy, EffHandlers, DmIdx, "vm.dm.p");
			Value* DmRaw  = LB.CreateLoad(PtrTy, DmPtr, "vm.dm.raw");
			Value* DmInt  = LB.CreateTrunc(
								LB.CreatePtrToInt(DmRaw, I64Ty, "vm.dm.i64"),
								I32Ty, "vm.dm.i32");
			auto*  SaltL  = LB.CreateLoad(I32Ty, EffSalt, "vm.dm.salt");
			SaltL->setVolatile(true);
			Value* Dec    = LB.CreateXor(DmInt, SaltL, "vm.dm.dec");
			FinalSlot     = Dec;
		} else {
			FinalSlot = P;
		}

		// M1: intra-function handler-variant dispatch. Table is now laid
		// out [P*K + v] per opcode; select v at runtime from (ip, salt) so
		// different dispatches of the same opcode can reach different
		// variant bodies. Guarded on NumVariants > 1 -- emits no new IR and
		// leaves the GEP consuming FinalSlot verbatim when K==1 (identity,
		// byte-identical to pre-M1).
		//
		// Uses the raw incoming "salt" ARGUMENT (HFn->getArg(kParamSalt)),
		// not a load from EffSalt/SS->EngineSalt: hardenVMEngine()'s RDTSC
		// handler-timing traps XOR-poison that alloca on a suspected debugger
		// (a documented, load-sensitive false-positive risk). Pre-M1, nothing
		// in this code path read that alloca unless keyedDispatch/encDispatch
		// (opt-in, off by default) were on, so a false trip was control-flow
		// inert here. Reading it for vsel would make EVERY default VM build
		// (handlerVariants=3) newly control-flow-sensitive to that flake.
		// The argument SSA value is immutable and dominates the whole
		// function, so it is never affected by the poison store.
		Value* TableSlot = FinalSlot;
		if (NumVariants > 1) {
			Value* SaltL = HFn->getArg(VMEngine::kParamSalt);
			Value* Mix = LB.CreateXor(
				LB.CreateMul(IP, LB.getInt32(0x9E3779B1u), "vm.vs.mul"),
				LB.CreateLShr(SaltL, LB.getInt32(3), "vm.vs.shr"),
				"vm.vs.mix");
			Value* VSel = LB.CreateURem(Mix, LB.getInt32(NumVariants), "vm.vs.sel");
			TableSlot = LB.CreateAdd(
				LB.CreateMul(FinalSlot, LB.getInt32(NumVariants), "vm.vs.base"),
				VSel, "vm.vs.slot");
		}

		// cloudDispatch: 云值驱动的动态 offset。合法云值下运行时返回 0，
		// TableSlot 不变；过期/错误/缺失云值下返回非 0（最高 VM_DISPATCH_OFFSET_MASK），
		// 把 handler 表索引推离有效区，indirectbr 到非法地址自然崩溃。
		// 本地不做任何范围/时效判断——越界即崩是解码的天然后果。
		if (CloudDispatch) {
			FunctionCallee OffsetFn = M.getOrInsertFunction(
				"__zone_get_dispatch_offset",
				FunctionType::get(I64Ty, {}, false));
			Value* Off64 = LB.CreateCall(OffsetFn, {}, "vm.zone.off64");
			Value* Off = LB.CreateTrunc(Off64, I32Ty, "vm.zone.off");
			TableSlot = LB.CreateAdd(TableSlot, Off, "vm.zone.slot");
		}

		// GEP into handler table[table_slot]
		Value* Slot = LB.CreateGEP(PtrTy, EffHandlers, TableSlot, "vm.ohsl");
		Value* Hndl = Cfg.encodedTargets ? emitVMTargetLoad(LB, EffHandlers, TableSlot, EffHandlers, "vm.hndl") : LB.CreateLoad(PtrTy, Slot, "vm.hndl");

		// indirectbr with all opcode blocks (all variants) declared as successors
		IndirectBrInst* IBR = LB.CreateIndirectBr(Hndl, OP_COUNT * NumVariants + 1);
		for (unsigned i = 0; i < OP_COUNT; ++i)
			for (unsigned v = 0; v < NumVariants; ++v)
				IBR->addDestination(OpcBB[i][v] ? OpcBB[i][v] : InvalidBB);
		IBR->addDestination(ExitBB);
	}

	// Terminate vm.entry with branch to vm.dispatch
	if (Entry && !llvm::obf::hasTerminatorCompat(Entry)) {
		IRBuilder<> EB(Entry);
		nextInsn(EB);
	}
}


// emitThreadedTail / nextInsn
// threadedDispatch: inline the fetch/decode/indirectbr sequence into every
// handler's own back-edge instead of routing through one shared vm.dispatch/
// vm.fetch pair. Mirrors buildDispatch()'s central logic exactly, just
// emitted per call-site: a bounds check in the caller's current block,
// followed by a private continuation block holding the fetch/decode/
// indirectbr. Requires ExitBB and every OpcBB[i][v] to already exist (see
// populateVMEngine's pre-creation pass) since the first handler built may
// dispatch to the last one.

void VMImpl::emitThreadedTail(IRBuilder<>& B) {
	auto* IP = B.CreateLoad(I32Ty, VMIP, "vm.ip.d"); IP->setVolatile(true);
	Value* BCLen = EffBCLen ? EffBCLen
		: (Value*)B.getInt32((uint32_t)E.BC.size());
	Value* OOB = B.CreateICmpUGE(IP, BCLen, "vm.oob");

	BasicBlock* ContBB = BasicBlock::Create(Ctx, "vm.next", HFn);
	B.CreateCondBr(OOB, ExitBB, ContBB);

	IRBuilder<> FB(ContBB);
	auto* IP2 = FB.CreateLoad(I32Ty, VMIP, "vm.ip.f"); IP2->setVolatile(true);
	Value* Raw = loadBC(FB, IP2, 0, "vm.raw");

	// loadBC() already decrypts when EncBytecode=1
	Value* OpB = Raw;

	// keyedDispatch: un-XOR the per-IP opcode key applied by
	// BytecodeEmitter::bop() at write time, before mapping the byte to a
	// permuted opcode index. Mirrors buildDispatch()'s vm.fetch logic exactly.
	if (KeyedDispatch) {
		auto* SaltL = FB.CreateLoad(I32Ty, EffSalt, "vm.opk.salt"); SaltL->setVolatile(true);
		OpB = FB.CreateXor(OpB, opKeyByteIR(FB, SaltL, IP2, "vm.opk"), "vm.opd");
	}

	// Advance IP past opcode byte
	FB.CreateStore(FB.CreateAdd(IP2, FB.getInt32(1), "vm.ip1"), VMIP)->setVolatile(true);

	// Demand-mode opcode-domain check (mirrors buildDispatch): out-of-domain
	// opcodes branch to the trap block instead of being modulo-clamped.
	Value* OIdx = FB.CreateZExt(OpB, I32Ty, "vm.oidx");
	Value* Invalid = FB.CreateICmpUGE(OIdx, FB.getInt32(OP_COUNT), "vm.op.invalid");
	BasicBlock* LookupBB = BasicBlock::Create(Ctx, "vm.lookup", HFn);
	FB.CreateCondBr(Invalid, InvalidBB, LookupBB);

	IRBuilder<> LB(LookupBB);
	// Opcode byte is already in [0,OP_COUNT) -- use verbatim (no URem).
	Value* P = OIdx;

	// P2: route through the encrypted dispatch map (dmap) when encDispatch
	// is on -- mirrors buildDispatch()'s vm.fetch logic exactly.
	Value* FinalSlot;
	if (EncDispatch) {
		Value* DmIdx = LB.CreateAdd(P,
			LB.getInt32(OP_COUNT * NumVariants + 1), "vm.dm.i");
		Value* DmPtr = Cfg.encodedTargets ? emitVMTargetRecord(LB, EffHandlers, DmIdx) : LB.CreateGEP(PtrTy, EffHandlers, DmIdx, "vm.dm.p");
		Value* DmRaw = LB.CreateLoad(PtrTy, DmPtr, "vm.dm.raw");
		Value* DmInt = LB.CreateTrunc(
							LB.CreatePtrToInt(DmRaw, I64Ty, "vm.dm.i64"),
							I32Ty, "vm.dm.i32");
		auto*  SaltL = LB.CreateLoad(I32Ty, EffSalt, "vm.dm.salt");
		SaltL->setVolatile(true);
		Value* Dec   = LB.CreateXor(DmInt, SaltL, "vm.dm.dec");
		FinalSlot    = Dec;
	} else {
		FinalSlot = P;
	}

	// M1: intra-function handler-variant dispatch -- mirrors buildDispatch()'s
	// vm.fetch logic exactly. Guarded on NumVariants > 1; identity (no new
	// IR, GEP consumes FinalSlot verbatim) when K==1. Uses the raw incoming
	// "salt" ARGUMENT, not a load from EffSalt/SS->EngineSalt -- see the
	// comment in buildDispatch()'s vm.fetch for why (RDTSC handler-trap
	// false-positive poisoning of that alloca).
	Value* TableSlot = FinalSlot;
	if (NumVariants > 1) {
		Value* SaltL = HFn->getArg(VMEngine::kParamSalt);
		Value* Mix = LB.CreateXor(
			LB.CreateMul(IP2, LB.getInt32(0x9E3779B1u), "vm.vs.mul"),
			LB.CreateLShr(SaltL, LB.getInt32(3), "vm.vs.shr"),
			"vm.vs.mix");
		Value* VSel = LB.CreateURem(Mix, LB.getInt32(NumVariants), "vm.vs.sel");
		TableSlot = LB.CreateAdd(
			LB.CreateMul(FinalSlot, LB.getInt32(NumVariants), "vm.vs.base"),
			VSel, "vm.vs.slot");
	}

	// cloudDispatch: 云值驱动的动态 offset（threadedDispatch 版本，语义同 buildDispatch）
	if (CloudDispatch) {
		FunctionCallee OffsetFn = M.getOrInsertFunction(
			"__zone_get_dispatch_offset",
			FunctionType::get(I64Ty, {}, false));
		Value* Off64 = LB.CreateCall(OffsetFn, {}, "vm.zone.off64");
		Value* Off = LB.CreateTrunc(Off64, I32Ty, "vm.zone.off");
		TableSlot = LB.CreateAdd(TableSlot, Off, "vm.zone.slot");
	}

	// GEP into handler table[table_slot]
	Value* Slot = LB.CreateGEP(PtrTy, EffHandlers, TableSlot, "vm.ohsl");
	Value* Hndl = Cfg.encodedTargets ? emitVMTargetLoad(LB, EffHandlers, TableSlot, EffHandlers, "vm.hndl") : LB.CreateLoad(PtrTy, Slot, "vm.hndl");

	// indirectbr with all opcode blocks (all variants) declared as successors
	IndirectBrInst* IBR = LB.CreateIndirectBr(Hndl, OP_COUNT * NumVariants + 2);
	for (unsigned i = 0; i < OP_COUNT; ++i)
		for (unsigned v = 0; v < NumVariants; ++v)
			IBR->addDestination(OpcBB[i][v]);
	IBR->addDestination(InvalidBB);
	IBR->addDestination(ExitBB);
}


void VMImpl::nextInsn(IRBuilder<>& B) {
	if (ThreadedDispatch) emitThreadedTail(B);
	else B.CreateBr(Dispatch);
}




// ============================================================================
// SharedState management + vm_engine shell + engine population
// ============================================================================

#include <mutex>

namespace {
	static std::mutex SharedStateMu;
	// Keyed by (Module*, EngineId): EngineId 0 = plain engine, 1 = nesting
	// engine. Each key gets its own independent SharedState, so the two
	// engines' "first function populates" guards can never cross-contaminate.
	static DenseMap<std::pair<Module*, unsigned>, std::unique_ptr<VMEngine::SharedState>> SharedStateMap;
}


namespace llvm {
	namespace VMEngine {

		static constexpr const char* kPopulatedMDKey = "obf.vm.engine.populated";

		Function* getOrBuildVMEngine(Module& M, unsigned EngineId) {
			// Lookup only — returns null if not yet created.
			// populateVMEngine() handles atomic creation + population.
			if (Function* Existing = M.getFunction(vmEngineName(EngineId))) {
				assert((Existing->arg_size() == kNumParams ||
					Existing->arg_size() == kNumParams + 1) &&
					"vm_engine parameter count mismatch");
				return Existing;
			}
			return nullptr;
		}

		bool isEnginePopulated(Function* VMEngineFunc) {
			if (!VMEngineFunc) return false;
			MDNode* MD = VMEngineFunc->getMetadata(kPopulatedMDKey);
			if (!MD || MD->getNumOperands() == 0) return false;
			auto* CAM = dyn_cast<ConstantAsMetadata>(MD->getOperand(0));
			if (!CAM) return false;
			auto* CI = dyn_cast<ConstantInt>(CAM->getValue());
			return CI && CI->isOne();
		}

		void markEnginePopulated(Function* VMEngineFunc) {
			if (!VMEngineFunc) return;
			LLVMContext& C = VMEngineFunc->getContext();
			MDNode* TrueMD = MDNode::get(C, {
				ConstantAsMetadata::get(ConstantInt::getTrue(C))
				});
			VMEngineFunc->setMetadata(kPopulatedMDKey, TrueMD);
		}

		SharedState* getSharedState(Module& M, unsigned EngineId) {
			std::lock_guard<std::mutex> LK(SharedStateMu);
			auto& Ptr = SharedStateMap[{&M, EngineId}];
			if (!Ptr) Ptr = std::make_unique<SharedState>();
			return Ptr.get();
		}

		void releaseSharedState(Module& M) {
			std::lock_guard<std::mutex> LK(SharedStateMu);
			SmallVector<std::pair<Module*, unsigned>, 4> ToErase;
			for (auto& KV : SharedStateMap)
				if (KV.first.first == &M) ToErase.push_back(KV.first);
			for (auto& K : ToErase) SharedStateMap.erase(K);
		}

	} // namespace VMEngine
} // namespace llvm


// setupEffLocal: point Eff* at per-function allocas/globals

void VMImpl::setupEffLocal() {
	HFn = &F;
	EffBC = ((EncBytecode || Cfg.usesCloudMaterial()) && GVBytecodeRT)
		? (Value*)GVBytecodeRT : (Value*)GVBytecode;
	EffBCLen = nullptr;
	EffSalt = VMSalt;
	EffRegs = VMRegs;
	EffRegs64 = VMRegs64;
	EffFregs = VMFregs;
	EffPregs = VMPRegs;
	EffCallees = GVCallees;
	EffFTyIndices = GVFTyIndices;
	EffHandlers = GVHandlers;
	MaskVR = ConstantInt::get(I32Ty, NVRAlloc > 0 ? NVRAlloc - 1 : 0);
	MaskVR64 = ConstantInt::get(I32Ty, NVR64Alloc > 0 ? NVR64Alloc - 1 : 0);
	MaskFR = ConstantInt::get(I32Ty, NFRAlloc > 0 ? NFRAlloc - 1 : 0);
	MaskPR = ConstantInt::get(I32Ty, NPRAlloc > 0 ? NPRAlloc - 1 : 0);
	// local mode never encrypts registers (no engine params)
	EffRegKeys = nullptr;
	EffReg64Keys = nullptr;
	EffFRegKeys = nullptr;
	EffCalleeMask = nullptr;  // no callee masking in local mode
	EffLazyCtx = nullptr;    // local mode never uses lazy AES fetch
	SharedEngineMode = false;
}


// populateVMEngine: build all handlers inside shared vm_engine 

void VMImpl::populateVMEngine() {
	auto* SS = VMEngine::getSharedState(M, EngineId);
	if (SS->Populated) return;

	// Create __vm_engine AND populate it atomically 
	// The function must never be visible to LLVM infrastructure as an
	// empty declaration — MSVC debug ilist sentinel assertions fire when
	// anything iterates an empty basic block list.  We create the function
	// and immediately start adding blocks in the same C++ scope.

	FunctionType* FTy = VMEngine::getVMEngineFunctionType(Ctx, LazyDecrypt);
	Function* EF = Function::Create(FTy, GlobalValue::InternalLinkage,
		VMEngine::vmEngineName(EngineId), &M);

	// CRITICAL: Create the entry block IMMEDIATELY after Function::Create.
	// The function must never be observable with an empty block list —
	// MSVC debug builds assert on ilist sentinel dereference if anything
	// (pass manager, analysis invalidation) iterates an empty function.
	BasicBlock* EngEntry = BasicBlock::Create(Ctx, "vm.entry", EF);

	{
		unsigned PIdx = 0;
		static const char* const PNames[] = {
			"bc", "bc_len", "regs", "regs64", "fregs", "pregs",
			"callees", "salt", "regMask", "reg64Mask", "fregMask", "pregMask",
			"handlers", "fty_indices",
			"regkeys", "reg64keys", "fregkeys",
			"callee_mask",
			"ret_storage", "ret_kind",
			"lazyctx",
		};
		for (Argument& A : EF->args()) A.setName(PNames[PIdx++]);
	}
	EF->addFnAttr(Attribute::NoUnwind);
	EF->addFnAttr(Attribute::NoInline);
	EF->addFnAttr(Attribute::OptimizeNone);
	EF->setUnnamedAddr(GlobalValue::UnnamedAddr::None);
	llvm::obf::markObfGenerated(*EF);
	SS->EngineFn = EF;



	// Set up Eff* to point at vm_engine parameters
	HFn = EF;
	SharedEngineMode = true;

	EffBC = EF->getArg(VMEngine::kParamBC);
	EffBCLen = EF->getArg(VMEngine::kParamBCLen);
	EffRegs = EF->getArg(VMEngine::kParamRegs);
	EffRegs64 = EF->getArg(VMEngine::kParamRegs64);
	EffFregs = EF->getArg(VMEngine::kParamFregs);
	EffPregs = EF->getArg(VMEngine::kParamPregs);
	EffCallees = EF->getArg(VMEngine::kParamCallees);
	EffHandlers = EF->getArg(VMEngine::kParamHandlers);
	EffFTyIndices = EF->getArg(VMEngine::kParamFTyIndices);
	MaskVR = EF->getArg(VMEngine::kParamRegMask);
	MaskVR64 = EF->getArg(VMEngine::kParamReg64Mask);
	MaskFR = EF->getArg(VMEngine::kParamFregMask);
	MaskPR = EF->getArg(VMEngine::kParamPregMask);
	// key array pointers (null when regEncrypt is off)
	EffRegKeys = EF->getArg(VMEngine::kParamRegKeys);
	EffReg64Keys = EF->getArg(VMEngine::kParamReg64Keys);
	EffFRegKeys = EF->getArg(VMEngine::kParamFRegKeys);
	EffCalleeMask = EF->getArg(VMEngine::kParamCalleeMask);
	EffRetStorage = EF->getArg(VMEngine::kParamRetStorage);
	EffRetKind = EF->getArg(VMEngine::kParamRetKind);
	EffLazyCtx = LazyDecrypt ? EF->getArg(VMEngine::kParamLazyCtx) : nullptr;

	// lazyDecrypt: forward-declare the runtime keystream helper so the fetch
	// path (loadBC/loadBCDyn, built below) can call it. buildEncryptCtor()
	// links the AES stub bitcode (which defines this symbol) later, for the
	// founding function's own ctor — the linker resolves this declaration
	// against that definition.
	if (LazyDecrypt) {
		KeystreamFn = Cfg.whiteboxAES ? getVMWhiteBoxCTRFunction(M) : M.getFunction("__obf_aes_ctr_keystream_block");
		if (!KeystreamFn) {
			FunctionType* KSFTy = FunctionType::get(Type::getVoidTy(Ctx),
				{ PtrTy, PtrTy, I32Ty, PtrTy }, /*isVarArg=*/false);
			KeystreamFn = Function::Create(KSFTy, GlobalValue::ExternalLinkage,
				"__obf_aes_ctr_keystream_block", &M);
		}
	}

	// Build vm.entry with VMIP + salt alloca
	Entry = EngEntry;  // already created above
	IRBuilder<> EB(Entry);
	VMIP = EB.CreateAlloca(I32Ty, nullptr, "vm.ip");
	AllocaInst* SaltAlloca = EB.CreateAlloca(I32Ty, nullptr, "vm.salt");
	EB.CreateStore(EF->getArg(VMEngine::kParamSalt), SaltAlloca)->setVolatile(true);
	EffSalt = SaltAlloca;
	EB.CreateStore(EB.getInt32(0), VMIP)->setVolatile(true);

	SS->EngineVMIP = VMIP;
	SS->EngineSalt = SaltAlloca;
	SS->Entry = Entry;

	// Create Dispatch shell (central-dispatch builds only; threadedDispatch
	// has no shared vm.dispatch/vm.fetch pair -- see buildDispatch()).
	if (!ThreadedDispatch) {
		Dispatch = BasicBlock::Create(Ctx, "vm.dispatch", EF);
		SS->Dispatch = Dispatch;
	}

	// Build all 51 opcode handlers
	InvalidBB = BasicBlock::Create(Ctx, "vm.invalid", EF);
	emitTrapBlock(InvalidBB);
	SS->Invalid = InvalidBB;
	NumVariants = Cfg.handlerVariants;
	if (NumVariants < 1) NumVariants = 1;
	if (NumVariants > kMaxHandlerVariants) NumVariants = kMaxHandlerVariants;
	EncDispatch = Cfg.encDispatch;

	// threadedDispatch: every handler inlines its own fetch/decode/indirectbr
	// tail (see emitThreadedTail()), which needs the FULL successor set --
	// every opcode/variant block plus ExitBB -- before any handler body is
	// built (the first handler emitted may branch to the last one). Pre-create
	// empty placeholder blocks for all of them up front; mkOpc() fills each in
	// (renaming, not reallocating) as buildOpcodeHandlers() reaches it.
	if (ThreadedDispatch) {
		ExitBB = BasicBlock::Create(Ctx, "vm.exit", EF);
		new UnreachableInst(Ctx, ExitBB);
		for (unsigned i = 0; i < OP_COUNT; ++i)
			for (unsigned v = 0; v < NumVariants; ++v) {
				BasicBlock* BB = BasicBlock::Create(Ctx, "vm.opc.pending", EF);
				OpcBB[i][v] = BB;
				VariantOf[BB] = (uint8_t)v;
			}
	}

	buildOpcodeHandlers();

	// threadedDispatch pre-creates a placeholder block for every
	// (opcode, variant) pair, but buildOpcodeHandlers only fills those where
	// needsOpcode() is true (e.g. MULADD/SHLADD/CMPSEL/ANDCMPZ stay empty when
	// superOps is off). Every placeholder is nevertheless listed as an
	// indirectbr destination, so an unfilled one has no terminator and the
	// module fails the verifier ("Basic Block ... does not have terminator").
	// Give each remaining empty placeholder an unreachable: the bytecode
	// emitter never selects a non-needed opcode, so these blocks stay dead.
	if (ThreadedDispatch) {
		for (unsigned i = 0; i < OP_COUNT; ++i)
			for (unsigned v = 0; v < NumVariants; ++v) {
				BasicBlock* BB = OpcBB[i][v];
				if (BB && BB->empty())
					new UnreachableInst(Ctx, BB);
			}
	}

	// Make the K structurally-identical variants distinct (per-variant MBA).
	diversifyHandlerVariants(EF);

	// Make this pool clone's handler bodies distinct from the other engines'
	// (per-clone MBA, seeded by EngineId). No-op unless metamorphicEngines is on.
	metamorphRewriteEngine(EF);

	// M3: static decoy handlers. computeNumDecoys() returns 0 when
	// handlerDecoys==0 or nestedVM==1 -- buildDecoyHandlers() is then a
	// no-op that touches no IR (byte-identical to pre-M3 output).
	NumDecoys = computeNumDecoys();
	buildDecoyHandlers();
	SS->NumDecoys = NumDecoys;
	SS->EngineJunk = EngineJunk;
	SS->DecoyBB.clear();
	for (unsigned i = 0; i < NumDecoys; ++i)
		SS->DecoyBB.push_back(DecoyBB[i]);

	// M4: live decoys. No-op unless handlerDecoys>=2 AND NumDecoys>0 (see
	// wireLiveDecoys' own guard), so handlerDecoys<=1 stays byte-identical.
	wireLiveDecoys(EF);

	SS->NumVariants = NumVariants;
	SS->EncDispatch = EncDispatch;
	SS->LazyMode = LazyDecrypt;
	for (unsigned i = 0; i < OP_COUNT; ++i)
		for (unsigned v = 0; v < NumVariants; ++v)
			SS->OpcBB[i][v] = OpcBB[i][v];

	// Build dispatch loop
	buildDispatch();
	SS->ExitBB = ExitBB;
	// 未列为任何 indirectbr 目标的静态诱饵可能被后端折叠成 blockaddress=1。
	// 保留保守目标集合，正式编码表中的每个诱饵仍必须是真实可执行地址。
	if (NumDecoys) for (BasicBlock& BB : *EF)
		if (auto* IB = dyn_cast<IndirectBrInst>(BB.getTerminator()))
			for (auto* Decoy : DecoyBB) IB->addDestination(Decoy);

	// insert anti-debug timing gate between dispatch and fetch
	buildAntiDebugGate(SS);

	SS->Populated = true;
	SS->FTyCountAtLastBuild = (unsigned)SS->SharedFTys.size();
	VMEngine::markEnginePopulated(EF);
	// Persist the engine witness on the final IR so report generation does not
	// depend on the transient SharedState map after the module pass completes.
	LLVMContext& ReportCtx = EF->getContext();
	EF->setMetadata("obf.vm.engine", MDNode::get(ReportCtx, {
		ConstantAsMetadata::get(ConstantInt::get(Type::getInt32Ty(ReportCtx), EngineId)),
		ConstantAsMetadata::get(ConstantInt::get(Type::getInt32Ty(ReportCtx), SS->NumVariants)),
		ConstantAsMetadata::get(ConstantInt::get(Type::getInt32Ty(ReportCtx), SS->NumDecoys)),
		ConstantAsMetadata::get(ConstantInt::get(Type::getInt32Ty(ReportCtx),
			OP_COUNT * SS->NumVariants + 1 + (SS->EncDispatch ? OP_COUNT : 0) + SS->NumDecoys)),
		ConstantAsMetadata::get(ConstantInt::get(Type::getInt1Ty(ReportCtx), SS->EncDispatch))
	}));
	if (Cfg.operandLayout) EF->setMetadata("obf.vm.layout", MDNode::get(ReportCtx, {
		ConstantAsMetadata::get(ConstantInt::get(Type::getInt32Ty(ReportCtx), VMInstructionLayout::Version)),
		ConstantAsMetadata::get(ConstantInt::get(Type::getInt64Ty(ReportCtx), Layout.fingerprint()))
	}));

	if (Cfg.hardened)
		hardenVMEngine(EF, SS);

	LLVM_DEBUG(dbgs() << "[vm] populated vm_engine with "
		<< OP_COUNT << " handler blocks\n");
	if (ObfVerbose)
		errs() << "[vm] vm_engine populated: " << OP_COUNT << " handlers\n";

	// Restore per-function state
	SharedEngineMode = false;
	HFn = &F;
}




// ensureCallFTyCases: extend CALL switches for new FunctionTypes
//
// Called after buildCalleeGlobal() in each function's run().  If this
// function introduced FunctionTypes not seen when the engine was first
// populated, adds new case blocks to the existing CALL handler switches
// inside __vm_engine.

void VMImpl::ensureCallFTyCases() {
	auto* SS = VMEngine::getSharedState(M, EngineId);
	if (!SS->Populated) return;
	unsigned OldCount = SS->FTyCountAtLastBuild;
	unsigned NewCount = (unsigned)SS->SharedFTys.size();
	if (NewCount <= OldCount) return;

	Function* EF = SS->EngineFn;
	if (!EF) return;

	LLVM_DEBUG(dbgs() << "[vm] extending CALL switches: " << OldCount
		<< " -> " << NewCount << " FunctionTypes\n");

	// For each CALL opcode (indexed by RetKind2 0..4):
	for (unsigned RKIdx = 0; RKIdx < 5; ++RKIdx)
		for (auto& CSW : SS->CallSW[RKIdx])
			for (unsigned TIdx = OldCount; TIdx < NewCount; ++TIdx)
				extendVMCallSwitch(CSW, SS->SharedFTys[TIdx], TIdx, SS->SharedCallAttrs[TIdx]);

	SS->FTyCountAtLastBuild = NewCount;
	if (ObfVerbose && NewCount > OldCount)
		errs() << "[vm] extended CALL handlers: +"
		<< (NewCount - OldCount) << " FunctionTypes\n";
}
