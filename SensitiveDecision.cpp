// ============================================================================
// SensitiveDecision.cpp — validate a sensitive decision boundary before VM.
//
// This pass is name-agnostic: it seeds taint from any non-void call to a
// declaration-only, non-intrinsic function inside the annotated function and
// tracks where that taint flows. It never matches on Zone/OpenSSL/API names.
//
// Diagnostics (stable tokens, used by tests):
//   sensitive result escapes through return
//   sensitive result escapes through store
//   sensitive result escapes to unknown call
//   sensitive result escapes to inline asm
//   sensitive decision has no in-region success/failure branch
// ============================================================================

#include "llvm/Transforms/Obfuscator/SensitiveDecision.h"

#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Metadata.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Obfuscator/FunctionObfContextAnalysis.h"
#include "llvm/Transforms/Obfuscator/ObfuscationAnnotationAnalysis.h"
#include "llvm/Transforms/Obfuscator/Utils.h"

using namespace llvm;

AnalysisKey SensitiveDecisionAnalysis::Key;

namespace {

	// A sensitive source is a non-void call to a declaration-only,
	// non-intrinsic function: i.e. an external verifier/transport result.
	bool isSensitiveSource(const Instruction& I) {
		const auto* CB = dyn_cast<CallBase>(&I);
		if (!CB) return false;
		if (CB->getType()->isVoidTy()) return false;
		const Function* Callee = CB->getCalledFunction();
		if (!Callee) return false;
		if (Callee->isIntrinsic()) return false;
		return Callee->isDeclaration();
	}

	// Resolve a pointer through GEP/bitcast chains to its underlying object.
	Value* stripOffsets(Value* P) {
		while (true) {
			if (auto* GEP = dyn_cast<GetElementPtrInst>(P)) {
				P = GEP->getPointerOperand();
				continue;
			}
			if (auto* BC = dyn_cast<BitCastInst>(P)) {
				P = BC->getOperand(0);
				continue;
			}
			if (auto* ASC = dyn_cast<AddrSpaceCastInst>(P)) {
				P = ASC->getOperand(0);
				continue;
			}
			return P;
		}
	}

	// A provably function-local, non-escaping alloca: every use is a load,
	// store, or address computation. Passing the alloca to a call (or
	// ptrtoint-ing it) makes it escape and disables memory taint.
	AllocaInst* getLocalAlloca(Value* Ptr, Function& F) {
		Value* Obj = stripOffsets(Ptr);
		auto* AI = dyn_cast<AllocaInst>(Obj);
		if (!AI || AI->getFunction() != &F) return nullptr;
		for (const User* U : AI->users()) {
			if (isa<LoadInst>(U) || isa<StoreInst>(U) ||
				isa<GetElementPtrInst>(U) || isa<BitCastInst>(U) ||
				isa<AddrSpaceCastInst>(U))
				continue;
			return nullptr;
		}
		return AI;
	}

} // namespace

bool llvm::validateSensitiveConfig(const ObfuscationConfig& Cfg, std::string* Reason) {
	auto S = Cfg.getPassConfig("sensitive");
	if (!S) return true;
	if (!Cfg.isPassEnabled("vm")) {
		if (Reason) *Reason = "sensitive requires an enabled vm pass";
		return false;
	}
	return true;
}

bool llvm::validateSensitiveDecision(Function& F, const SensitiveDecisionConfig& Cfg,
	SensitiveDecisionAnalysisResult& Out) {
	Out.Enabled = Cfg.enable;
	Out.Strict = Cfg.strict;
	Out.Region = Cfg.region;
	Out.Valid = false;
	Out.Diagnostic.clear();
	Out.Callees.clear();

	if (!Cfg.enable) {
		Out.Valid = true;
		return true;
	}

	SmallPtrSet<Value*, 32> Tainted;
	SmallPtrSet<AllocaInst*, 8> TaintedMem;
	SmallVector<Value*, 32> Worklist;
	SmallVector<AllocaInst*, 8> MemWorklist;

	auto taint = [&](Value* V) {
		if (!V || V->getType()->isVoidTy()) return;
		if (Tainted.insert(V).second) Worklist.push_back(V);
	};

	// Seed from every external verifier result.
	for (BasicBlock& BB : F)
		for (Instruction& I : BB)
			if (isSensitiveSource(I)) {
				Out.Callees.push_back(cast<CallBase>(&I)->getCalledFunction());
				taint(&I);
			}

	bool EscapesReturn = false, EscapesStore = false, EscapesUnknownCall = false;
	bool EscapesInlineAsm = false, HasTaintedBranch = false;

	auto process = [&](Value* V) {
		for (User* U : V->users()) {
			if (auto* CI = dyn_cast<CastInst>(U)) {
				taint(CI);
			}
			else if (auto* Cmp = dyn_cast<CmpInst>(U)) {
				taint(Cmp);
			}
			else if (auto* SI = dyn_cast<SelectInst>(U)) {
				taint(SI);
			}
			else if (auto* PHI = dyn_cast<PHINode>(U)) {
				taint(PHI);
			}
			else if (auto* BO = dyn_cast<BinaryOperator>(U)) {
				if (BO->getType()->isIntegerTy()) taint(BO);
			}
			else if (auto* RI = dyn_cast<ReturnInst>(U)) {
				if (RI->getReturnValue() == V) EscapesReturn = true;
			}
			else if (auto* ST = dyn_cast<StoreInst>(U)) {
				if (ST->getValueOperand() != V) continue;
				if (AllocaInst* AI = getLocalAlloca(ST->getPointerOperand(), F)) {
					if (TaintedMem.insert(AI).second) MemWorklist.push_back(AI);
				}
				else {
					EscapesStore = true;
				}
			}
			else if (auto* CB = dyn_cast<CallBase>(U)) {
				if (isa<InlineAsm>(CB->getCalledOperand())) {
					EscapesInlineAsm = true;
					continue;
				}
				if (isSensitiveSource(*CB)) continue; // the seed call itself
				const Function* Callee = CB->getCalledFunction();
				if (!Callee || !Callee->isDeclaration() || Callee->isIntrinsic())
					continue;
				for (unsigned I = 0, E = CB->arg_size(); I != E; ++I)
					if (CB->getArgOperand(I) == V) {
						EscapesUnknownCall = true;
						break;
					}
			}
			else if (auto* BR = dyn_cast<BranchInst>(U)) {
				if (BR->isConditional() && BR->getCondition() == V)
					HasTaintedBranch = true;
			}
		}
	};

	while (!Worklist.empty() || !MemWorklist.empty()) {
		while (!Worklist.empty())
			process(Worklist.pop_back_val());
		while (!MemWorklist.empty()) {
			AllocaInst* AI = MemWorklist.pop_back_val();
			for (User* U : AI->users())
				if (auto* LI = dyn_cast<LoadInst>(U))
					taint(LI);
		}
	}

	if (EscapesReturn) Out.Diagnostic = "sensitive result escapes through return";
	else if (EscapesStore) Out.Diagnostic = "sensitive result escapes through store";
	else if (EscapesUnknownCall) Out.Diagnostic = "sensitive result escapes to unknown call";
	else if (EscapesInlineAsm) Out.Diagnostic = "sensitive result escapes to inline asm";
	else if (!HasTaintedBranch)
		Out.Diagnostic = "sensitive decision has no in-region success/failure branch";

	Out.Valid = Out.Diagnostic.empty();
	return Out.Valid;
}

SensitiveDecisionAnalysisResult SensitiveDecisionAnalysis::run(
	Function& F, FunctionAnalysisManager& AM) {
	SensitiveDecisionAnalysisResult Out;
	const ObfuscationConfig& Cfg = getObfConfig(F, AM);
	auto PC = Cfg.getPassConfig("sensitive");
	if (!PC) return Out;
	SensitiveDecisionConfig S = SensitiveDecisionConfig::fromPassConfig(*PC);
	if (!S.enable) return Out;
	validateSensitiveDecision(F, S, Out);
	return Out;
}

bool llvm::verifyCommittedSensitiveRegions(Module& M, raw_ostream& Err) {
	bool Ok = true;
	for (Function& F : M) {
		if (F.isDeclaration()) continue;
		MDNode* Val = F.getMetadata("obf.sensitive.validated");
		if (!Val || Val->getNumOperands() < 2) continue;

		std::string Region = "<unknown>";
		if (auto* S = dyn_cast<MDString>(Val->getOperand(0)))
			Region = S->getString().str();
		bool Strict = true;
		if (auto* C = dyn_cast<ConstantAsMetadata>(Val->getOperand(1)))
			if (auto* CI = dyn_cast<ConstantInt>(C->getValue()))
				Strict = !CI->isZero();

		MDNode* Com = F.getMetadata("obf.sensitive.committed");
		if (!Com) {
			Err << "obfuscator: sensitive region '" << Region << "': function '"
				<< F.getName() << "' has no committed proof metadata\n";
			Ok = false;
			continue;
		}
		std::string CommittedRegion;
		if (Com->getNumOperands() >= 1)
			if (auto* S = dyn_cast<MDString>(Com->getOperand(0)))
				CommittedRegion = S->getString().str();
		if (CommittedRegion != Region) {
			Err << "obfuscator: sensitive region '" << Region << "': function '"
				<< F.getName() << "' committed under region '"
				<< CommittedRegion << "'\n";
			Ok = false;
			continue;
		}
		if (!Strict) continue;

		if (!F.getMetadata("obf.vm.caller")) {
			Err << "obfuscator: sensitive region '" << Region << "': function '"
				<< F.getName() << "' is not a VM wrapper\n";
			Ok = false;
		}

		// The wrapper must not retain a direct call to any external
		// declaration; the verifier/transport calls live in the callee table.
		for (BasicBlock& BB : F) {
			for (Instruction& I : BB) {
				auto* CB = dyn_cast<CallBase>(&I);
				if (!CB) continue;
				if (isa<InlineAsm>(CB->getCalledOperand())) continue;
				Function* Callee = CB->getCalledFunction();
				if (!Callee || !Callee->isDeclaration() || Callee->isIntrinsic())
					continue;
				Err << "obfuscator: sensitive region '" << Region
					<< "': function '" << F.getName()
					<< "' retains direct call to '" << Callee->getName() << "'\n";
				Ok = false;
			}
		}
	}
	return Ok;
}

PreservedAnalyses SensitiveDecisionPass::run(Function& F, FunctionAnalysisManager& AM) {
	if (F.isDeclaration()) return PreservedAnalyses::all();

	const ObfuscationConfig& Cfg = getObfConfig(F, AM);
	auto PC = Cfg.getPassConfig("sensitive");
	if (!PC) return PreservedAnalyses::all();

	SensitiveDecisionConfig S = SensitiveDecisionConfig::fromPassConfig(*PC);
	if (!S.enable) return PreservedAnalyses::all();

	// A sensitive annotation without a VM pass can never be enforced.
	std::string ConfigReason;
	if (!validateSensitiveConfig(Cfg, &ConfigReason))
		report_fatal_error(Twine("obfuscator: sensitive region '") + S.region +
			"': " + ConfigReason, /*gen_crash_diag=*/false);

	std::string ValidateReason;
	if (!S.validate(&ValidateReason))
		report_fatal_error(Twine("obfuscator: sensitive: ") + ValidateReason,
			/*gen_crash_diag=*/false);

	auto& Result = AM.getResult<SensitiveDecisionAnalysis>(F);
	if (!Result.Valid) {
		if (Result.Strict)
			report_fatal_error(Twine("obfuscator: sensitive region '") +
				Result.Region + "': " + Result.Diagnostic, /*gen_crash_diag=*/false);
		auto& MutFOC = *AM.getResult<FunctionObfContextAnalysis>(F);
		llvm::obf::recordObfPassSkip(MutFOC, "sensitive", Result.Diagnostic);
		return PreservedAnalyses::all();
	}

	LLVMContext& C = F.getContext();
	Metadata* Ops[] = {
		MDString::get(C, Result.Region),
		ConstantAsMetadata::get(ConstantInt::getTrue(C)),
	};
	F.setMetadata("obf.sensitive.validated", MDNode::get(C, Ops));
	return PreservedAnalyses::all();
}
