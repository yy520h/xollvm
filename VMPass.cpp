// ============================================================================
// VMPass.cpp — Code Virtualisation pass : pass driver
//
// This file contains only:
//   - VMPassConfig::fromPassConfig() and validate()
//   - VMPass::run()
//
// The heavy lifting is split across:
//   VMPass_ISA.h            ISA enums, VMOpcodeMap, LCG constants
//   VMPass_Emitter.h/.cpp   BytecodeEmitter (two-pass IR -> bytecode compiler)
//   VMPass_Verifier.h/.cpp  verifyBytecode (post-emission sanity checker)
//   VMPass_Impl.h/.cpp      VMCtx, isVMEligible, VMImpl (IR transformation engine)
// ============================================================================

#include "llvm/ADT/Statistic.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"

#include "llvm/Transforms/Obfuscator/VMPass.h"
#include "llvm/Transforms/Obfuscator/VMPass_Impl.h"
#include "llvm/Transforms/Obfuscator/VMPass_Plan.h"
#include "llvm/Transforms/Obfuscator/ObfuscationOptions.h"
#include "llvm/Transforms/Obfuscator/FunctionObfContextAnalysis.h"
#include "llvm/Transforms/Obfuscator/SensitiveDecision.h"
#include "llvm/Transforms/Obfuscator/Utils.h"
#include "llvm/Transforms/Obfuscator/AntiDebug.h"

#include "llvm/IR/Constants.h"
#include "llvm/IR/Metadata.h"

using namespace llvm;

#define DEBUG_TYPE "vm"

// ============================================================================
// VMPassConfig
// ============================================================================

VMPassConfig VMPassConfig::fromPassConfig(const PassConfig& PC, bool Normalize) {
	VMPassConfig Cfg;
	Cfg.enable = PC.enabled;

	// preset=<medium|high|max>: shortcut bundle applied before explicit knobs
	// below, so any explicit knob in the annotation overrides the preset.
	// (The former `light` preset was removed: real-lift resilience bench on
	// v0.8.0 showed it produced NEGATIVE resilience on straight-line code --
	// attacker's opt-O3 folded the light-preset VM output smaller than the
	// unobfuscated baseline it was hiding. Anyone who wants the same bundle
	// can spell it out explicitly.)
	auto It = PC.params.find("preset");
	if (It != PC.params.end()) {
		const std::string& P = It->second;
		if (P == "medium") {
			// current defaults; explicit for readability + stability
			Cfg.obfRegIdx = true;
			Cfg.encBytecode = true;
			Cfg.handlerVariants = 3;
			Cfg.encDispatch = true;
			Cfg.strongBytecode = true;
			Cfg.blindTargets = true;
		} else if (P == "high") {
			// medium + hardened + threaded + keyed
			Cfg.obfRegIdx = true;
			Cfg.encBytecode = true;
			Cfg.handlerVariants = 3;
			Cfg.encDispatch = true;
			Cfg.strongBytecode = true;
			Cfg.blindTargets = true;
			Cfg.hardened = true;
			Cfg.threadedDispatch = true;
			Cfg.keyedDispatch = true;
		} else if (P == "max") {
			// high + all remaining knobs on
			Cfg.obfRegIdx = true;
			Cfg.encBytecode = true;
			Cfg.handlerVariants = 3;
			Cfg.encDispatch = true;
			Cfg.strongBytecode = true;
			Cfg.blindTargets = true;
			Cfg.hardened = true;
			Cfg.threadedDispatch = true;
			Cfg.keyedDispatch = true;
			Cfg.lazyDecrypt = true;
			Cfg.constInStream = true;
			Cfg.nestedVM = true;
			Cfg.superOps = true;
			Cfg.rollingRegKey = true;
			Cfg.bindAntiDebug = true;
			Cfg.randISA = true;
			Cfg.extendedISA = Cfg.operandLayout = Cfg.encodedTargets = true;
			Cfg.whiteboxAES = Cfg.nestedVMHardened = true;
			Cfg.wrapperFamily = "auto";
			Cfg.perFnEngine = true;         // dedicated engine per virtualized fn
			Cfg.metamorphicEngines = true;  // distinct handler body per engine
			Cfg.handlerVariants = 4;        // M6: preset flip -- benchmarked K=4/8/16;
			Cfg.handlerDecoys = 2;          // K=4 is the highest that keeps both opt
			// AND the downstream clang -O0 compile of the resulting IR under the
			// 180s harness cap (K=8: opt ~65s ok, but 373x-bloat IR blows clang
			// -O0 past 180s; K=16: opt itself exceeds 180s). See docs/VM.md
			// "Handler Polymorphism II" for the full writeup.
		} else {
			report_fatal_error(Twine("vm: unknown preset '") + P + "'", false);
		}
	}

	auto getUInt = [&](StringRef K, unsigned& O) {
		auto It = PC.params.find(K.str());
		if (It != PC.params.end()) {
			uint64_t N = 0;
			if (StringRef(It->second).getAsInteger(10, N) || N > UINT32_MAX)
				report_fatal_error(Twine("vm: invalid unsigned value for ") + K, false);
			O = static_cast<unsigned>(N);
		}
		};
	auto getBool = [&](StringRef K, bool& O) {
		auto It = PC.params.find(K.str());
		if (It != PC.params.end()) {
			StringRef V = It->second;
			if (V != "0" && V != "1" && V != "false" && V != "true")
				report_fatal_error(Twine("vm: invalid boolean for ") + K, false);
			O = V == "1" || V == "true";
		}
		};
	getUInt("minBlocks", Cfg.minBlocks);
	getUInt("maxBlocks", Cfg.maxBlocks);
	getBool("obfRegIdx", Cfg.obfRegIdx);
	getBool("encDispatch", Cfg.encDispatch);
	getBool("encBytecode", Cfg.encBytecode);
	getBool("constInStream", Cfg.constInStream);
	getBool("strongBytecode", Cfg.strongBytecode);
	getBool("blindTargets", Cfg.blindTargets);
	getBool("lazyDecrypt", Cfg.lazyDecrypt);
	getBool("hardened", Cfg.hardened);
	getBool("regEncrypt", Cfg.regEncrypt);
	getBool("rollingRegKey", Cfg.rollingRegKey);
	getBool("antiDebug", Cfg.antiDebug);
	getUInt("adDispatchThreshold", Cfg.adDispatchThreshold);
	getUInt("adHandlerThreshold", Cfg.adHandlerThreshold);
	getUInt("adDispatchInterval", Cfg.adDispatchInterval);
	getUInt("adHandlerProb", Cfg.adHandlerProb);
	getBool("bindAntiDebug", Cfg.bindAntiDebug);
	getUInt("handlerVariants", Cfg.handlerVariants);
	getUInt("handlerDecoys", Cfg.handlerDecoys);
	getBool("nestedVM", Cfg.nestedVM);
	getUInt("nestedVMOpcodes", Cfg.nestedVMOpcodes);
	getBool("nestedVMHardened", Cfg.nestedVMHardened);
	getBool("threadedDispatch", Cfg.threadedDispatch);
	getBool("keyedDispatch", Cfg.keyedDispatch);
	getBool("cloudDispatch", Cfg.cloudDispatch);
	getBool("superOps", Cfg.superOps);
	getBool("randISA", Cfg.randISA);
	getBool("operandLayout", Cfg.operandLayout);
	getBool("extendedISA", Cfg.extendedISA);
	getBool("encodedTargets", Cfg.encodedTargets);
	getBool("whiteboxAES", Cfg.whiteboxAES);
	if (Cfg.whiteboxAES && !Cfg.encBytecode) report_fatal_error("whiteboxAES requires encBytecode=1");
	getUInt("enginePoolSize", Cfg.enginePoolSize);
	getBool("metamorphicEngines", Cfg.metamorphicEngines);
	getBool("perFnEngine", Cfg.perFnEngine);

	if (auto It = PC.params.find("wrapperFamily"); It != PC.params.end()) {
		const std::string& F = It->second;
		if (F == "auto" || F == "split" || F == "arena" || F == "outlined")
			Cfg.wrapperFamily = F;
		else report_fatal_error("vm: unknown wrapperFamily", false);
	}

	// 请求报告保留依赖归一化之前的值，与实际引擎配置分开。
	if (!Normalize) return Cfg;
	// lazyDecrypt requires encBytecode — nothing to defer if bytecode isn't encrypted.
	if (!Cfg.encBytecode) Cfg.lazyDecrypt = false;
	// hardened requires encBytecode (meaningful only with encrypted bytecode)
	if (!Cfg.encBytecode) Cfg.hardened = false;
	// constInStream requires encBytecode — the whole point is to hide constants
	// in the encrypted stream instead of plaintext wrapper stores.
	if (!Cfg.encBytecode) Cfg.constInStream = false;
	// hardened implies regEncrypt — encrypted registers complement MBA-obscured handlers
	if (Cfg.hardened) Cfg.regEncrypt = true;
	// 检测来源在合并独立 antidebug pass 后确定；此处保留请求。
	if (Cfg.handlerVariants < 1) Cfg.handlerVariants = 1;
	if (Cfg.handlerVariants > kMaxHandlerVariants) Cfg.handlerVariants = kMaxHandlerVariants;
	if (Cfg.handlerDecoys > 3) Cfg.handlerDecoys = 3;
	if (Cfg.enginePoolSize < 1) Cfg.enginePoolSize = 1;
	// metamorphicEngines needs >1 engine to diversify across -- either an
	// explicit pool or per-function engines.
	if (Cfg.enginePoolSize < 2 && !Cfg.perFnEngine) Cfg.metamorphicEngines = false;
	if (!Cfg.nestedVM) Cfg.nestedVMHardened = false;
	return Cfg;
}

bool VMPassConfig::validate() const {
	if (minBlocks < 1) return false;
	if (maxBlocks > 0 && maxBlocks < minBlocks) return false;
	return true;
}

// ============================================================================
// VMPass::run
// ============================================================================

PreservedAnalyses VMPass::run(Function& F, FunctionAnalysisManager& AM) {
	if (F.isDeclaration()) return PreservedAnalyses::all();

	VMCtx VCtx(F, AM);
	if (!VCtx.Cfg.enable) return PreservedAnalyses::all();

	// Task 4: a sensitive(strict=1) region's function is registered before
	// eligibility so it cannot silently disappear. Provenance (declaration
	// callees) is captured now, while the original body still exists.
	bool SensitiveRequired = false;
	bool SensitiveStrict = true;
	std::string SensitiveRegion;
	SmallVector<Function*, 4> SensitiveCallees;
	if (auto* SD = AM.getCachedResult<SensitiveDecisionAnalysis>(F); SD && SD->Enabled) {
		SensitiveRequired = true;
		SensitiveStrict = SD->Strict;
		SensitiveRegion = SD->Region;
		SensitiveCallees.assign(SD->Callees.begin(), SD->Callees.end());
	}
	else {
		// The analysis isn't cached when the sensitive pass didn't run for this
		// function; fall back to the validated metadata it would have attached.
		if (MDNode* MD = F.getMetadata("obf.sensitive.validated")) {
			if (MD->getNumOperands() == 2) {
				if (auto* S = dyn_cast<MDString>(MD->getOperand(0)))
					SensitiveRegion = S->getString().str();
				if (auto* C = dyn_cast<ConstantAsMetadata>(MD->getOperand(1)))
					if (auto* CI = dyn_cast<ConstantInt>(C->getValue()))
						SensitiveStrict = CI->isOne();
				SensitiveRequired = !SensitiveRegion.empty();
			}
		}
	}

	auto registerRequired = [&](VMPreparedCandidate* C, StringRef Reason) {
		if (!C) return;
		C->Required = SensitiveRequired;
		C->SensitiveStrict = SensitiveStrict;
		C->Region = SensitiveRegion;
		C->SensitiveCallees.assign(SensitiveCallees.begin(), SensitiveCallees.end());
		C->SkipReason = Reason.str();
	};

	{
		std::string Reason; raw_string_ostream RS(Reason);
		if (!isVMEligible(F, VCtx.FOC, VCtx.Cfg, &RS)) {
			LLVM_DEBUG(dbgs() << "[vm] skip '" << F.getName() << "': " << RS.str() << "\n");
			if (ObfVerbose) errs() << "[vm] skip '" << F.getName() << "': " << Reason << "\n";
			auto& MutFOC = *AM.getResult<FunctionObfContextAnalysis>(F);
			std::string R = Reason.empty() ? "ineligible" : Reason;
			llvm::obf::recordObfPassSkip(MutFOC, "vm", R);
			if (SensitiveRequired) {
				if (auto* Coordinator = VMPlanCoordinator::active()) {
					if (auto* C = Coordinator->addCandidate(F, VCtx.Cfg,
						EngineConfigKey::fromConfig(VCtx.Cfg, 0, 0), BytecodeEmitter{}, {}))
						registerRequired(C, R);
				}
			}
			return PreservedAnalyses::all();
		}
	}

	auto Impl = std::make_unique<VMImpl>(VCtx);
	if (auto PC = getObfConfig(F, AM).getPassConfig("vm"))
		Impl->RequestedCfg = VMPassConfig::fromPassConfig(*PC, false);
	if (auto AD = getObfConfig(F, AM).getPassConfig("antidebug"))
		Impl->AntiDebug = AntiDebugConfig::fromPassConfig(*AD);
	Impl->AntiDebug.mergeCompatibility(VCtx.Cfg);
	Impl->AntiDebug = effectiveAntiDebugConfig(*F.getParent(), Impl->AntiDebug);
	const auto& AD = Impl->AntiDebug;
	bool HasChecks = hasAntiDebugDetectionSource(AD);
	Impl->BindAntiDebug = VCtx.Cfg.bindAntiDebug && VCtx.Cfg.hardened &&
		AD.enabled && AD.responseCorrupt && HasChecks;
	Impl->Cfg.bindAntiDebug = Impl->BindAntiDebug;
	Impl->Cfg.antiDebugConfig = AD;
	if (VCtx.Cfg.bindAntiDebug && !Impl->BindAntiDebug)
		Impl->BindDisabledReason = !VCtx.Cfg.hardened ? "requires_hardened" :
			(!AD.enabled || !HasChecks) ? "no_detection_source" : "response_disabled";
	if (auto* Coordinator = VMPlanCoordinator::active()) {
		if (!Impl->prepare()) {
			std::string R = Impl->FailReason.empty() ? "impl_failed" : Impl->FailReason;
			auto& MutFOC = *AM.getResult<FunctionObfContextAnalysis>(F);
			llvm::obf::recordObfPassSkip(MutFOC, "vm", R);
			if (SensitiveRequired) {
				if (auto* C = Coordinator->addCandidate(F, VCtx.Cfg,
					EngineConfigKey::fromConfig(VCtx.Cfg, 0, 0), BytecodeEmitter{}, {}))
					registerRequired(C, R);
			}
			return PreservedAnalyses::all();
		}
		EngineConfigKey Key = EngineConfigKey::fromConfig(Impl->Cfg,
			VMEngine::enginePoolOf(Impl->EngineId), Impl->EngineId, VCtx.MasterSeed,
			&Impl->AntiDebug);
		VMImpl* Raw = Impl.get();
		VMPassConfig Effective = Impl->Cfg;
		if (auto* C = Coordinator->addPrepared(std::move(Impl), Effective, Key)) {
			if (SensitiveRequired) {
				C->Required = true;
				C->SensitiveStrict = SensitiveStrict;
				C->Region = SensitiveRegion;
				C->SensitiveCallees.assign(SensitiveCallees.begin(), SensitiveCallees.end());
			}
		}
		(void)Raw;
		// Tag the caller so the report can attach a VM witness to it (the full
		// engine witness is finalized by the coordinator after commit).
		F.setMetadata("obf.vm.caller", MDNode::get(F.getContext(), {}));
		return PreservedAnalyses::all();
	}
	if (!Impl->run()) {
		LLVM_DEBUG(dbgs() << "[vm] fail '" << F.getName() << "': " << Impl->FailReason << "\n");
		if (ObfVerbose) {
			if (!Impl->FailReason.empty())
				errs() << "[vm] fail '" << F.getName() << "': " << Impl->FailReason << "\n";
			else
				errs() << "[vm] fail '" << F.getName() << "'" << "\n";
		}
		auto& MutFOC = *AM.getResult<FunctionObfContextAnalysis>(F);
		llvm::obf::recordObfPassSkip(MutFOC, "vm",
			Impl->FailReason.empty() ? "impl_failed" : Impl->FailReason);
		return PreservedAnalyses::all();
	}

	if (ObfVerbose)
		errs() << "[vm] virtualised '" << F.getName() << "' ["
		<< Impl->E.BC.size() << "B bytecode | "
		<< (unsigned)Impl->E.NVR << "vregs+"
		<< (unsigned)Impl->E.NVR64 << "vregs64+"
		<< (unsigned)Impl->E.NPR << "pregs"
		<< (VCtx.Cfg.obfRegIdx ? " |obf-idx" : "")
		<< (VCtx.Cfg.encBytecode ? " |enc-bc" : "")
		<< (VCtx.Cfg.hardened ? " |hardened" : "")
		<< "]\n";

	F.setMetadata("obf.vm.caller", MDNode::get(F.getContext(), {}));
	return PreservedAnalyses::none();
}
