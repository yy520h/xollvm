#pragma once

#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Transforms/Obfuscator/ObfuscationConfig.h"

#include <string>

namespace llvm {

	class Function;
	class Module;
	class raw_ostream;

	// Result of validating one sensitive-decision function. `Valid` is true
	// only when the boundary rules in the design's §6.2/§6.3 hold; otherwise
	// `Diagnostic` names the first violation found.
	struct SensitiveDecisionAnalysisResult {
		bool Enabled = false;
		bool Valid = false;
		bool Strict = true;
		std::string Region;
		std::string Diagnostic;
		// Declaration-only, non-intrinsic callees observed before any VM
		// transformation replaces the original body.
		SmallVector<Function*, 4> Callees;
	};

	// Config-level prerequisite: a `sensitive` annotation is meaningless
	// without an enabled `vm` pass. Returns true when the requirement holds.
	bool validateSensitiveConfig(const ObfuscationConfig& Cfg, std::string* Reason = nullptr);

	// Standalone def-use validation. Seeds taint from non-void calls to
	// declaration-only non-intrinsic functions and rejects a tainted return,
	// a store to non-local memory, a tainted argument to an unknown call, an
	// inline-asm use, or a region with no branch on the tainted result.
	bool validateSensitiveDecision(Function& F, const SensitiveDecisionConfig& Cfg,
		SensitiveDecisionAnalysisResult& Out);

	class SensitiveDecisionAnalysis
		: public AnalysisInfoMixin<SensitiveDecisionAnalysis> {
	public:
		using Result = SensitiveDecisionAnalysisResult;
		Result run(Function& F, FunctionAnalysisManager& AM);

	private:
		friend AnalysisInfoMixin<SensitiveDecisionAnalysis>;
		static AnalysisKey Key;
	};

	// Validates the annotated function and, on success, attaches
	//   !obf.sensitive.validated = !{!"<region>", i1 <strict>}
	// so VM planning can recognize a required strict candidate. Under
	// strict=1 a validation failure is fatal; under strict=0 it is recorded
	// as a pass skip.
	class SensitiveDecisionPass : public PassInfoMixin<SensitiveDecisionPass> {
	public:
		PreservedAnalyses run(Function& F, FunctionAnalysisManager& AM);
		static bool isRequired() { return true; }
	};

	// Post-commit structural proof (Task 5). For every function carrying
	// !obf.sensitive.validated, require matching !obf.sensitive.committed, the
	// VM caller marker, and no direct call to a declaration-only non-intrinsic
	// function left in the wrapper. Returns false and writes diagnostics to
	// Err on the first structural violation per function.
	bool verifyCommittedSensitiveRegions(Module& M, raw_ostream& Err);

} // namespace llvm
