#pragma once

#include "llvm/IR/PassManager.h"
#include "llvm/Transforms/Obfuscator/ObfuscationConfig.h"

namespace llvm {

class GlobalVariable;
GlobalVariable* getOrCreateAntiDebugResponse(Module& M);
bool applyAntiDebug(Function& F, AntiDebugConfig Cfg);

class AntiDebugPass : public PassInfoMixin<AntiDebugPass> {
public:
	PreservedAnalyses run(Function& F, FunctionAnalysisManager& AM);
	static bool isRequired() { return true; }
};

} // namespace llvm
