#pragma once

#include "llvm/Transforms/Obfuscator/ObfuscationConfig.h"
#include "llvm/IR/PassManager.h"
#include <cstdint>
#include <string>

namespace llvm {

struct ZoneAuthConfig {
	bool enabled = false;
	std::string capability;
	std::string policy = "fail_closed";
	uint32_t heartbeatPeriodSec = 120;
	uint32_t offlineGraceSec = 180;
	std::string algorithm;
	std::string softwareId;
	std::string version;
	std::string codeManifest;

	static ZoneAuthConfig fromPassConfig(const PassConfig& pc);
	bool validate() const;
};

class ZoneAuthModulePass : public PassInfoMixin<ZoneAuthModulePass> {
public:
	PreservedAnalyses run(Module& M, ModuleAnalysisManager& MAM);
	static bool isRequired() { return true; }
};

} // namespace llvm
