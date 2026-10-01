#pragma once

#include "llvm/ADT/StringMap.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Transforms/Obfuscator/VMPass_Emitter.h"
#include "llvm/Transforms/Obfuscator/VMPass_Requirements.h"

#include <memory>
#include <string>
#include <vector>

namespace llvm {

struct VMImpl;

struct VMPreparedCandidate {
	~VMPreparedCandidate();
	Function* Fn = nullptr;
	VMPassConfig Config;
	EngineConfigKey Key;
	BytecodeEmitter Emitter;
	VMRequirementSet Requirements;
	std::unique_ptr<VMImpl> Impl;
	std::string SkipReason;
	bool Accepted = false;
};

class VMPlanCoordinator {
public:
	~VMPlanCoordinator();
	VMPreparedCandidate* addCandidate(Function& Fn, const VMPassConfig& Config,
		const EngineConfigKey& Key, BytecodeEmitter&& Emitter,
		const VMRequirementSet& Requirements);
	bool freeze();
	VMPreparedCandidate* addPrepared(std::unique_ptr<VMImpl> Impl,
		const VMPassConfig& Config, const EngineConfigKey& Key);
	bool commit();
	static VMPlanCoordinator* active();
	static VMPlanCoordinator* setActive(VMPlanCoordinator* Coordinator);
	unsigned candidateCount() const { return Candidates.size(); }
	unsigned groupCount() const { return Groups.size(); }
	const VMEnginePlan* groupPlan(unsigned Index) const;
	const VMEnginePlan* planFor(const EngineConfigKey& Key) const;
	bool addHelperRequirements(const EngineConfigKey& Key, VMOp Helper,
		const VMRequirementSet& Requirements);
	bool closeNestedRequirements(const EngineConfigKey& Key,
		ArrayRef<std::pair<VMOp, VMRequirementSet>> Helpers);
	void release();

private:
	struct Group {
		VMEnginePlan Plan;
		std::vector<VMPreparedCandidate*> Candidates;
	};
	std::vector<std::unique_ptr<VMPreparedCandidate>> Candidates;
	std::vector<Group> Groups;
	bool Frozen = false;
};

} // namespace llvm
