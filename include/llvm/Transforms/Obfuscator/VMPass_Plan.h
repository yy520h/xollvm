#pragma once

#include "llvm/ADT/SmallVector.h"
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

	// Sensitive-decision metadata (Task 4). A required candidate was named by
	// a `sensitive(strict=1)` region and must not silently vanish.
	bool Required = false;
	bool SensitiveStrict = true;
	std::string Region;
	// Declaration-only callees captured before VM replaces the original body.
	// Task 5 consumes this post-commit provenance.
	SmallVector<Function*, 4> SensitiveCallees;
};

class VMPlanCoordinator {
public:
	~VMPlanCoordinator();
	VMPreparedCandidate* addCandidate(Function& Fn, const VMPassConfig& Config,
		const EngineConfigKey& Key, BytecodeEmitter&& Emitter,
		const VMRequirementSet& Requirements);
	// Register a sensitive region's function BEFORE eligibility checks so a
	// strict candidate that cannot be prepared is still visible to
	// verifyRequiredCandidates().
	VMPreparedCandidate* addRequired(Function& Fn, const std::string& Region,
		bool Strict, const SmallVectorImpl<Function*>& Callees,
		const VMPassConfig& Config, const EngineConfigKey& Key,
		BytecodeEmitter&& Emitter, const VMRequirementSet& Requirements);
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

	// A strict sensitive candidate that never prepared (or whose preparation
	// failed) is a hard error: report_fatal_error. Non-strict required
	// candidates append a report entry instead. Returns true when every strict
	// candidate prepared and (after commit) committed.
	bool verifyRequiredCandidates() const;

	// Post-commit verification of sensitive metadata: every strict region
	// needs a candidate that both committed and carries `obf.sensitive.committed`.
	bool verifySensitiveCommits() const;

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
