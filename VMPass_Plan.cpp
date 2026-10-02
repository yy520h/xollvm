#include "llvm/Transforms/Obfuscator/VMPass_Plan.h"
#include "llvm/Transforms/Obfuscator/VMPass_Impl.h"

#include "llvm/ADT/STLExtras.h"

#include <set>

using namespace llvm;

static thread_local VMPlanCoordinator* ActiveCoordinator = nullptr;

VMPreparedCandidate::~VMPreparedCandidate() = default;
VMPlanCoordinator::~VMPlanCoordinator() = default;

VMPreparedCandidate* VMPlanCoordinator::addCandidate(Function& Fn,
	const VMPassConfig& Config, const EngineConfigKey& Key,
	BytecodeEmitter&& Emitter, const VMRequirementSet& Requirements) {
	if (Frozen) return nullptr;
	auto Candidate = std::make_unique<VMPreparedCandidate>();
	Candidate->Fn = &Fn;
	Candidate->Config = Config;
	Candidate->Key = Key;
	Candidate->Emitter = std::move(Emitter);
	Candidate->Requirements = Requirements;
	Candidate->Accepted = true;
	VMPreparedCandidate* Result = Candidate.get();
	Candidates.push_back(std::move(Candidate));
	return Result;
}

bool VMPlanCoordinator::freeze() {
	if (Frozen) return false;
	Groups.clear();
	for (const auto& Candidate : Candidates) {
		if (!Candidate->Accepted) continue;
		auto It = llvm::find_if(Groups, [&](const Group& G) {
			return G.Plan.Key == Candidate->Key;
		});
		if (It == Groups.end()) {
			Group G;
			G.Plan.Config = Candidate->Config;
			G.Plan.Key = Candidate->Key;
			G.Plan.DirectRequirements = Candidate->Requirements;
			G.Plan.Requirements = Candidate->Requirements;
			G.Candidates.push_back(Candidate.get());
			Groups.push_back(std::move(G));
		}
		else {
			It->Plan.DirectRequirements.merge(Candidate->Requirements);
			It->Plan.Requirements.merge(Candidate->Requirements);
			It->Candidates.push_back(Candidate.get());
		}
	}
	for (auto& Group : Groups)
		Group.Plan.Requirements.closeDependencies(Group.Plan.Config);

	// Distinct EngineConfigKeys may map to the same base EngineId (e.g. two
	// functions in a single-engine module whose configs differ only in
	// randISA -- prepare() runs before pooling assigns ids). Left alone they
	// would both build @__vm_engine and silently merge into one engine. Give
	// every colliding group a fresh pool id, derived from its key hash, so
	// incompatible configurations get physically separate engines. The first
	// (uncollided) group keeps its id, preserving single-config builds.
	{
		std::set<unsigned> Used;
		for (auto& Group : Groups) {
			unsigned Base = Group.Candidates.front()->Impl->EngineId;
			if (Used.insert(Base).second) {
				Group.Plan.EngineId = Base;
				continue;
			}
			unsigned Layer = VMEngine::engineLayer(Base);
			unsigned Pool = (unsigned)(Group.Plan.Key.stableHash() & 0x3FFFFFFFu) | 0x40000000u;
			unsigned New = VMEngine::makeEngineId(Pool, Layer);
			while (!Used.insert(New).second)
				New = VMEngine::makeEngineId(++Pool, Layer);
			Group.Plan.EngineId = New;
		}
	}
	Frozen = true;
	return true;
}

VMPreparedCandidate* VMPlanCoordinator::addPrepared(std::unique_ptr<VMImpl> Impl,
	const VMPassConfig& Config, const EngineConfigKey& Key) {
	if (Frozen || !Impl) return nullptr;
	Impl->remapPreparedExternalValues();
	auto Candidate = std::make_unique<VMPreparedCandidate>();
	Candidate->Fn = &Impl->F;
	Candidate->Config = Config;
	Candidate->Key = Key;
	Candidate->Requirements = Impl->E.getRequirements();
	Candidate->Accepted = true;
	Candidate->Impl = std::move(Impl);
	VMPreparedCandidate* Result = Candidate.get();
	Candidates.push_back(std::move(Candidate));
	Groups.clear();
	Frozen = false;
	return Result;
}

bool VMPlanCoordinator::commit() {
	if (!Frozen) return false;
	for (auto& Candidate : Candidates) {
		if (!Candidate->Accepted || !Candidate->Impl) continue;
		const VMEnginePlan* Plan = planFor(Candidate->Key);
		if (!Plan) return false;
		// Apply the group's (possibly reassigned) engine id. prepare() does not
		// bind EngineId; the engine function/state are built here in commit().
		Candidate->Impl->EngineId = Plan->EngineId;
		// Nested helpers are currently prepared during commit; their requirements
		// are not frozen into the outer plan yet, so keep the complete handler
		// domain for nested groups until helper closure moves before freeze.
		if (Candidate->Config.nestedVM)
			Candidate->Impl->setFullHandlerRequirements();
		else
			Candidate->Impl->setHandlerRequirements(Plan->Requirements);
		if (!Candidate->Impl->commit()) return false;
	}
	return true;
}

VMPlanCoordinator* VMPlanCoordinator::active() { return ActiveCoordinator; }

VMPlanCoordinator* VMPlanCoordinator::setActive(VMPlanCoordinator* Coordinator) {
	VMPlanCoordinator* Previous = ActiveCoordinator;
	ActiveCoordinator = Coordinator;
	return Previous;
}

const VMEnginePlan* VMPlanCoordinator::groupPlan(unsigned Index) const {
	if (Index >= Groups.size()) return nullptr;
	return &Groups[Index].Plan;
}

const VMEnginePlan* VMPlanCoordinator::planFor(const EngineConfigKey& Key) const {
	for (const auto& Group : Groups)
		if (Group.Plan.Key == Key) return &Group.Plan;
	return nullptr;
}

bool VMPlanCoordinator::addHelperRequirements(const EngineConfigKey& Key,
	VMOp Helper, const VMRequirementSet& Requirements) {
	if (Frozen) return false;
	for (auto& Candidate : Candidates) {
		if (Candidate->Key == Key && Candidate->Accepted) {
			Candidate->Requirements.merge(Requirements);
			if (!llvm::is_contained(Candidate->Requirements.NestedHelpers, Helper))
				Candidate->Requirements.NestedHelpers.push_back(Helper);
			return true;
		}
	}
	return false;
}

bool VMPlanCoordinator::closeNestedRequirements(const EngineConfigKey& Key,
	ArrayRef<std::pair<VMOp, VMRequirementSet>> Helpers) {
	if (Frozen) return false;
	bool Changed = false;
	for (const auto& [Op, Requirements] : Helpers) {
		for (auto& Candidate : Candidates) {
			if (!(Candidate->Key == Key) || !Candidate->Accepted) continue;
			unsigned Before = Candidate->Requirements.Opcodes.count();
			Candidate->Requirements.merge(Requirements);
			if (!llvm::is_contained(Candidate->Requirements.NestedHelpers, Op))
				Candidate->Requirements.NestedHelpers.push_back(Op);
			Changed |= Before != Candidate->Requirements.Opcodes.count();
		}
	}
	return Changed;
}

void VMPlanCoordinator::release() {
	Groups.clear();
	Candidates.clear();
	Frozen = false;
}
