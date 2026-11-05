#pragma once

#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Support/Error.h"
#include "llvm/Support/JSON.h"

#include <string>

namespace llvm {

struct BytecodeEmitter;
struct VMOpcodeMap;
struct VMPassConfig;
class VMPlanCoordinator;

struct DynamicArtifactExport {
	json::Object PublicManifest;
	json::Object PrivateRegistration;
};

enum class MaterialExportFault {
	None, Create, Write, FileSync, Close, DirectorySync, Rename, RootSync,
	DestinationSwap, MemberContent, MemberSwap
};

enum class MaterialCodecProfile {
	CanonicalRegion,
	PublicManifest,
	PrivateRegistration,
};

enum class MaterialCommitDurability {
	Durable,
	Unknown,
};

enum class MaterialCommitIntegrity {
	Verified,
	Unknown,
};

struct MaterialCommitResult {
	std::string Path;
	MaterialCommitDurability Durability = MaterialCommitDurability::Durable;
	MaterialCommitIntegrity Integrity = MaterialCommitIntegrity::Verified;
};

class MaterialCommitToken {
public:
	MaterialCommitToken(const MaterialCommitToken&) = default;
#ifdef OBF_TEST_VM_IMPL
	static MaterialCommitToken forExportOnlyTest(
		MaterialExportFault Fault = MaterialExportFault::None);
#endif

private:
	static MaterialCommitToken afterNoFallbackCommit();
	explicit MaterialCommitToken(unsigned Value,
		MaterialExportFault Fault = MaterialExportFault::None)
		: Value(Value), Fault(Fault) {}
	unsigned Value;
	MaterialExportFault Fault;
	friend class VMPlanCoordinator;
	friend Expected<MaterialCommitResult> commitCanonicalRegions(StringRef, StringRef,
		ArrayRef<json::Object>, const MaterialCommitToken&);
	friend Expected<MaterialCommitResult> commitDynamicArtifacts(StringRef, StringRef,
		ArrayRef<DynamicArtifactExport>, const MaterialCommitToken&);
};

Expected<json::Object> exportCanonicalRegion(const BytecodeEmitter& Emitter,
	const VMPassConfig& Config, const VMOpcodeMap& Opcodes);

Expected<DynamicArtifactExport> exportDynamicArtifact(const BytecodeEmitter& Emitter,
	const VMPassConfig& Config, const VMOpcodeMap& Opcodes);

Expected<std::string> canonicalMaterialJSON(const json::Value& Value,
	MaterialCodecProfile Profile);

Error verifyCanonicalRegionWithDescriptor(const json::Object& Region,
	StringRef VerifierBytes, ArrayRef<uint8_t> Bytecode,
	uint64_t* OutTargetLookupOperations = nullptr);

Expected<MaterialCommitResult> commitCanonicalRegions(StringRef ExportRoot,
	StringRef SoftwareId, ArrayRef<json::Object> Regions,
	const MaterialCommitToken& Token);

Expected<MaterialCommitResult> commitDynamicArtifacts(StringRef ExportRoot,
	StringRef SoftwareId, ArrayRef<DynamicArtifactExport> Artifacts,
	const MaterialCommitToken& Token);

} // namespace llvm
