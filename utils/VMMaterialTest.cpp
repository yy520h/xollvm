#include "llvm/Transforms/Obfuscator/VMPass_Material.h"
#include "runtime/cloud_material/dynamic_vm_artifact.h"
#include "runtime/cloud_material/dynamic_vm_schema.h"
#include "runtime/cloud_material/dynamic_vm_shard.h"
#ifdef XOLLVM_MATERIAL_PACKAGE_TEST_BRIDGE
#include "runtime/cloud_material/material_package.h"
#endif

#include "llvm/ADT/ScopeExit.h"
#include "llvm/AsmParser/Parser.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/Base64.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/SHA256.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/Transforms/Obfuscator/VMPass_Emitter.h"
#include "llvm/Transforms/Obfuscator/VMPass_ISA.h"
#include "llvm/Transforms/Obfuscator/VMPass_Verifier.h"
#include "gtest/gtest.h"

#include <cstdlib>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <string>
#include <sys/stat.h>
#include <thread>
#include <utility>
#include <vector>

using namespace llvm;

namespace {

struct ExportFixture {
	std::unique_ptr<LLVMContext> Context;
	std::unique_ptr<Module> M;
	VMOpcodeMap Opcodes;
	BytecodeEmitter Emitter;
	VMPassConfig Config;
};

static void swapLoadAndReturnOpcodes(VMOpcodeMap& Opcodes) {
	uint8_t Saved = Opcodes.L2P[OP_LOADI];
	Opcodes.L2P[OP_LOADI] = Opcodes.L2P[OP_RET_INT];
	Opcodes.L2P[OP_RET_INT] = Saved;
	for (unsigned I = 0; I < OP_COUNT; ++I)
		Opcodes.P2L[Opcodes.L2P[I]] = static_cast<uint8_t>(I);
}

static ExportFixture makeFixture(StringRef Region = "auth/payment", int Constant = 7) {
	ExportFixture F;
	F.Context = std::make_unique<LLVMContext>();
	SMDiagnostic Diagnostic;
	std::string IR = R"IR(
target triple = "aarch64-linux-android26"
declare i32 @callee(i32, double)
define i32 @target(i32 %x, float %f) {
entry:
  %a = add i32 %x, CONST
  %fp = fadd float %f, 1.250000e+00
  %d = fpext float %fp to double
  %c = call i32 @callee(i32 %a, double %d)
  switch i32 %c, label %other [i32 0, label %zero]
zero:
  ret i32 %a
other:
  ret i32 %c
}
)IR";
	size_t Pos = IR.find("CONST");
	IR.replace(Pos, 5, std::to_string(Constant));
	F.M = parseAssemblyString(IR, Diagnostic, *F.Context);
	EXPECT_NE(F.M, nullptr);
	swapLoadAndReturnOpcodes(F.Opcodes);
	F.Emitter.setOpcodeMap(&F.Opcodes);
	F.Emitter.setTargetBlind(0x12345678u, true);
	F.Emitter.setConstInStream(true);
	F.Emitter.setLayout(VMInstructionLayout::forSeed(42));
	EXPECT_TRUE(F.Emitter.run(*F.M->getFunction("target"), 0x2a, F.M->getDataLayout()));
	F.Config.cloudMaterial = CloudMaterialMode::Lease;
	F.Config.materialRegion = Region.str();
	F.Config.constInStream = true;
	return F;
}

static ExportFixture makeDynamicFixture(StringRef Region = "auth/payment", int Constant = 7,
	uint8_t DecodeSalt = 0x2a, bool KeyedDispatch = false, bool ShuffledLayout = false,
	bool I64Argument = false) {
	ExportFixture F;
	F.Context = std::make_unique<LLVMContext>();
	SMDiagnostic Diagnostic;
	std::string IR = I64Argument
		? "target triple = \"aarch64-linux-android26\"\n"
		  "define i32 @target(i64 %unused) { ret i32 CONST }\n"
		: "target triple = \"aarch64-linux-android26\"\n"
		  "define i32 @target() { ret i32 CONST }\n";
	size_t Pos = IR.find("CONST");
	IR.replace(Pos, 5, std::to_string(Constant));
	F.M = parseAssemblyString(IR, Diagnostic, *F.Context);
	EXPECT_NE(F.M, nullptr);
	swapLoadAndReturnOpcodes(F.Opcodes);
	F.Emitter.setOpcodeMap(&F.Opcodes);
	F.Emitter.setConstInStream(true);
	if (KeyedDispatch) F.Emitter.setKeyedDispatch(0x12345678u, true);
	if (ShuffledLayout) F.Emitter.setLayout(VMInstructionLayout::forSeed(42));
	EXPECT_TRUE(F.Emitter.run(*F.M->getFunction("target"), DecodeSalt,
		F.M->getDataLayout()));
	F.Config.cloudMaterial = CloudMaterialMode::Lease;
	F.Config.materialRegion = Region.str();
	F.Config.constInStream = true;
	return F;
}

static std::string temporaryRoot() {
	SmallString<256> Root;
	EXPECT_FALSE(sys::fs::createUniqueDirectory("xovm-material-test", Root));
	return Root.str().str();
}

static std::optional<xovm::material::DynamicHash> parseDynamicHash(StringRef Text) {
	if (Text.size() != 64) return std::nullopt;
	auto HexValue = [](char C) -> int {
		if (C >= '0' && C <= '9') return C - '0';
		if (C >= 'a' && C <= 'f') return C - 'a' + 10;
		return -1;
	};
	xovm::material::DynamicHash Result{};
	for (size_t I = 0; I < Result.size(); ++I) {
		int High = HexValue(Text[I * 2]);
		int Low = HexValue(Text[I * 2 + 1]);
		if (High < 0 || Low < 0) return std::nullopt;
		Result[I] = static_cast<uint8_t>((High << 4) | Low);
	}
	return Result;
}

static std::optional<xovm::material::DecryptedVmArtifact> decryptDynamicExport(
	const DynamicArtifactExport& Export) {
	auto Ciphertext = Export.PublicManifest.getString("encrypted_artifact_b64");
	auto KeyText = Export.PrivateRegistration.getString("artifact_key_b64");
	auto BuildText = Export.PublicManifest.getString("build_id");
	auto RegionText = Export.PublicManifest.getString("region_id");
	auto ArtifactText = Export.PublicManifest.getString("artifact_hash");
	if (!Ciphertext || !KeyText || !BuildText || !RegionText || !ArtifactText)
		return std::nullopt;
	std::vector<char> Encoded;
	std::vector<char> KeyBytes;
	if (Error E = decodeBase64(*Ciphertext, Encoded)) {
		consumeError(std::move(E));
		return std::nullopt;
	}
	if (Error E = decodeBase64(*KeyText, KeyBytes)) {
		consumeError(std::move(E));
		return std::nullopt;
	}
	if (KeyBytes.size() != 32) return std::nullopt;
	auto Build = parseDynamicHash(*BuildText);
	auto Region = parseDynamicHash(*RegionText);
	auto ArtifactHash = parseDynamicHash(*ArtifactText);
	if (!Build || !Region || !ArtifactHash) return std::nullopt;
	auto Artifact = xovm::material::decodeEncryptedVmArtifact(ArrayRef<uint8_t>(
		reinterpret_cast<const uint8_t*>(Encoded.data()), Encoded.size()));
	if (!Artifact) return std::nullopt;
	std::array<uint8_t, 32> Key{};
	std::copy(KeyBytes.begin(), KeyBytes.end(), Key.begin());
	return xovm::material::decryptEncryptedVmArtifact(*Artifact, Key,
		*Build, *Region, *ArtifactHash);
}

static const json::Array& arrayField(const json::Object& Object, StringRef Name) {
	auto* Array = Object.getArray(Name);
	EXPECT_NE(Array, nullptr);
	return *Array;
}

static std::string hashBytes(StringRef Bytes) {
	auto Digest = SHA256::hash(ArrayRef<uint8_t>(
		reinterpret_cast<const uint8_t*>(Bytes.data()), Bytes.size()));
	return toHex(ArrayRef<uint8_t>(Digest), true);
}

static std::string frameHash(StringRef Label, StringRef Part) {
	std::string Bytes = Label.str();
	Bytes.push_back('\0');
	uint32_t Size = Part.size();
	for (int Shift : {24, 16, 8, 0}) Bytes.push_back(static_cast<char>(Size >> Shift));
	Bytes.append(Part);
	return hashBytes(Bytes);
}

static void rehashRegion(json::Object& Region) {
	json::Object Core = Region;
	Core.erase("region_content_hash");
	Core.erase("region_id");
	auto CoreBytes = canonicalMaterialJSON(json::Value(std::move(Core)),
		MaterialCodecProfile::CanonicalRegion);
	ASSERT_TRUE(static_cast<bool>(CoreBytes)) << toString(CoreBytes.takeError());
	std::string ContentHash = frameHash("XOVM2/region-content", *CoreBytes);
	Region["region_content_hash"] = ContentHash;
	json::Object Identity{
		{"format_version", 1}, {"region_name", *Region.getString("region_name")},
		{"region_content_hash", ContentHash},
		{"engine_abi_hash", *Region.getString("engine_abi_hash")},
		{"call_abi_hash", *Region.getString("call_abi_hash")},
		{"layout_hash", *Region.getString("layout_hash")},
		{"mode", *Region.getString("mode")},
		{"target_triple", *Region.getString("target_triple")},
	};
	auto IdentityBytes = canonicalMaterialJSON(json::Value(std::move(Identity)),
		MaterialCodecProfile::CanonicalRegion);
	ASSERT_TRUE(static_cast<bool>(IdentityBytes)) << toString(IdentityBytes.takeError());
	Region["region_id"] = frameHash("XOVM2/region-id", *IdentityBytes);
}

TEST(VMMaterial, ExportsEmitterRecordsAfterConstPrologue) {
	auto Fixture = makeFixture();
	auto RegionOr = exportCanonicalRegion(Fixture.Emitter, Fixture.Config, Fixture.Opcodes);
	ASSERT_TRUE(static_cast<bool>(RegionOr)) << toString(RegionOr.takeError());
	json::Object Region = std::move(*RegionOr);
	const auto& Offsets = arrayField(Region, "instruction_offsets");
	const auto& Opcodes = arrayField(Region, "logical_opcodes");
	ASSERT_EQ(Offsets.size(), Opcodes.size());
	ASSERT_FALSE(Offsets.empty());
	uint64_t Previous = UINT64_MAX;
	bool SawCall = false;
	bool SawSwitch = false;
	for (unsigned I = 0; I < Offsets.size(); ++I) {
		auto Offset = Offsets[I].getAsInteger();
		auto Opcode = Opcodes[I].getAsInteger();
		ASSERT_TRUE(Offset.has_value());
		ASSERT_TRUE(Opcode.has_value());
		if (I) EXPECT_LT(Previous, static_cast<uint64_t>(*Offset));
		Previous = *Offset;
		ASSERT_LT(static_cast<uint64_t>(*Offset), Fixture.Emitter.BC.size());
		EXPECT_EQ(Fixture.Emitter.BC[*Offset], Fixture.Opcodes.encode(static_cast<VMOp>(*Opcode)));
		SawCall |= *Opcode == OP_CALL_INT;
		SawSwitch |= *Opcode == OP_SWITCH;
		VMOp Op = static_cast<VMOp>(*Opcode);
		uint64_t Size = Fixture.Emitter.getLayout().size(Op);
		if (Op == OP_CALL_VOID || Op == OP_CALL_INT || Op == OP_CALL_INT64 ||
			Op == OP_CALL_PTR || Op == OP_CALL_F) {
			unsigned ArgCount = Fixture.Emitter.getLayout().offset(Op, VMFieldRole::ArgCount);
			Size += Fixture.Emitter.BC[*Offset + ArgCount];
		}
		else if (Op == OP_SWITCH) {
			unsigned Cases = Fixture.Emitter.getLayout().offset(Op, VMFieldRole::CaseCount);
			Size += 8u * (Fixture.Emitter.BC[*Offset + Cases] |
				(Fixture.Emitter.BC[*Offset + Cases + 1] << 8));
		}
		uint64_t End = I + 1 == Offsets.size()
			? Fixture.Emitter.BC.size() : *Offsets[I + 1].getAsInteger();
		EXPECT_EQ(*Offset + Size, End);
	}
	EXPECT_EQ(Offsets.front().getAsInteger(), 0);
	EXPECT_TRUE(SawCall);
	EXPECT_TRUE(SawSwitch);
	EXPECT_EQ(Region.getInteger("bytecode_size"), Fixture.Emitter.BC.size());
	EXPECT_EQ(Region.getInteger("opcode_count"), OP_COUNT);
	for (StringRef Field : {"engine_abi_hash", "call_abi_hash", "layout_hash",
		"region_content_hash", "region_id"}) {
		auto Value = Region.getString(Field);
		ASSERT_TRUE(Value.has_value());
		EXPECT_EQ(Value->size(), 64u);
	}
	json::Object Copy = Region;
	auto Bytes = canonicalMaterialJSON(json::Value(std::move(Copy)),
		MaterialCodecProfile::CanonicalRegion);
	ASSERT_TRUE(static_cast<bool>(Bytes)) << toString(Bytes.takeError());
	EXPECT_FALSE(Bytes->empty());
}

TEST(VMMaterial, DynamicArtifactExportSealsCanonicalV2ExecutionMaterial) {
	using namespace xovm::material;
	auto Fixture = makeDynamicFixture();
	const auto Records = Fixture.Emitter.getInstructionRecords();
	ASSERT_EQ(Records.size(), 2u);
	EXPECT_EQ(Records[0], std::make_pair(0u, OP_LOADI));
	EXPECT_EQ(Records[1], std::make_pair(6u, OP_RET_INT));
	auto Export = exportDynamicArtifact(Fixture.Emitter, Fixture.Config, Fixture.Opcodes);
	ASSERT_TRUE(static_cast<bool>(Export)) << toString(Export.takeError());
	const json::Object& Public = Export->PublicManifest;
	const json::Object& Private = Export->PrivateRegistration;
	ASSERT_EQ(Public.getInteger("format_version"), 2);
	ASSERT_EQ(Public.getString("material_source"), "dynamic_vm");
	EXPECT_TRUE(Public.getString("artifact_hash").has_value());
	EXPECT_TRUE(Public.getString("encrypted_artifact_b64").has_value());
	EXPECT_EQ(Public.getString("artifact_key_b64"), std::nullopt);
	EXPECT_FALSE(Public.getString("canonical_bc").has_value());
	EXPECT_EQ(Public.getArray("decode_map"), nullptr);
	EXPECT_TRUE(Private.getString("artifact_key_b64").has_value());
	EXPECT_FALSE(Private.getString("canonical_bc").has_value());
	EXPECT_EQ(Private.getArray("decode_map"), nullptr);
	EXPECT_NE(*Public.getString("encrypted_artifact_b64"),
		encodeBase64(Fixture.Emitter.BC));
	EXPECT_EQ(Public.getString("encrypted_artifact_b64")->find("XOVM-DYNAMIC"),
		StringRef::npos);

	auto Decrypted = decryptDynamicExport(*Export);
	ASSERT_TRUE(Decrypted.has_value());
	EXPECT_EQ(Decrypted->bytecode,
		std::vector<uint8_t>(Fixture.Emitter.BC.begin(), Fixture.Emitter.BC.end()));
	ASSERT_GT(Decrypted->continuation_descriptors.size(),
		kDynamicVmExecutionAbiV2EncodedSize);
	auto Descriptor = ArrayRef<uint8_t>(Decrypted->continuation_descriptors);
	auto Abi = decodeDynamicVmExecutionAbiV2(
		Descriptor.take_front(kDynamicVmExecutionAbiV2EncodedSize));
	auto Graph = decodeContinuationGraphV2(
		Descriptor.drop_front(kDynamicVmExecutionAbiV2EncodedSize));
	auto HandlerPayload = decodeHandlerShardPayload(Decrypted->handler_shards);
	ASSERT_TRUE(Abi.has_value());
	ASSERT_TRUE(Graph.has_value());
	ASSERT_TRUE(HandlerPayload.has_value());
	EXPECT_EQ(Abi->i32_register_count, Fixture.Emitter.NVR);
	EXPECT_EQ(Abi->i64_register_count, Fixture.Emitter.NVR64);
	EXPECT_EQ(Abi->pointer_register_count, Fixture.Emitter.NPR);
	EXPECT_EQ(Abi->f64_register_count, Fixture.Emitter.NFR);
	EXPECT_EQ(Abi->decode_salt, Fixture.Emitter.getDecodeSalt());
	EXPECT_EQ(Abi->loadi32_opcode, Fixture.Opcodes.encode(OP_LOADI));
	EXPECT_EQ(Abi->return_i32_opcode, Fixture.Opcodes.encode(OP_RET_INT));
	EXPECT_EQ(Abi->loadi32_destination_offset,
		Fixture.Emitter.getLayout().offset(OP_LOADI, VMFieldRole::Dst));
	EXPECT_EQ(Abi->loadi32_immediate_offset,
		Fixture.Emitter.getLayout().offset(OP_LOADI, VMFieldRole::Immediate));
	EXPECT_EQ(Abi->return_i32_source_offset,
		Fixture.Emitter.getLayout().offset(OP_RET_INT, VMFieldRole::SrcA));
	ASSERT_EQ(Graph->nodes.size(), 2u);
	EXPECT_EQ(Graph->nodes[0].semantic, ContinuationNodeSemanticV2::LoadI32);
	EXPECT_EQ(Graph->nodes[0].status, ContinuationNodeStatusV2::Continue);
	EXPECT_EQ(Graph->nodes[0].next_node_id, Graph->nodes[1].node_id);
	EXPECT_EQ(Graph->nodes[1].semantic, ContinuationNodeSemanticV2::ReturnI32);
	EXPECT_EQ(Graph->nodes[1].status, ContinuationNodeStatusV2::Return);
	EXPECT_EQ(Graph->nodes[1].next_node_id, 0u);
	EXPECT_EQ(Graph->nodes[0].register_index, Graph->nodes[1].register_index);
	EXPECT_EQ(static_cast<uint8_t>(Decrypted->bytecode[
		Abi->loadi32_destination_offset] ^ Abi->decode_salt),
		Graph->nodes[0].register_index);
	EXPECT_EQ(static_cast<uint8_t>(Decrypted->bytecode[Records[1].first +
		Abi->return_i32_source_offset] ^ Abi->decode_salt),
		Graph->nodes[1].register_index);
	EXPECT_EQ(validateContinuationGraphV2(*Abi, *Graph, Decrypted->bytecode,
		HandlerPayload->code), DynamicVmSchemaStatusV2::Valid);
	secureClear(*Decrypted);
}

TEST(VMMaterial, DynamicArtifactUsesCanonicalRegionIdentity) {
	auto Fixture = makeDynamicFixture();
	auto Canonical = exportCanonicalRegion(Fixture.Emitter, Fixture.Config, Fixture.Opcodes);
	ASSERT_TRUE(static_cast<bool>(Canonical)) << toString(Canonical.takeError());
	auto Dynamic = exportDynamicArtifact(Fixture.Emitter, Fixture.Config, Fixture.Opcodes);
	ASSERT_TRUE(static_cast<bool>(Dynamic)) << toString(Dynamic.takeError());
	EXPECT_EQ(Dynamic->PublicManifest.getString("region_id"),
		Canonical->getString("region_id"));
}

TEST(VMMaterial, DynamicArtifactFailsClosedOutsideExactCompilerSubset) {
	auto ExpectRejected = [](ExportFixture&& Fixture) {
		auto Export = exportDynamicArtifact(Fixture.Emitter, Fixture.Config, Fixture.Opcodes);
		if (Export) return false;
		consumeError(Export.takeError());
		return true;
	};
	EXPECT_TRUE(ExpectRejected(makeFixture()));
	EXPECT_TRUE(ExpectRejected(makeDynamicFixture("keyed", 7, 0x2a, true)));
	EXPECT_TRUE(ExpectRejected(makeDynamicFixture("layout", 7, 0x2a, false, true)));
	EXPECT_TRUE(ExpectRejected(makeDynamicFixture("i64", 7, 0x2a, false, false, true)));

	auto Mismatched = makeDynamicFixture("mismatched");
	const uint32_t ReturnIP = Mismatched.Emitter.getInstructionRecords()[1].first;
	const unsigned ReturnRegister = Mismatched.Emitter.getLayout().offset(
		OP_RET_INT, VMFieldRole::SrcA);
	Mismatched.Emitter.BC[ReturnIP + ReturnRegister] ^= 1;
	EXPECT_TRUE(ExpectRejected(std::move(Mismatched)));

	auto OutOfRange = makeDynamicFixture("out-of-range");
	const uint8_t EncodedOutOfRange =
		OutOfRange.Emitter.NVR ^ OutOfRange.Emitter.getDecodeSalt();
	const unsigned LoadRegister = OutOfRange.Emitter.getLayout().offset(
		OP_LOADI, VMFieldRole::Dst);
	const uint32_t OutOfRangeReturnIP = OutOfRange.Emitter.getInstructionRecords()[1].first;
	const unsigned OutOfRangeReturnRegister = OutOfRange.Emitter.getLayout().offset(
		OP_RET_INT, VMFieldRole::SrcA);
	OutOfRange.Emitter.BC[LoadRegister] = EncodedOutOfRange;
	OutOfRange.Emitter.BC[OutOfRangeReturnIP + OutOfRangeReturnRegister] =
		EncodedOutOfRange;
	EXPECT_TRUE(ExpectRejected(std::move(OutOfRange)));
}

TEST(VMMaterial, DynamicCommitRejectsAuthenticatedHandlerSemanticMismatch) {
	using namespace xovm::material;
	auto Fixture = makeDynamicFixture();
	auto Export = exportDynamicArtifact(Fixture.Emitter, Fixture.Config, Fixture.Opcodes);
	ASSERT_TRUE(static_cast<bool>(Export)) << toString(Export.takeError());
	auto Decrypted = decryptDynamicExport(*Export);
	ASSERT_TRUE(Decrypted.has_value());
	auto Descriptor = ArrayRef<uint8_t>(Decrypted->continuation_descriptors);
	auto Abi = decodeDynamicVmExecutionAbiV2(
		Descriptor.take_front(kDynamicVmExecutionAbiV2EncodedSize));
	auto Graph = decodeContinuationGraphV2(
		Descriptor.drop_front(kDynamicVmExecutionAbiV2EncodedSize));
	auto Payload = decodeHandlerShardPayload(Decrypted->handler_shards);
	ASSERT_TRUE(Abi.has_value());
	ASSERT_TRUE(Graph.has_value());
	ASSERT_TRUE(Payload.has_value());
	ASSERT_EQ(Graph->nodes.size(), 2u);

	auto& LoadNode = Graph->nodes[0];
	auto& ReturnNode = Graph->nodes[1];
	auto WrongLoad = buildAarch64LoadImmediateShard(LoadNode.register_index, 9,
		ReturnNode.bytecode_offset);
	ASSERT_TRUE(WrongLoad.has_value());
	ASSERT_EQ(WrongLoad->size(), LoadNode.shard_size);
	std::copy(WrongLoad->begin(), WrongLoad->end(),
		Payload->code.begin() + LoadNode.shard_offset);
	LoadNode.handler_shard_commitment = hashDynamicVmHandlerShardV2(*WrongLoad);
	auto LoadTail = hashDynamicVmTransitionTailV2(LoadNode);
	ASSERT_TRUE(LoadTail.has_value());
	LoadNode.transition_tail_commitment = *LoadTail;
	auto GraphHash = hashDynamicVmContinuationGraphV2(*Graph);
	ASSERT_TRUE(GraphHash.has_value());
	Graph->descriptor.graph_commitment = *GraphHash;
	EXPECT_EQ(validateContinuationGraphV2(*Abi, *Graph, Decrypted->bytecode,
		Payload->code), DynamicVmSchemaStatusV2::Valid);

	auto AbiBytes = encodeDynamicVmExecutionAbiV2(*Abi);
	auto GraphBytes = encodeContinuationGraphV2(*Graph);
	ASSERT_FALSE(AbiBytes.empty());
	ASSERT_FALSE(GraphBytes.empty());
	AbiBytes.insert(AbiBytes.end(), GraphBytes.begin(), GraphBytes.end());
	Payload->descriptor.commitment = hashAarch64ShardCode(Payload->code);
	auto HandlerBytes = encodeHandlerShardPayload(Payload->descriptor, Payload->code);
	ASSERT_FALSE(HandlerBytes.empty());

	auto Build = parseDynamicHash(*Export->PublicManifest.getString("build_id"));
	auto Region = parseDynamicHash(*Export->PublicManifest.getString("region_id"));
	ASSERT_TRUE(Build.has_value());
	ASSERT_TRUE(Region.has_value());
	std::vector<char> DecodedKey;
	ASSERT_FALSE(decodeBase64(*Export->PrivateRegistration.getString("artifact_key_b64"),
		DecodedKey));
	ASSERT_EQ(DecodedKey.size(), 32u);
	ArtifactSource Source;
	Source.build_id = *Build;
	Source.region_id = *Region;
	std::copy(DecodedKey.begin(), DecodedKey.end(), Source.artifact_key.begin());
	Source.bytecode = Decrypted->bytecode;
	Source.handler_shards = std::move(HandlerBytes);
	Source.continuation_descriptors = std::move(AbiBytes);
	// The artifact boundary independently binds exact native semantics to the
	// authenticated bytecode operands, so a self-consistent graph/code mutation
	// is rejected before encryption or publication.
	auto Rebuilt = buildEncryptedVmArtifact(Source);
	EXPECT_FALSE(Rebuilt.has_value());
	secureClear(*Decrypted);
}

TEST(VMMaterial, DynamicArtifactCommitPublishesSeparatePublicAndPrivateFiles) {
	std::string Root = temporaryRoot();
	auto Cleanup = make_scope_exit([&] { sys::fs::remove_directories(Root); });
	auto Fixture = makeDynamicFixture();
	auto Export = exportDynamicArtifact(Fixture.Emitter, Fixture.Config, Fixture.Opcodes);
	ASSERT_TRUE(static_cast<bool>(Export)) << toString(Export.takeError());
	SmallVector<DynamicArtifactExport, 1> Artifacts;
	Artifacts.push_back(std::move(*Export));
	auto First = commitDynamicArtifacts(Root, "test.app", Artifacts,
		MaterialCommitToken::forExportOnlyTest());
	ASSERT_TRUE(static_cast<bool>(First)) << toString(First.takeError());
	EXPECT_TRUE(StringRef(First->Path).ends_with(".dynamic"));
	EXPECT_TRUE(sys::fs::exists(First->Path + "/public-manifest.json"));
	EXPECT_TRUE(sys::fs::exists(First->Path + "/registration.private.json"));
	auto Again = commitDynamicArtifacts(Root, "test.app", Artifacts,
		MaterialCommitToken::forExportOnlyTest());
	ASSERT_TRUE(static_cast<bool>(Again)) << toString(Again.takeError());
	EXPECT_EQ(Again->Path, First->Path);
}

TEST(VMMaterial, DynamicArtifactCommitAggregatesMultipleRegions) {
	std::string Root = temporaryRoot();
	auto Cleanup = make_scope_exit([&] { sys::fs::remove_directories(Root); });
	SmallVector<DynamicArtifactExport, 2> Artifacts;
	for (StringRef Region : {"auth/payment", "auth/profile"}) {
		auto Fixture = makeDynamicFixture(Region);
		auto Export = exportDynamicArtifact(Fixture.Emitter, Fixture.Config, Fixture.Opcodes);
		ASSERT_TRUE(static_cast<bool>(Export)) << toString(Export.takeError());
		Artifacts.push_back(std::move(*Export));
	}
	auto Result = commitDynamicArtifacts(Root, "test.app", Artifacts,
		MaterialCommitToken::forExportOnlyTest());
	ASSERT_TRUE(static_cast<bool>(Result)) << toString(Result.takeError());
	EXPECT_TRUE(sys::fs::exists(Result->Path + "/public-manifest.json"));
	EXPECT_TRUE(sys::fs::exists(Result->Path + "/registration.private.json"));
}

TEST(VMMaterial, FailedDynamicCommitNeverPublishesBundle) {
	for (MaterialExportFault Fault : {MaterialExportFault::Create,
		MaterialExportFault::Write, MaterialExportFault::FileSync,
		MaterialExportFault::Close, MaterialExportFault::DirectorySync,
		MaterialExportFault::Rename}) {
		std::string Root = temporaryRoot();
		auto Cleanup = make_scope_exit([&] { sys::fs::remove_directories(Root); });
		auto Fixture = makeDynamicFixture();
		auto Export = exportDynamicArtifact(Fixture.Emitter, Fixture.Config, Fixture.Opcodes);
		ASSERT_TRUE(static_cast<bool>(Export)) << toString(Export.takeError());
		SmallVector<DynamicArtifactExport, 1> Artifacts;
		Artifacts.push_back(std::move(*Export));
		auto Result = commitDynamicArtifacts(Root, "test.app", Artifacts,
			MaterialCommitToken::forExportOnlyTest(Fault));
		ASSERT_FALSE(static_cast<bool>(Result));
		consumeError(Result.takeError());
		std::error_code EC;
		sys::fs::directory_iterator It(Root, EC), End;
		ASSERT_FALSE(EC);
		if (It != End) {
			EXPECT_TRUE(StringRef(It->path()).ends_with(".xovm-publish.lock"));
			It.increment(EC);
		}
		EXPECT_EQ(It, End);
	}
}

TEST(VMMaterial, DynamicParentSyncFailureReportsUnknownDurability) {
	std::string Root = temporaryRoot();
	auto Cleanup = make_scope_exit([&] { sys::fs::remove_directories(Root); });
	auto Fixture = makeDynamicFixture();
	auto Export = exportDynamicArtifact(Fixture.Emitter, Fixture.Config, Fixture.Opcodes);
	ASSERT_TRUE(static_cast<bool>(Export)) << toString(Export.takeError());
	SmallVector<DynamicArtifactExport, 1> Artifacts;
	Artifacts.push_back(std::move(*Export));
	auto Result = commitDynamicArtifacts(Root, "test.app", Artifacts,
		MaterialCommitToken::forExportOnlyTest(MaterialExportFault::RootSync));
	ASSERT_TRUE(static_cast<bool>(Result)) << toString(Result.takeError());
	EXPECT_EQ(Result->Durability, MaterialCommitDurability::Unknown);
	struct stat St {};
	EXPECT_EQ(::stat(Result->Path.c_str(), &St), 0);
}

TEST(VMMaterial, DynamicCommitRejectsMismatchedOrMalformedRegistration) {
	for (unsigned Case : {0u, 1u, 2u}) {
		std::string Root = temporaryRoot();
		auto Cleanup = make_scope_exit([&] { sys::fs::remove_directories(Root); });
		auto Fixture = makeDynamicFixture();
		auto Export = exportDynamicArtifact(Fixture.Emitter, Fixture.Config, Fixture.Opcodes);
		ASSERT_TRUE(static_cast<bool>(Export)) << toString(Export.takeError());
		if (Case == 0)
			Export->PrivateRegistration["artifact_hash"] = std::string(64, '0');
		else if (Case == 1)
			Export->PublicManifest["artifact_size"] = 1;
		else
			Export->PublicManifest.erase("encrypted_artifact_b64");
		SmallVector<DynamicArtifactExport, 1> Artifacts;
		Artifacts.push_back(std::move(*Export));
		auto Result = commitDynamicArtifacts(Root, "test.app", Artifacts,
			MaterialCommitToken::forExportOnlyTest());
		ASSERT_FALSE(static_cast<bool>(Result)) << Case;
		consumeError(Result.takeError());
	}
}

TEST(VMMaterial, DynamicCommitRejectsDuplicateRegionIdentity) {
	std::string Root = temporaryRoot();
	auto Cleanup = make_scope_exit([&] { sys::fs::remove_directories(Root); });
	auto Fixture = makeDynamicFixture();
	auto First = exportDynamicArtifact(Fixture.Emitter, Fixture.Config, Fixture.Opcodes);
	ASSERT_TRUE(static_cast<bool>(First)) << toString(First.takeError());
	auto Second = exportDynamicArtifact(Fixture.Emitter, Fixture.Config, Fixture.Opcodes);
	ASSERT_TRUE(static_cast<bool>(Second)) << toString(Second.takeError());
	SmallVector<DynamicArtifactExport, 2> Artifacts;
	Artifacts.push_back(std::move(*First));
	Artifacts.push_back(std::move(*Second));
	auto Result = commitDynamicArtifacts(Root, "test.app", Artifacts,
		MaterialCommitToken::forExportOnlyTest());
	ASSERT_FALSE(static_cast<bool>(Result));
	consumeError(Result.takeError());
}

TEST(VMMaterial, DynamicCommitRejectsCrossBundleRegionConflict) {
	std::string Root = temporaryRoot();
	auto Cleanup = make_scope_exit([&] { sys::fs::remove_directories(Root); });
	auto FirstFixture = makeDynamicFixture("auth/payment", 7);
	auto FirstExport = exportDynamicArtifact(FirstFixture.Emitter, FirstFixture.Config,
		FirstFixture.Opcodes);
	ASSERT_TRUE(static_cast<bool>(FirstExport)) << toString(FirstExport.takeError());
	SmallVector<DynamicArtifactExport, 1> FirstArtifacts;
	FirstArtifacts.push_back(std::move(*FirstExport));
	ASSERT_TRUE(static_cast<bool>(commitDynamicArtifacts(Root, "test.app", FirstArtifacts,
		MaterialCommitToken::forExportOnlyTest())));
	auto SecondFixture = makeDynamicFixture("auth/payment", 9);
	auto SecondExport = exportDynamicArtifact(SecondFixture.Emitter, SecondFixture.Config,
		SecondFixture.Opcodes);
	ASSERT_TRUE(static_cast<bool>(SecondExport)) << toString(SecondExport.takeError());
	SmallVector<DynamicArtifactExport, 1> SecondArtifacts;
	SecondArtifacts.push_back(std::move(*SecondExport));
	auto Result = commitDynamicArtifacts(Root, "test.app", SecondArtifacts,
		MaterialCommitToken::forExportOnlyTest());
	ASSERT_FALSE(static_cast<bool>(Result));
	consumeError(Result.takeError());
}

TEST(VMMaterial, DynamicCommitRejectsUndecryptableArtifact) {
	for (unsigned Case : {0u, 1u, 2u}) {
		std::string Root = temporaryRoot();
		auto Cleanup = make_scope_exit([&] { sys::fs::remove_directories(Root); });
		auto Fixture = makeDynamicFixture();
		auto Export = exportDynamicArtifact(Fixture.Emitter, Fixture.Config, Fixture.Opcodes);
		ASSERT_TRUE(static_cast<bool>(Export)) << toString(Export.takeError());
		if (Case == 0) {
			std::vector<char> Encoded;
			ASSERT_FALSE(decodeBase64(*Export->PublicManifest.getString("encrypted_artifact_b64"), Encoded));
			Encoded.back() ^= 1;
			Export->PublicManifest["encrypted_artifact_b64"] = encodeBase64(Encoded);
		} else if (Case == 1) {
			Export->PublicManifest["artifact_hash"] = std::string(64, '0');
			Export->PrivateRegistration["artifact_hash"] = std::string(64, '0');
		} else {
			Export->PrivateRegistration["artifact_key_b64"] = encodeBase64(
				ArrayRef<uint8_t>(std::array<uint8_t, 32>{}));
		}
		SmallVector<DynamicArtifactExport, 1> Artifacts;
		Artifacts.push_back(std::move(*Export));
		auto Result = commitDynamicArtifacts(Root, "test.app", Artifacts,
			MaterialCommitToken::forExportOnlyTest());
		ASSERT_FALSE(static_cast<bool>(Result)) << Case;
		consumeError(Result.takeError());
	}
}

TEST(VMMaterial, FailedPrivateCommitNeverPromotesInvocation) {
	for (MaterialExportFault Fault : {MaterialExportFault::Create,
		MaterialExportFault::Write,
		MaterialExportFault::FileSync, MaterialExportFault::Close,
		MaterialExportFault::DirectorySync, MaterialExportFault::Rename}) {
		std::string Root = temporaryRoot();
		auto Cleanup = make_scope_exit([&] { sys::fs::remove_directories(Root); });
		auto Fixture = makeFixture();
		auto Region = exportCanonicalRegion(Fixture.Emitter, Fixture.Config, Fixture.Opcodes);
		ASSERT_TRUE(static_cast<bool>(Region)) << toString(Region.takeError());
		SmallVector<json::Object, 1> Regions;
		Regions.push_back(std::move(*Region));
		auto Result = commitCanonicalRegions(Root, "test.app", Regions,
			MaterialCommitToken::forExportOnlyTest(Fault));
		ASSERT_FALSE(static_cast<bool>(Result));
		consumeError(Result.takeError());
		std::error_code EC;
		sys::fs::directory_iterator It(Root, EC), End;
		ASSERT_FALSE(EC);
		if (It != End) {
			EXPECT_TRUE(StringRef(It->path()).ends_with(".xovm-publish.lock"));
			It.increment(EC);
		}
		EXPECT_EQ(It, End);
	}
}

TEST(VMMaterial, ParentSyncFailureReportsCommittedDurabilityUnknown) {
	std::string Root = temporaryRoot();
	auto Cleanup = make_scope_exit([&] { sys::fs::remove_directories(Root); });
	auto Fixture = makeFixture();
	auto Region = exportCanonicalRegion(Fixture.Emitter, Fixture.Config, Fixture.Opcodes);
	ASSERT_TRUE(static_cast<bool>(Region)) << toString(Region.takeError());
	SmallVector<json::Object, 1> Regions;
	Regions.push_back(std::move(*Region));
	auto Result = commitCanonicalRegions(Root, "test.app", Regions,
		MaterialCommitToken::forExportOnlyTest(MaterialExportFault::RootSync));
	ASSERT_TRUE(static_cast<bool>(Result)) << toString(Result.takeError());
	EXPECT_EQ(Result->Durability, MaterialCommitDurability::Unknown);
	struct stat St {};
	EXPECT_EQ(::stat(Result->Path.c_str(), &St), 0);
	auto Retry = commitCanonicalRegions(Root, "test.app", Regions,
		MaterialCommitToken::forExportOnlyTest());
	ASSERT_TRUE(static_cast<bool>(Retry)) << toString(Retry.takeError());
	EXPECT_EQ(Retry->Path, Result->Path);
	EXPECT_EQ(Retry->Durability, MaterialCommitDurability::Durable);
}

TEST(VMMaterial, PrivateCommitIsAtomicIdempotentAndRejectsConflicts) {
	std::string Root = temporaryRoot();
	auto Cleanup = make_scope_exit([&] { sys::fs::remove_directories(Root); });
	auto First = makeFixture();
	auto FirstRegion = exportCanonicalRegion(First.Emitter, First.Config, First.Opcodes);
	ASSERT_TRUE(static_cast<bool>(FirstRegion)) << toString(FirstRegion.takeError());
	SmallVector<json::Object, 1> Regions;
	Regions.push_back(std::move(*FirstRegion));
	auto Token = MaterialCommitToken::forExportOnlyTest();
	auto Path = commitCanonicalRegions(Root, "test.app", Regions, Token);
	ASSERT_TRUE(static_cast<bool>(Path)) << toString(Path.takeError());
	auto Again = commitCanonicalRegions(Root, "test.app", Regions, Token);
	ASSERT_TRUE(static_cast<bool>(Again)) << toString(Again.takeError());
	EXPECT_EQ(Path->Path, Again->Path);
	struct stat St {};
	ASSERT_EQ(::stat(Path->Path.c_str(), &St), 0);
	EXPECT_EQ(St.st_mode & 0777u, 0700u);

	auto Second = makeFixture("auth/payment", 9);
	auto SecondRegion = exportCanonicalRegion(Second.Emitter, Second.Config, Second.Opcodes);
	ASSERT_TRUE(static_cast<bool>(SecondRegion)) << toString(SecondRegion.takeError());
	SmallVector<json::Object, 1> Conflict;
	Conflict.push_back(std::move(*SecondRegion));
	auto Rejected = commitCanonicalRegions(Root, "test.app", Conflict, Token);
	ASSERT_FALSE(static_cast<bool>(Rejected));
	consumeError(Rejected.takeError());

	SmallString<256> Link(Root);
	sys::path::append(Link, "link");
	ASSERT_FALSE(sys::fs::create_link(Root, Link));
	auto ThroughLink = commitCanonicalRegions(Link, "test.app", Regions, Token);
	ASSERT_FALSE(static_cast<bool>(ThroughLink));
	consumeError(ThroughLink.takeError());
}

TEST(VMMaterial, PrivateCommitRejectsTamperedCanonicalRegion) {
	for (StringRef Field : {"canonical_bc", "region_content_hash", "region_id"}) {
		std::string Root = temporaryRoot();
		auto Cleanup = make_scope_exit([&] { sys::fs::remove_directories(Root); });
		auto Fixture = makeFixture();
		auto Region = exportCanonicalRegion(Fixture.Emitter, Fixture.Config, Fixture.Opcodes);
		ASSERT_TRUE(static_cast<bool>(Region)) << toString(Region.takeError());
		if (Field == "canonical_bc") (*Region)[Field] = "AAAA";
		else (*Region)[Field] = std::string(64, '0');
		SmallVector<json::Object, 1> Regions;
		Regions.push_back(std::move(*Region));
		auto Result = commitCanonicalRegions(Root, "test.app", Regions,
			MaterialCommitToken::forExportOnlyTest());
		ASSERT_FALSE(static_cast<bool>(Result)) << Field.str();
		consumeError(Result.takeError());
		std::error_code EC;
		sys::fs::directory_iterator It(Root, EC), End;
		ASSERT_FALSE(EC);
		if (It != End) {
			EXPECT_TRUE(StringRef(It->path()).ends_with(".xovm-publish.lock"));
			It.increment(EC);
		}
		EXPECT_EQ(It, End);
	}
}

TEST(VMMaterial, IndependentVerifierRejectsNonPartitioningRecordsAndMalformedTails) {
	auto CommitRejected = [](json::Object Region) {
		std::string Root = temporaryRoot();
		auto Cleanup = make_scope_exit([&] { sys::fs::remove_directories(Root); });
		rehashRegion(Region);
		SmallVector<json::Object, 1> Regions;
		Regions.push_back(std::move(Region));
		auto Result = commitCanonicalRegions(Root, "test.app", Regions,
			MaterialCommitToken::forExportOnlyTest());
		if (Result) return false;
		consumeError(Result.takeError());
		return true;
	};

	auto Fixture = makeFixture();
	auto Original = exportCanonicalRegion(Fixture.Emitter, Fixture.Config, Fixture.Opcodes);
	ASSERT_TRUE(static_cast<bool>(Original)) << toString(Original.takeError());

	json::Object MissingZero = *Original;
	MissingZero.getArray("instruction_offsets")->erase(
		MissingZero.getArray("instruction_offsets")->begin());
	MissingZero.getArray("logical_opcodes")->erase(
		MissingZero.getArray("logical_opcodes")->begin());
	EXPECT_TRUE(CommitRejected(std::move(MissingZero)));

	json::Object MissingMiddle = *Original;
	size_t Middle = MissingMiddle.getArray("instruction_offsets")->size() / 2;
	MissingMiddle.getArray("instruction_offsets")->erase(
		MissingMiddle.getArray("instruction_offsets")->begin() + Middle);
	MissingMiddle.getArray("logical_opcodes")->erase(
		MissingMiddle.getArray("logical_opcodes")->begin() + Middle);
	EXPECT_TRUE(CommitRejected(std::move(MissingMiddle)));

	json::Object MidTail = *Original;
	auto First = *(*MidTail.getArray("instruction_offsets"))[0].getAsInteger();
	(*MidTail.getArray("instruction_offsets"))[1] = First + 1;
	EXPECT_TRUE(CommitRejected(std::move(MidTail)));

	for (VMOp Wanted : {OP_CALL_INT, OP_SWITCH}) {
		json::Object Malformed = *Original;
		std::vector<char> Bytecode;
		ASSERT_FALSE(decodeBase64(*Malformed.getString("canonical_bc"), Bytecode));
		auto* Offsets = Malformed.getArray("instruction_offsets");
		auto* Opcodes = Malformed.getArray("logical_opcodes");
		bool Found = false;
		for (size_t I = 0; I < Opcodes->size(); ++I) {
			if ((*Opcodes)[I].getAsInteger() != static_cast<int64_t>(Wanted)) continue;
			uint32_t Offset = *(*Offsets)[I].getAsInteger();
			if (Wanted == OP_CALL_INT) {
				unsigned Count = Fixture.Emitter.getLayout().offset(Wanted, VMFieldRole::ArgCount);
				Bytecode[Offset + Count] = 0x7f;
			} else {
				unsigned Count = Fixture.Emitter.getLayout().offset(Wanted, VMFieldRole::CaseCount);
				Bytecode[Offset + Count] = static_cast<char>(0xff);
				Bytecode[Offset + Count + 1] = static_cast<char>(0xff);
			}
			Found = true;
			break;
		}
		ASSERT_TRUE(Found);
		Malformed["canonical_bc"] = encodeBase64(Bytecode);
		EXPECT_TRUE(CommitRejected(std::move(Malformed)));
	}

	json::Object BranchIntoTail = *Original;
	std::vector<char> Bytecode;
	ASSERT_FALSE(decodeBase64(*BranchIntoTail.getString("canonical_bc"), Bytecode));
	auto* Offsets = BranchIntoTail.getArray("instruction_offsets");
	auto* Opcodes = BranchIntoTail.getArray("logical_opcodes");
	bool FoundSwitch = false;
	for (size_t I = 0; I < Opcodes->size(); ++I) {
		if ((*Opcodes)[I].getAsInteger() != static_cast<int64_t>(OP_SWITCH)) continue;
		uint32_t Offset = *(*Offsets)[I].getAsInteger();
		unsigned Target = Fixture.Emitter.getLayout().offset(OP_SWITCH, VMFieldRole::Target);
		uint32_t Invalid = Offset + 1;
		for (unsigned B = 0; B < 4; ++B)
			Bytecode[Offset + Target + B] = static_cast<char>(Invalid >> (8 * B));
		FoundSwitch = true;
		break;
	}
	ASSERT_TRUE(FoundSwitch);
	BranchIntoTail["canonical_bc"] = encodeBase64(Bytecode);
	EXPECT_TRUE(CommitRejected(std::move(BranchIntoTail)));
}

TEST(VMMaterial, BranchDenseCanonicalVerificationHasLinearTargetLookupBound) {
	constexpr uint32_t Count = 2048;
	VMInstructionLayout Layout;
	VMOpcodeMap Opcodes;
	const uint32_t Size = Layout.size(OP_JMP);
	const uint32_t TargetField = Layout.offset(OP_JMP, VMFieldRole::Target);
	std::vector<uint8_t> Bytecode(Count * Size);
	std::vector<uint32_t> Offsets;
	std::vector<uint8_t> Logical(Count, static_cast<uint8_t>(OP_JMP));
	Offsets.reserve(Count);
	const uint32_t Target = (Count - 1) * Size;
	for (uint32_t I = 0; I < Count; ++I) {
		uint32_t IP = I * Size;
		Offsets.push_back(IP);
		Bytecode[IP] = Opcodes.L2P[OP_JMP];
		for (unsigned B = 0; B < 4; ++B)
			Bytecode[IP + TargetField + B] = static_cast<uint8_t>(Target >> (8 * B));
	}
	std::string Error;
	uint32_t BadIP = 0;
	uint64_t Operations = 0;
	ASSERT_TRUE(verifyCanonicalBytecode(Bytecode, Offsets, Logical, Layout, Opcodes,
		{}, {}, 0, Error, BadIP, &Operations)) << Error;
	EXPECT_LE(Operations, static_cast<uint64_t>(Count) * 2);
}

TEST(VMMaterial, ConcurrentSameNameDifferentContentPublishesOnlyOneIdentity) {
	std::string Root = temporaryRoot();
	auto Cleanup = make_scope_exit([&] { sys::fs::remove_directories(Root); });
	auto FirstFixture = makeFixture("auth/payment", 7);
	auto SecondFixture = makeFixture("auth/payment", 9);
	auto First = exportCanonicalRegion(FirstFixture.Emitter, FirstFixture.Config,
		FirstFixture.Opcodes);
	auto Second = exportCanonicalRegion(SecondFixture.Emitter, SecondFixture.Config,
		SecondFixture.Opcodes);
	ASSERT_TRUE(static_cast<bool>(First)) << toString(First.takeError());
	ASSERT_TRUE(static_cast<bool>(Second)) << toString(Second.takeError());

	std::mutex Mutex;
	std::condition_variable Ready;
	unsigned Waiting = 0;
	bool Start = false;
	std::vector<uint8_t> Succeeded(2);
	std::vector<std::thread> Threads;
	for (unsigned I = 0; I < Succeeded.size(); ++I) {
		Threads.emplace_back([&, I] {
			{
				std::unique_lock Lock(Mutex);
				++Waiting;
				Ready.notify_all();
				Ready.wait(Lock, [&] { return Start; });
			}
			SmallVector<json::Object, 1> Regions;
			Regions.push_back(I & 1 ? *First : *Second);
			auto Result = commitCanonicalRegions(Root, "test.app", Regions,
				MaterialCommitToken::forExportOnlyTest());
			Succeeded[I] = static_cast<bool>(Result);
			if (!Result) consumeError(Result.takeError());
		});
	}
	{
		std::unique_lock Lock(Mutex);
		Ready.wait(Lock, [&] { return Waiting == Succeeded.size(); });
		Start = true;
		Ready.notify_all();
	}
	for (auto& Thread : Threads) Thread.join();

	std::error_code EC;
	unsigned Bundles = 0;
	for (sys::fs::directory_iterator It(Root, EC), End; It != End && !EC; It.increment(EC))
		Bundles += StringRef(It->path()).ends_with(".materials");
	ASSERT_FALSE(EC);
	EXPECT_EQ(Bundles, 1u);
	EXPECT_EQ(llvm::count(Succeeded, 1), 1u);
}

TEST(VMMaterial, IdempotentCommitRejectsUnexpectedPublishedFiles) {
	std::string Root = temporaryRoot();
	auto Cleanup = make_scope_exit([&] { sys::fs::remove_directories(Root); });
	auto Fixture = makeFixture();
	auto Region = exportCanonicalRegion(Fixture.Emitter, Fixture.Config, Fixture.Opcodes);
	ASSERT_TRUE(static_cast<bool>(Region)) << toString(Region.takeError());
	SmallVector<json::Object, 1> Regions;
	Regions.push_back(std::move(*Region));
	auto Token = MaterialCommitToken::forExportOnlyTest();
	auto Path = commitCanonicalRegions(Root, "test.app", Regions, Token);
	ASSERT_TRUE(static_cast<bool>(Path)) << toString(Path.takeError());
	SmallString<256> Unexpected(Path->Path);
	sys::path::append(Unexpected, "unexpected");
	int FD = ::open(Unexpected.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
	ASSERT_GE(FD, 0);
	ASSERT_EQ(::write(FD, "x", 1), 1);
	ASSERT_EQ(::close(FD), 0);
	auto Again = commitCanonicalRegions(Root, "test.app", Regions, Token);
	ASSERT_FALSE(static_cast<bool>(Again));
	consumeError(Again.takeError());
}

TEST(VMMaterial, IdempotentCommitRejectsDestinationSwapAfterComparison) {
	std::string Root = temporaryRoot();
	auto Cleanup = make_scope_exit([&] { sys::fs::remove_directories(Root); });
	auto Fixture = makeFixture();
	auto Region = exportCanonicalRegion(Fixture.Emitter, Fixture.Config, Fixture.Opcodes);
	ASSERT_TRUE(static_cast<bool>(Region)) << toString(Region.takeError());
	SmallVector<json::Object, 1> Regions;
	Regions.push_back(std::move(*Region));
	auto First = commitCanonicalRegions(Root, "test.app", Regions,
		MaterialCommitToken::forExportOnlyTest());
	ASSERT_TRUE(static_cast<bool>(First)) << toString(First.takeError());
	auto Retry = commitCanonicalRegions(Root, "test.app", Regions,
		MaterialCommitToken::forExportOnlyTest(MaterialExportFault::DestinationSwap));
	ASSERT_FALSE(static_cast<bool>(Retry));
	consumeError(Retry.takeError());
}

TEST(VMMaterial, IdempotentCommitRejectsMemberMutationAndPathSwap) {
	for (MaterialExportFault Fault : {MaterialExportFault::MemberContent,
		MaterialExportFault::MemberSwap}) {
		std::string Root = temporaryRoot();
		auto Cleanup = make_scope_exit([&] { sys::fs::remove_directories(Root); });
		auto Fixture = makeFixture();
		auto Region = exportCanonicalRegion(Fixture.Emitter, Fixture.Config, Fixture.Opcodes);
		ASSERT_TRUE(static_cast<bool>(Region)) << toString(Region.takeError());
		SmallVector<json::Object, 1> Regions;
		Regions.push_back(std::move(*Region));
		auto First = commitCanonicalRegions(Root, "test.app", Regions,
			MaterialCommitToken::forExportOnlyTest());
		ASSERT_TRUE(static_cast<bool>(First)) << toString(First.takeError());
		auto Retry = commitCanonicalRegions(Root, "test.app", Regions,
			MaterialCommitToken::forExportOnlyTest(Fault));
		ASSERT_FALSE(static_cast<bool>(Retry));
		consumeError(Retry.takeError());
	}
}

TEST(VMMaterial, ExportFixtureForAggregator) {
	const char* Requested = std::getenv("XOVM_TEST_EXPORT_ROOT");
	std::string Owned;
	StringRef Root;
	if (Requested) Root = Requested;
	else { Owned = temporaryRoot(); Root = Owned; }
	auto Cleanup = make_scope_exit([&] {
		if (!Requested) sys::fs::remove_directories(Owned);
	});
	auto Fixture = makeFixture();
	auto Region = exportCanonicalRegion(Fixture.Emitter, Fixture.Config, Fixture.Opcodes);
	ASSERT_TRUE(static_cast<bool>(Region)) << toString(Region.takeError());
	auto OtherFixture = makeFixture("zeta", 19);
	auto Other = exportCanonicalRegion(OtherFixture.Emitter, OtherFixture.Config,
		OtherFixture.Opcodes);
	ASSERT_TRUE(static_cast<bool>(Other)) << toString(Other.takeError());
	SmallVector<json::Object, 2> Regions;
	Regions.push_back(std::move(*Region));
	Regions.push_back(std::move(*Other));
	auto Result = commitCanonicalRegions(Root, "test.app", Regions,
		MaterialCommitToken::forExportOnlyTest());
	ASSERT_TRUE(static_cast<bool>(Result)) << toString(Result.takeError());
}

#ifdef XOLLVM_MATERIAL_PACKAGE_TEST_BRIDGE
TEST(VMMaterial, VerifyExecutionPackageFixture) {
	if (!std::getenv("XOVM_TEST_PACKAGE_BRIDGE")) GTEST_SKIP();
	std::string MetadataText;
	ASSERT_TRUE(static_cast<bool>(std::getline(std::cin, MetadataText)));
	std::string PackageText((std::istreambuf_iterator<char>(std::cin)),
		std::istreambuf_iterator<char>());
	nlohmann::json Metadata;
	ASSERT_NO_THROW(Metadata = nlohmann::json::parse(MetadataText));
	ASSERT_TRUE(Metadata.is_object());
	ASSERT_TRUE(Metadata.contains("binding"));
	ASSERT_TRUE(Metadata.contains("region"));
	ASSERT_TRUE(Metadata.contains("verifier_descriptor"));

	auto Binding = xovm::material::parseMaterialBinding(Metadata.at("binding"));
	ASSERT_FALSE(std::holds_alternative<xovm::material::PackageError>(Binding));
	auto Package = xovm::material::parseExecutionPackage(ArrayRef<uint8_t>(
		reinterpret_cast<const uint8_t*>(PackageText.data()), PackageText.size()),
		std::get<xovm::material::MaterialBinding>(Binding));
	ASSERT_FALSE(std::holds_alternative<xovm::material::PackageError>(Package));
	auto& Parsed = std::get<xovm::material::ParsedPackage>(Package);

	auto RegionValue = json::parse(Metadata.at("region").dump());
	ASSERT_TRUE(static_cast<bool>(RegionValue));
	auto* Region = RegionValue->getAsObject();
	ASSERT_NE(Region, nullptr);
	const auto* Offsets = Region->getArray("instruction_offsets");
	const auto* Logical = Region->getArray("logical_opcodes");
	auto CanonicalText = Region->getString("canonical_bc");
	ASSERT_NE(Offsets, nullptr);
	ASSERT_NE(Logical, nullptr);
	ASSERT_TRUE(CanonicalText.has_value());
	std::vector<char> CanonicalChars;
	ASSERT_FALSE(decodeBase64(*CanonicalText, CanonicalChars));
	std::vector<uint8_t> Canonical(CanonicalChars.begin(), CanonicalChars.end());
	ASSERT_EQ(Parsed.bytecode.size(), Canonical.size());
	ASSERT_EQ(Offsets->size(), Logical->size());
	for (const json::Value& Value : *Offsets) {
		auto Offset = Value.getAsUINT64();
		ASSERT_TRUE(Offset.has_value());
		ASSERT_LT(*Offset, Parsed.bytecode.size());
		uint16_t Physical = Parsed.decode_map[Parsed.bytecode[*Offset]];
		ASSERT_LE(Physical, 255u);
		Parsed.bytecode[*Offset] = static_cast<uint8_t>(Physical);
	}
	ASSERT_EQ(Parsed.bytecode, Canonical);

	std::vector<char> DescriptorChars;
	ASSERT_FALSE(decodeBase64(Metadata.at("verifier_descriptor").get<std::string>(),
		DescriptorChars));
	uint64_t Operations = 0;
	Error VerifyError = verifyCanonicalRegionWithDescriptor(*Region,
		StringRef(DescriptorChars.data(), DescriptorChars.size()), Parsed.bytecode,
		&Operations);
	ASSERT_FALSE(static_cast<bool>(VerifyError)) << toString(std::move(VerifyError));

	bool SawArithmetic = false;
	bool SawFP = false;
	bool SawCall = false;
	bool SawSwitch = false;
	bool SawBranch = false;
	for (const json::Value& Value : *Logical) {
		auto Raw = Value.getAsUINT64();
		ASSERT_TRUE(Raw.has_value());
		VMOp Op = static_cast<VMOp>(*Raw);
		SawArithmetic |= Op == OP_BINOP || Op == OP_BINOP64 ||
			(Op >= OP_MULADD && Op <= OP_GEP_STORE64);
		SawFP |= (Op >= OP_LOADI_F && Op <= OP_SELECT_F) ||
			(Op >= OP_FNEG && Op <= OP_FCAST_V64F);
		SawCall |= Op == OP_CALL_VOID || Op == OP_CALL_INT || Op == OP_CALL_PTR ||
			Op == OP_CALL_INT64 || Op == OP_CALL_F;
		SawSwitch |= Op == OP_SWITCH;
		SawBranch |= Op == OP_JMP || Op == OP_JMPC || Op == OP_SWITCH;
	}
	ASSERT_TRUE(SawArithmetic);
	ASSERT_TRUE(SawFP);
	ASSERT_TRUE(SawCall);
	ASSERT_TRUE(SawSwitch);
	ASSERT_TRUE(SawBranch);
	outs() << "XOVM_NATIVE_VERDICT {\"ok\":true,\"bytecode_size\":" << Parsed.bytecode.size()
		<< ",\"generation\":\"" << Parsed.binding.generation
		<< "\",\"native_descriptor_verified\":true"
		<< ",\"native_semantics_verified\":true"
		<< ",\"package_hash\":\"" << Parsed.binding.package_hash
		<< "\",\"reverse_matches_canonical\":true}\n";
}
#endif

} // namespace
