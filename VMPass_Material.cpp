#include "llvm/Transforms/Obfuscator/VMPass_Material.h"

#include "llvm/ADT/ScopeExit.h"
#include "llvm/ADT/SmallString.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/Support/Base64.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/RandomNumberGenerator.h"
#include "llvm/Support/SHA256.h"
#include "llvm/Transforms/Obfuscator/ObfuscationConfig.h"
#include "llvm/Transforms/Obfuscator/VMPass_Emitter.h"
#include "llvm/Transforms/Obfuscator/VMPass_ISA.h"
#include "llvm/Transforms/Obfuscator/VMPass_Verifier.h"
#include "runtime/cloud_material/dynamic_vm_artifact.h"
#include "runtime/cloud_material/dynamic_vm_schema.h"
#include "runtime/cloud_material/dynamic_vm_shard.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <dirent.h>
#include <fcntl.h>
#include <mutex>
#include <set>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unordered_map>
#include <unistd.h>

using namespace llvm;

namespace {

constexpr size_t kMaxRegionBytes = 192 * 1024 * 1024;
constexpr size_t kMaxManifestBytes = 4 * 1024 * 1024;
constexpr size_t kMaxRegistrationBytes = 512 * 1024 * 1024;
constexpr size_t kMaxBytecodeBytes = 8388608;
constexpr size_t kMaxBase64Bytes = 11184812;
constexpr size_t kMaxInstructionItems = 8388608;
constexpr unsigned kCommitToken = 0x584f564d;
constexpr StringLiteral kLockName = ".xovm-publish.lock";

std::mutex VerifierDescriptorsMutex;
std::unordered_map<std::string, std::string> VerifierDescriptors;

Error materialError(StringRef Message) {
	return createStringError(inconvertibleErrorCode(), Message.str());
}

bool validASCII(StringRef Text, size_t Max) {
	if (Text.size() > Max) return false;
	return llvm::all_of(Text, [](unsigned char C) { return C >= 0x20 && C <= 0x7e; });
}

bool validId(StringRef Text) {
	if (Text.empty() || Text.size() > 64) return false;
	auto Alnum = [](unsigned char C) {
		return (C >= 'A' && C <= 'Z') || (C >= 'a' && C <= 'z') ||
			(C >= '0' && C <= '9');
	};
	if (!Alnum(Text.front())) return false;
	return llvm::all_of(Text.drop_front(), [&](unsigned char C) {
		return Alnum(C) || C == '.' || C == '_' || C == '-';
	});
}

bool validName(StringRef Text) {
	if (Text.empty() || Text.size() > 128) return false;
	auto Alnum = [](unsigned char C) {
		return (C >= 'A' && C <= 'Z') || (C >= 'a' && C <= 'z') ||
			(C >= '0' && C <= '9');
	};
	if (!Alnum(Text.front())) return false;
	return llvm::all_of(Text.drop_front(), [&](unsigned char C) {
		return Alnum(C) || C == '.' || C == '_' || C == ':' || C == '/' || C == '-';
	});
}

bool validHash(StringRef Text) {
	return Text.size() == 64 && llvm::all_of(Text, [](unsigned char C) {
		return (C >= '0' && C <= '9') || (C >= 'a' && C <= 'f');
	});
}

size_t profileLimit(MaterialCodecProfile Profile) {
	switch (Profile) {
	case MaterialCodecProfile::CanonicalRegion: return kMaxRegionBytes;
	case MaterialCodecProfile::PublicManifest: return kMaxManifestBytes;
	case MaterialCodecProfile::PrivateRegistration: return kMaxRegistrationBytes;
	}
	llvm_unreachable("unknown material codec profile");
}

size_t arrayLimit(MaterialCodecProfile Profile, StringRef Owner) {
	if ((Profile == MaterialCodecProfile::CanonicalRegion ||
		Profile == MaterialCodecProfile::PrivateRegistration) &&
		(Owner == "instruction_offsets" || Owner == "logical_opcodes"))
		return kMaxInstructionItems;
	if (Owner == "regions") return 4096;
	if (Owner == "register_counts") return 32;
	return 256;
}

void appendEscaped(std::string& Out, StringRef Text) {
	Out.push_back('"');
	for (char C : Text) {
		if (C == '"' || C == '\\') Out.push_back('\\');
		Out.push_back(C);
	}
	Out.push_back('"');
}

Error encodeCanonical(const json::Value& Value, std::string& Out, unsigned Depth,
	MaterialCodecProfile Profile, StringRef Owner = {}) {
	if (Depth > 8) return materialError("material JSON depth limit");
	switch (Value.kind()) {
	case json::Value::Null:
		return materialError("material JSON null is not canonical");
	case json::Value::Boolean:
		Out += *Value.getAsBoolean() ? "true" : "false";
		return Error::success();
	case json::Value::Number: {
		auto Number = Value.getAsUINT64();
		if (!Number || *Number > UINT32_MAX)
			return materialError("material JSON number is not U32");
		Out += std::to_string(*Number);
		return Error::success();
	}
	case json::Value::String: {
		auto Text = Value.getAsString();
		size_t Limit = ((Owner == "canonical_bc" &&
			Profile != MaterialCodecProfile::PublicManifest) ||
			Owner == "encrypted_artifact_b64") ? kMaxBase64Bytes : 256;
		if (!Text || !validASCII(*Text, Limit))
			return materialError("material JSON string is not ASCII");
		appendEscaped(Out, *Text);
		return Error::success();
	}
	case json::Value::Array: {
		const auto* Array = Value.getAsArray();
		if (!Array || Array->size() > arrayLimit(Profile, Owner))
			return materialError("material JSON array limit");
		Out.push_back('[');
		for (unsigned I = 0; I < Array->size(); ++I) {
			if (I) Out.push_back(',');
			if (Error E = encodeCanonical((*Array)[I], Out, Depth + 1, Profile, Owner)) return E;
		}
		Out.push_back(']');
		return Error::success();
	}
	case json::Value::Object: {
		const auto* Object = Value.getAsObject();
		if (!Object || Object->size() > 40)
			return materialError("material JSON object limit");
		SmallVector<std::pair<StringRef, const json::Value*>, 40> Fields;
		for (const auto& Entry : *Object) Fields.push_back({Entry.first, &Entry.second});
		llvm::sort(Fields, [](const auto& A, const auto& B) { return A.first < B.first; });
		Out.push_back('{');
		for (unsigned I = 0; I < Fields.size(); ++I) {
			StringRef Key = Fields[I].first;
			if (Key.empty() || Key.size() > 64 || Key.front() < 'a' || Key.front() > 'z' ||
				!llvm::all_of(Key.drop_front(), [](unsigned char C) {
					return (C >= 'a' && C <= 'z') || (C >= '0' && C <= '9') || C == '_';
				})) return materialError("material JSON invalid key");
			if (I) Out.push_back(',');
			appendEscaped(Out, Key);
			Out.push_back(':');
			if (Error E = encodeCanonical(*Fields[I].second, Out, Depth + 1,
				Profile, Key)) return E;
		}
		Out.push_back('}');
		return Error::success();
	}
	}
	llvm_unreachable("unknown JSON kind");
}

std::string hashBytes(StringRef Bytes) {
	auto Digest = SHA256::hash(arrayRefFromStringRef(Bytes));
	return toHex(ArrayRef<uint8_t>(Digest), true);
}

std::string frameHash(StringRef Label, StringRef Part) {
	std::string Bytes = Label.str();
	Bytes.push_back('\0');
	uint32_t Size = Part.size();
	for (int Shift : {24, 16, 8, 0}) Bytes.push_back(static_cast<char>(Size >> Shift));
	Bytes.append(Part);
	return hashBytes(Bytes);
}

xovm::material::DynamicHash dynamicHash(StringRef Label, StringRef Part) {
	std::string Framed = Label.str();
	Framed.push_back('\0');
	uint32_t Size = Part.size();
	for (int Shift : {24, 16, 8, 0}) Framed.push_back(static_cast<char>(Size >> Shift));
	Framed.append(Part);
	auto Digest = SHA256::hash(arrayRefFromStringRef(Framed));
	xovm::material::DynamicHash Result{};
	std::copy(Digest.begin(), Digest.end(), Result.begin());
	return Result;
}

std::string dynamicHashHex(const xovm::material::DynamicHash& Hash) {
	return toHex(ArrayRef<uint8_t>(Hash), true);
}

std::optional<xovm::material::DynamicHash> parseDynamicHash(StringRef Text) {
	if (Text.size() != 64) return std::nullopt;
	auto HexValue = [](char C) -> int {
		if (C >= '0' && C <= '9') return C - '0';
		if (C >= 'a' && C <= 'f') return C - 'a' + 10;
		if (C >= 'A' && C <= 'F') return C - 'A' + 10;
		return -1;
	};
	xovm::material::DynamicHash Result{};
	for (unsigned I = 0; I < Result.size(); ++I) {
		int High = HexValue(Text[I * 2]);
		int Low = HexValue(Text[I * 2 + 1]);
		if (High < 0 || Low < 0) return std::nullopt;
		Result[I] = static_cast<uint8_t>((High << 4) | Low);
	}
	return Result;
}

std::string stableType(Type* Ty) {
	if (Ty->isVoidTy()) return "void";
	if (Ty->isPointerTy()) return "ptr";
	if (Ty->isFloatTy()) return "f32";
	if (Ty->isDoubleTy()) return "f64";
	if (auto* Integer = dyn_cast<IntegerType>(Ty))
		return (Twine("i") + Twine(Integer->getBitWidth())).str();
	return "unsupported";
}

std::string stableFunctionABI(FunctionType* Type, AttributeList Attrs) {
	std::string Result = "xovm-call-abi-v1|ret=" + stableType(Type->getReturnType());
	Result += "|vararg=" + std::to_string(Type->isVarArg());
	for (unsigned I = 0; I < Type->getNumParams(); ++I) {
		Result += "|arg=" + stableType(Type->getParamType(I));
		Result += "|attrs=" + Attrs.getParamAttrs(I).getAsString();
	}
	Result += "|retattrs=" + Attrs.getRetAttrs().getAsString();
	Result += "|fnattrs=" + Attrs.getFnAttrs().getAsString();
	return Result;
}

std::string engineABISpec() {
	return "xovm-engine-abi-v1|banks=vreg:i32,vreg64:i64,freg:f64,preg:ptr|"
		"call-index:u8|opcode:u8|target:u32le|bytecode-size:u32";
}

std::string layoutSpec(const VMInstructionLayout& Layout) {
	std::string Result = "xovm-layout-v2";
	for (unsigned Op = 0; Op < OP_COUNT; ++Op) {
		Result += "|op=" + std::to_string(Op) + ",size=" + std::to_string(Layout.size(static_cast<VMOp>(Op))) +
			",var=" + std::to_string(Layout.variable(static_cast<VMOp>(Op)));
		for (const auto& Field : Layout.fields(static_cast<VMOp>(Op))) {
			Result += ",field=" + std::to_string(static_cast<unsigned>(Field.Role)) + ":" +
				std::to_string(Field.Canonical) + ":" + std::to_string(Field.Offset) + ":" +
				std::to_string(Field.Width);
		}
	}
	return Result;
}

std::string operandSpec(const ISAEnc* Encoding, const VMOpcodeMap* Opcodes = nullptr,
	uint32_t TargetKey = 0) {
	ISAEnc Identity;
	const ISAEnc& E = Encoding ? *Encoding : Identity;
	std::string Result = "xovm-operand-encoding-v2";
	auto Append = [&](StringRef Name, const uint8_t* Values, unsigned Count) {
		Result += "|" + Name.str() + "=";
		for (unsigned I = 0; I < Count; ++I) {
			if (I) Result.push_back(',');
			Result += std::to_string(Values[I]);
		}
	};
	Append("bin", E.BinSubopL2P, ISAEnc::kNumBinSubop);
	Append("icmp", E.IcmpPredL2P, ISAEnc::kNumIcmpPred);
	Append("cast", E.CastKindL2P, ISAEnc::kNumCastKind);
	Append("fbin", E.FBinSubopL2P, ISAEnc::kNumFBinSubop);
	Append("fcmp", E.FcmpPredL2P, ISAEnc::kNumFcmpPred);
	Append("cast64", E.Cast64KindL2P, ISAEnc::kNumCast64Kind);
	Append("fcast", E.FCastKindL2P, ISAEnc::kNumFCastKind);
	Append("select", E.SelectKindL2P, ISAEnc::kNumSelectKind);
	if (Opcodes) Append("opcode", Opcodes->L2P, OP_COUNT);
	Result += "|target-format=xor-le32-v1|target-key=" + std::to_string(TargetKey);
	return Result;
}

uint32_t targetKey(const BytecodeEmitter& Emitter) {
	if (!Emitter.hasBlindedTargets()) return 0;
	uint32_t Key = Emitter.getTargetSalt() ^ 0x2545F491u;
	Key *= 0x9E3779B1u;
	return Key ^ (Key >> 16);
}

std::string callABISpec(const BytecodeEmitter& Emitter);

void appendU16(std::string& Out, uint16_t Value) {
	Out.push_back(static_cast<char>(Value));
	Out.push_back(static_cast<char>(Value >> 8));
}

void appendU32(std::string& Out, uint32_t Value) {
	for (unsigned Shift : {0, 8, 16, 24})
		Out.push_back(static_cast<char>(Value >> Shift));
}

std::string verifierDescriptor(const BytecodeEmitter& Emitter,
	const VMOpcodeMap& Opcodes) {
	std::string Result("XOVMVR1\0", 8);
	appendU32(Result, 1);
	appendU32(Result, targetKey(Emitter));
	appendU16(Result, OP_COUNT);
	Result.append(reinterpret_cast<const char*>(Opcodes.L2P), OP_COUNT);
	appendU16(Result, Emitter.CalleeFTyTab.size());
	for (FunctionType* FunctionTy : Emitter.CalleeFTyTab) {
		Result.push_back(static_cast<char>(FunctionTy->getNumParams()));
		Type* Return = FunctionTy->getReturnType();
		uint8_t Kind = Return->isVoidTy() ? 0 : Return->isIntegerTy(32) ? 1 :
			Return->isPointerTy() ? 2 : Return->isIntegerTy(64) ? 3 :
			Return->isFloatingPointTy() ? 4 : 0xff;
		Result.push_back(static_cast<char>(Kind));
	}
	appendU16(Result, OP_COUNT);
	const VMInstructionLayout& Layout = Emitter.getLayout();
	for (unsigned Value = 0; Value < OP_COUNT; ++Value) {
		VMOp Op = static_cast<VMOp>(Value);
		Result.push_back(static_cast<char>(Layout.size(Op)));
		Result.push_back(Layout.variable(Op) ? 1 : 0);
		Result.push_back(static_cast<char>(Layout.fields(Op).size()));
		for (const VMLayoutField& Field : Layout.fields(Op)) {
			Result.push_back(static_cast<char>(Field.Role));
			Result.push_back(static_cast<char>(Field.Canonical));
			Result.push_back(static_cast<char>(Field.Offset));
			Result.push_back(static_cast<char>(Field.Width));
		}
	}
	std::string Call = callABISpec(Emitter);
	appendU32(Result, Call.size());
	Result.append(Call);
	std::string Operand = operandSpec(Emitter.getISAEnc(), &Opcodes, targetKey(Emitter));
	appendU32(Result, Operand.size());
	Result.append(Operand);
	return Result;
}

bool decodeVerifierDescriptor(StringRef Bytes, VMInstructionLayout& Layout,
	VMOpcodeMap& Opcodes, SmallVectorImpl<uint8_t>& CallArities,
	SmallVectorImpl<uint8_t>& CallReturnKinds,
	uint32_t& TargetKey, std::string& CallSpec, std::string& OperandSpec) {
	size_t Position = 0;
	auto take = [&](size_t Count) -> StringRef {
		if (Count > Bytes.size() - Position) return {};
		StringRef Result = Bytes.substr(Position, Count);
		Position += Count;
		return Result;
	};
	auto readU16 = [&]() -> std::optional<uint16_t> {
		StringRef Data = take(2);
		if (Data.size() != 2) return std::nullopt;
		return static_cast<uint16_t>(static_cast<uint8_t>(Data[0]) |
			(static_cast<uint16_t>(static_cast<uint8_t>(Data[1])) << 8));
	};
	auto readU32 = [&]() -> std::optional<uint32_t> {
		StringRef Data = take(4);
		if (Data.size() != 4) return std::nullopt;
		return static_cast<uint32_t>(static_cast<uint8_t>(Data[0])) |
			(static_cast<uint32_t>(static_cast<uint8_t>(Data[1])) << 8) |
			(static_cast<uint32_t>(static_cast<uint8_t>(Data[2])) << 16) |
			(static_cast<uint32_t>(static_cast<uint8_t>(Data[3])) << 24);
	};
	if (take(8) != StringRef("XOVMVR1\0", 8)) return false;
	auto Version = readU32();
	auto Key = readU32();
	auto OpcodeCount = readU16();
	if (!Version || *Version != 1 || !Key || !OpcodeCount || *OpcodeCount != OP_COUNT)
		return false;
	TargetKey = *Key;
	StringRef Map = take(OP_COUNT);
	if (Map.size() != OP_COUNT) return false;
	std::array<bool, OP_COUNT> Seen{};
	for (unsigned Logical = 0; Logical < OP_COUNT; ++Logical) {
		uint8_t Physical = static_cast<uint8_t>(Map[Logical]);
		if (Physical >= OP_COUNT || Seen[Physical]) return false;
		Seen[Physical] = true;
		Opcodes.L2P[Logical] = Physical;
		Opcodes.P2L[Physical] = Logical;
	}
	auto CallCount = readU16();
	if (!CallCount || *CallCount > 252) return false;
	StringRef Calls = take(*CallCount * 2);
	if (Calls.size() != *CallCount * 2) return false;
	for (unsigned I = 0; I < *CallCount; ++I) {
		uint8_t Arity = static_cast<uint8_t>(Calls[I * 2]);
		uint8_t Kind = static_cast<uint8_t>(Calls[I * 2 + 1]);
		if (Arity > 16) return false;
		CallArities.push_back(Arity);
		if (Kind > 4) return false;
		CallReturnKinds.push_back(Kind);
	}
	auto LayoutCount = readU16();
	if (!LayoutCount || *LayoutCount != OP_COUNT) return false;
	for (unsigned Value = 0; Value < OP_COUNT; ++Value) {
		StringRef Header = take(3);
		if (Header.size() != 3) return false;
		VMOp Op = static_cast<VMOp>(Value);
		if (static_cast<uint8_t>(Header[0]) != Layout.size(Op) ||
			static_cast<uint8_t>(Header[1]) != Layout.variable(Op)) return false;
		SmallVector<VMLayoutField, 8> Fields;
		for (unsigned I = 0; I < static_cast<uint8_t>(Header[2]); ++I) {
			StringRef Field = take(4);
			if (Field.size() != 4) return false;
			Fields.push_back({static_cast<VMFieldRole>(static_cast<uint8_t>(Field[0])),
				static_cast<uint8_t>(Field[1]), static_cast<uint8_t>(Field[2]),
				static_cast<uint8_t>(Field[3])});
		}
		if (!Layout.setFields(Op, Fields)) return false;
	}
	auto CallSize = readU32();
	if (!CallSize) return false;
	StringRef CallsSpec = take(*CallSize);
	if (CallsSpec.size() != *CallSize) return false;
	CallSpec = CallsSpec.str();
	auto OperandSize = readU32();
	if (!OperandSize) return false;
	StringRef Operands = take(*OperandSize);
	if (Operands.size() != *OperandSize || Position != Bytes.size())
		return false;
	OperandSpec = Operands.str();
	std::string OpcodeSuffix = "|opcode=";
	for (unsigned I = 0; I < OP_COUNT; ++I) {
		if (I) OpcodeSuffix.push_back(',');
		OpcodeSuffix += std::to_string(Opcodes.L2P[I]);
	}
	OpcodeSuffix += "|target-format=xor-le32-v1|target-key=" +
		std::to_string(TargetKey);
	if (!StringRef(OperandSpec).ends_with(OpcodeSuffix)) return false;
	StringRef Remaining(CallSpec);
	if (!Remaining.consume_front("xovm-call-table-v1")) return false;
	for (unsigned Slot = 0; Slot < *CallCount; ++Slot) {
		std::string Prefix = "|slot=" + std::to_string(Slot) + "|";
		if (!Remaining.consume_front(Prefix)) return false;
		size_t Next = Remaining.find("|slot=");
		StringRef Entry = Remaining.take_front(Next);
		Remaining = Next == StringRef::npos ? StringRef() : Remaining.drop_front(Next);
		unsigned Arguments = 0;
		for (size_t Position = 0; (Position = Entry.find("|arg=", Position)) != StringRef::npos;
			Position += 5) ++Arguments;
		if (Arguments != CallArities[Slot]) return false;
		StringRef Return = Entry.split("|ret=").second.split('|').first;
		uint8_t Kind = Return == "void" ? 0 : Return == "i32" ? 1 :
			Return == "ptr" ? 2 : Return == "i64" ? 3 :
			(Return == "f32" || Return == "f64") ? 4 : 0xff;
		if (Kind != CallReturnKinds[Slot]) return false;
	}
	if (!Remaining.empty()) return false;
	return Layout.validate();
}

std::string callABISpec(const BytecodeEmitter& Emitter) {
	std::string Result = "xovm-call-table-v1";
	for (unsigned I = 0; I < Emitter.CalleeFTyTab.size(); ++I) {
		Result += "|slot=" + std::to_string(I) + "|" +
			stableFunctionABI(Emitter.CalleeFTyTab[I], Emitter.CalleeABIAttrs[I]);
	}
	return Result;
}

Error writeAll(int FD, StringRef Bytes, MaterialExportFault Fault) {
	if (Fault == MaterialExportFault::Write)
		return materialError("material private write failed");
	while (!Bytes.empty()) {
		ssize_t Written = ::write(FD, Bytes.data(), Bytes.size());
		if (Written < 0) {
			if (errno == EINTR) continue;
			return materialError("material private write failed");
		}
		if (Written == 0) return materialError("material private write failed");
		Bytes = Bytes.drop_front(Written);
	}
	if (Fault == MaterialExportFault::FileSync || ::fsync(FD) != 0)
		return materialError("material private fsync failed");
	return Error::success();
}

Expected<std::string> objectBytes(const json::Object& Object,
	MaterialCodecProfile Profile = MaterialCodecProfile::CanonicalRegion) {
	json::Object Copy = Object;
	return canonicalMaterialJSON(json::Value(std::move(Copy)), Profile);
}

bool hasExactFields(const json::Object& Object, ArrayRef<StringRef> Fields) {
	if (Object.size() != Fields.size()) return false;
	return llvm::all_of(Fields, [&](StringRef Field) { return Object.get(Field); });
}

std::optional<uint32_t> getU32(const json::Value& Value,
	uint32_t Minimum = 0, uint32_t Maximum = UINT32_MAX) {
	auto Number = Value.getAsUINT64();
	if (!Number || *Number < Minimum || *Number > Maximum) return std::nullopt;
	return static_cast<uint32_t>(*Number);
}

Error validateCanonicalRegion(const json::Object& Region,
	std::optional<StringRef> SuppliedVerifier = std::nullopt,
	ArrayRef<uint8_t> SuppliedBytecode = {},
	uint64_t* OutTargetLookupOperations = nullptr) {
	static const StringRef RegionFields[] = {
		"format_version", "isa_version", "target_triple", "region_name", "mode",
		"canonical_bc", "bytecode_size", "instruction_offsets", "logical_opcodes",
		"opcode_count", "engine_abi_hash", "register_counts", "call_abi_hash",
		"layout_hash", "static_decode_descriptor", "region_content_hash", "region_id",
	};
	static const StringRef DescriptorFields[] = {
		"decode_salt", "isa_version", "layout_hash", "operand_encoding_hash",
	};
	if (!hasExactFields(Region, RegionFields))
		return materialError("canonical region schema mismatch");
	auto Format = Region.getInteger("format_version");
	auto ISA = Region.getInteger("isa_version");
	auto Target = Region.getString("target_triple");
	auto Name = Region.getString("region_name");
	auto Mode = Region.getString("mode");
	auto BytecodeText = Region.getString("canonical_bc");
	auto BytecodeSize = Region.getInteger("bytecode_size");
	auto OpcodeCount = Region.getInteger("opcode_count");
	auto EngineHash = Region.getString("engine_abi_hash");
	auto CallHash = Region.getString("call_abi_hash");
	auto LayoutHash = Region.getString("layout_hash");
	auto ContentHash = Region.getString("region_content_hash");
	auto RegionId = Region.getString("region_id");
	if (!Format || *Format != 1 || !ISA || *ISA != 1 ||
		!Target || *Target != "aarch64-linux-android26" || !Name || !validName(*Name) ||
		!Mode || (*Mode != "session" && *Mode != "lease") || !BytecodeText ||
		!BytecodeSize || *BytecodeSize < 1 ||
		static_cast<uint64_t>(*BytecodeSize) > kMaxBytecodeBytes ||
		!OpcodeCount || *OpcodeCount != OP_COUNT ||
		!EngineHash || !validHash(*EngineHash) || !CallHash || !validHash(*CallHash) ||
		!LayoutHash || !validHash(*LayoutHash) || !ContentHash || !validHash(*ContentHash) ||
		!RegionId || !validHash(*RegionId))
		return materialError("canonical region field invalid");
	if (BytecodeText->empty() || BytecodeText->size() > kMaxBase64Bytes ||
		BytecodeText->size() % 4 != 0)
		return materialError("canonical region bytecode encoding invalid");
	std::vector<char> Bytecode;
	if (Error E = decodeBase64(*BytecodeText, Bytecode)) {
		consumeError(std::move(E));
		return materialError("canonical region bytecode encoding invalid");
	}
	if (Bytecode.size() != static_cast<size_t>(*BytecodeSize) ||
		encodeBase64(Bytecode) != *BytecodeText)
		return materialError("canonical region bytecode size mismatch");

	const auto* Offsets = Region.getArray("instruction_offsets");
	const auto* Logical = Region.getArray("logical_opcodes");
	if (!Offsets || !Logical || Offsets->empty() || Offsets->size() != Logical->size() ||
		Offsets->size() > kMaxInstructionItems)
		return materialError("canonical region instruction arrays invalid");
	std::array<int16_t, 256> LogicalToPhysical;
	std::array<int16_t, 256> PhysicalToLogical;
	LogicalToPhysical.fill(-1);
	PhysicalToLogical.fill(-1);
	uint32_t Previous = 0;
	for (size_t I = 0; I < Offsets->size(); ++I) {
		auto Offset = getU32((*Offsets)[I], 0, static_cast<uint32_t>(*BytecodeSize - 1));
		auto Opcode = getU32((*Logical)[I], 0, static_cast<uint32_t>(*OpcodeCount - 1));
		if (!Offset || !Opcode || (I && *Offset <= Previous))
			return materialError("canonical region instruction boundary invalid");
		Previous = *Offset;
		uint8_t Physical = static_cast<uint8_t>(Bytecode[*Offset]);
		if ((LogicalToPhysical[*Opcode] >= 0 && LogicalToPhysical[*Opcode] != Physical) ||
			(PhysicalToLogical[Physical] >= 0 &&
				static_cast<uint32_t>(PhysicalToLogical[Physical]) != *Opcode))
			return materialError("canonical region opcode map invalid");
		LogicalToPhysical[*Opcode] = Physical;
		PhysicalToLogical[Physical] = static_cast<int16_t>(*Opcode);
	}

	const auto* Registers = Region.getArray("register_counts");
	if (!Registers || Registers->empty() || Registers->size() > 32)
		return materialError("canonical region register counts invalid");
	for (const json::Value& Count : *Registers)
		if (!getU32(Count, 0, 65535))
			return materialError("canonical region register count invalid");
	const auto* Descriptor = Region.getObject("static_decode_descriptor");
	if (!Descriptor || !hasExactFields(*Descriptor, DescriptorFields))
		return materialError("canonical region decode descriptor invalid");
	auto DecodeSalt = Descriptor->getInteger("decode_salt");
	auto DescriptorISA = Descriptor->getInteger("isa_version");
	auto DescriptorLayout = Descriptor->getString("layout_hash");
	auto OperandHash = Descriptor->getString("operand_encoding_hash");
	if (!DecodeSalt || *DecodeSalt < 0 || *DecodeSalt > UINT32_MAX ||
		!DescriptorISA || *DescriptorISA != *ISA || !DescriptorLayout ||
		*DescriptorLayout != *LayoutHash || !OperandHash || !validHash(*OperandHash))
		return materialError("canonical region decode descriptor mismatch");
	std::string VerifierBytes;
	if (SuppliedVerifier) {
		VerifierBytes = SuppliedVerifier->str();
	} else {
		std::lock_guard Lock(VerifierDescriptorsMutex);
		std::string Key = (Twine(*LayoutHash) + ":" + *CallHash + ":" + *OperandHash).str();
		auto It = VerifierDescriptors.find(Key);
		if (It == VerifierDescriptors.end())
			return materialError("canonical region verifier descriptor unavailable");
		VerifierBytes = It->second;
	}
	VMInstructionLayout VerifierLayout;
	VMOpcodeMap VerifierOpcodes;
	SmallVector<uint8_t, 16> CallArities;
	SmallVector<uint8_t, 16> CallReturnKinds;
	uint32_t TargetKey = 0;
	std::string VerifierCallSpec;
	std::string VerifierOperandSpec;
	if (!decodeVerifierDescriptor(VerifierBytes, VerifierLayout, VerifierOpcodes,
		CallArities, CallReturnKinds, TargetKey, VerifierCallSpec, VerifierOperandSpec) ||
		hashBytes(layoutSpec(VerifierLayout)) != *LayoutHash ||
		hashBytes(VerifierCallSpec) != *CallHash ||
		hashBytes(VerifierOperandSpec) != *OperandHash)
		return materialError("canonical region verifier descriptor mismatch");
	SmallVector<uint32_t, 64> VerifiedOffsets;
	SmallVector<uint8_t, 64> VerifiedOpcodes;
	for (size_t I = 0; I < Offsets->size(); ++I) {
		VerifiedOffsets.push_back(static_cast<uint32_t>(*(*Offsets)[I].getAsInteger()));
		VerifiedOpcodes.push_back(static_cast<uint8_t>(*(*Logical)[I].getAsInteger()));
	}
	std::string VerifyError;
	uint32_t BadIP = 0;
	ArrayRef<uint8_t> CanonicalBytes(
		reinterpret_cast<const uint8_t*>(Bytecode.data()), Bytecode.size());
	ArrayRef<uint8_t> VerifiedBytes = SuppliedBytecode.empty() ? CanonicalBytes : SuppliedBytecode;
	if (VerifiedBytes.size() != CanonicalBytes.size() ||
		!verifyCanonicalBytecode(VerifiedBytes,
		VerifiedOffsets, VerifiedOpcodes, VerifierLayout, VerifierOpcodes,
		CallArities, CallReturnKinds, TargetKey, VerifyError, BadIP,
		OutTargetLookupOperations))
		return materialError("canonical region bytecode verification failed");
	auto DescriptorBytes = objectBytes(*Descriptor);
	if (!DescriptorBytes) return DescriptorBytes.takeError();
	if (DescriptorBytes->size() > 4096)
		return materialError("canonical region decode descriptor too large");

	json::Object Core = Region;
	Core.erase("region_content_hash");
	Core.erase("region_id");
	auto CoreBytes = objectBytes(Core);
	if (!CoreBytes) return CoreBytes.takeError();
	if (frameHash("XOVM2/region-content", *CoreBytes) != *ContentHash)
		return materialError("canonical region content hash mismatch");
	json::Object Identity{
		{"format_version", 1}, {"region_name", *Name},
		{"region_content_hash", *ContentHash}, {"engine_abi_hash", *EngineHash},
		{"call_abi_hash", *CallHash}, {"layout_hash", *LayoutHash},
		{"mode", *Mode}, {"target_triple", *Target},
	};
	auto IdentityBytes = objectBytes(Identity);
	if (!IdentityBytes) return IdentityBytes.takeError();
	if (frameHash("XOVM2/region-id", *IdentityBytes) != *RegionId)
		return materialError("canonical region id mismatch");
	return Error::success();
}

Error validateDynamicArtifactExport(const DynamicArtifactExport& Export) {
	static const StringRef PublicFields[] = {
		"format_version", "material_source", "region_name", "build_id", "region_id",
		"artifact_hash", "encrypted_artifact_b64", "artifact_size",
	};
	static const StringRef PrivateFields[] = {
		"format_version", "material_source", "region_name", "build_id", "region_id",
		"artifact_hash", "artifact_key_b64",
	};
	if (!hasExactFields(Export.PublicManifest, PublicFields) ||
		!hasExactFields(Export.PrivateRegistration, PrivateFields))
		return materialError("dynamic artifact manifest schema mismatch");
	auto PublicVersion = Export.PublicManifest.getInteger("format_version");
	auto PrivateVersion = Export.PrivateRegistration.getInteger("format_version");
	auto PublicSource = Export.PublicManifest.getString("material_source");
	auto PrivateSource = Export.PrivateRegistration.getString("material_source");
	auto PublicName = Export.PublicManifest.getString("region_name");
	auto PrivateName = Export.PrivateRegistration.getString("region_name");
	auto PublicBuild = Export.PublicManifest.getString("build_id");
	auto PrivateBuild = Export.PrivateRegistration.getString("build_id");
	auto PublicRegion = Export.PublicManifest.getString("region_id");
	auto PrivateRegion = Export.PrivateRegistration.getString("region_id");
	auto PublicHash = Export.PublicManifest.getString("artifact_hash");
	auto PrivateHash = Export.PrivateRegistration.getString("artifact_hash");
	auto Ciphertext = Export.PublicManifest.getString("encrypted_artifact_b64");
	auto ArtifactSize = Export.PublicManifest.getInteger("artifact_size");
	auto Key = Export.PrivateRegistration.getString("artifact_key_b64");
	if (!PublicVersion || *PublicVersion != 2 || !PrivateVersion || *PrivateVersion != 2 ||
		!PublicSource || *PublicSource != "dynamic_vm" || !PrivateSource ||
		*PrivateSource != "dynamic_vm" || !PublicName || !PrivateName ||
		*PublicName != *PrivateName || !validName(*PublicName) || !PublicBuild ||
		!PrivateBuild || *PublicBuild != *PrivateBuild || !validHash(*PublicBuild) ||
		!PublicRegion || !PrivateRegion || *PublicRegion != *PrivateRegion ||
		!validHash(*PublicRegion) || !PublicHash || !PrivateHash ||
		*PublicHash != *PrivateHash || !validHash(*PublicHash) || !Ciphertext ||
		Ciphertext->empty() || Ciphertext->size() > kMaxBase64Bytes ||
		Ciphertext->size() % 4 != 0 || !ArtifactSize || *ArtifactSize < 1 ||
		static_cast<uint64_t>(*ArtifactSize) > kMaxBytecodeBytes * 64 || !Key ||
		Key->empty() || Key->size() > 128 || Key->size() % 4 != 0)
		return materialError("dynamic artifact manifest field invalid");
	std::vector<char> Encoded;
	if (Error E = decodeBase64(*Ciphertext, Encoded)) {
		consumeError(std::move(E));
		return materialError("dynamic artifact encoding invalid");
	}
	if (Encoded.size() != static_cast<size_t>(*ArtifactSize) ||
		encodeBase64(Encoded) != *Ciphertext)
		return materialError("dynamic artifact size mismatch");
	std::vector<char> DecodedKey;
	if (Error E = decodeBase64(*Key, DecodedKey)) {
		consumeError(std::move(E));
		return materialError("dynamic artifact key encoding invalid");
	}
	if (DecodedKey.size() != 32 || encodeBase64(DecodedKey) != *Key)
		return materialError("dynamic artifact key size mismatch");
	auto BuildId = parseDynamicHash(*PublicBuild);
	auto RegionId = parseDynamicHash(*PublicRegion);
	auto ArtifactHash = parseDynamicHash(*PublicHash);
	if (!BuildId || !RegionId || !ArtifactHash)
		return materialError("dynamic artifact identity encoding invalid");
	ArrayRef<uint8_t> EncodedBytes(reinterpret_cast<const uint8_t*>(Encoded.data()), Encoded.size());
	auto Artifact = xovm::material::decodeEncryptedVmArtifact(EncodedBytes);
	if (!Artifact || Artifact->build_id != *BuildId || Artifact->region_id != *RegionId ||
		Artifact->artifact_hash != *ArtifactHash)
		return materialError("dynamic artifact identity commitment mismatch");
	std::array<uint8_t, 32> ArtifactKey{};
	std::copy(DecodedKey.begin(), DecodedKey.end(), ArtifactKey.begin());
	if (!xovm::material::decryptEncryptedVmArtifact(*Artifact, ArtifactKey,
		*BuildId, *RegionId))
		return materialError("dynamic artifact decryption failed");
	return Error::success();
}

bool sameStatIdentity(const struct stat& A, const struct stat& B) {
	return A.st_dev == B.st_dev && A.st_ino == B.st_ino && A.st_size == B.st_size &&
		A.st_mode == B.st_mode && A.st_uid == B.st_uid && A.st_nlink == B.st_nlink &&
		A.st_mtim.tv_sec == B.st_mtim.tv_sec && A.st_mtim.tv_nsec == B.st_mtim.tv_nsec &&
		A.st_ctim.tv_sec == B.st_ctim.tv_sec && A.st_ctim.tv_nsec == B.st_ctim.tv_nsec;
}

bool matchesExpectedBytes(int FD, StringRef Expected) {
	if (::lseek(FD, 0, SEEK_SET) < 0) return false;
	std::array<char, 16384> Buffer{};
	size_t Offset = 0;
	while (Offset < Expected.size()) {
		ssize_t Count = ::read(FD, Buffer.data(),
			std::min(Buffer.size(), Expected.size() - Offset));
		if (Count < 0 && errno == EINTR) continue;
		if (Count <= 0 || !std::equal(Buffer.begin(), Buffer.begin() + Count,
			Expected.begin() + Offset)) return false;
		Offset += Count;
	}
	char Extra;
	return ::read(FD, &Extra, 1) == 0;
}

bool sameBundleContents(int RootFD, StringRef FinalName, StringRef SoftwareId,
	ArrayRef<std::pair<std::string, std::string>> Files,
	MaterialExportFault Fault = MaterialExportFault::None) {
	int FinalFD = ::openat(RootFD, FinalName.str().c_str(),
		O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
	if (FinalFD < 0) return false;
	auto CloseFinal = make_scope_exit([&] { ::close(FinalFD); });
	struct stat Directory {}, DirectoryAfter {}, Named {};
	if (::fstat(FinalFD, &Directory) != 0 || !S_ISDIR(Directory.st_mode) ||
		(Directory.st_mode & 0777u) != 0700u || Directory.st_uid != ::geteuid())
		return false;
	std::set<std::string> Expected{"software-id"};
	for (const auto& [Name, Bytes] : Files) Expected.insert(Name);
	DIR* DirectoryStream = ::fdopendir(::dup(FinalFD));
	if (!DirectoryStream) return false;
	auto CloseDirectory = make_scope_exit([&] { ::closedir(DirectoryStream); });
	while (dirent* Entry = ::readdir(DirectoryStream)) {
		StringRef Name(Entry->d_name);
		if (Name == "." || Name == "..") continue;
		if (!Expected.erase(Name.str())) return false;
		struct stat File {};
		if (::fstatat(FinalFD, Entry->d_name, &File, AT_SYMLINK_NOFOLLOW) != 0 ||
			!S_ISREG(File.st_mode) || (File.st_mode & 0777u) != 0600u ||
			File.st_uid != ::geteuid() || File.st_nlink != 1)
			return false;
	}
	if (!Expected.empty()) return false;
	struct OpenedMember {
		std::string Name;
		StringRef Expected;
		int FD;
		struct stat Before;
	};
	SmallVector<OpenedMember, 8> Members;
	auto CloseMembers = make_scope_exit([&] {
		for (OpenedMember& Member : Members) ::close(Member.FD);
	});
	auto OpenExpected = [&](StringRef Name, StringRef Bytes) {
		int FD = ::openat(FinalFD, Name.str().c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
		struct stat Before {};
		if (FD < 0 || ::fstat(FD, &Before) != 0 || !S_ISREG(Before.st_mode) ||
			(Before.st_mode & 0777u) != 0600u || Before.st_uid != ::geteuid() ||
			Before.st_nlink != 1 || static_cast<uint64_t>(Before.st_size) != Bytes.size()) {
			if (FD >= 0) ::close(FD);
			return false;
		}
		Members.push_back({Name.str(), Bytes, FD, Before});
		return true;
	};
	if (!OpenExpected("software-id", SoftwareId)) return false;
	for (const auto& [Name, Bytes] : Files)
		if (!OpenExpected(Name, Bytes)) return false;
	for (const OpenedMember& Member : Members)
		if (!matchesExpectedBytes(Member.FD, Member.Expected)) return false;
	if ((Fault == MaterialExportFault::MemberContent ||
		Fault == MaterialExportFault::MemberSwap) && !Members.empty()) {
		OpenedMember& Member = Members.front();
		if (Fault == MaterialExportFault::MemberContent) {
			int Mutator = ::openat(FinalFD, Member.Name.c_str(),
				O_WRONLY | O_TRUNC | O_CLOEXEC | O_NOFOLLOW);
			if (Mutator < 0 || ::write(Mutator, "x", 1) != 1 || ::close(Mutator) != 0)
				return false;
		} else {
			std::string Displaced = Member.Name + ".displaced";
			if (::renameat(FinalFD, Member.Name.c_str(), FinalFD, Displaced.c_str()) != 0)
				return false;
			int Replacement = ::openat(FinalFD, Member.Name.c_str(),
				O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
			if (Replacement < 0) return false;
			if (Error E = writeAll(Replacement, Member.Expected, MaterialExportFault::None)) {
				consumeError(std::move(E));
				::close(Replacement);
				return false;
			}
			if (::close(Replacement) != 0) return false;
		}
	}
	for (const OpenedMember& Member : Members) {
		struct stat After {}, MemberNamed {};
		if (::fstat(Member.FD, &After) != 0 || !sameStatIdentity(Member.Before, After) ||
			::fstatat(FinalFD, Member.Name.c_str(), &MemberNamed,
				AT_SYMLINK_NOFOLLOW) != 0 || !sameStatIdentity(After, MemberNamed))
			return false;
	}
	if (Fault == MaterialExportFault::DestinationSwap) {
		std::string Displaced = FinalName.str() + ".displaced";
		if (::renameat(RootFD, FinalName.str().c_str(), RootFD, Displaced.c_str()) != 0 ||
			::mkdirat(RootFD, FinalName.str().c_str(), 0700) != 0)
			return false;
	}
	return ::fstat(FinalFD, &DirectoryAfter) == 0 &&
		sameStatIdentity(Directory, DirectoryAfter) &&
		::fstatat(RootFD, FinalName.str().c_str(), &Named, AT_SYMLINK_NOFOLLOW) == 0 &&
		S_ISDIR(Named.st_mode) && Named.st_dev == Directory.st_dev &&
		Named.st_ino == Directory.st_ino && sameStatIdentity(DirectoryAfter, Named);
}

Expected<std::string> readBundleMember(int DirectoryFD, StringRef Name, size_t Maximum) {
	int FD = ::openat(DirectoryFD, Name.str().c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (FD < 0) return materialError("dynamic existing bundle member open failed");
	auto Close = make_scope_exit([&] { ::close(FD); });
	struct stat St{};
	if (::fstat(FD, &St) != 0 || !S_ISREG(St.st_mode) || (St.st_mode & 0777u) != 0600u ||
		St.st_uid != ::geteuid() || St.st_nlink != 1 || St.st_size < 0 ||
		static_cast<uint64_t>(St.st_size) > Maximum)
		return materialError("dynamic existing bundle member invalid");
	std::string Bytes(static_cast<size_t>(St.st_size), '\0');
	size_t Offset = 0;
	while (Offset < Bytes.size()) {
		ssize_t Count = ::read(FD, Bytes.data() + Offset, Bytes.size() - Offset);
		if (Count < 0 && errno == EINTR) continue;
		if (Count <= 0) return materialError("dynamic existing bundle member read failed");
		Offset += static_cast<size_t>(Count);
	}
	char Extra;
	if (::read(FD, &Extra, 1) != 0) return materialError("dynamic existing bundle member grew");
	return Bytes;
}

Error rejectExistingDynamicConflicts(int RootFD, StringRef FinalName,
		ArrayRef<std::pair<std::string, std::string>> Files) {
	std::set<std::string> RegionNames;
	std::set<std::string> RegionIds;
	for (const auto& [Name, Bytes] : Files) {
		if (Name != "public-manifest.json") continue;
		auto Parsed = json::parse(Bytes);
		if (!Parsed) return materialError("dynamic public manifest parse failed");
		auto* Object = Parsed->getAsObject();
		if (!Object || Object->getInteger("format_version") != 2 ||
			Object->getString("material_source") != "dynamic_vm")
			return materialError("dynamic public manifest schema invalid");
		auto* Regions = Object->getArray("regions");
		if (!Regions || Regions->empty()) return materialError("dynamic public manifest regions missing");
		for (const json::Value& Value : *Regions) {
			auto* Region = Value.getAsObject();
			auto NameValue = Region ? Region->getString("region_name") : std::nullopt;
			auto IdValue = Region ? Region->getString("region_id") : std::nullopt;
			if (!NameValue || !IdValue || !validName(*NameValue) || !validHash(*IdValue))
				return materialError("dynamic public manifest region identity invalid");
			RegionNames.insert(NameValue->str());
			RegionIds.insert(IdValue->str());
		}
	}
	if (RegionNames.empty() || RegionIds.empty())
		return materialError("dynamic public manifest identities missing");
	DIR* RootDir = ::fdopendir(::dup(RootFD));
	if (!RootDir) return materialError("dynamic export root enumeration failed");
	auto CloseRootDir = make_scope_exit([&] { ::closedir(RootDir); });
	while (dirent* Entry = ::readdir(RootDir)) {
		StringRef ExistingName(Entry->d_name);
		if (!ExistingName.ends_with(".dynamic") || ExistingName == FinalName) continue;
		int ExistingFD = ::openat(RootFD, Entry->d_name,
			O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
		if (ExistingFD < 0) return materialError("dynamic existing bundle open failed");
		auto CloseExisting = make_scope_exit([&] { ::close(ExistingFD); });
		struct stat St{};
		if (::fstat(ExistingFD, &St) != 0 || !S_ISDIR(St.st_mode) ||
			(St.st_mode & 0777u) != 0700u || St.st_uid != ::geteuid())
			return materialError("dynamic existing bundle permissions invalid");
		auto Manifest = readBundleMember(ExistingFD, "public-manifest.json", kMaxManifestBytes);
		if (!Manifest) return Manifest.takeError();
		auto Parsed = json::parse(*Manifest);
		if (!Parsed) return materialError("dynamic existing public manifest parse failed");
		auto* Object = Parsed->getAsObject();
		auto* Regions = Object ? Object->getArray("regions") : nullptr;
		if (!Object || Object->getInteger("format_version") != 2 ||
			Object->getString("material_source") != "dynamic_vm" || !Regions)
			return materialError("dynamic existing public manifest invalid");
		for (const json::Value& Value : *Regions) {
			auto* Region = Value.getAsObject();
			auto NameValue = Region ? Region->getString("region_name") : std::nullopt;
			auto IdValue = Region ? Region->getString("region_id") : std::nullopt;
			if (!NameValue || !IdValue || !validName(*NameValue) || !validHash(*IdValue))
				return materialError("dynamic existing public manifest region identity invalid");
			if (RegionNames.count(NameValue->str()) || RegionIds.count(IdValue->str()))
				return materialError("dynamic material region identity conflict");
		}
	}
	return Error::success();
}

int renameNoReplace(int OldDir, const char* OldName, int NewDir, const char* NewName) {
#if defined(SYS_renameat2)
	return static_cast<int>(::syscall(SYS_renameat2, OldDir, OldName, NewDir, NewName, 1));
#else
	errno = ENOTSUP;
	return -1;
#endif
}

Expected<int> lockMaterialRoot(int RootFD) {
	int FD = ::openat(RootFD, kLockName.data(),
		O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
	if (FD < 0) return materialError("material root lock open failed");
	struct stat Opened {}, Named {};
	if (::fstat(FD, &Opened) != 0 || !S_ISREG(Opened.st_mode) ||
		(Opened.st_mode & 0777u) != 0600u || Opened.st_uid != ::geteuid() ||
		Opened.st_nlink != 1 || ::flock(FD, LOCK_EX) != 0 ||
		::flock(RootFD, LOCK_EX) != 0 ||
		::fstatat(RootFD, kLockName.data(), &Named, AT_SYMLINK_NOFOLLOW) != 0 ||
		!S_ISREG(Named.st_mode) || Opened.st_dev != Named.st_dev ||
		Opened.st_ino != Named.st_ino) {
		::close(FD);
		return materialError("material root lock validation failed");
	}
	return FD;
}

bool lockStillNamed(int RootFD, int LockFD) {
	struct stat Opened {}, Named {};
	return ::fstat(LockFD, &Opened) == 0 &&
		::fstatat(RootFD, kLockName.data(), &Named, AT_SYMLINK_NOFOLLOW) == 0 &&
		S_ISREG(Named.st_mode) && Opened.st_dev == Named.st_dev &&
		Opened.st_ino == Named.st_ino && (Named.st_mode & 0777u) == 0600u &&
		Named.st_uid == ::geteuid() && Named.st_nlink == 1;
}

} // namespace

Expected<std::string> llvm::canonicalMaterialJSON(const json::Value& Value,
	MaterialCodecProfile Profile) {
	std::string Result;
	if (Error E = encodeCanonical(Value, Result, 1, Profile)) return std::move(E);
	if (Result.size() > profileLimit(Profile))
		return materialError("material JSON profile size limit");
	return Result;
}

Error llvm::verifyCanonicalRegionWithDescriptor(const json::Object& Region,
	StringRef VerifierBytes, ArrayRef<uint8_t> Bytecode,
	uint64_t* OutTargetLookupOperations) {
	return validateCanonicalRegion(Region, VerifierBytes, Bytecode,
		OutTargetLookupOperations);
}

Expected<json::Object> llvm::exportCanonicalRegion(const BytecodeEmitter& Emitter,
	const VMPassConfig& Config, const VMOpcodeMap& Opcodes) {
	if (!Config.usesCloudMaterial() || Config.cloudMaterial == CloudMaterialMode::Operation)
		return materialError("canonical region requires session or lease material mode");
	if (!validName(Config.materialRegion) || Emitter.BC.empty() ||
		Emitter.BC.size() > kMaxBytecodeBytes)
		return materialError("canonical region bounds invalid");
	if (!Emitter.getLayout().validate()) return materialError("canonical region layout invalid");

	json::Array Offsets;
	json::Array Logical;
	uint32_t Previous = 0;
	bool First = true;
	for (const auto& [Offset, Opcode] : Emitter.getInstructionRecords()) {
		if (Offset >= Emitter.BC.size() || (!First && Offset <= Previous) ||
			Emitter.BC[Offset] != Opcodes.encode(Opcode))
			return materialError("canonical region emitter record mismatch");
		Offsets.push_back(Offset);
		Logical.push_back(static_cast<unsigned>(Opcode));
		Previous = Offset;
		First = false;
	}
	if (First || Offsets.size() > 8388608)
		return materialError("canonical region instruction records empty");

	std::string LayoutHash = hashBytes(layoutSpec(Emitter.getLayout()));
	std::string VerifierBytes = verifierDescriptor(Emitter, Opcodes);
	std::string CallSpec = callABISpec(Emitter);
	std::string CallHash = hashBytes(CallSpec);
	std::string OperandHash = hashBytes(operandSpec(Emitter.getISAEnc(), &Opcodes,
		targetKey(Emitter)));
	{
		std::lock_guard Lock(VerifierDescriptorsMutex);
		VerifierDescriptors[LayoutHash + ":" + CallHash + ":" + OperandHash] = VerifierBytes;
	}
	json::Object Descriptor{{"decode_salt", Emitter.getDecodeSalt()}, {"isa_version", 1},
		{"layout_hash", LayoutHash},
		{"operand_encoding_hash", OperandHash}};
	json::Array Registers{Emitter.NVR, Emitter.NVR64, Emitter.NFR, Emitter.NPR};
	json::Object Core{
		{"format_version", 1}, {"isa_version", 1},
		{"target_triple", "aarch64-linux-android26"},
		{"region_name", Config.materialRegion},
		{"mode", cloudMaterialModeName(Config.cloudMaterial)},
		{"canonical_bc", encodeBase64(Emitter.BC)},
		{"bytecode_size", static_cast<unsigned>(Emitter.BC.size())},
		{"instruction_offsets", std::move(Offsets)},
		{"logical_opcodes", std::move(Logical)},
		{"opcode_count", static_cast<unsigned>(OP_COUNT)},
		{"engine_abi_hash", hashBytes(engineABISpec())},
		{"register_counts", std::move(Registers)},
		{"call_abi_hash", CallHash},
		{"layout_hash", LayoutHash},
		{"static_decode_descriptor", std::move(Descriptor)},
	};
	auto CoreBytes = objectBytes(Core);
	if (!CoreBytes) return CoreBytes.takeError();
	std::string ContentHash = frameHash("XOVM2/region-content", *CoreBytes);
	json::Object Identity{
		{"format_version", 1}, {"region_name", Config.materialRegion},
		{"region_content_hash", ContentHash},
		{"engine_abi_hash", *Core.getString("engine_abi_hash")},
		{"call_abi_hash", *Core.getString("call_abi_hash")},
		{"layout_hash", LayoutHash}, {"mode", *Core.getString("mode")},
		{"target_triple", "aarch64-linux-android26"},
	};
	auto IdentityBytes = objectBytes(Identity);
	if (!IdentityBytes) return IdentityBytes.takeError();
	Core["region_content_hash"] = ContentHash;
	Core["region_id"] = frameHash("XOVM2/region-id", *IdentityBytes);
	if (Error E = validateCanonicalRegion(Core)) return std::move(E);
	return Core;
}

Expected<DynamicArtifactExport> llvm::exportDynamicArtifact(
	const BytecodeEmitter& Emitter, const VMPassConfig& Config,
	const VMOpcodeMap& Opcodes) {
	if (!Config.usesCloudMaterial() || Config.cloudMaterial == CloudMaterialMode::Operation)
		return materialError("dynamic artifact requires session or lease material mode");
	if (!validName(Config.materialRegion) || Emitter.BC.empty() ||
		Emitter.BC.size() > kMaxBytecodeBytes)
		return materialError("dynamic artifact bounds invalid");

	auto Canonical = exportCanonicalRegion(Emitter, Config, Opcodes);
	if (!Canonical) return Canonical.takeError();
	auto CanonicalRegionId = Canonical->getString("region_id");
	if (!CanonicalRegionId) return materialError("dynamic canonical region identity missing");
	auto CanonicalBytes = canonicalMaterialJSON(json::Value(std::move(*Canonical)),
		MaterialCodecProfile::CanonicalRegion);
	if (!CanonicalBytes) return CanonicalBytes.takeError();

	xovm::material::ArtifactSource Source;
	Source.build_id = dynamicHash("XOVM2/dynamic-build", *CanonicalBytes);
	auto ParsedRegionId = parseDynamicHash(*CanonicalRegionId);
	if (!ParsedRegionId) return materialError("dynamic canonical region identity invalid");
	Source.region_id = *ParsedRegionId;
	if (std::error_code EC = getRandomBytes(Source.artifact_key.data(),
		Source.artifact_key.size()))
		return materialError("dynamic artifact key generation failed");
	Source.bytecode.assign(Emitter.BC.begin(), Emitter.BC.end());
	xovm::material::HandlerShardDescriptor HandlerDescriptor;
	HandlerDescriptor.shard_id = 1;
	std::optional<std::vector<uint8_t>> ShardCode;
	bool NativeProgramSupported = false;
	if (Emitter.BC.size() == 8 &&
		Emitter.BC[0] == Opcodes.encode(OP_LOADI) &&
		Emitter.BC[6] == Opcodes.encode(OP_RET_INT)) {
		uint32_t Immediate = static_cast<uint32_t>(Emitter.BC[2]) |
			(static_cast<uint32_t>(Emitter.BC[3]) << 8) |
			(static_cast<uint32_t>(Emitter.BC[4]) << 16) |
			(static_cast<uint32_t>(Emitter.BC[5]) << 24);
		ShardCode = xovm::material::buildAarch64LoadAndReturnIntShard(
			Emitter.BC[1], Immediate, Emitter.BC[7], 8);
		NativeProgramSupported = static_cast<bool>(ShardCode);
	}
	if (!ShardCode) ShardCode = xovm::material::buildAarch64BridgeShard();
	if (!ShardCode) return materialError("dynamic AArch64 handler shard unavailable");
	HandlerDescriptor.code_size = static_cast<uint32_t>(ShardCode->size());
	HandlerDescriptor.relocation_count = 0;
	HandlerDescriptor.commitment = xovm::material::hashAarch64ShardCode(*ShardCode);
	Source.handler_shards = xovm::material::encodeHandlerShardPayload(HandlerDescriptor, *ShardCode);
	xovm::material::DynamicVmShardContext::ProgramDescriptor Program;
	Program.load_opcode = Opcodes.encode(OP_LOADI);
	Program.ret_opcode = Opcodes.encode(OP_RET_INT);
	Program.supported = NativeProgramSupported;
	Source.continuation_descriptors = xovm::material::encodeProgramDescriptor(Program);

	auto Artifact = xovm::material::buildEncryptedVmArtifact(Source);
	if (!Artifact) return materialError("dynamic artifact encryption failed");
	auto Encoded = xovm::material::encodeEncryptedVmArtifact(*Artifact);
	if (Encoded.empty()) return materialError("dynamic artifact encoding failed");

	DynamicArtifactExport Result;
	Result.PublicManifest = json::Object{
		{"format_version", 2},
		{"material_source", "dynamic_vm"},
		{"region_name", Config.materialRegion},
		{"build_id", dynamicHashHex(Source.build_id)},
		{"region_id", dynamicHashHex(Source.region_id)},
		{"artifact_hash", dynamicHashHex(Artifact->artifact_hash)},
		{"encrypted_artifact_b64", encodeBase64(Encoded)},
		{"artifact_size", static_cast<unsigned>(Encoded.size())},
	};
	Result.PrivateRegistration = json::Object{
		{"format_version", 2},
		{"material_source", "dynamic_vm"},
		{"region_name", Config.materialRegion},
		{"build_id", dynamicHashHex(Source.build_id)},
		{"region_id", dynamicHashHex(Source.region_id)},
		{"artifact_hash", dynamicHashHex(Artifact->artifact_hash)},
		{"artifact_key_b64", encodeBase64(ArrayRef<uint8_t>(Source.artifact_key))},
	};
	return Result;
}

#ifdef OBF_TEST_VM_IMPL
MaterialCommitToken MaterialCommitToken::forExportOnlyTest(MaterialExportFault Fault) {
	return MaterialCommitToken(kCommitToken, Fault);
}
#endif

MaterialCommitToken MaterialCommitToken::afterNoFallbackCommit() {
	return MaterialCommitToken(kCommitToken);
}

Expected<MaterialCommitResult> llvm::commitCanonicalRegions(StringRef ExportRoot,
	StringRef SoftwareId, ArrayRef<json::Object> Regions,
	const MaterialCommitToken& Token) {
	if (Token.Value != kCommitToken) return materialError("invalid material commit token");
	if (!sys::path::is_absolute(ExportRoot) || !validId(SoftwareId) || Regions.empty() ||
		Regions.size() > 4096)
		return materialError("invalid material export request");
	SmallString<256> RealRoot;
	if (std::error_code EC = sys::fs::real_path(ExportRoot, RealRoot, true))
		return materialError("material export root resolution failed");
	if (RealRoot != ExportRoot)
		return materialError("material export root may not traverse symlinks");
	struct stat RootStat {};
	if (::lstat(ExportRoot.str().c_str(), &RootStat) != 0 || !S_ISDIR(RootStat.st_mode) ||
		S_ISLNK(RootStat.st_mode) || RootStat.st_uid != ::geteuid() ||
		(RootStat.st_mode & 0077u) != 0)
		return materialError("material export root must be an existing non-symlink directory");
	int RootFD = ::open(ExportRoot.str().c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
	if (RootFD < 0) return materialError("material export root open failed");
	auto CloseRoot = make_scope_exit([&] { ::close(RootFD); });
	auto LockOr = lockMaterialRoot(RootFD);
	if (!LockOr) return LockOr.takeError();
	int LockFD = *LockOr;
	auto CloseLock = make_scope_exit([&] { ::close(LockFD); });

	SmallVector<std::pair<std::string, std::string>, 8> Files;
	struct RegionIdentity {
		std::string Name;
		std::string NameHash;
		std::string RegionId;
		std::string ContentHash;
	};
	SmallVector<RegionIdentity, 8> Identities;
	std::set<std::string> Names;
	std::set<std::string> DescriptorNames;
	for (const auto& Region : Regions) {
		if (Error E = validateCanonicalRegion(Region)) return std::move(E);
		auto Name = Region.getString("region_name");
		auto RegionId = Region.getString("region_id");
		auto Content = Region.getString("region_content_hash");
		if (!Name || !RegionId || !Content || RegionId->size() != 64 || Content->size() != 64 ||
			!Names.insert(Name->str()).second)
			return materialError("invalid or duplicate material region identity");
		auto Bytes = objectBytes(Region);
		if (!Bytes) return Bytes.takeError();
		if (Bytes->size() > kMaxRegionBytes)
			return materialError("canonical region exceeds 192 MiB");
		std::string NameHash = hashBytes(*Name);
		std::string File = NameHash + "." + RegionId->str() + "." +
			Content->str() + ".region.json";
		Files.push_back({std::move(File), std::move(*Bytes)});
		Identities.push_back({Name->str(), std::move(NameHash), RegionId->str(), Content->str()});
		auto* Descriptor = Region.getObject("static_decode_descriptor");
		auto DescriptorHash = Descriptor ? Descriptor->getString("operand_encoding_hash") : std::nullopt;
		if (!DescriptorHash) return materialError("material verifier descriptor identity missing");
		std::string DescriptorBytes;
		{
			std::lock_guard Lock(VerifierDescriptorsMutex);
			std::string Key = (Twine(*Region.getString("layout_hash")) + ":" +
				*Region.getString("call_abi_hash") + ":" + *DescriptorHash).str();
			auto It = VerifierDescriptors.find(Key);
			if (It == VerifierDescriptors.end())
				return materialError("material verifier descriptor unavailable");
			DescriptorBytes = It->second;
		}
		std::string DescriptorName = RegionId->str() + ".verifier";
		if (DescriptorNames.insert(DescriptorName).second)
			Files.push_back({std::move(DescriptorName), std::move(DescriptorBytes)});
	}
	llvm::sort(Files, [](const auto& A, const auto& B) { return A.first < B.first; });
	std::string ModuleInput = "xovm-private-module-v1|software=" + SoftwareId.str();
	for (const auto& [Name, Bytes] : Files)
		ModuleInput += "|" + Name + "|" + hashBytes(Bytes);
	std::string ModuleHash = hashBytes(ModuleInput);
	std::string FinalName = ModuleHash + ".materials";

	// 文件名前缀绑定 region_name；只比较公开身份，不读取或记录秘密内容。
	DIR* RootDir = ::fdopendir(::dup(RootFD));
	if (!RootDir) return materialError("material export root enumeration failed");
	auto CloseRootDir = make_scope_exit([&] { ::closedir(RootDir); });
	while (dirent* Entry = ::readdir(RootDir)) {
		StringRef ExistingName(Entry->d_name);
		if (ExistingName == kLockName) continue;
		if (!ExistingName.ends_with(".materials")) continue;
		int ExistingFD = ::openat(RootFD, Entry->d_name,
			O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
		if (ExistingFD < 0) return materialError("material existing bundle open failed");
		auto CloseExisting = make_scope_exit([&] { ::close(ExistingFD); });
		struct stat ExistingStat {};
		if (::fstat(ExistingFD, &ExistingStat) != 0 ||
			(ExistingStat.st_mode & 0777u) != 0700u)
			return materialError("material existing bundle permissions invalid");
		DIR* ExistingDir = ::fdopendir(::dup(ExistingFD));
		if (!ExistingDir) return materialError("material existing bundle enumeration failed");
		auto CloseExistingDir = make_scope_exit([&] { ::closedir(ExistingDir); });
		while (dirent* File = ::readdir(ExistingDir)) {
			StringRef ExistingFile(File->d_name);
			if (ExistingFile == "." || ExistingFile == "..") continue;
			struct stat ExistingFileStat {};
			if (::fstatat(ExistingFD, File->d_name, &ExistingFileStat,
				AT_SYMLINK_NOFOLLOW) != 0 || !S_ISREG(ExistingFileStat.st_mode) ||
				(ExistingFileStat.st_mode & 0777u) != 0600u)
				return materialError("material existing bundle entry invalid");
			if (ExistingFile == "software-id") continue;
			if (!ExistingFile.ends_with(".region.json")) continue;
			for (const RegionIdentity& New : Identities) {
				if (!ExistingFile.starts_with(New.NameHash) ||
					ExistingFile == New.NameHash + "." + New.RegionId + "." +
						New.ContentHash + ".region.json") continue;
				StringRef ExistingId = ExistingFile.drop_front(65).take_front(64);
				StringRef ExistingHash = ExistingFile.drop_front(130).take_front(64);
				if (ExistingFile.size() != 206 || ExistingFile[64] != '.' ||
					ExistingFile[129] != '.' || !validHash(ExistingId) ||
					!validHash(ExistingHash))
					return materialError("material existing region identity invalid");
				return materialError((Twine("material region conflict name=") + New.Name +
					" old_id=" + ExistingId + " old_hash=" + ExistingHash +
					" new_id=" + New.RegionId + " new_hash=" + New.ContentHash).str());
			}
		}
	}

	std::array<uint8_t, 16> Random{};
	if (std::error_code EC = getRandomBytes(Random.data(), Random.size()))
		return materialError("material staging randomness unavailable");
	std::string StageName = ".staging-" + toHex(ArrayRef<uint8_t>(Random), true);
	if (::mkdirat(RootFD, StageName.c_str(), 0700) != 0)
		return materialError("material staging directory creation failed");
	SmallString<256> StagePath(ExportRoot);
	sys::path::append(StagePath, StageName);
	bool Published = false;
	auto Cleanup = make_scope_exit([&] {
		if (!Published) sys::fs::remove_directories(StagePath);
	});
	int StageFD = ::openat(RootFD, StageName.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
	if (StageFD < 0) return materialError("material staging directory open failed");
	auto CloseStage = make_scope_exit([&] { ::close(StageFD); });
	if (::fchmod(StageFD, 0700) != 0)
		return materialError("material staging directory permissions failed");

	auto WriteFile = [&](StringRef Name, StringRef Bytes) -> Error {
		if (Token.Fault == MaterialExportFault::Create)
			return materialError("material private file creation failed");
		int FD = ::openat(StageFD, Name.str().c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
		if (FD < 0) return materialError("material private file creation failed");
		if (::fchmod(FD, 0600) != 0) {
			::close(FD);
			return materialError("material private file permissions failed");
		}
		if (Error E = writeAll(FD, Bytes, Token.Fault)) { ::close(FD); return E; }
		if (::close(FD) != 0 || Token.Fault == MaterialExportFault::Close)
			return materialError("material private file close failed");
		return Error::success();
	};
	if (Error E = WriteFile("software-id", SoftwareId)) return std::move(E);
	for (const auto& [Name, Bytes] : Files)
		if (Error E = WriteFile(Name, Bytes)) return std::move(E);
	if (!sameBundleContents(RootFD, StageName, SoftwareId, Files))
		return materialError("material staging directory validation failed");
	if (Token.Fault == MaterialExportFault::DirectorySync || ::fsync(StageFD) != 0)
		return materialError("material staging directory fsync failed");
	if (!lockStillNamed(RootFD, LockFD))
		return materialError("material root lock replaced");
	if (::fsync(RootFD) != 0)
		return materialError("material export root precommit fsync failed");

	if (Token.Fault == MaterialExportFault::Rename) {
		errno = EIO;
		return materialError("material publish rename failed");
	}
	if (renameNoReplace(RootFD, StageName.c_str(), RootFD, FinalName.c_str()) != 0) {
		if (errno != EEXIST) return materialError("material publish rename failed");
		if (!sameBundleContents(RootFD, FinalName, SoftwareId, Files, Token.Fault))
			return materialError("material module identity conflict");
		Published = false;
		MaterialCommitDurability Durability = ::fsync(RootFD) == 0
			? MaterialCommitDurability::Durable : MaterialCommitDurability::Unknown;
		return MaterialCommitResult{(Twine(ExportRoot) + "/" + FinalName).str(), Durability};
	}
	Published = true;
	struct stat FinalStat {}, StageStat {};
	if (::fstat(StageFD, &StageStat) != 0 ||
		::fstatat(RootFD, StageName.c_str(), &FinalStat, AT_SYMLINK_NOFOLLOW) == 0 ||
		errno != ENOENT || ::fstatat(RootFD, FinalName.c_str(), &FinalStat,
			AT_SYMLINK_NOFOLLOW) != 0 || FinalStat.st_dev != StageStat.st_dev ||
		FinalStat.st_ino != StageStat.st_ino) {
		std::string Path = (Twine(ExportRoot) + "/" + FinalName).str();
		return MaterialCommitResult{std::move(Path), MaterialCommitDurability::Unknown,
			MaterialCommitIntegrity::Unknown};
	}
	std::string Path = (Twine(ExportRoot) + "/" + FinalName).str();
	if (!lockStillNamed(RootFD, LockFD))
		return MaterialCommitResult{std::move(Path), MaterialCommitDurability::Unknown,
			MaterialCommitIntegrity::Unknown};
	if (Token.Fault == MaterialExportFault::RootSync || ::fsync(RootFD) != 0)
		return MaterialCommitResult{std::move(Path), MaterialCommitDurability::Unknown};
	return MaterialCommitResult{std::move(Path), MaterialCommitDurability::Durable};
}

Expected<MaterialCommitResult> llvm::commitDynamicArtifacts(StringRef ExportRoot,
	StringRef SoftwareId, ArrayRef<DynamicArtifactExport> Artifacts,
	const MaterialCommitToken& Token) {
	if (Token.Value != kCommitToken || !sys::path::is_absolute(ExportRoot) ||
		!validId(SoftwareId) || Artifacts.empty() || Artifacts.size() > 4096)
		return materialError("invalid dynamic material export request");
	std::set<std::string> RegionNames;
	std::set<std::string> RegionIds;
	for (const DynamicArtifactExport& Artifact : Artifacts)
		if (Error E = validateDynamicArtifactExport(Artifact)) return std::move(E);
		else {
			auto Name = Artifact.PublicManifest.getString("region_name");
			auto Id = Artifact.PublicManifest.getString("region_id");
			if (!Name || !Id || !RegionNames.insert(Name->str()).second ||
				!RegionIds.insert(Id->str()).second)
				return materialError("duplicate dynamic artifact region identity");
		}
	SmallString<256> RealRoot;
	if (std::error_code EC = sys::fs::real_path(ExportRoot, RealRoot, true))
		return materialError("dynamic material export root resolution failed");
	if (RealRoot != ExportRoot) return materialError("dynamic material export root may not traverse symlinks");
	struct stat RootStat{};
	if (::lstat(ExportRoot.str().c_str(), &RootStat) != 0 || !S_ISDIR(RootStat.st_mode) ||
		RootStat.st_uid != ::geteuid() || (RootStat.st_mode & 0077u) != 0)
		return materialError("dynamic material export root permissions invalid");
	int RootFD = ::open(ExportRoot.str().c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
	if (RootFD < 0) return materialError("dynamic material export root open failed");
	auto CloseRoot = make_scope_exit([&] { ::close(RootFD); });
	struct stat OpenedRootStat{};
	if (::fstat(RootFD, &OpenedRootStat) != 0 ||
		!sameStatIdentity(RootStat, OpenedRootStat))
		return materialError("dynamic material export root changed during validation");
	auto LockOr = lockMaterialRoot(RootFD);
	if (!LockOr) return LockOr.takeError();
	int LockFD = *LockOr;
	auto CloseLock = make_scope_exit([&] { ::close(LockFD); });

	json::Array PublicRegions;
	json::Array PrivateRegions;
	for (const DynamicArtifactExport& Artifact : Artifacts) {
		json::Object Public = Artifact.PublicManifest;
		json::Object Private = Artifact.PrivateRegistration;
		PublicRegions.push_back(json::Value(std::move(Public)));
		PrivateRegions.push_back(json::Value(std::move(Private)));
	}
	json::Object PublicBundle{{"format_version", 2}, {"material_source", "dynamic_vm"},
		{"regions", std::move(PublicRegions)}};
	json::Object PrivateBundle{{"format_version", 2}, {"material_source", "dynamic_vm"},
		{"regions", std::move(PrivateRegions)}};
	auto PublicBytes = objectBytes(PublicBundle, MaterialCodecProfile::PublicManifest);
	if (!PublicBytes) return PublicBytes.takeError();
	auto PrivateBytes = objectBytes(PrivateBundle, MaterialCodecProfile::PrivateRegistration);
	if (!PrivateBytes) return PrivateBytes.takeError();
	SmallVector<std::pair<std::string, std::string>, 3> Files;
	Files.push_back({"software-id", SoftwareId.str()});
	std::string ModuleInput = "xovm-dynamic-private-v1|software=" + SoftwareId.str();
	ModuleInput += "|public|" + hashBytes(*PublicBytes) + "|private|" + hashBytes(*PrivateBytes);
	Files.push_back({"public-manifest.json", std::move(*PublicBytes)});
	Files.push_back({"registration.private.json", std::move(*PrivateBytes)});
	std::string FinalName = hashBytes(ModuleInput) + ".dynamic";
	if (Error E = rejectExistingDynamicConflicts(RootFD, FinalName, Files))
		return std::move(E);
	std::array<uint8_t, 16> Random{};
	if (std::error_code EC = getRandomBytes(Random.data(), Random.size()))
		return materialError("dynamic material staging randomness unavailable");
	std::string StageName = ".staging-dynamic-" + toHex(ArrayRef<uint8_t>(Random), true);
	if (::mkdirat(RootFD, StageName.c_str(), 0700) != 0)
		return materialError("dynamic material staging directory creation failed");
	SmallString<256> StagePath(ExportRoot); sys::path::append(StagePath, StageName);
	bool Published = false;
	auto Cleanup = make_scope_exit([&] { if (!Published) sys::fs::remove_directories(StagePath); });
	int StageFD = ::openat(RootFD, StageName.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
	if (StageFD < 0) return materialError("dynamic material staging directory open failed");
	auto CloseStage = make_scope_exit([&] { ::close(StageFD); });
	if (::fchmod(StageFD, 0700) != 0)
		return materialError("dynamic material staging directory permissions failed");
	for (const auto& [Name, Bytes] : Files) {
		if (Token.Fault == MaterialExportFault::Create)
			return materialError("dynamic material file creation failed");
		int FD = ::openat(StageFD, Name.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
		if (FD < 0) return materialError("dynamic material file creation failed");
		if (::fchmod(FD, 0600) != 0) {
			::close(FD);
			return materialError("dynamic material file permissions failed");
		}
		if (Error E = writeAll(FD, Bytes, Token.Fault)) { ::close(FD); return E; }
		if (::close(FD) != 0 || Token.Fault == MaterialExportFault::Close)
			return materialError("dynamic material file close failed");
	}
	if (!sameBundleContents(RootFD, StageName, SoftwareId, ArrayRef(Files).drop_front()))
		return materialError("dynamic material staging validation failed");
	if (Token.Fault == MaterialExportFault::DirectorySync || ::fsync(StageFD) != 0)
		return materialError("dynamic material staging directory fsync failed");
	if (!lockStillNamed(RootFD, LockFD) || ::fsync(RootFD) != 0)
		return materialError("dynamic material staging sync failed");
	if (Token.Fault == MaterialExportFault::Rename) {
		errno = EIO;
		return materialError("dynamic material publish rename failed");
	}
	if (renameNoReplace(RootFD, StageName.c_str(), RootFD, FinalName.c_str()) != 0) {
		if (errno != EEXIST || !sameBundleContents(RootFD, FinalName, SoftwareId,
			ArrayRef(Files).drop_front(), Token.Fault))
			return materialError("dynamic material publish conflict");
		if (!lockStillNamed(RootFD, LockFD) || ::fsync(RootFD) != 0)
			return MaterialCommitResult{(Twine(ExportRoot) + "/" + FinalName).str(),
				MaterialCommitDurability::Unknown, MaterialCommitIntegrity::Unknown};
		return MaterialCommitResult{(Twine(ExportRoot) + "/" + FinalName).str(),
			MaterialCommitDurability::Durable};
	}
	Published = true;
	struct stat FinalStat{}, StageStat{};
	if (::fstat(StageFD, &StageStat) != 0 ||
		::fstatat(RootFD, StageName.c_str(), &FinalStat, AT_SYMLINK_NOFOLLOW) == 0 ||
		errno != ENOENT || ::fstatat(RootFD, FinalName.c_str(), &FinalStat,
			AT_SYMLINK_NOFOLLOW) != 0 || FinalStat.st_dev != StageStat.st_dev ||
		FinalStat.st_ino != StageStat.st_ino ||
		!sameBundleContents(RootFD, FinalName, SoftwareId, ArrayRef(Files).drop_front()) ||
		!lockStillNamed(RootFD, LockFD))
		return MaterialCommitResult{(Twine(ExportRoot) + "/" + FinalName).str(),
			MaterialCommitDurability::Unknown, MaterialCommitIntegrity::Unknown};
	if (Token.Fault == MaterialExportFault::RootSync || ::fsync(RootFD) != 0)
		return MaterialCommitResult{(Twine(ExportRoot) + "/" + FinalName).str(),
			MaterialCommitDurability::Unknown, MaterialCommitIntegrity::Unknown};
	return MaterialCommitResult{(Twine(ExportRoot) + "/" + FinalName).str(),
		MaterialCommitDurability::Durable};
}
