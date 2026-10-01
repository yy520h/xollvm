#include "llvm/Transforms/Obfuscator/VMPass_Requirements.h"

#include "llvm/ADT/STLExtras.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/raw_ostream.h"

#include <algorithm>

using namespace llvm;

namespace {

constexpr const char *OpcodeNames[] = {
	"loadi", "movr", "binop", "icmp", "cast", "ptrtoint", "inttoptr",
	"load32", "store32", "gep", "jmp", "jmpc", "ret_void", "ret_int",
	"ret_ptr", "call_void", "call_int", "call_ptr", "select", "ptrtoint64",
	"load64", "store64", "cast64", "binop64", "switch", "gep64", "icmp64",
	"load8", "store8", "load16", "store16", "loadptr", "storeptr",
	"loadi_f", "movr_f", "binop_f", "fcmp", "fcast_ff", "load_f", "store_f",
	"ret_f", "select_f", "call_int64", "call_f", "fneg", "load_f32",
	"store_f32", "fcast_fv", "fcast_fv64", "fcast_vf", "fcast_v64f",
	"loadi64", "muladd", "shladd", "cmpsel", "andcmpz"
};
static_assert(std::size(OpcodeNames) == OP_COUNT);

int binFamily(VMOp Op) {
	return Op == OP_BINOP ? 0 : Op == OP_BINOP64 ? 1 : -1;
}

int castFamily(VMOp Op) {
	return Op == OP_CAST ? 0 : Op == OP_CAST64 ? 1 : -1;
}

int fcastFamily(VMOp Op) {
	switch (Op) {
	case OP_FCAST_FF: return 0;
	case OP_FCAST_FV: return 1;
	case OP_FCAST_FV64: return 2;
	case OP_FCAST_VF: return 3;
	case OP_FCAST_V64F: return 4;
	default: return -1;
	}
}

bool validFCast(VMOp Op, uint8_t Kind, bool IsF32) {
	switch (Op) {
	case OP_FCAST_FF: return !IsF32 && (Kind == FK_FPEXT || Kind == FK_FPTRUNC);
	case OP_FCAST_FV: return !IsF32 && (Kind == FK_FPTOSI || Kind == FK_FPTOUI);
	case OP_FCAST_FV64: return !IsF32 && (Kind == FK_FPTOSI64 || Kind == FK_FPTOUI64);
	case OP_FCAST_VF: return Kind == FK_SITOFP || Kind == FK_UITOFP;
	case OP_FCAST_V64F: return Kind == FK_SI64TOFP || Kind == FK_UI64TOFP;
	default: return false;
	}
}

const SmallBitVector *predicateSet(const VMRequirementSet &R, VMOp Op) {
	switch (Op) {
	case OP_ICMP: return &R.IcmpPredicates[0];
	case OP_ICMP64: return &R.IcmpPredicates[1];
	case OP_CMPSEL: return &R.SuperPredicates[0];
	case OP_ANDCMPZ: return &R.SuperPredicates[1];
	default: return nullptr;
	}
}

bool hasBit(const SmallBitVector &Bits, unsigned Value) {
	return Value < Bits.size() && Bits.test(Value);
}

void requireValid(bool Valid) {
	if (!Valid) report_fatal_error("VM requirement contains an invalid semantic family/value");
}

std::string typeKey(FunctionType *FTy) {
	std::string Result;
	raw_string_ostream OS(Result);
	FTy->print(OS);
	return Result;
}

void requireTypeFile(VMRequirementSet &R, Type *Ty) {
	if (Ty->isIntegerTy()) R.NeedsRegFile[Ty->getIntegerBitWidth() > 32 ? 1 : 0] = true;
	else if (Ty->isFloatingPointTy()) R.NeedsRegFile[2] = true;
	else if (Ty->isPointerTy()) R.NeedsRegFile[3] = true;
}

json::Array bitValues(const SmallBitVector &Bits) {
	json::Array Result;
	for (unsigned I = 0; I < Bits.size(); ++I)
		if (Bits.test(I)) Result.push_back(I);
	return Result;
}

json::Array opcodeValues(ArrayRef<VMOp> Ops) {
	json::Array Result;
	for (VMOp Op : Ops) Result.push_back(vmOpcodeName(Op));
	return Result;
}

template <size_t N>
json::Array mapValues(const uint8_t (&Map)[N]) {
	json::Array Result;
	for (uint8_t Value : Map) Result.push_back(Value);
	return Result;
}

} // namespace

StringRef llvm::vmOpcodeName(VMOp Op) {
	return Op < OP_COUNT ? OpcodeNames[Op] : "invalid";
}

void VMRequirementSet::requireOpcode(VMOp Op) {
	requireValid(Op < OP_COUNT);
	Opcodes.set(Op);
}

void VMRequirementSet::requireBinSubop(VMOp Op, uint8_t Logical) {
	int F = binFamily(Op);
	requireValid(F >= 0 && Logical < ISAEnc::kNumBinSubop);
	requireOpcode(Op);
	BinSubops[F].set(Logical);
}

void VMRequirementSet::requireIcmpPredicate(VMOp Op, uint8_t Logical) {
	auto *Bits = const_cast<SmallBitVector *>(predicateSet(*this, Op));
	requireValid(Bits && Logical >= ISAEnc::kIcmpPredBase &&
		Logical < ISAEnc::kIcmpPredBase + ISAEnc::kNumIcmpPred &&
		(Op != OP_ANDCMPZ || Logical <= ISAEnc::kIcmpPredBase + 1));
	requireOpcode(Op);
	Bits->set(Logical);
}

void VMRequirementSet::requireCastKind(VMOp Op, uint8_t Logical) {
	int F = castFamily(Op);
	requireValid(F >= 0 && Logical < CastKinds[F].size());
	requireOpcode(Op);
	CastKinds[F].set(Logical);
}

void VMRequirementSet::requireFBinSubop(uint8_t Logical, bool IsF32) {
	requireValid(Logical < ISAEnc::kNumFBinSubop);
	requireOpcode(OP_BINOP_F);
	FBinSubops.set(Logical);
	PrecisionFlags.set(IsF32 ? 1 : 0);
	FBinPrecision[Logical] |= IsF32 ? 2 : 1;
}

void VMRequirementSet::requireFcmpPredicate(uint8_t Logical) {
	requireValid(Logical < 16);
	requireOpcode(OP_FCMP);
	FcmpPredicates.set(Logical);
}

void VMRequirementSet::requireFCastKind(VMOp Op, uint8_t Logical, bool IsF32) {
	requireValid(validFCast(Op, Logical, IsF32));
	unsigned F = fcastFamily(Op);
	requireOpcode(Op);
	FCastKinds[F].set(Logical);
	PrecisionFlags.set(IsF32 ? 1 : 0);
	FCastPrecision[F][Logical] |= IsF32 ? 2 : 1;
}

void VMRequirementSet::requireSelectKind(uint8_t Logical) {
	requireValid(Logical < 3);
	requireOpcode(OP_SELECT);
	SelectKinds.set(Logical);
}

void VMRequirementSet::requireCallType(FunctionType *FTy) {
	requireValid(FTy != nullptr);
	if (!allowsCallType(FTy))
		CallTypes.push_back(FTy);
	requireTypeFile(*this, FTy->getReturnType());
	for (Type *Ty : FTy->params()) requireTypeFile(*this, Ty);
}

void VMRequirementSet::merge(const VMRequirementSet &Other) {
	Opcodes |= Other.Opcodes;
	for (unsigned I = 0; I < 2; ++I) {
		BinSubops[I] |= Other.BinSubops[I];
		IcmpPredicates[I] |= Other.IcmpPredicates[I];
		SuperPredicates[I] |= Other.SuperPredicates[I];
		CastKinds[I] |= Other.CastKinds[I];
	}
	FBinSubops |= Other.FBinSubops;
	FcmpPredicates |= Other.FcmpPredicates;
	SelectKinds |= Other.SelectKinds;
	PrecisionFlags |= Other.PrecisionFlags;
	for (unsigned I = 0; I < 5; ++I) {
		FBinPrecision[I] |= Other.FBinPrecision[I];
		FCastKinds[I] |= Other.FCastKinds[I];
		for (unsigned K = 0; K < 10; ++K)
			FCastPrecision[I][K] |= Other.FCastPrecision[I][K];
	}
	for (auto *FTy : Other.CallTypes) requireCallType(FTy);
	for (VMOp Op : Other.NestedHelpers)
		if (!llvm::is_contained(NestedHelpers, Op)) NestedHelpers.push_back(Op);
	llvm::sort(NestedHelpers);
	NeedsSuperOps |= Other.NeedsSuperOps;
	NeedsConstStream |= Other.NeedsConstStream;
	for (unsigned I = 0; I < 4; ++I) NeedsRegFile[I] |= Other.NeedsRegFile[I];
}

void VMRequirementSet::closeDependencies(const VMPassConfig &Cfg) {
	// 控制/寻址中的宿主算术不构成 VM BINOP 需求；所有 opcode 都来自发射点。
	for (unsigned I = 0; I < OP_COUNT; ++I) {
		if (!Opcodes.test(I)) continue;
		switch (static_cast<VMOp>(I)) {
		case OP_LOADI: case OP_MOVR: case OP_BINOP: case OP_ICMP: case OP_CAST:
		case OP_JMPC: case OP_RET_INT: case OP_SWITCH: case OP_CALL_INT:
			NeedsRegFile[0] = true; break;
		case OP_LOADI64: case OP_BINOP64: case OP_CALL_INT64:
			NeedsRegFile[1] = true; break;
		case OP_CAST64: case OP_ICMP64:
			NeedsRegFile[0] = NeedsRegFile[1] = true; break;
		case OP_PTRTOINT: case OP_INTTOPTR: case OP_LOAD32: case OP_STORE32:
		case OP_LOAD8: case OP_STORE8: case OP_LOAD16: case OP_STORE16: case OP_GEP:
			NeedsRegFile[0] = NeedsRegFile[3] = true; break;
		case OP_PTRTOINT64: case OP_LOAD64: case OP_STORE64: case OP_GEP64:
			NeedsRegFile[1] = NeedsRegFile[3] = true; break;
		case OP_LOADPTR: case OP_STOREPTR: case OP_RET_PTR: case OP_CALL_PTR:
			NeedsRegFile[3] = true; break;
		case OP_LOADI_F: case OP_MOVR_F: case OP_BINOP_F: case OP_FCAST_FF:
		case OP_RET_F: case OP_CALL_F: case OP_FNEG:
			NeedsRegFile[2] = true; break;
		case OP_FCMP: case OP_SELECT_F: case OP_FCAST_FV: case OP_FCAST_VF:
			NeedsRegFile[0] = NeedsRegFile[2] = true; break;
		case OP_FCAST_FV64: case OP_FCAST_V64F:
			NeedsRegFile[1] = NeedsRegFile[2] = true; break;
		case OP_LOAD_F: case OP_STORE_F: case OP_LOAD_F32: case OP_STORE_F32:
			NeedsRegFile[2] = NeedsRegFile[3] = true; break;
		case OP_SELECT:
			NeedsRegFile[0] = true;
			if (SelectKinds.test(1)) NeedsRegFile[3] = true;
			if (SelectKinds.test(2)) NeedsRegFile[1] = true;
			break;
		case OP_MULADD: case OP_SHLADD: case OP_CMPSEL: case OP_ANDCMPZ:
			NeedsRegFile[0] = NeedsSuperOps = true; break;
		case OP_JMP: case OP_RET_VOID: case OP_CALL_VOID: case OP_COUNT: break;
		}
	}
	NeedsConstStream |= Cfg.constInStream &&
		(contains(OP_LOADI) || contains(OP_LOADI64) || contains(OP_LOADI_F));
	if (Cfg.nestedVM) {
		constexpr VMOp Order[] = {OP_BINOP, OP_BINOP64, OP_ICMP, OP_ICMP64,
			OP_FCMP, OP_CAST, OP_BINOP_F};
		unsigned N = Cfg.nestedVMOpcodes ? std::min<unsigned>(Cfg.nestedVMOpcodes, std::size(Order)) : std::size(Order);
		for (unsigned I = 0; I < N; ++I)
			if (contains(Order[I]) && !llvm::is_contained(NestedHelpers, Order[I]))
				NestedHelpers.push_back(Order[I]);
	}
}

bool VMRequirementSet::contains(VMOp Op) const { return hasBit(Opcodes, Op); }

bool VMRequirementSet::allowsBinSubop(VMOp Op, uint8_t Logical) const {
	int F = binFamily(Op);
	return F >= 0 && contains(Op) && hasBit(BinSubops[F], Logical);
}

bool VMRequirementSet::allowsIcmpPredicate(VMOp Op, uint8_t Logical) const {
	auto *Bits = predicateSet(*this, Op);
	return Bits && contains(Op) && hasBit(*Bits, Logical);
}

bool VMRequirementSet::allowsCastKind(VMOp Op, uint8_t Logical) const {
	int F = castFamily(Op);
	return F >= 0 && contains(Op) && hasBit(CastKinds[F], Logical);
}

bool VMRequirementSet::allowsFBinSubop(uint8_t Logical, bool IsF32) const {
	return contains(OP_BINOP_F) && Logical < FBinPrecision.size() &&
		(FBinPrecision[Logical] & (IsF32 ? 2 : 1));
}

bool VMRequirementSet::allowsFCastKind(VMOp Op, uint8_t Logical, bool IsF32) const {
	int F = fcastFamily(Op);
	return F >= 0 && contains(Op) && validFCast(Op, Logical, IsF32) &&
		(FCastPrecision[F][Logical] & (IsF32 ? 2 : 1));
}

bool VMRequirementSet::allowsCallType(FunctionType *FTy) const {
	if (!FTy) return false;
	std::string Key = typeKey(FTy);
	return llvm::any_of(CallTypes, [&](FunctionType *Other) { return typeKey(Other) == Key; });
}

json::Object VMRequirementSet::toJson() const {
	json::Object O;
	for (unsigned I = 0; I < OP_COUNT; ++I) {
		VMOp Op = static_cast<VMOp>(I);
		if (!contains(Op)) continue;
		json::Object Family;
		if (int F = binFamily(Op); F >= 0) Family["subops"] = bitValues(BinSubops[F]);
		if (auto *Bits = predicateSet(*this, Op)) Family["predicates"] = bitValues(*Bits);
		if (int F = castFamily(Op); F >= 0) Family["kinds"] = bitValues(CastKinds[F]);
		if (Op == OP_FCMP) Family["predicates"] = bitValues(FcmpPredicates);
		if (Op == OP_SELECT) Family["kinds"] = bitValues(SelectKinds);
		int FC = fcastFamily(Op);
		if (Op == OP_BINOP_F || FC >= 0) {
			json::Array Cases;
			unsigned N = Op == OP_BINOP_F ? 5 : 10;
			for (unsigned K = 0; K < N; ++K) {
				unsigned Mask = Op == OP_BINOP_F ? FBinPrecision[K] : FCastPrecision[FC][K];
				for (unsigned P = 0; P < 2; ++P) {
					if (!(Mask & (1u << P))) continue;
					json::Object C;
					C[Op == OP_BINOP_F ? "subop" : "kind"] = K;
					C["f32"] = P != 0;
					Cases.push_back(std::move(C));
				}
			}
			Family["cases"] = std::move(Cases);
		}
		O[vmOpcodeName(Op)] = std::move(Family);
	}
	json::Array Types;
	std::vector<std::string> TypeNames;
	for (auto *FTy : CallTypes) TypeNames.push_back(typeKey(FTy));
	llvm::sort(TypeNames);
	for (const auto &Name : TypeNames) Types.push_back(Name);
	O["call_types"] = std::move(Types);
	O["nested_helpers"] = opcodeValues(NestedHelpers);
	json::Array RegFiles;
	constexpr const char *Names[] = {"i32", "i64", "float", "pointer"};
	for (unsigned I = 0; I < 4; ++I)
		if (NeedsRegFile[I]) RegFiles.push_back(Names[I]);
	O["register_files"] = std::move(RegFiles);
	O["constant_stream"] = NeedsConstStream;
	O["superops"] = NeedsSuperOps;
	return O;
}

EngineConfigKey EngineConfigKey::fromConfig(const VMPassConfig &Cfg,
unsigned EnginePool, unsigned EngineOwner, uint64_t MappingSeed,
	const AntiDebugConfig* AntiDebug) {
	EngineConfigKey Key;
#define VM_BOOL(Name) Key.Fields.emplace_back(#Name, Cfg.Name)
	VM_BOOL(lazyDecrypt); VM_BOOL(obfRegIdx); VM_BOOL(encDispatch);
	VM_BOOL(encBytecode); VM_BOOL(constInStream); VM_BOOL(strongBytecode);
	VM_BOOL(blindTargets); VM_BOOL(hardened); VM_BOOL(regEncrypt);
	VM_BOOL(rollingRegKey); VM_BOOL(antiDebug); VM_BOOL(bindAntiDebug);
	VM_BOOL(nestedVM); VM_BOOL(nestedVMHardened); VM_BOOL(threadedDispatch);
	VM_BOOL(keyedDispatch); VM_BOOL(superOps); VM_BOOL(randISA);
	VM_BOOL(metamorphicEngines); VM_BOOL(perFnEngine);
#undef VM_BOOL
	Key.BoolFields = Key.Fields.size();
#define VM_UINT(Name) Key.Fields.emplace_back(#Name, Cfg.Name)
	VM_UINT(handlerVariants); VM_UINT(handlerDecoys);
	VM_UINT(adDispatchThreshold); VM_UINT(adHandlerThreshold);
	VM_UINT(adDispatchInterval); VM_UINT(adHandlerProb);
	VM_UINT(nestedVMOpcodes); VM_UINT(enginePoolSize);
#undef VM_UINT
	Key.Fields.emplace_back("engine_pool", EnginePool);
	Key.Fields.emplace_back("engine_owner", Cfg.perFnEngine ? EngineOwner : 0);
	Key.Fields.emplace_back("isa_version", ISAEnc::kEncodingVersion);
	Key.Fields.emplace_back("mapping_seed", Cfg.randISA ? MappingSeed : 0);
	const AntiDebugConfig& AD = AntiDebug ? *AntiDebug : Cfg.antiDebugConfig;
	Key.Fields.emplace_back("ad_enabled", AD.enabled);
	Key.Fields.emplace_back("ad_tracer_pid", AD.tracerPid);
	Key.Fields.emplace_back("ad_ptrace", AD.ptrace);
	Key.Fields.emplace_back("ad_timing", AD.timing);
	Key.Fields.emplace_back("ad_maps", AD.maps);
	Key.Fields.emplace_back("ad_integrity", AD.integrity);
	Key.Fields.emplace_back("ad_dynamic", AD.dynamic);
	Key.Fields.emplace_back("ad_interval", AD.intervalMs);
	Key.Fields.emplace_back("ad_threshold", AD.thresholdNs);
	Key.Fields.emplace_back("ad_response_corrupt", AD.responseCorrupt);
	return Key;
}

bool EngineConfigKey::operator==(const EngineConfigKey &Other) const {
	return BoolFields == Other.BoolFields && Fields == Other.Fields;
}

uint64_t EngineConfigKey::stableHash() const {
	// 显式逐字节 FNV-1a，不依赖宿主字节序或 LLVM 的进程随机 hash seed。
	uint64_t H = 14695981039346656037ULL;
	auto Byte = [&](uint8_t B) { H = (H ^ B) * 1099511628211ULL; };
	for (const auto &[Name, Value] : Fields) {
		for (unsigned char C : Name) Byte(C);
		Byte(0);
		for (unsigned I = 0; I < 8; ++I) Byte(static_cast<uint8_t>(Value >> (I * 8)));
	}
	return H;
}

json::Object EngineConfigKey::toJson() const {
	json::Object O;
	for (unsigned I = 0; I < Fields.size(); ++I) {
		const auto &[Name, Value] = Fields[I];
		if (I < BoolFields) O[Name] = Value != 0;
		else if (Name == "mapping_seed") O[Name] = std::to_string(Value);
		else O[Name] = Value;
	}
	return O;
}

unsigned VMEnginePlan::handlerTableEntries() const {
	return OP_COUNT * Config.handlerVariants + 1 + (Config.encDispatch ? OP_COUNT : 0) + Decoys;
}

json::Object VMEngineWitness::toJson() const {
	json::Object O;
	O["version"] = 1;
	O["engine_id"] = EngineId;
	O["config_key"] = ConfigKey.toJson();
	O["requirements"] = Requirements.toJson();
	json::Array CallerValues;
	for (const auto &Caller : Callers) {
		json::Object C;
		C["name"] = Caller.Name;
		C["requirements"] = Caller.Requirements.toJson();
		CallerValues.push_back(std::move(C));
	}
	O["callers"] = std::move(CallerValues);
	json::Array Edges;
	for (const auto &Dep : Dependencies) {
		json::Object D;
		D["from"] = Dep.From;
		D["to"] = Dep.To;
		D["reason"] = Dep.Reason;
		Edges.push_back(std::move(D));
	}
	O["dependencies"] = std::move(Edges);
	O["real_handlers"] = opcodeValues(RealHandlers);
	O["handler_variants"] = HandlerVariants;
	O["decoys"] = Decoys;
	O["handler_table_entries"] = HandlerTableEntries;
	O["module_seed"] = std::to_string(ModuleSeed);
	json::Object M;
	M["version"] = ISAEnc::kEncodingVersion;
	M["bin_subop"] = mapValues(Maps.BinSubopL2P);
	M["icmp_predicate"] = mapValues(Maps.IcmpPredL2P);
	M["cast_kind"] = mapValues(Maps.CastKindL2P);
	M["fbin_subop"] = mapValues(Maps.FBinSubopL2P);
	M["fcmp_predicate"] = mapValues(Maps.FcmpPredL2P);
	O["isa_maps"] = std::move(M);
	return O;
}
