#pragma once

#include "llvm/ADT/SmallBitVector.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Support/JSON.h"
#include "llvm/Transforms/Obfuscator/ObfuscationConfig.h"
#include "llvm/Transforms/Obfuscator/VMPass_ISA.h"

#include <array>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace llvm {

class FunctionType;

StringRef vmOpcodeName(VMOp Op);

struct VMRequirementSet {
	SmallBitVector Opcodes = SmallBitVector(OP_COUNT);
	SmallBitVector BinSubops[2] = {SmallBitVector(13), SmallBitVector(13)};
	SmallBitVector IcmpPredicates[2] = {SmallBitVector(42), SmallBitVector(42)};
	SmallBitVector SuperPredicates[2] = {SmallBitVector(42), SmallBitVector(42)};
	SmallBitVector CastKinds[2] = {SmallBitVector(8), SmallBitVector(11)};
	SmallBitVector FBinSubops = SmallBitVector(5);
	SmallBitVector FcmpPredicates = SmallBitVector(16);
	SmallBitVector FCastKinds[5] = {SmallBitVector(10), SmallBitVector(10),
		SmallBitVector(10), SmallBitVector(10), SmallBitVector(10)};
	SmallBitVector SelectKinds = SmallBitVector(3);
	SmallBitVector PrecisionFlags = SmallBitVector(2);
	// 位 0 为 f64，位 1 为 f32；精度必须绑定语义，不能生成笛卡尔积。
	std::array<uint8_t, 5> FBinPrecision = {};
	std::array<std::array<uint8_t, 10>, 5> FCastPrecision = {};
	SmallVector<FunctionType *, 16> CallTypes;
	SmallVector<VMOp, 8> NestedHelpers;
	bool NeedsSuperOps = false;
	bool NeedsConstStream = false;
	bool NeedsRegFile[4] = {}; // i32、i64、浮点、指针

	void requireOpcode(VMOp Op);
	void requireBinSubop(VMOp Op, uint8_t Logical);
	void requireIcmpPredicate(VMOp Op, uint8_t Logical);
	void requireCastKind(VMOp Op, uint8_t Logical);
	void requireFBinSubop(uint8_t Logical, bool IsF32);
	void requireFcmpPredicate(uint8_t Logical);
	void requireFCastKind(VMOp Op, uint8_t Logical, bool IsF32);
	void requireSelectKind(uint8_t Logical);
	void requireCallType(FunctionType *FTy);
	void merge(const VMRequirementSet &Other);
	void closeDependencies(const VMPassConfig &Cfg);
	bool contains(VMOp Op) const;
	bool allowsBinSubop(VMOp Op, uint8_t Logical) const;
	bool allowsIcmpPredicate(VMOp Op, uint8_t Logical) const;
	bool allowsCastKind(VMOp Op, uint8_t Logical) const;
	bool allowsFBinSubop(uint8_t Logical, bool IsF32) const;
	bool allowsFCastKind(VMOp Op, uint8_t Logical, bool IsF32) const;
	bool allowsCallType(FunctionType *FTy) const;
	json::Object toJson() const;
};

class EngineConfigKey {
	// 有序命名字段同时驱动比较、稳定 hash 和报告，避免三个清单漂移。
	std::vector<std::pair<std::string, uint64_t>> Fields;
	unsigned BoolFields = 0;

public:
	bool operator==(const EngineConfigKey &Other) const;
	static EngineConfigKey fromConfig(const VMPassConfig &Cfg,
		unsigned EnginePool, unsigned EngineOwner, uint64_t MappingSeed = 0,
		const AntiDebugConfig* AntiDebug = nullptr);
	uint64_t stableHash() const;
	json::Object toJson() const;
};

struct VMEnginePlan {
	unsigned EngineId = 0;
	VMPassConfig Config;
	EngineConfigKey Key;
	VMRequirementSet DirectRequirements;
	VMRequirementSet Requirements;
	unsigned Decoys = 0;
	bool Frozen = false;

	unsigned handlerTableEntries() const;
};

struct VMCallerWitness {
	std::string Name;
	VMRequirementSet Requirements;
};

struct VMDependencyWitness {
	std::string From;
	std::string To;
	std::string Reason;
};

struct VMEngineWitness {
	unsigned EngineId = 0;
	EngineConfigKey ConfigKey;
	VMRequirementSet Requirements;
	std::vector<VMCallerWitness> Callers;
	std::vector<VMDependencyWitness> Dependencies;
	SmallVector<VMOp, 16> RealHandlers;
	unsigned HandlerVariants = 0;
	unsigned Decoys = 0;
	unsigned HandlerTableEntries = 0;
	uint64_t ModuleSeed = 0;
	ISAEnc Maps;

	json::Object toJson() const;
};

} // namespace llvm
