#pragma once

#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/Transforms/Obfuscator/VMPass_ISA.h"
#include <array>

namespace llvm {

enum class VMFieldRole : uint8_t {
	Dst, SrcA, SrcB, SrcC, SrcD, Predicate, Kind, Immediate, Pointer,
	Index, Scale, Target, FalseTarget, Callee, ArgCount, CaseCount, Alignment
};

struct VMLayoutField {
	VMFieldRole Role;
	unsigned Canonical;
	unsigned Offset;
	unsigned Width;
};

class VMInstructionLayout {
	std::array<SmallVector<VMLayoutField, 7>, OP_COUNT> Fields;
	std::array<unsigned, OP_COUNT> Sizes = {};
	std::array<bool, OP_COUNT> Variable = {};

public:
	static constexpr unsigned Version = 2;
	VMInstructionLayout();
	static VMInstructionLayout forSeed(uint64_t Seed);
	ArrayRef<VMLayoutField> fields(VMOp Op) const { return Fields[Op]; }
	unsigned offset(VMOp Op, VMFieldRole Role) const;
	unsigned size(VMOp Op) const { return Sizes[Op]; }
	bool variable(VMOp Op) const { return Variable[Op]; }
	unsigned physicalByte(VMOp Op, unsigned Canonical) const;
	unsigned canonicalByte(VMOp Op, unsigned Physical) const;
	bool setFields(VMOp Op, ArrayRef<VMLayoutField> NewFields);
	bool validate() const;
	uint64_t fingerprint() const;
};

} // namespace llvm
