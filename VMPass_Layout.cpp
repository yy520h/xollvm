#include "llvm/Transforms/Obfuscator/VMPass_Layout.h"
#include "llvm/Transforms/Obfuscator/Rng.h"
#include <cassert>

using namespace llvm;

VMInstructionLayout::VMInstructionLayout() {
	using R = VMFieldRole;
	auto Define = [&](VMOp Op, std::initializer_list<std::pair<R, unsigned>> Spec, bool Var = false) {
		unsigned Off = 1;
		for (auto F : Spec) {
			Fields[Op].push_back({F.first, Off, Off, F.second});
			Off += F.second;
		}
		Sizes[Op] = Off;
		Variable[Op] = Var;
	};
	for (VMOp Op : {OP_LOADI, OP_LOADI64, OP_LOADI_F})
		Define(Op, {{R::Dst, 1}, {R::Immediate, Op == OP_LOADI ? 4u : 8u}});
	for (VMOp Op : {OP_MOVR, OP_MOVR_F, OP_FNEG, OP_PTRTOINT, OP_PTRTOINT64, OP_INTTOPTR})
		Define(Op, {{R::Dst, 1}, {R::SrcA, 1}});
	for (VMOp Op : {OP_BINOP, OP_BINOP64, OP_BINOP_F})
		Define(Op, {{R::Dst, 1}, {R::SrcA, 1}, {R::SrcB, 1}, {R::Kind, 1}});
	for (VMOp Op : {OP_ICMP, OP_ICMP64, OP_FCMP, OP_ANDCMPZ})
		Define(Op, {{R::Dst, 1}, {R::SrcA, 1}, {R::SrcB, 1}, {R::Predicate, 1}});
	for (VMOp Op : {OP_CAST, OP_CAST64, OP_FCAST_FF, OP_FCAST_FV, OP_FCAST_FV64, OP_FCAST_VF, OP_FCAST_V64F})
		Define(Op, {{R::Dst, 1}, {R::SrcA, 1}, {R::Kind, 1}});
	for (VMOp Op : {OP_LOAD8, OP_LOAD16, OP_LOAD32, OP_LOAD64, OP_LOADPTR, OP_LOAD_F, OP_LOAD_F32})
		Define(Op, {{R::Dst, 1}, {R::Pointer, 1}});
	for (VMOp Op : {OP_STORE8, OP_STORE16, OP_STORE32, OP_STORE64, OP_STOREPTR, OP_STORE_F, OP_STORE_F32})
		Define(Op, {{R::SrcA, 1}, {R::Pointer, 1}});
	for (VMOp Op : {OP_GEP, OP_GEP64})
		Define(Op, {{R::Dst, 1}, {R::Pointer, 1}, {R::Index, 1}, {R::Scale, 2}});
	Define(OP_JMP, {{R::Target, 4}});
	Define(OP_JMPC, {{R::Index, 1}, {R::Target, 4}, {R::FalseTarget, 4}});
	Define(OP_RET_VOID, {});
	for (VMOp Op : {OP_RET_INT, OP_RET_PTR, OP_RET_F}) Define(Op, {{R::SrcA, 1}});
	Define(OP_SELECT, {{R::Kind, 1}, {R::Dst, 1}, {R::Index, 1}, {R::SrcA, 1}, {R::SrcB, 1}});
	Define(OP_SELECT_F, {{R::Dst, 1}, {R::Index, 1}, {R::SrcA, 1}, {R::SrcB, 1}});
	for (VMOp Op : {OP_MULADD, OP_SHLADD})
		Define(Op, {{R::Dst, 1}, {R::SrcA, 1}, {R::SrcB, 1}, {R::SrcC, 1}});
	Define(OP_CMPSEL, {{R::Dst, 1}, {R::SrcA, 1}, {R::SrcB, 1}, {R::Predicate, 1}, {R::SrcC, 1}, {R::SrcD, 1}});
	// 变长指令仅描述固定头；尾部长度仍由 nargs/ncases 的专用 verifier 处理。
	Define(OP_CALL_VOID, {{R::Callee, 1}, {R::ArgCount, 1}}, true);
	for (VMOp Op : {OP_CALL_INT, OP_CALL_INT64, OP_CALL_PTR, OP_CALL_F})
		Define(Op, {{R::Dst, 1}, {R::Callee, 1}, {R::ArgCount, 1}}, true);
	Define(OP_SWITCH, {{R::Index, 1}, {R::CaseCount, 2}, {R::Target, 4}}, true);
	for (unsigned Op = OP_ADDI32; Op <= OP_ASHRI64; ++Op)
		Define(static_cast<VMOp>(Op), {{R::Dst, 1}, {R::SrcA, 1}, {R::Immediate, Op >= OP_ADDI64 ? 8u : 4u}});
	for (unsigned Op = OP_MULADD64; Op <= OP_MULXOR64; ++Op) {
		if (Op == OP_CMPSEL64 || Op == OP_ANDCMPZ64) continue;
		Define(static_cast<VMOp>(Op), {{R::Dst, 1}, {R::SrcA, 1}, {R::SrcB, 1}, {R::SrcC, 1}});
	}
	Define(OP_CMPSEL64, {{R::Dst, 1}, {R::SrcA, 1}, {R::SrcB, 1}, {R::Predicate, 1}, {R::SrcC, 1}, {R::SrcD, 1}});
	Define(OP_ANDCMPZ64, {{R::Dst, 1}, {R::SrcA, 1}, {R::SrcB, 1}, {R::Predicate, 1}});
	for (unsigned Op = OP_GEP_LOAD8; Op <= OP_GEP_STORE64; ++Op)
		Define(static_cast<VMOp>(Op), {{R::Dst, 1}, {R::Pointer, 1}, {R::Index, 1}, {R::Kind, 1}, {R::Scale, 2}, {R::Alignment, 1}});
	assert(validate());
}

VMInstructionLayout VMInstructionLayout::forSeed(uint64_t Seed) {
	VMInstructionLayout Result;
	for (unsigned Op = 0; Op < OP_COUNT; ++Op) {
		if (Result.Variable[Op]) continue;
		auto Order = Result.Fields[Op];
		obf::Rng R(obf::mix64(Seed ^ obf::fnv1a64("vm.layout.v2") ^ Op));
		for (unsigned i = Order.size(); i > 1; --i) std::swap(Order[i - 1], Order[R.u32() % i]);
		unsigned Off = 1;
		for (auto& Field : Order) { Field.Offset = Off; Off += Field.Width; }
		bool Ok = Result.setFields(static_cast<VMOp>(Op), Order);
		assert(Ok); (void)Ok;
	}
	return Result;
}

unsigned VMInstructionLayout::offset(VMOp Op, VMFieldRole Role) const {
	for (const auto& F : Fields[Op]) if (F.Role == Role) return F.Offset;
	assert(false && "VM field role missing");
	return 0;
}

unsigned VMInstructionLayout::physicalByte(VMOp Op, unsigned Canonical) const {
	for (const auto& F : Fields[Op])
		if (Canonical >= F.Canonical && Canonical - F.Canonical < F.Width)
			return F.Offset + Canonical - F.Canonical;
	return Canonical; // opcode 与专用变长尾部保持原位
}

unsigned VMInstructionLayout::canonicalByte(VMOp Op, unsigned Physical) const {
	for (const auto& F : Fields[Op])
		if (Physical >= F.Offset && Physical - F.Offset < F.Width)
			return F.Canonical + Physical - F.Offset;
	return Physical;
}

bool VMInstructionLayout::setFields(VMOp Op, ArrayRef<VMLayoutField> NewFields) {
	if (NewFields.size() != Fields[Op].size()) return false;
	SmallVector<bool, 32> Used(Sizes[Op], false);
	Used[0] = true;
	for (unsigned i = 0; i < NewFields.size(); ++i) {
		const auto& F = NewFields[i];
		bool Matches = false;
		for (const auto& Old : Fields[Op])
			Matches |= F.Role == Old.Role && F.Width == Old.Width && F.Canonical == Old.Canonical;
		if (!Matches || F.Offset == 0 || F.Offset >= Sizes[Op] || F.Width > Sizes[Op] - F.Offset)
			return false;
		for (unsigned j = 0; j < i; ++j) if (NewFields[j].Role == F.Role) return false;
		if (Variable[Op] && F.Offset != F.Canonical) return false;
		for (unsigned b = 0; b < F.Width; ++b) {
			if (Used[F.Offset + b]) return false;
			Used[F.Offset + b] = true;
		}
	}
	for (bool U : Used) if (!U) return false;
	Fields[Op].assign(NewFields.begin(), NewFields.end());
	return true;
}

bool VMInstructionLayout::validate() const {
	auto Copy = *this;
	for (unsigned Op = 0; Op < OP_COUNT; ++Op)
		if (!Sizes[Op] || !Copy.setFields(static_cast<VMOp>(Op), Fields[Op])) return false;
	return true;
}

uint64_t VMInstructionLayout::fingerprint() const {
	uint64_t H = 14695981039346656037ULL;
	for (unsigned Op = 0; Op < OP_COUNT; ++Op)
		for (unsigned b = 0; b < Sizes[Op]; ++b) {
			H ^= physicalByte(static_cast<VMOp>(Op), b);
			H *= 1099511628211ULL;
		}
	return H;
}
