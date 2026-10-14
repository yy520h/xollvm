#include "llvm/Transforms/Obfuscator/VMPass_Emitter.h"
#include "llvm/IR/Operator.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/Support/MathExtras.h"

using namespace llvm;

bool BytecodeEmitter::legalFusion(Instruction* P, Instruction* C, bool UniqueUse) const {
	if (!P || (UniqueUse && !P->hasOneUse()) || P->getParent() != C->getParent() ||
			SkippedFusions.count(P) || Fusions.count(P) || Fusions.count(C)) return false;
	// 延迟计算不能跨调用、访存或 poison-sensitive flags；仅融合定义良好的 wrapping 运算。
	if (auto* O = dyn_cast<OverflowingBinaryOperator>(P))
		if (O->hasNoSignedWrap() || O->hasNoUnsignedWrap()) return false;
	if (auto* O = dyn_cast<OverflowingBinaryOperator>(C))
		if (O->hasNoSignedWrap() || O->hasNoUnsignedWrap()) return false;
	for (auto It = std::next(P->getIterator()); It != P->getParent()->end(); ++It) {
		if (&*It == C) return true;
		if (It->mayHaveSideEffects() || It->mayReadOrWriteMemory()) return false;
	}
	return false;
}

void BytecodeEmitter::scanExtendedSuperOps(Function& F) {
	auto Record = [&](Instruction* C, Instruction* P, VMOp Op, ArrayRef<Value*> Args, uint8_t Pred = 0) {
		VMFusion V{C, P, Op, {}, Pred};
		V.Operands.assign(Args.begin(), Args.end());
		Fusions.try_emplace(C, std::move(V));
		SkippedFusions.insert(P);
	};
	for (BasicBlock& BB : F) for (Instruction& C : BB) {
		auto* Load = dyn_cast<LoadInst>(&C);
		auto* Store = dyn_cast<StoreInst>(&C);
		if ((!Load && !Store) || (Load && (Load->isVolatile() || Load->isAtomic())) ||
			(Store && (Store->isVolatile() || Store->isAtomic()))) continue;
		Type* Ty = Load ? Load->getType() : Store->getValueOperand()->getType();
		if (!Ty->isIntegerTy()) continue;
		unsigned Width = Ty->getIntegerBitWidth();
		if (Width != 32 && Width != 64 && (!Load || (Width != 8 && Width != 16))) continue;
		auto* G = dyn_cast<GetElementPtrInst>(Load ? Load->getPointerOperand() : Store->getPointerOperand());
		if (!G || G->getPointerAddressSpace() != 0 || DL->getIndexSizeInBits(0) != 64 || !legalFusion(G, &C)) continue;
		Value* Index = nullptr;
		Type* Element = G->getSourceElementType();
		if (G->getNumIndices() == 1) Index = *G->idx_begin();
		else if (G->getNumIndices() == 2) {
			auto It = G->idx_begin();
			auto* Zero = dyn_cast<ConstantInt>(*It++);
			auto* Array = dyn_cast<ArrayType>(Element);
			if (!Zero || !Zero->isZero() || !Array) continue;
			Element = Array->getElementType(); Index = *It;
		}
		if (!Index || (!Index->getType()->isIntegerTy(32) && !Index->getType()->isIntegerTy(64)) ||
			!Element->isSized() || Element->isAggregateType() || Element->isVectorTy()) continue;
		auto Size = DL->getTypeAllocSize(Element);
		if (Size.isScalable() || Size == 0 || Size > 65535) continue;
		VMOp Op = Load ? (Width == 8 ? OP_GEP_LOAD8 : Width == 16 ? OP_GEP_LOAD16 : Width == 32 ? OP_GEP_LOAD32 : OP_GEP_LOAD64)
			: Width == 32 ? OP_GEP_STORE32 : OP_GEP_STORE64;
		if (Store) Record(&C, G, Op, {G->getPointerOperand(), Index, Store->getValueOperand()});
		else Record(&C, G, Op, {G->getPointerOperand(), Index});
		auto& V = Fusions.find(&C)->second;
		V.Scale = Size.getFixedValue();
		V.Alignment = Log2_64((Load ? Load->getAlign() : Store->getAlign()).value());
	}
	// 先选 compare-select，避免同一个 compare 被 andcmpz 抢占。
	for (BasicBlock& BB : F) for (Instruction& C : BB) {
		auto* S = dyn_cast<SelectInst>(&C);
		if (!S || !S->getType()->isIntegerTy(64)) continue;
		auto* P = dyn_cast<ICmpInst>(S->getCondition());
		if (!P || !P->getOperand(0)->getType()->isIntegerTy(64) || !legalFusion(P, S)) continue;
		Record(S, P, OP_CMPSEL64, {P->getOperand(0), P->getOperand(1), S->getTrueValue(), S->getFalseValue()}, P->getPredicate());
	}
	for (BasicBlock& BB : F) for (Instruction& C : BB) {
		if (SkippedFusions.count(&C) || Fusions.count(&C)) continue;
		if (auto* Compare = dyn_cast<ICmpInst>(&C)) {
			if (Compare->getPredicate() != CmpInst::ICMP_EQ && Compare->getPredicate() != CmpInst::ICMP_NE) continue;
			for (unsigned Side = 0; Side < 2; ++Side) {
				auto* Zero = dyn_cast<ConstantInt>(Compare->getOperand(1 - Side));
				auto* P = dyn_cast<BinaryOperator>(Compare->getOperand(Side));
				if (!Zero || !Zero->isZero() || !P || P->getOpcode() != Instruction::And ||
					!P->getType()->isIntegerTy(64) || !legalFusion(P, Compare)) continue;
				Record(Compare, P, OP_ANDCMPZ64, {P->getOperand(0), P->getOperand(1)}, Compare->getPredicate());
				break;
			}
			continue;
		}
		bool Is64 = C.getType()->isIntegerTy(64);
		if (!Is64 && !C.getType()->isIntegerTy(32)) continue;
		if (C.getOpcode() != Instruction::Add && C.getOpcode() != Instruction::Xor) continue;
		for (unsigned Side = 0; Side < 2; ++Side) {
			auto* P = dyn_cast<BinaryOperator>(C.getOperand(Side));
			if (!P || P->getType() != C.getType() || !legalFusion(P, &C)) continue;
			VMOp Op = OP_COUNT;
			unsigned PO = P->getOpcode();
			if (C.getOpcode() == Instruction::Add) {
				if (PO == Instruction::Mul && Is64) Op = OP_MULADD64;
				if (PO == Instruction::Shl && Is64) Op = OP_SHLADD64;
				if (PO == Instruction::Xor) Op = Is64 ? OP_XORADD64 : OP_XORADD32;
				if (PO == Instruction::And) Op = Is64 ? OP_ANDADD64 : OP_ANDADD32;
				if (PO == Instruction::Or) Op = Is64 ? OP_ORADD64 : OP_ORADD32;
			} else {
				if (PO == Instruction::Add) Op = Is64 ? OP_ADDXOR64 : OP_ADDXOR32;
				if (PO == Instruction::Sub) Op = Is64 ? OP_SUBXOR64 : OP_SUBXOR32;
				if (PO == Instruction::Mul) Op = Is64 ? OP_MULXOR64 : OP_MULXOR32;
			}
			if (Op == OP_COUNT) continue;
			Record(&C, P, Op, {P->getOperand(0), P->getOperand(1), C.getOperand(1 - Side)});
			break;
		}
	}
}
