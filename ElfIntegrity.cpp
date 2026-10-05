// ============================================================================
// ElfIntegrity.cpp — emit the ELF integrity manifest placeholder, the runtime
// checker constructor, and the freestanding SHA-256 helper (Task 8).
//
// The post-link tool (xollvm-elf-hardener seal) fills the digest + ranges.
// The runtime constructor computes the module base from &manifest, hashes the
// same manifest-zeroed PF_X ranges, constant-time compares, and mixes failure
// into __obf_elf_integrity_state (never a public boolean).
// ============================================================================

#include "llvm/Transforms/Obfuscator/ElfIntegrity.h"
#include "llvm/Transforms/Obfuscator/ElfIntegrityBitcode.h"

#include "llvm/ADT/ArrayRef.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Metadata.h"
#include "llvm/IR/Module.h"
#include "llvm/Bitcode/BitcodeReader.h"
#include "llvm/Linker/Linker.h"
#include "llvm/Support/Error.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

using namespace llvm;

namespace {

	// True when the module carries at least one strict sensitive region.
	bool hasStrictSensitiveRegion(Module& M) {
		for (Function& F : M) {
			if (F.isDeclaration()) continue;
			const MDNode* MD = F.getMetadata("obf.sensitive.validated");
			if (!MD || MD->getNumOperands() < 2) continue;
			const auto* C = dyn_cast<ConstantAsMetadata>(MD->getOperand(1));
			const auto* CI = C ? dyn_cast<ConstantInt>(C->getValue()) : nullptr;
			if (CI && CI->isOne()) return true;
		}
		return false;
	}

} // namespace

void llvm::ElfIntegrityPrepare(Module& M) {
	LLVMContext& Ctx = M.getContext();
	Type* I8Ty = Type::getInt8Ty(Ctx);
	Type* I64Ty = Type::getInt64Ty(Ctx);

	// Manifest placeholder: 184 zero bytes in .text.xollvm.integrity. Patched
	// by the post-link tool. isConstant=true so lld routes it into a READ-ONLY
	// section (never a writable RWE load); the tool patches the file bytes, not
	// the in-memory copy, so read-only is correct.
	if (!M.getGlobalVariable(kIntegrityManifestSymbol, /*AllowInternal=*/true)) {
		auto* ManTy = ArrayType::get(I8Ty, sizeof(ElfIntegrityManifestV1));
		Constant* Zero = Constant::getNullValue(ManTy);
		auto* Manifest = new GlobalVariable(
			M, ManTy, /*isConstant=*/true, GlobalValue::LinkOnceODRLinkage, Zero,
			kIntegrityManifestSymbol);
		Manifest->setSection(kIntegritySectionName);
		Manifest->setAlignment(Align(8));
		Manifest->setUnnamedAddr(GlobalValue::UnnamedAddr::None);
		appendToCompilerUsed(M, { Manifest });
	}

	// Runtime integrity state: writable i64; failure poisons it. Emitted
	// EARLY so strict VM wrappers (built during commit) can reference it.
	if (!M.getGlobalVariable(kIntegrityStateSymbol, /*AllowInternal=*/true)) {
		auto* State = new GlobalVariable(
			M, I64Ty, /*isConstant=*/false, GlobalValue::InternalLinkage,
			ConstantInt::get(I64Ty, 0), kIntegrityStateSymbol);
		State->setAlignment(Align(8));
	}
}

PreservedAnalyses ElfIntegrityPass::run(Module& M, ModuleAnalysisManager&) {
	if (!hasStrictSensitiveRegion(M)) return PreservedAnalyses::all();

	LLVMContext& Ctx = M.getContext();
	Type* I8Ty = Type::getInt8Ty(Ctx);
	Type* I32Ty = Type::getInt32Ty(Ctx);
	Type* I64Ty = Type::getInt64Ty(Ctx);

	// 1+2. Reuse the globals emitted by ElfIntegrityPrepare() before commit.
	ElfIntegrityPrepare(M);
	auto* ManTy = ArrayType::get(I8Ty, sizeof(ElfIntegrityManifestV1));
	auto* Manifest = cast<GlobalVariable>(
		M.getGlobalVariable(kIntegrityManifestSymbol, true));
	auto* State = cast<GlobalVariable>(
		M.getGlobalVariable(kIntegrityStateSymbol, true));

	// 3. Link the freestanding SHA-256 helper (deduped across modules).
	if (!M.getFunction(kIntegritySha256Symbol)) {
		if (obf::IntegrityBitcodeSize > 0) {
			MemoryBufferRef MBR(
				StringRef(reinterpret_cast<const char*>(obf::IntegrityBitcode),
					obf::IntegrityBitcodeSize),
				"integrity_sha256.bc");
			auto StubOrErr = parseBitcodeFile(MBR, Ctx);
			if (!StubOrErr) {
				std::string Msg;
				handleAllErrors(StubOrErr.takeError(),
					[&](const ErrorInfoBase& EI) { Msg = EI.message(); });
				report_fatal_error(Twine("[elf-integrity] SHA-256 stub parse failed: ") + Msg,
					/*gen_crash_diag=*/false);
			}
			auto StubM = std::move(*StubOrErr);
			StubM->setDataLayout(M.getDataLayout());
			StubM->setTargetTriple(M.getTargetTriple());
			if (auto* MDFlags = StubM->getModuleFlagsMetadata())
				MDFlags->eraseFromParent();
			if (Linker::linkModules(M, std::move(StubM), 0))
				report_fatal_error("[elf-integrity] SHA-256 stub link failed",
					/*gen_crash_diag=*/false);
		}
	}
	Function* SHA256 = M.getFunction(kIntegritySha256Symbol);
	Function* SHAInit = M.getFunction("__xollvm_integrity_sha256_init");
	Function* SHAUpdate = M.getFunction("__xollvm_integrity_sha256_update");
	Function* SHAFinal = M.getFunction("__xollvm_integrity_sha256_final");
	if (!SHA256 || !SHAInit || !SHAUpdate || !SHAFinal)
		report_fatal_error("[elf-integrity] SHA-256 helper missing after link",
			/*gen_crash_diag=*/false);

	// 4. Runtime checker constructor.
	FunctionType* VoidFnTy = FunctionType::get(Type::getVoidTy(Ctx), false);
	Function* Ctor = Function::Create(
		VoidFnTy, GlobalValue::InternalLinkage, "__xollvm_elf_integrity_ctor", M);
	BasicBlock* Entry = BasicBlock::Create(Ctx, "entry", Ctor);
	IRBuilder<> B(Entry);

	// Module base = &manifest - ManifestVirtualAddress. Manifest VA is patched
	// into offset 16; before sealing it is 0, so guard the check to a no-op
	// when unpatched (the tool always patches in a sealed build).
	auto* ManifestVA = B.CreateConstGEP2_64(ManTy, Manifest, 0, 16, "vmva.p");
	auto* ManifestVAV = B.CreateLoad(I64Ty, ManifestVA, "vmva");
	auto* ManifestPtr = B.CreatePtrToInt(Manifest, I64Ty, "mp");
	auto* Base = B.CreateSub(ManifestPtr, ManifestVAV, "base");

	// Compute SHA-256 over every sealed range, treating manifest bytes as zero.
	// Ranges are read from the manifest. Each range is hashed in sequence by
	// feeding the running digest; for the first version we hash the first
	// range only when RangeCount > 0 and fold a second pass for subsequent
	// ranges via a simple concatenation into the same helper is not possible
	// without a streaming API, so we hash range[0] and mix the rest by XOR of
	// their per-range digests is weaker; instead we hash each range and fold
	// with the state (documented limitation for >1 range).
	Type* CtxTy = ArrayType::get(I8Ty, 128);  // xol_sha256_ctx
	auto* SHAState = B.CreateAlloca(CtxTy, nullptr, "shast");
	auto* Digest = B.CreateAlloca(ArrayType::get(I8Ty, 32), nullptr, "dig");
	auto* RangeCount = B.CreateLoad(I32Ty,
		B.CreateConstGEP2_64(ManTy, Manifest, 0, 12), "rcnt");

	// Manifest's own vaddr relative to Base; used to detect which recorded
	// range contains the manifest and to zero its window while hashing.
	auto* ManVAddr = B.CreateSub(B.CreatePtrToInt(Manifest, I64Ty), Base, "manvaddr");

	Function* Zeros = B.GetInsertBlock()->getModule()->getFunction(
		"__xollvm_integrity_sha256_update_zeros");
	if (!Zeros)
		report_fatal_error("[elf-integrity] SHA-256 zeros helper missing",
			/*gen_crash_diag=*/false);

	B.CreateCall(SHAInit, { SHAState });

	// 1. Canonical ELF header + program header table region [base, base+HdrEnd).
	//    e_phoff @32, e_phentsize @54, e_phnum @56 in Elf64_Ehdr. HdrEnd =
	//    e_phoff + e_phentsize*e_phnum. All header reads are guarded by the
	//    ELF magic check below so an unsealed/invalid base never faults.
	auto* BasePtr = B.CreateIntToPtr(Base, PointerType::getUnqual(Ctx), "bptr");
	// Validate ELF magic at Base before any out-of-header dereference.
	Value* M0 = B.CreateLoad(I8Ty, BasePtr, "elf.m0");
	Value* M1 = B.CreateLoad(I8Ty, B.CreateConstGEP1_64(I8Ty, BasePtr, 1), "elf.m1");
	Value* M2 = B.CreateLoad(I8Ty, B.CreateConstGEP1_64(I8Ty, BasePtr, 2), "elf.m2");
	Value* M3 = B.CreateLoad(I8Ty, B.CreateConstGEP1_64(I8Ty, BasePtr, 3), "elf.m3");
	Value* MagicOk = B.CreateAnd(
		B.CreateAnd(B.CreateICmpEQ(M0, B.getInt8(0x7f)),
		            B.CreateICmpEQ(M1, B.getInt8('E'))),
		B.CreateAnd(B.CreateICmpEQ(M2, B.getInt8('L')),
		            B.CreateICmpEQ(M3, B.getInt8('F'))), "elf.magic.ok");

	// Select a safe pointer: Base when valid, else the manifest itself (always
	// mapped) so the reads below never touch an unmapped address.
	Value* SafeBase = B.CreateSelect(MagicOk, BasePtr, Manifest, "safebase");
	auto* PhOffV = B.CreateLoad(I64Ty, B.CreateConstGEP1_64(I8Ty, SafeBase, 32), "phoff");
	auto* PhEntV = B.CreateZExt(
		B.CreateLoad(Type::getInt16Ty(Ctx), B.CreateConstGEP1_64(I8Ty, SafeBase, 54)),
		I64Ty, "phent");
	auto* PhNumV = B.CreateZExt(
		B.CreateLoad(Type::getInt16Ty(Ctx), B.CreateConstGEP1_64(I8Ty, SafeBase, 56)),
		I64Ty, "phnum");
	Value* HdrEnd = B.CreateAdd(PhOffV, B.CreateMul(PhEntV, PhNumV), "hdrend");
	B.CreateCall(SHAUpdate, { SHAState, SafeBase, HdrEnd });

	// 2. Every recorded executable range, in order, with the manifest window
	//    treated as zero (the manifest lies inside one of them). This mirrors
	//    the seal tool exactly: [EHDR..phdrs) then range[0], range[1], ...
	//    Range[i] = {vaddr, filesz} at manifest offsets 24 + 16*i.
	// ManFound tracks that exactly one recorded range contains the manifest;
	// if none does, the split zeroing never happens and the digest would be
	// hashed as-is (self-referential). Treat "manifest not in any range" as
	// Bad so a digest-only tamper cannot pass.
	Value* ManFound = B.getFalse();
	for (unsigned I = 0; I < kIntegrityMaxRanges; ++I) {
		Value* RV = B.CreateLoad(I64Ty,
			B.CreateConstGEP2_64(ManTy, Manifest, 0, 24 + (uint64_t)I * 16), "rng.va");
		Value* RS = B.CreateLoad(I64Ty,
			B.CreateConstGEP2_64(ManTy, Manifest, 0, 32 + (uint64_t)I * 16), "rng.sz");
		// Skip beyond RangeCount.
		Value* Active = B.CreateICmpULT(B.getInt32(I), RangeCount, "rng.act");
		Value* A = B.CreateAnd(MagicOk, Active, "rng.a");
		Value* BaseI = B.CreateAdd(Base, RV, "rng.base");
		Value* PtrI = B.CreateIntToPtr(BaseI, PointerType::getUnqual(Ctx), "rng.ptr");
		// If this range is the manifest's own, split around the zeroed window.
		Value* ManInRange = B.CreateAnd(
			B.CreateICmpUGE(ManVAddr, RV, "mir.lo"),
			B.CreateICmpULT(ManVAddr,
				B.CreateAdd(RV, RS, "mir.hi1"), "mir.hi"), "mir.in");
		Value* DoSplit = B.CreateAnd(A, ManInRange, "rng.split");
		ManFound = B.CreateOr(ManFound, DoSplit, "man.found");
		// Non-manifest range: hash the whole range.
		B.CreateCall(SHAUpdate, { SHAState,
			B.CreateSelect(DoSplit, Manifest, PtrI, "rng.p1"),
			B.CreateSelect(DoSplit, B.getInt64(0), RS, "rng.l1") });
		// Manifest range: head + zeros([0,152) metadata) + tail from digest on.
		Value* HeadLen = B.CreateSub(ManVAddr, RV, "rng.head");
		B.CreateCall(SHAUpdate, { SHAState,
			B.CreateSelect(DoSplit, PtrI, Manifest, "rng.p2"),
			B.CreateSelect(DoSplit, HeadLen, B.getInt64(0), "rng.l2") });
		B.CreateCall(Zeros, { SHAState,
			B.CreateSelect(DoSplit, B.getInt64(sizeof(ElfIntegrityManifestV1)), B.getInt64(0), "rng.z") });
		// Tail = range bytes from (manifest end) to range end, hashed as-is.
		Value* TailLen = B.CreateSub(RS, B.CreateAdd(HeadLen,
			B.getInt64(sizeof(ElfIntegrityManifestV1))), "rng.tail");
		Value* TailP = B.CreateIntToPtr(
			B.CreateAdd(BaseI, B.CreateAdd(HeadLen,
				B.getInt64(sizeof(ElfIntegrityManifestV1))), "rng.toff"),
			PointerType::getUnqual(Ctx), "rng.tp");
		B.CreateCall(SHAUpdate, { SHAState,
			B.CreateSelect(DoSplit, TailP, Manifest, "rng.p3"),
			B.CreateSelect(DoSplit, TailLen, B.getInt64(0), "rng.l3") });
	}
	B.CreateCall(SHAFinal, { SHAState, Digest });

	// Constant-time compare digest vs manifest digest (offset 152).
	auto* ManDigest = B.CreateConstGEP2_64(ManTy, Manifest, 0, 152);
	Value* Diff = B.getInt8(0);
	for (unsigned I = 0; I < 32; ++I) {
		Value* DP = B.CreateGEP(I8Ty, Digest, B.getInt64(I));
		Value* MP = B.CreateGEP(I8Ty, ManDigest, B.getInt64(I));
		Diff = B.CreateOr(Diff, B.CreateXor(B.CreateLoad(I8Ty, DP), B.CreateLoad(I8Ty, MP)));
	}
	// Bad when the base is not a valid ELF image, unpatched (range count 0), or
	// the digest mismatches.
	Value* Unpatched = B.CreateICmpEQ(RangeCount, B.getInt32(0));
	Value* Mismatch = B.CreateICmpNE(Diff, B.getInt8(0));
	Value* Bad = B.CreateOr(B.CreateNot(MagicOk),
		B.CreateOr(Unpatched, B.CreateOr(Mismatch, B.CreateNot(ManFound, "no.man"))), "bad");
	Value* Poison = B.CreateSelect(Bad, B.getInt64(0xDEAD00DUL), B.getInt64(0), "poison");
	B.CreateStore(Poison, State);
	B.CreateRetVoid();

	// Register the constructor in .init_array via llvm.global_ctors.
	appendToGlobalCtors(M, Ctor, /*Priority=*/65535);

	return PreservedAnalyses::none();
}
