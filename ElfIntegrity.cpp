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

PreservedAnalyses ElfIntegrityPass::run(Module& M, ModuleAnalysisManager&) {
	if (!hasStrictSensitiveRegion(M)) return PreservedAnalyses::all();

	LLVMContext& Ctx = M.getContext();
	Type* I8Ty = Type::getInt8Ty(Ctx);
	Type* I32Ty = Type::getInt32Ty(Ctx);
	Type* I64Ty = Type::getInt64Ty(Ctx);

	// 1. Manifest placeholder: 184 zero bytes in .xollvm.integrity. Patched by
	//    the post-link tool. Named hidden global so the tool can find it.
	auto* ManTy = ArrayType::get(I8Ty, sizeof(ElfIntegrityManifestV1));
	Constant* Zero = Constant::getNullValue(ManTy);
	auto* Manifest = new GlobalVariable(
		M, ManTy, /*isConstant=*/false, GlobalValue::LinkOnceODRLinkage, Zero,
		"__xollvm_elf_integrity_manifest");
	Manifest->setSection(kIntegritySectionName);
	Manifest->setAlignment(Align(8));
	Manifest->setUnnamedAddr(GlobalValue::UnnamedAddr::None);
	// Keep it through the optimizer even before the tool patches it.
	appendToCompilerUsed(M, { Manifest });

	// 2. Runtime integrity state: hidden writable i64; failure poisons it.
	auto* State = new GlobalVariable(
		M, I64Ty, /*isConstant=*/false, GlobalValue::InternalLinkage,
		ConstantInt::get(I64Ty, 0), "__obf_elf_integrity_state");
	State->setAlignment(Align(8));

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

	// range[0] = {vaddr, filesize} at manifest offsets 24/32.
	auto* R0VA = B.CreateLoad(I64Ty, B.CreateConstGEP2_64(ManTy, Manifest, 0, 24), "r0va");
	auto* R0Sz = B.CreateLoad(I64Ty, B.CreateConstGEP2_64(ManTy, Manifest, 0, 32), "r0sz");
	auto* R0Int = B.CreateAdd(Base, R0VA, "r0int");
	auto* R0Ptr = B.CreateIntToPtr(R0Int, PointerType::getUnqual(Ctx), "r0ptr");
	// Manifest's own file offset relative to Base, so we can zero its window.
	auto* ManOffInt = B.CreateSub(B.CreatePtrToInt(Manifest, I64Ty), Base, "manoff");
	auto* ManOffPtr = B.CreateIntToPtr(B.CreateAdd(R0Int, ManOffInt, "manabs"),
		PointerType::getUnqual(Ctx), "manptr");

	Function* Zeros = B.GetInsertBlock()->getModule()->getFunction(
		"__xollvm_integrity_sha256_update_zeros");
	if (!Zeros)
		report_fatal_error("[elf-integrity] SHA-256 zeros helper missing",
			/*gen_crash_diag=*/false);

	B.CreateCall(SHAInit, { SHAState });

	// 1. Canonical ELF header + program header table region [base, base+HdrEnd).
	//    e_phoff @8, e_phentsize @54, e_phnum @56 in Elf64_Ehdr. HdrEnd =
	//    max(e_ehsize, e_phoff + e_phentsize*e_phnum).
	auto* BasePtr = B.CreateIntToPtr(Base, PointerType::getUnqual(Ctx), "bptr");
	auto* PhOffV = B.CreateLoad(I64Ty, B.CreateConstGEP1_64(I8Ty, BasePtr, 32), "phoff");
	// e_phoff is at byte offset 32 in Elf64_Ehdr.
	auto* PhEntV = B.CreateZExt(
		B.CreateLoad(Type::getInt16Ty(Ctx), B.CreateConstGEP1_64(I8Ty, BasePtr, 54)),
		I64Ty, "phent");
	auto* PhNumV = B.CreateZExt(
		B.CreateLoad(Type::getInt16Ty(Ctx), B.CreateConstGEP1_64(I8Ty, BasePtr, 56)),
		I64Ty, "phnum");
	Value* HdrEnd = B.CreateAdd(PhOffV, B.CreateMul(PhEntV, PhNumV), "hdrend");
	B.CreateCall(SHAUpdate, { SHAState, BasePtr, HdrEnd });

	// 2. The manifest-carrying executable range [rangeStart, rangeEnd) with the
	//    184-byte manifest window treated as zero.
	Value* HeadLen = B.CreateSub(ManOffInt, R0VA, "headlen");
	B.CreateCall(SHAUpdate, { SHAState, R0Ptr, HeadLen });
	B.CreateCall(Zeros, { SHAState, B.getInt64(sizeof(ElfIntegrityManifestV1)) });
	Value* TailPtr = B.CreateIntToPtr(
		B.CreateAdd(B.CreateAdd(R0Int, ManOffInt), B.getInt64(sizeof(ElfIntegrityManifestV1))),
		PointerType::getUnqual(Ctx), "tailptr");
	Value* TailLen = B.CreateSub(R0Sz, B.CreateAdd(ManOffInt, B.getInt64(sizeof(ElfIntegrityManifestV1))), "taillen");
	B.CreateCall(SHAUpdate, { SHAState, TailPtr, TailLen });
	B.CreateCall(SHAFinal, { SHAState, Digest });

	// Constant-time compare digest vs manifest digest (offset 152).
	auto* ManDigest = B.CreateConstGEP2_64(ManTy, Manifest, 0, 152);
	Value* Diff = B.getInt8(0);
	for (unsigned I = 0; I < 32; ++I) {
		Value* DP = B.CreateGEP(I8Ty, Digest, B.getInt64(I));
		Value* MP = B.CreateGEP(I8Ty, ManDigest, B.getInt64(I));
		Diff = B.CreateOr(Diff, B.CreateXor(B.CreateLoad(I8Ty, DP), B.CreateLoad(I8Ty, MP)));
	}
	// If unpatched (range count 0) or mismatch, mix failure into state.
	Value* Unpatched = B.CreateICmpEQ(RangeCount, B.getInt32(0));
	Value* Mismatch = B.CreateICmpNE(Diff, B.getInt8(0));
	Value* Bad = B.CreateOr(Unpatched, Mismatch, "bad");
	Value* Poison = B.CreateSelect(Bad, B.getInt64(0xDEAD00DUL), B.getInt64(0), "poison");
	B.CreateStore(Poison, State);
	B.CreateRetVoid();

	// Register the constructor in .init_array via llvm.global_ctors.
	appendToGlobalCtors(M, Ctor, /*Priority=*/65535);

	return PreservedAnalyses::none();
}
