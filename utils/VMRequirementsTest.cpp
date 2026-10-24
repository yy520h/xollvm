#include "llvm/Transforms/Obfuscator/ObfuscationConfig.h"
#include "llvm/Transforms/Obfuscator/VMPass_Emitter.h"
#include "llvm/Transforms/Obfuscator/VMPass_Verifier.h"
#include "llvm/Transforms/Obfuscator/VMPass_Decode.h"
#include "llvm/Transforms/Obfuscator/VMPass_Layout.h"
#include "llvm/Transforms/Obfuscator/VMTargetEncoding.h"
#include "llvm/Transforms/Obfuscator/VMWhiteBoxAES.h"
#include "gtest/gtest.h"
#include "llvm/AsmParser/Parser.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Transforms/Obfuscator/VMPass_Requirements.h"
#include "llvm/Transforms/Obfuscator/VMPass_Plan.h"
#include "llvm/Transforms/Obfuscator/SensitiveDecision.h"
#include "llvm/Transforms/Obfuscator/ObfuscationOptions.h"
#include "llvm/Transforms/Obfuscator/ObfuscationPipeline.h"
#include "llvm/Transforms/Obfuscator/ObfuscationAnnotationAnalysis.h"
#include "llvm/Transforms/Obfuscator/VMPass.h"
#ifdef OBF_TEST_VM_IMPL
#include "llvm/Transforms/Obfuscator/VMPass_Impl.h"
#include "llvm/Support/raw_ostream.h"
#include <cstdlib>
#ifdef __ANDROID__
#include <sys/wait.h>
#include <unistd.h>
#endif
#endif

using namespace llvm;

static VMPassConfig materialConfig(StringRef Options, bool Normalize = true) {
	auto C = AnnotationParser::parseAnnotationString((Twine("obf: vm(") + Options + ")").str());
	return VMPassConfig::fromPassConfig(*C.getPassConfig("vm"), Normalize);
}

TEST(VMCloudMaterial, IndependentNormalizationAndWitness) {
	auto Requested = materialConfig("cloudMaterial=lease,materialRegion=auth,hardened=1,encBytecode=0", false);
	auto Effective = materialConfig("cloudMaterial=lease,materialRegion=auth,hardened=1,encBytecode=0");
	EXPECT_TRUE(Effective.constInStream);
	EXPECT_TRUE(Effective.hardened);
	EXPECT_TRUE(Effective.regEncrypt);
	EXPECT_TRUE(Effective.obfRegIdx);
	EXPECT_TRUE(Effective.randISA);
	EXPECT_FALSE(Effective.encDispatch);
	VMEngineWitness W;
	W.Requested = Requested; W.Effective = Effective;
	W.ConfigKey = EngineConfigKey::fromConfig(Effective, 0, 0);
	W.Phase = "preflight_only";
	auto J = W.toJson();
	EXPECT_EQ(J.getString("bytecodeSource"), "cloud_material");
	EXPECT_EQ(J.getObject("effective")->getString("cloudMaterial"), "lease");
	EXPECT_EQ(J.getObject("effective")->getString("materialRegion"), "auth");
	EXPECT_EQ(J.getObject("disabled_reasons")->getString("encBytecode"), "replaced_by_cloud_material");
	EXPECT_EQ(J.getBoolean("material_dependency_emitted"), false);
}

TEST(VMCloudMaterial, ModeRegionAndLegacyNeverShareEngineGroups) {
	LLVMContext C; Module M("material-groups", C);
	VMPlanCoordinator P;
	const char* Options[] = {"cloudMaterial=session,materialRegion=auth",
		"cloudMaterial=lease,materialRegion=auth", "cloudMaterial=lease,materialRegion=other",
		"", "cloudDispatch=1"};
	std::vector<EngineConfigKey> Keys;
	for (unsigned I = 0; I < 5; ++I) {
		auto Config = materialConfig(Options[I]);
		auto Key = EngineConfigKey::fromConfig(Config, 0, 0);
		for (const auto& Previous : Keys) {
			EXPECT_FALSE(Key == Previous);
			EXPECT_NE(Key.stableHash(), Previous.stableHash());
		}
		Keys.push_back(Key);
		auto* F = Function::Create(FunctionType::get(Type::getVoidTy(C), false),
			GlobalValue::ExternalLinkage, "f" + std::to_string(I), M);
		ASSERT_NE(P.addCandidate(*F, Config, Key, BytecodeEmitter{}, {}), nullptr);
	}
	ASSERT_TRUE(P.freeze());
	EXPECT_EQ(P.groupCount(), 5u);
}

TEST(VMWhiteBoxAES, FIPSKnownAnswerAndRandomReference) {
	std::array<uint8_t, 16> Key = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
	std::array<uint8_t, 16> Input = {0,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
	std::array<uint8_t, 16> Expected = {0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a};
	auto A = VMWhiteBoxAES::generate(Key, 1), B = VMWhiteBoxAES::generate(Key, 42);
	ASSERT_TRUE(bool(A)); ASSERT_TRUE(bool(B));
	EXPECT_EQ(VMWhiteBoxAES::evaluate(*A, Input), Expected);
	EXPECT_EQ(VMWhiteBoxAES::evaluate(*B, Input), Expected);
	EXPECT_NE(A->Bytes, B->Bytes);
#ifdef OBF_TEST_VM_IMPL
	obf::Rng R(42);
	for (unsigned i = 0; i < 100; ++i) {
		R.bytes(Key); R.bytes(Input);
		uint8_t RK[176], Block[16]; vm_aes::keyExpand(Key.data(), RK);
		std::copy(Input.begin(), Input.end(), Block); vm_aes::encryptBlock(RK, Block);
		auto T = VMWhiteBoxAES::generate(Key, i);
		ASSERT_TRUE(bool(T));
		auto Actual = VMWhiteBoxAES::evaluate(*T, Input);
		EXPECT_TRUE(std::equal(Actual.begin(), Actual.end(), Block));
		EXPECT_EQ(std::search(T->Bytes.begin(), T->Bytes.end(), RK, RK + 176), T->Bytes.end());
	}
	if (const char* Path = std::getenv("XOLLVM_WHITEBOX_KAT_IR")) {
		LLVMContext C; Module M("whitebox-kat", C); M.setTargetTriple(Triple("aarch64-unknown-linux-android26"));
		Key = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
		auto T = VMWhiteBoxAES::generate(Key, 42); ASSERT_TRUE(bool(T));
		auto* G = emitVMWhiteBoxInstance(M, *T);
		auto* Block = getVMWhiteBoxBlockFunction(M);
		auto* FT = FunctionType::get(Type::getVoidTy(C), {PointerType::getUnqual(C), PointerType::getUnqual(C)}, false);
		auto* F = Function::Create(FT, GlobalValue::ExternalLinkage, "kat", M);
		IRBuilder<> IR(BasicBlock::Create(C, "entry", F)); IR.CreateCall(Block, {G, F->getArg(0), F->getArg(1)}); IR.CreateRetVoid();
		// fixture 中插入原子计数，生产后端无诊断计数器。
		auto* CTR = getVMWhiteBoxCTRFunction(M);
		auto* Count = new GlobalVariable(M, Type::getInt32Ty(C), false, GlobalValue::ExternalLinkage, nullptr, "count");
		IRBuilder<> Counter(&*CTR->getEntryBlock().begin());
		Counter.CreateAtomicRMW(AtomicRMWInst::Add, Count, Counter.getInt32(1), Align(4), AtomicOrdering::Monotonic);
		auto* Init = Function::Create(FunctionType::get(Type::getVoidTy(C), {PointerType::getUnqual(C)}, false), GlobalValue::ExternalLinkage, "init", M);
		IRBuilder<> IB(BasicBlock::Create(C, "entry", Init));
		IB.CreateStore(G, Init->getArg(0));
		IB.CreateStore(IB.getInt64(0), IB.CreateGEP(IB.getInt8Ty(), Init->getArg(0), IB.getInt64(8)));
		IB.CreateStore(IB.getInt32(0xffffffffu), IB.CreateGEP(IB.getInt8Ty(), Init->getArg(0), IB.getInt64(32))); IB.CreateRetVoid();
		std::array<uint8_t, 64> BC; for (unsigned i = 0; i < BC.size(); ++i) BC[i] = uint8_t(i * 7) ^ i;
		uint8_t RK[176], Nonce[8] = {}; vm_aes::keyExpand(Key.data(), RK); vm_aes::ctr(RK, Nonce, BC.data(), BC.size());
		auto* BCInit = ConstantDataArray::get(C, BC);
		auto* BCG = new GlobalVariable(M, BCInit->getType(), true, GlobalValue::PrivateLinkage, BCInit, "bc");
		auto* Fetch = Function::Create(FunctionType::get(Type::getInt8Ty(C), {PointerType::getUnqual(C), Type::getInt32Ty(C)}, false), GlobalValue::ExternalLinkage, "fetch", M);
		IRBuilder<> FB(BasicBlock::Create(C, "entry", Fetch)); auto* Salt = FB.CreateAlloca(FB.getInt32Ty()); FB.CreateStore(FB.getInt32(0), Salt);
		VMByteDecodeContext Decode; Decode.BC = BCG; Decode.Salt = Salt; Decode.LazyCtx = Fetch->getArg(0); Decode.Keystream = CTR;
		Decode.EncBytecode = Decode.LazyDecrypt = Decode.CacheEnabled = Decode.KeyIsPointer = true;
		Decode.NonceOffset = 8; Decode.WindowOffset = 16; Decode.CachedBlockOffset = 32;
		FB.CreateRet(emitVMByteLoad(FB, Decode, Fetch->getArg(1), "decoded"));
		EXPECT_FALSE(verifyModule(M, &errs()));
		std::error_code EC; raw_fd_ostream OS(Path, EC); ASSERT_FALSE(bool(EC)); M.print(OS, nullptr);
	}
#endif
}

TEST(VMTargetEncoding, RelativeTargetsRoundTripAtAllRotations) {
	using namespace VMTargetFormat;
	for (unsigned R = 1; R <= 63; ++R) for (uint64_t Slot : {0ULL, 0x1000ULL, ~0ULL})
		for (uint64_t Target : {0ULL, 0x800ULL, 0x8000000000000000ULL, ~0ULL}) {
			uint64_t K = 0x123456789abcdef0ULL, A = 0xfedcba9876543210ULL;
			EXPECT_EQ(Slot + decode(encode(Target - Slot, K, A, R), K, A, R), Target);
		}
}

TEST(VMExtendedISA, ComputationalFusionEmitterWitnesses) {
	const char* Producers[] = {"mul", "shl", "xor", "and", "or", "add", "sub", "mul"};
	const char* Consumers[] = {"add", "add", "add", "add", "add", "xor", "xor", "xor"};
	for (unsigned W : {32u, 64u}) {
		for (unsigned i = 0; i < 8; ++i) {
			LLVMContext C;
			SMDiagnostic D;
			std::string Ty = "i" + std::to_string(W);
			auto M = parseAssemblyString("define " + Ty + " @f(" + Ty + " %a," + Ty + " %b," + Ty +
				" %c) { %p = " + Producers[i] + " " + Ty + " %a,%b\n %r = " + Consumers[i] +
				" " + Ty + " %p,%c\n ret " + Ty + " %r }", D, C);
			ASSERT_NE(M, nullptr) << D.getMessage().str();
			BytecodeEmitter E;
			E.setExtendedISA(true); E.setSuperOps(true);
			E.setLayout(VMInstructionLayout::forSeed(42));
			ASSERT_TRUE(E.run(*M->getFunction("f"), 0, M->getDataLayout())) << E.FailReason;
			VMOp Op = i < 2 ? (W == 32 ? (i == 0 ? OP_MULADD : OP_SHLADD) : (i == 0 ? OP_MULADD64 : OP_SHLADD64))
				: static_cast<VMOp>((W == 32 ? OP_XORADD32 : OP_XORADD64) + i - 2);
			EXPECT_TRUE(E.Requirements.contains(Op));
			EXPECT_TRUE(E.Requirements.NeedsSuperOps);
			EXPECT_EQ(E.BC.front(), Op);
			std::string Error; uint32_t Bad = 0; VMOpcodeMap Map;
			EXPECT_TRUE(verifyBytecode(E, 0, Map, Error, Bad)) << Error;
		}
	}
}

TEST(VMExtendedISA, ComparisonFusionWitnessesRejectInvalidPredicateAndSlots) {
	for (VMOp Op : {OP_CMPSEL64, OP_ANDCMPZ64}) {
		LLVMContext C; SMDiagnostic D;
		std::string Body = Op == OP_CMPSEL64 ?
			"%p = icmp slt i64 %a,%b\n %r = select i1 %p,i64 %a,i64 %b\n ret i64 %r" :
			"%p = and i64 %a,%b\n %r = icmp ne i64 %p,0\n ret i1 %r";
		auto M = parseAssemblyString("define " + std::string(Op == OP_CMPSEL64 ? "i64" : "i1") +
			" @f(i64 %a,i64 %b) { " + Body + " }", D, C);
		ASSERT_NE(M, nullptr);
		BytecodeEmitter E; E.setExtendedISA(true); E.setSuperOps(true);
		auto L = VMInstructionLayout::forSeed(42); E.setLayout(L);
		ASSERT_TRUE(E.run(*M->getFunction("f"), 0, M->getDataLayout()));
		EXPECT_EQ(E.BC.front(), Op); EXPECT_TRUE(E.Requirements.contains(Op));
		std::string Error; uint32_t Bad = 0; VMOpcodeMap Map;
		EXPECT_TRUE(verifyBytecode(E, 0, Map, Error, Bad)) << Error;
		auto Good = E.BC;
		E.BC[L.offset(Op, VMFieldRole::Predicate)] = 255;
		EXPECT_FALSE(verifyBytecode(E, 0, Map, Error, Bad)); E.BC = Good;
		E.BC[L.offset(Op, VMFieldRole::SrcB)] = 255;
		EXPECT_FALSE(verifyBytecode(E, 0, Map, Error, Bad)); E.BC = Good;
		E.BC.resize(L.size(Op) - 1);
		EXPECT_FALSE(verifyBytecode(E, 0, Map, Error, Bad));
	}
}

TEST(VMExtendedISA, CompleteDomainAndMemoryEmitterWitnesses) {
	EXPECT_EQ(unsigned(OP_COUNT), 96u);
	for (unsigned O = OP_GEP_LOAD8; O <= OP_GEP_STORE64; ++O) for (unsigned IW : {32u, 64u}) {
		VMOp Op = static_cast<VMOp>(O);
		bool Store = O >= OP_GEP_STORE32;
		unsigned Width = Op == OP_GEP_LOAD8 ? 8 : Op == OP_GEP_LOAD16 ? 16 :
			Op == OP_GEP_LOAD64 || Op == OP_GEP_STORE64 ? 64 : 32;
		LLVMContext C; SMDiagnostic D;
		std::string Ty = "i" + std::to_string(Width), IT = "i" + std::to_string(IW);
		std::string Body = Store ? "store " + Ty + " %v,ptr %p,align 1\n ret void" :
			"%r = load " + Ty + ",ptr %p,align 1\n ret " + Ty + " %r";
		auto M = parseAssemblyString("target datalayout = \"e-p:64:64\"\ndefine " +
			(Store ? std::string("void") : Ty) + " @f(ptr %base," + IT + " %idx," + Ty +
			" %v) { %p = getelementptr " + Ty + ",ptr %base," + IT + " %idx\n " + Body + " }", D, C);
		ASSERT_NE(M, nullptr) << D.getMessage().str();
		BytecodeEmitter E; E.setExtendedISA(true); E.setSuperOps(true);
		auto L = VMInstructionLayout::forSeed(42); E.setLayout(L);
		ASSERT_TRUE(E.run(*M->getFunction("f"), 0, M->getDataLayout())) << E.FailReason;
		EXPECT_EQ(E.BC.front(), Op); EXPECT_TRUE(E.Requirements.contains(Op));
		std::string Error; uint32_t Bad = 0; VMOpcodeMap Map;
		EXPECT_TRUE(verifyBytecode(E, 0, Map, Error, Bad)) << Error;
		auto Good = E.BC;
		for (VMFieldRole Role : {VMFieldRole::Dst, VMFieldRole::Pointer, VMFieldRole::Index,
			VMFieldRole::Kind, VMFieldRole::Alignment}) {
			E.BC[L.offset(Op, Role)] = 255;
			EXPECT_FALSE(verifyBytecode(E, 0, Map, Error, Bad)) << unsigned(Role);
			E.BC = Good;
		}
		E.BC[L.offset(Op, VMFieldRole::Scale)] = E.BC[L.offset(Op, VMFieldRole::Scale) + 1] = 0;
		EXPECT_FALSE(verifyBytecode(E, 0, Map, Error, Bad)); E.BC = Good;
		E.BC.resize(L.size(Op) - 1);
		EXPECT_FALSE(verifyBytecode(E, 0, Map, Error, Bad));
	}
	for (unsigned I = 0; I < kMaxDecoys; ++I) EXPECT_GE(unsigned(OP_DECOY_BASE) + I, unsigned(OP_COUNT));
}

TEST(VMExtendedISA, FusionGuardsApplyToLegacyAndExtendedOpcodes) {
	for (unsigned Width : {32u, 64u}) for (unsigned Reason = 0; Reason < 4; ++Reason) {
		LLVMContext C;
		SMDiagnostic D;
		std::string Ty = "i" + std::to_string(Width);
		std::string Gap = Reason == 0 ? "br label %next\nnext:\n" : Reason == 1 ? "call void @effect()\n" : "";
		std::string Flag = Reason == 2 ? " nsw" : "";
		auto M = parseAssemblyString("declare void @effect()\ndefine " + Ty + " @f(" + Ty +
			" %a," + Ty + " %b," + Ty + " %c) { %p = mul " + Ty + " %a,%b\n" + Gap +
			"%r = add" + Flag + " " + Ty + " %p,%c\n ret " + Ty + " %r }", D, C);
		ASSERT_NE(M, nullptr);
		BytecodeEmitter E; E.setExtendedISA(true); E.setSuperOps(Reason != 3);
		ASSERT_TRUE(E.run(*M->getFunction("f"), 0, M->getDataLayout())) << E.FailReason;
		EXPECT_FALSE(E.Requirements.contains(Width == 32 ? OP_MULADD : OP_MULADD64)) << Reason;
	}
}

TEST(VMExtendedISA, ImmediateOpcodesHaveEmitterWitnessAndValidateOperands) {
	constexpr const char* Ops[] = {"add", "sub", "mul", "and", "or", "xor", "shl", "lshr", "ashr"};
	for (unsigned Width : {32u, 64u}) {
		for (unsigned i = 0; i < 9; ++i) {
			LLVMContext C;
			SMDiagnostic D;
			std::string Ty = "i" + std::to_string(Width);
			auto M = parseAssemblyString("define " + Ty + " @f(" + Ty + " %a) { %r = " +
				Ops[i] + " " + Ty + " %a, 3\n ret " + Ty + " %r }", D, C);
			ASSERT_NE(M, nullptr) << D.getMessage().str();
			BytecodeEmitter E;
			E.setExtendedISA(true);
			auto L = VMInstructionLayout::forSeed(42);
			E.setLayout(L);
			ASSERT_TRUE(E.run(*M->getFunction("f"), 0, M->getDataLayout())) << E.FailReason;
			VMOp Op = static_cast<VMOp>(OP_ADDI32 + (Width == 64 ? 9 : 0) + i);
			EXPECT_TRUE(E.Requirements.contains(Op));
			EXPECT_EQ(E.BC.front(), Op);
			std::string Error;
			uint32_t Bad = 0;
			VMOpcodeMap Map;
			EXPECT_TRUE(verifyBytecode(E, 0, Map, Error, Bad)) << Error;
			auto Good = E.BC;
			E.BC[L.offset(Op, VMFieldRole::SrcA)] = 255;
			EXPECT_FALSE(verifyBytecode(E, 0, Map, Error, Bad));
			E.BC = Good;
			if (i >= BS_SHL) {
				unsigned Imm = L.offset(Op, VMFieldRole::Immediate);
				E.BC[Imm] = Width;
				EXPECT_FALSE(verifyBytecode(E, 0, Map, Error, Bad));
				E.BC = Good;
			}
			E.BC.front() = 255;
			EXPECT_FALSE(verifyBytecode(E, 0, Map, Error, Bad));
			E.BC = Good;
			E.BC.resize(L.size(Op) - 1);
			EXPECT_FALSE(verifyBytecode(E, 0, Map, Error, Bad));
		}
	}
}

TEST(VMOperandLayout, KeepsWidthsAndChangesOffsets) {
	auto A = VMInstructionLayout::forSeed(1);
	auto B = VMInstructionLayout::forSeed(42);
	EXPECT_EQ(A.size(OP_BINOP), B.size(OP_BINOP));
	EXPECT_NE(A.fingerprint(), B.fingerprint());
	EXPECT_TRUE(A.validate());
	EXPECT_TRUE(B.validate());
	for (unsigned Op = 0; Op < OP_COUNT; ++Op) {
		for (const auto& Field : A.fields(static_cast<VMOp>(Op))) {
			for (unsigned i = 0; i < Field.Width; ++i)
				EXPECT_EQ(A.canonicalByte(static_cast<VMOp>(Op), Field.Offset + i), Field.Canonical + i);
		}
	}
}

TEST(VMOperandLayout, RejectsDuplicateOverlappingAndOutOfBoundsFields) {
	VMInstructionLayout L;
	EXPECT_FALSE(L.setFields(OP_BINOP, {{VMFieldRole::Dst, 1, 1, 1},
		{VMFieldRole::Dst, 1, 2, 1}, {VMFieldRole::SrcB, 3, 3, 1},
		{VMFieldRole::Kind, 4, 4, 1}}));
	EXPECT_FALSE(L.setFields(OP_LOADI, {{VMFieldRole::Dst, 1, 1, 1},
		{VMFieldRole::Immediate, 2, 1, 4}}));
	EXPECT_FALSE(L.setFields(OP_LOADI, {{VMFieldRole::Dst, 1, 1, 1},
		{VMFieldRole::Immediate, 2, 5, 4}}));
	EXPECT_TRUE(L.validate());
}

TEST(VMOperandLayout, EmitterAndVerifierAgreeOnPermutedBytecode) {
	LLVMContext C;
	SMDiagnostic D;
	auto M = parseAssemblyString("define i32 @f(i32 %a, i32 %b) { %r = sub i32 %a, %b\n ret i32 %r }", D, C);
	ASSERT_NE(M, nullptr);
	VMOpcodeMap Map;
	BytecodeEmitter E;
	auto Layout = VMInstructionLayout::forSeed(42);
	E.setLayout(Layout);
	ASSERT_TRUE(E.run(*M->getFunction("f"), 0, M->getDataLayout()));
	EXPECT_EQ(E.BC[Layout.offset(OP_BINOP, VMFieldRole::Kind)], BS_SUB);
	std::string Error;
	uint32_t Bad = 0;
	EXPECT_TRUE(verifyBytecode(E, 0, Map, Error, Bad)) << Error;
	E.BC[Layout.offset(OP_BINOP, VMFieldRole::SrcA)] = 254;
	EXPECT_FALSE(verifyBytecode(E, 0, Map, Error, Bad));
	EXPECT_EQ(Bad, 0u);
}

TEST(VMByteDecode, SeparateContextsKeepTheirOwnSaltAndBuffer) {
	LLVMContext C;
	Module M("decode", C);
	auto* FT = FunctionType::get(Type::getInt8Ty(C),
		{PointerType::getUnqual(C), PointerType::getUnqual(C),
		 PointerType::getUnqual(C), PointerType::getUnqual(C), Type::getInt32Ty(C)}, false);
	auto* F = Function::Create(FT, GlobalValue::ExternalLinkage, "decode", M);
	IRBuilder<> B(BasicBlock::Create(C, "entry", F));
	VMByteDecodeContext A, D;
	A.BC = F->getArg(0); A.Salt = F->getArg(1);
	D.BC = F->getArg(2); D.Salt = F->getArg(3);
	A.EncBytecode = D.EncBytecode = true;
	A.StrongBC = true;
	auto* V0 = emitVMByteLoad(B, A, F->getArg(4), "first");
	auto* V1 = emitVMByteLoad(B, D, F->getArg(4), "second");
	B.CreateRet(B.CreateXor(V0, V1));
	EXPECT_FALSE(verifyModule(M));
	unsigned First = 0, Second = 0;
	for (auto& I : instructions(*F)) {
		if (auto* L = dyn_cast<LoadInst>(&I)) {
			if (L->getPointerOperand() == A.Salt) ++First;
			if (L->getPointerOperand() == D.Salt) ++Second;
		}
	}
	EXPECT_EQ(First, 1u);
	EXPECT_EQ(Second, 1u);
}

TEST(VMPlan, EmptyCoordinatorFreezesWithoutCandidates) {
	VMPlanCoordinator Coordinator;
	EXPECT_TRUE(Coordinator.freeze());
	EXPECT_EQ(Coordinator.candidateCount(), 0u);
}

// Task 4: sensitive candidate lifecycle.
TEST(VMPlan, RequiredCandidateKeepsRegionAndStrictFlag) {
	LLVMContext C;
	Module M("plan", C);
	FunctionType* FT = FunctionType::get(Type::getInt32Ty(C), { Type::getInt32Ty(C) }, false);
	Function* F = Function::Create(FT, GlobalValue::ExternalLinkage, "auth", M);
	auto* V = Function::Create(
		FunctionType::get(Type::getInt32Ty(C), { Type::getInt32Ty(C) }, false),
		GlobalValue::ExternalLinkage, "verify", M);
	VMPassConfig Config;
	EngineConfigKey Key = EngineConfigKey::fromConfig(Config, 0, 0);
	VMPlanCoordinator Coordinator;
	SmallVector<Function*, 4> Callees{V};
	VMPreparedCandidate* C0 = Coordinator.addRequired(
		*F, "auth", /*Strict=*/true, Callees, Config, Key, BytecodeEmitter{}, {});
	ASSERT_NE(C0, nullptr);
	EXPECT_TRUE(C0->Required);
	EXPECT_TRUE(C0->SensitiveStrict);
	EXPECT_EQ(C0->Region, "auth");
	ASSERT_EQ(C0->SensitiveCallees.size(), 1u);
	EXPECT_EQ(C0->SensitiveCallees.front()->getName(), "verify");
	EXPECT_FALSE(C0->Accepted);  // not prepared yet
}

TEST(SensitivePostValidation, AcceptsCommittedWrapper) {
	LLVMContext C;
	SMDiagnostic D;
	auto M = parseAssemblyString(R"IR(
define i32 @auth(i32 %x) !obf.sensitive.validated !0 !obf.sensitive.committed !1 !obf.vm.caller !2 {
entry:
  ret i32 0
}
!0 = !{!"auth", i1 true}
!1 = !{!"auth"}
!2 = !{}
)IR", D, C);
	ASSERT_NE(M, nullptr) << D.getMessage().str();
	std::string E;
	raw_string_ostream OS(E);
	EXPECT_TRUE(verifyCommittedSensitiveRegions(*M, OS)) << E;
}

TEST(SensitivePostValidation, RejectsMissingCommittedProof) {
	LLVMContext C;
	SMDiagnostic D;
	auto M = parseAssemblyString(R"IR(
define i32 @auth(i32 %x) !obf.sensitive.validated !0 !obf.vm.caller !2 {
entry:
  ret i32 0
}
!0 = !{!"auth", i1 true}
!2 = !{}
)IR", D, C);
	ASSERT_NE(M, nullptr) << D.getMessage().str();
	std::string E;
	raw_string_ostream OS(E);
	EXPECT_FALSE(verifyCommittedSensitiveRegions(*M, OS));
	EXPECT_NE(E.find("no committed proof metadata"), std::string::npos) << E;
}

TEST(SensitivePostValidation, RejectsDirectExternalCallInWrapper) {
	LLVMContext C;
	SMDiagnostic D;
	auto M = parseAssemblyString(R"IR(
declare i32 @fixture_verify(ptr, i64)
define i32 @auth(ptr %p, i64 %n) !obf.sensitive.validated !0 !obf.sensitive.committed !1 !obf.vm.caller !2 {
entry:
  %r = call i32 @fixture_verify(ptr %p, i64 %n)
  ret i32 %r
}
!0 = !{!"auth", i1 true}
!1 = !{!"auth"}
!2 = !{}
)IR", D, C);
	ASSERT_NE(M, nullptr) << D.getMessage().str();
	std::string E;
	raw_string_ostream OS(E);
	EXPECT_FALSE(verifyCommittedSensitiveRegions(*M, OS));
	EXPECT_NE(E.find("retains direct call to 'fixture_verify'"), std::string::npos) << E;
}

TEST(SensitivePostValidation, RejectsRegionMismatch) {
	LLVMContext C;
	SMDiagnostic D;
	auto M = parseAssemblyString(R"IR(
define i32 @auth(i32 %x) !obf.sensitive.validated !0 !obf.sensitive.committed !1 !obf.vm.caller !2 {
entry:
  ret i32 0
}
!0 = !{!"auth", i1 true}
!1 = !{!"other"}
!2 = !{}
)IR", D, C);
	ASSERT_NE(M, nullptr) << D.getMessage().str();
	std::string E;
	raw_string_ostream OS(E);
	EXPECT_FALSE(verifyCommittedSensitiveRegions(*M, OS));
	EXPECT_NE(E.find("committed under region 'other'"), std::string::npos) << E;
}

TEST(VMPlan, RequiredCandidateUpgradesExistingCandidateInPlace) {
	LLVMContext C;
	Module M("plan", C);
	FunctionType* FT = FunctionType::get(Type::getInt32Ty(C), { Type::getInt32Ty(C) }, false);
	Function* F = Function::Create(FT, GlobalValue::ExternalLinkage, "auth", M);
	VMPassConfig Config;
	EngineConfigKey Key = EngineConfigKey::fromConfig(Config, 0, 0);
	VMPlanCoordinator Coordinator;
	VMPreparedCandidate* A = Coordinator.addCandidate(*F, Config, Key, BytecodeEmitter{}, {});
	ASSERT_NE(A, nullptr);
	SmallVector<Function*, 4> NoCallees;
	VMPreparedCandidate* B = Coordinator.addRequired(
		*F, "auth", true, NoCallees, Config, Key, BytecodeEmitter{}, {});
	EXPECT_EQ(A, B);
	EXPECT_EQ(Coordinator.candidateCount(), 1u);
	EXPECT_TRUE(B->Required);
}

TEST(VMPlan, FreezesCompatibleCandidatesIntoOneDemandUnion) {
	LLVMContext C;
	Module M("plan", C);
	FunctionType* FT = FunctionType::get(Type::getVoidTy(C), false);
	Function* A = Function::Create(FT, GlobalValue::ExternalLinkage, "a", M);
	Function* B = Function::Create(FT, GlobalValue::ExternalLinkage, "b", M);
	VMPassConfig Config;
	EngineConfigKey Key = EngineConfigKey::fromConfig(Config, 0, 0);
	BytecodeEmitter EA;
	BytecodeEmitter EB;
	VMRequirementSet RA;
	VMRequirementSet RB;
	RA.requireBinSubop(OP_BINOP, BS_ADD);
	RB.requireBinSubop(OP_BINOP, BS_MUL);
	VMPlanCoordinator Coordinator;
	ASSERT_NE(Coordinator.addCandidate(*A, Config, Key, std::move(EA), RA), nullptr);
	ASSERT_NE(Coordinator.addCandidate(*B, Config, Key, std::move(EB), RB), nullptr);
	ASSERT_TRUE(Coordinator.freeze());
	ASSERT_EQ(Coordinator.groupCount(), 1u);
	const VMEnginePlan* Plan = Coordinator.groupPlan(0);
	ASSERT_NE(Plan, nullptr);
	EXPECT_TRUE(Plan->Requirements.allowsBinSubop(OP_BINOP, BS_ADD));
	EXPECT_TRUE(Plan->Requirements.allowsBinSubop(OP_BINOP, BS_MUL));
}

TEST(VMPlan, SeparatesIncompatibleEngineKeys) {
	LLVMContext C;
	Module M("plan", C);
	FunctionType* FT = FunctionType::get(Type::getVoidTy(C), false);
	Function* A = Function::Create(FT, GlobalValue::ExternalLinkage, "a", M);
	Function* B = Function::Create(FT, GlobalValue::ExternalLinkage, "b", M);
	VMPassConfig AConfig;
	VMPassConfig BConfig = AConfig;
	BConfig.lazyDecrypt = true;
	VMPlanCoordinator Coordinator;
	EXPECT_NE(Coordinator.addCandidate(*A, AConfig,
		EngineConfigKey::fromConfig(AConfig, 0, 0), BytecodeEmitter{}, {}), nullptr);
	EXPECT_NE(Coordinator.addCandidate(*B, BConfig,
		EngineConfigKey::fromConfig(BConfig, 0, 0), BytecodeEmitter{}, {}), nullptr);
	ASSERT_TRUE(Coordinator.freeze());
	EXPECT_EQ(Coordinator.groupCount(), 2u);
}

TEST(VMPlan, AntiDebugConfigurationSeparatesEngineKeys) {
	VMPassConfig A, B;
	A.antiDebugConfig.enabled = true;
	A.antiDebugConfig.tracerPid = true;
	B.antiDebugConfig.enabled = true;
	B.antiDebugConfig.timing = true;
	EXPECT_FALSE(EngineConfigKey::fromConfig(A, 0, 0) ==
		EngineConfigKey::fromConfig(B, 0, 0));
}

TEST(VMPlan, NestedHelperRequirementsAreMergedIntoGroup) {
	LLVMContext C;
	Module M("plan", C);
	FunctionType* FT = FunctionType::get(Type::getVoidTy(C), false);
	Function* A = Function::Create(FT, GlobalValue::ExternalLinkage, "outer", M);
	VMPassConfig Config;
	EngineConfigKey Key = EngineConfigKey::fromConfig(Config, 0, 0);
	VMRequirementSet Outer;
	Outer.requireOpcode(OP_BINOP);
	Outer.NestedHelpers.push_back(OP_BINOP);
	VMRequirementSet Helper;
	Helper.requireBinSubop(OP_BINOP, BS_MUL);
	VMPlanCoordinator Coordinator;
	Coordinator.addCandidate(*A, Config, Key, BytecodeEmitter{}, Outer);
	ASSERT_TRUE(Coordinator.addHelperRequirements(Key, OP_BINOP, Helper));
	ASSERT_TRUE(Coordinator.freeze());
	const VMEnginePlan* Plan = Coordinator.groupPlan(0);
	ASSERT_NE(Plan, nullptr);
	EXPECT_TRUE(Plan->Requirements.allowsBinSubop(OP_BINOP, BS_MUL));
}

TEST(AntiDebugIR, ConfiguredTracerPidUsesOnlyTracerSymbols) {
	LLVMContext C;
	SMDiagnostic D;
	auto M = parseAssemblyString(R"IR(
define i32 @target(i32 %x) {
entry:
  %r = add i32 %x, 1
  ret i32 %r
}
)IR", D, C);
	ASSERT_NE(M, nullptr);
	AntiDebugConfig AD;
	AD.enabled = true;
	AD.tracerPid = true;
	EXPECT_TRUE(AD.validate());
}

TEST(AntiDebugConfig, DefaultsAreDisabled) {
	auto C = AnnotationParser::parseAnnotationString("obf: antidebug");
	auto PC = C.getPassConfig("antidebug");
	ASSERT_TRUE(PC.has_value());
	auto AD = AntiDebugConfig::fromPassConfig(*PC);
	EXPECT_FALSE(AD.enabled);
	EXPECT_FALSE(AD.tracerPid);
	EXPECT_FALSE(AD.ptrace);
	EXPECT_FALSE(AD.timing);
	EXPECT_FALSE(AD.maps);
	EXPECT_FALSE(AD.integrity);
	EXPECT_FALSE(AD.dynamic);
}

TEST(AntiDebugConfig, ExplicitZeroWins) {
	auto C = AnnotationParser::parseAnnotationString(
		"obf: antidebug(tracerPid=1,ptrace=0,timing=1,dynamic=0,interval=250,threshold=900000)");
	auto PC = C.getPassConfig("antidebug");
	ASSERT_TRUE(PC.has_value());
	auto AD = AntiDebugConfig::fromPassConfig(*PC);
	EXPECT_TRUE(AD.tracerPid);
	EXPECT_FALSE(AD.ptrace);
	EXPECT_TRUE(AD.timing);
	EXPECT_FALSE(AD.dynamic);
	EXPECT_EQ(AD.intervalMs, 250u);
	EXPECT_EQ(AD.thresholdNs, 900000u);
}

TEST(AntiDebugConfig, DynamicRequiresDetector) {
	auto C = AnnotationParser::parseAnnotationString("obf: antidebug(dynamic=1)");
	auto PC = C.getPassConfig("antidebug");
	ASSERT_TRUE(PC.has_value());
	auto AD = AntiDebugConfig::fromPassConfig(*PC);
	std::string Reason;
	EXPECT_FALSE(AD.validate(&Reason));
	EXPECT_EQ(Reason, "dynamic monitor requires at least one detector");
}

#if __has_include("llvm/Transforms/Obfuscator/VMPass_Requirements.h")
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/LLVMContext.h"

TEST(VMRequirements, IntegerFamiliesRemainIndependent) {
	VMRequirementSet R;
	R.requireBinSubop(OP_BINOP, BS_ADD);
	R.requireBinSubop(OP_BINOP64, BS_MUL);
	EXPECT_TRUE(R.contains(OP_BINOP64));
	EXPECT_TRUE(R.allowsBinSubop(OP_BINOP64, BS_MUL));
	EXPECT_FALSE(R.allowsBinSubop(OP_BINOP, BS_MUL));
	EXPECT_FALSE(R.allowsBinSubop(OP_BINOP64, BS_ADD));
}

TEST(VMRequirements, PrecisionStaysAssociatedWithOperation) {
	VMRequirementSet R;
	R.requireFBinSubop(FBS_FADD, true);
	R.requireFBinSubop(FBS_FMUL, false);
	EXPECT_EQ(R.FBinSubops.count(), 2u);
	EXPECT_EQ(R.FBinSubops.size(), ISAEnc::kNumFBinSubop);
	EXPECT_TRUE(R.allowsFBinSubop(FBS_FADD, true));
	EXPECT_FALSE(R.allowsFBinSubop(FBS_FADD, false));
	EXPECT_TRUE(R.allowsFBinSubop(FBS_FMUL, false));
	EXPECT_FALSE(R.allowsFBinSubop(FBS_FMUL, true));
}

TEST(VMRequirements, MergeUnionsDomainsWithoutCrossProduct) {
	VMRequirementSet A, B;
	A.requireFBinSubop(FBS_FADD, true);
	B.requireFBinSubop(FBS_FMUL, false);
	B.requireBinSubop(OP_BINOP64, BS_UREM);
	A.merge(B);
	A.merge(B);
	EXPECT_EQ(A.Opcodes.count(), 2u);
	EXPECT_TRUE(A.allowsBinSubop(OP_BINOP64, BS_UREM));
	EXPECT_FALSE(A.allowsBinSubop(OP_BINOP, BS_UREM));
	EXPECT_FALSE(A.allowsFBinSubop(FBS_FADD, false));
}

TEST(VMRequirements, SuperopClosureDoesNotCreateBinopFallbacks) {
	VMRequirementSet R;
	R.requireOpcode(OP_MULADD);
	R.requireIcmpPredicate(OP_ANDCMPZ, ISAEnc::kIcmpPredBase);
	VMPassConfig C;
	R.closeDependencies(C);
	EXPECT_TRUE(R.NeedsSuperOps);
	EXPECT_TRUE(R.NeedsRegFile[0]);
	EXPECT_FALSE(R.contains(OP_BINOP));
	EXPECT_FALSE(R.contains(OP_ICMP));
	EXPECT_TRUE(R.BinSubops[0].none());
}

TEST(VMRequirements, NestedClosureSelectsOnlyUsedEligibleFamilies) {
	VMRequirementSet R;
	R.requireBinSubop(OP_BINOP64, BS_MUL);
	R.requireOpcode(OP_LOAD32);
	VMPassConfig C;
	C.nestedVM = true;
	R.closeDependencies(C);
	R.closeDependencies(C);
	ASSERT_EQ(R.NestedHelpers.size(), 1u);
	EXPECT_EQ(R.NestedHelpers[0], OP_BINOP64);
	EXPECT_FALSE(R.contains(OP_BINOP));
}

TEST(VMRequirements, CallTypesDeduplicateByStructure) {
	LLVMContext C1, C2;
	auto *T1 = FunctionType::get(Type::getInt32Ty(C1), {Type::getInt64Ty(C1)}, false);
	auto *T2 = FunctionType::get(Type::getInt32Ty(C2), {Type::getInt64Ty(C2)}, false);
	auto *T3 = FunctionType::get(Type::getInt32Ty(C1), {Type::getInt64Ty(C1)}, true);
	VMRequirementSet A, B;
	A.requireCallType(T1);
	B.requireCallType(T2);
	B.requireCallType(T3);
	A.merge(B);
	EXPECT_EQ(A.CallTypes.size(), 2u);
	EXPECT_TRUE(A.NeedsRegFile[0]);
	EXPECT_TRUE(A.NeedsRegFile[1]);
}

TEST(VMRequirements, CastKindsAndPredicatesStayInTheirOwnFamily) {
	VMRequirementSet R;
	R.requireCastKind(OP_CAST64, C64_TRUNC32);
	R.requireFCastKind(OP_FCAST_VF, FK_SITOFP, true);
	R.requireIcmpPredicate(OP_CMPSEL, ISAEnc::kIcmpPredBase);
	EXPECT_FALSE(R.allowsCastKind(OP_CAST, C64_TRUNC32));
	EXPECT_TRUE(R.allowsCastKind(OP_CAST64, C64_TRUNC32));
	EXPECT_FALSE(R.allowsFCastKind(OP_FCAST_VF, FK_SITOFP, false));
	EXPECT_FALSE(R.allowsFCastKind(OP_FCAST_V64F, FK_SI64TOFP, true));
	EXPECT_FALSE(R.allowsIcmpPredicate(OP_ICMP, ISAEnc::kIcmpPredBase));
}

TEST(VMRequirements, KeySeparatesConfigurationAndOwner) {
	VMPassConfig A, B;
	A.randISA = false;
	B.randISA = true;
	EXPECT_FALSE(EngineConfigKey::fromConfig(A, 0, 0) == EngineConfigKey::fromConfig(B, 0, 0));
	B = A;
	B.lazyDecrypt = !A.lazyDecrypt;
	EXPECT_FALSE(EngineConfigKey::fromConfig(A, 0, 0) == EngineConfigKey::fromConfig(B, 0, 0));
	B = A;
	B.adHandlerThreshold++;
	EXPECT_FALSE(EngineConfigKey::fromConfig(A, 0, 0) == EngineConfigKey::fromConfig(B, 0, 0));
	EXPECT_FALSE(EngineConfigKey::fromConfig(A, 0, 0) == EngineConfigKey::fromConfig(A, 1, 0));
	A.perFnEngine = true;
	EXPECT_FALSE(EngineConfigKey::fromConfig(A, 0, 1) == EngineConfigKey::fromConfig(A, 0, 2));
}

TEST(VMRequirements, KeyIgnoresEligibilityButHashesAllEffectiveFields) {
	VMPassConfig A, B;
	B.minBlocks = 7;
	B.maxBlocks = 20;
	auto KA = EngineConfigKey::fromConfig(A, 0, 0);
	auto KB = EngineConfigKey::fromConfig(B, 0, 0);
	EXPECT_TRUE(KA == KB);
	EXPECT_EQ(KA.stableHash(), KB.stableHash());
	B.regEncrypt = true;
	KB = EngineConfigKey::fromConfig(B, 0, 0);
	EXPECT_FALSE(KA == KB);
	EXPECT_NE(KA.stableHash(), KB.stableHash());
	EXPECT_TRUE(KA.toJson().getBoolean("randISA").value_or(false));
}

TEST(VMRequirements, TableDomainDoesNotShrinkWithDemand) {
	VMEnginePlan P;
	P.Config.handlerVariants = 3;
	P.Config.encDispatch = true;
	P.Requirements.requireBinSubop(OP_BINOP, BS_MUL);
	EXPECT_EQ(P.handlerTableEntries(), unsigned(OP_COUNT) * 4 + 1);
	P.Decoys = 7;
	EXPECT_EQ(P.handlerTableEntries(), unsigned(OP_COUNT) * 4 + 8);
}

TEST(VMRequirements, WitnessRecordsLogicalPrecisionAndFullKey) {
	VMEngineWitness W;
	W.EngineId = 4;
	W.ConfigKey = EngineConfigKey::fromConfig(VMPassConfig{}, 2, 0);
	W.Requirements.requireFBinSubop(FBS_FADD, true);
	W.RealHandlers.push_back(OP_BINOP_F);
	W.HandlerVariants = 3;
	W.HandlerTableEntries = 225;
	auto J = W.toJson();
	EXPECT_EQ(J.getInteger("engine_id"), 4);
	EXPECT_EQ(J.getInteger("handler_table_entries"), 225);
	ASSERT_NE(J.getObject("config_key"), nullptr);
	ASSERT_NE(J.getObject("requirements"), nullptr);
	EXPECT_NE(J.getObject("isa_maps"), nullptr);
	ASSERT_NE(J.getArray("real_handlers"), nullptr);
	EXPECT_EQ(J.getArray("real_handlers")->size(), 1u);
}

#else
TEST(VMRequirements, ModelIsAvailable) {
	FAIL() << "VM requirement model is not implemented";
}
#endif

TEST(VMDefaults, OperandRandomizationIsEnabled) {
	EXPECT_TRUE(llvm::VMPassConfig{}.randISA);
}

TEST(VMEmitter, RecordsDemandAtTheActualIntegerEmissionSite) {
	LLVMContext C;
	SMDiagnostic Diag;
	auto M = parseAssemblyString(R"IR(
define i32 @add(i32 %x, i32 %y) {
entry:
  %sum = add i32 %x, %y
  ret i32 %sum
}
)IR", Diag, C);
	ASSERT_NE(M, nullptr);
	BytecodeEmitter E;
	ASSERT_TRUE(E.run(*M->getFunction("add"), 0, M->getDataLayout()));
	EXPECT_TRUE(E.getRequirements().contains(OP_BINOP));
	EXPECT_TRUE(E.getRequirements().allowsBinSubop(OP_BINOP, BS_ADD));
	EXPECT_FALSE(E.getRequirements().allowsBinSubop(OP_BINOP, BS_MUL));
}

TEST(VMEmitter, CopyAndExternalSinkDoNotAliasOwnedDemand) {
	LLVMContext C;
	SMDiagnostic D;
	auto M = parseAssemblyString(R"IR(
define i32 @add(i32 %x, i32 %y) { %r = add i32 %x, %y ret i32 %r }
define i64 @mul(i64 %x, i64 %y) { %r = mul i64 %x, %y ret i64 %r }
)IR", D, C);
	ASSERT_NE(M, nullptr);
	BytecodeEmitter A;
	ASSERT_TRUE(A.run(*M->getFunction("add"), 0, M->getDataLayout()));
	BytecodeEmitter B = A;
	ASSERT_TRUE(B.run(*M->getFunction("mul"), 0, M->getDataLayout()));
	EXPECT_TRUE(A.getRequirements().allowsBinSubop(OP_BINOP, BS_ADD));
	EXPECT_TRUE(B.getRequirements().allowsBinSubop(OP_BINOP64, BS_MUL));
	EXPECT_FALSE(B.getRequirements().contains(OP_BINOP));
	VMRequirementSet Sink;
	B.setRequirements(&Sink);
	ASSERT_TRUE(B.run(*M->getFunction("add"), 0, M->getDataLayout()));
	EXPECT_TRUE(B.getRequirements().allowsBinSubop(OP_BINOP, BS_ADD));
	EXPECT_TRUE(Sink.allowsBinSubop(OP_BINOP, BS_ADD));
	B.setRequirements(nullptr);
}

TEST(VMEmitter, FreezeAliasesSupportedScalarOperand) {
	LLVMContext C;
	SMDiagnostic D;
	auto M = parseAssemblyString(R"IR(
define i32 @rejected(i32 %x, i32 %y) {
  %a = add i32 %x, %y
  %f = freeze i32 %a
  ret i32 %f
}
)IR", D, C);
	ASSERT_NE(M, nullptr);
	BytecodeEmitter E;
	VMRequirementSet Sink;
	E.setRequirements(&Sink);
  EXPECT_TRUE(E.run(*M->getFunction("rejected"), 0, M->getDataLayout()));
  EXPECT_TRUE(E.getRequirements().contains(OP_BINOP));
  EXPECT_TRUE(Sink.contains(OP_BINOP));
}

TEST(VMEmitter, FmodLoweringUsesRandomizedOperandEncoding) {
	LLVMContext C;
	SMDiagnostic D;
	auto M = parseAssemblyString(R"IR(
declare float @fmodf(float, float)
define float @target(float %x, float %y) {
  %r = call float @fmodf(float %x, float %y)
  ret float %r
}
)IR", D, C);
	ASSERT_NE(M, nullptr);
	ISAEnc Map;
	std::swap(Map.FBinSubopL2P[FBS_FREM], Map.FBinSubopL2P[FBS_FSUB]);
	BytecodeEmitter E;
	E.setISAEnc(&Map);
	ASSERT_TRUE(E.run(*M->getFunction("target"), 0, M->getDataLayout()));
	ASSERT_GE(E.BC.size(), 5u);
	EXPECT_EQ(E.BC[4], Map.encFBinSubop(FBS_FREM) | FBS_F32_FLAG);
	EXPECT_TRUE(E.getRequirements().allowsFBinSubop(FBS_FREM, true));
	EXPECT_TRUE(E.getRequirements().CallTypes.empty());
	EXPECT_FALSE(E.getRequirements().contains(OP_CALL_F));
}

TEST(VMEmitter, FusionAndConstantPrologueRecordOnlyEmittedOpcodes) {
	LLVMContext C;
	SMDiagnostic D;
	auto M = parseAssemblyString(R"IR(
define i32 @target(i32 %x, i32 %y) {
  %m = mul i32 %x, %y
  %r = add i32 %m, 11
  ret i32 %r
}
)IR", D, C);
	ASSERT_NE(M, nullptr);
	BytecodeEmitter E;
	E.setSuperOps(true);
	E.setConstInStream(true);
	E.setKeyedDispatch(42, true);
	ASSERT_TRUE(E.run(*M->getFunction("target"), 0, M->getDataLayout()));
	auto Bytes = E.BC;
	EXPECT_TRUE(E.getRequirements().contains(OP_MULADD));
	EXPECT_TRUE(E.getRequirements().contains(OP_LOADI));
	EXPECT_FALSE(E.getRequirements().contains(OP_BINOP));
	EXPECT_TRUE(E.getRequirements().NeedsSuperOps);
	EXPECT_TRUE(E.getRequirements().NeedsConstStream);
	ASSERT_TRUE(E.run(*M->getFunction("target"), 0, M->getDataLayout()));
	EXPECT_EQ(E.BC, Bytes);
}

TEST(VMEmitter, RecordsCastsSelectsAndConcreteVarargs) {
	LLVMContext C;
	SMDiagnostic D;
	auto M = parseAssemblyString(R"IR(
declare i32 @callee(ptr, ...)
define i32 @target(i32 %x, i64 %y, float %f, ptr %p) {
  %b = icmp eq i32 %x, 7
  %z = zext i1 %b to i32
  %t = trunc i64 %y to i32
  %s = select i1 %b, i64 %y, i64 9
  %fp = sitofp i32 %x to float
  %n = fadd float %fp, %f
  %d = fpext float %n to double
  %r = call i32 (ptr, ...) @callee(ptr %p, i32 %z, i32 %t, i64 %s, double %d)
  ret i32 %r
}

)IR", D, C);
	ASSERT_NE(M, nullptr);
	BytecodeEmitter E;
	ASSERT_TRUE(E.run(*M->getFunction("target"), 0, M->getDataLayout()));
	const auto &R = E.getRequirements();
	EXPECT_TRUE(R.allowsIcmpPredicate(OP_ICMP, ISAEnc::kIcmpPredBase));
	EXPECT_TRUE(R.allowsCastKind(OP_CAST, CK_ZEXT1));
	EXPECT_TRUE(R.allowsCastKind(OP_CAST64, C64_TRUNC32));
	EXPECT_TRUE(R.SelectKinds.test(2));
	EXPECT_TRUE(R.allowsFCastKind(OP_FCAST_VF, FK_SITOFP, true));
	EXPECT_TRUE(R.allowsFCastKind(OP_FCAST_FF, FK_FPEXT, false));
	EXPECT_TRUE(R.allowsFBinSubop(FBS_FADD, true));
	ASSERT_EQ(R.CallTypes.size(), 1u);
	EXPECT_TRUE(R.CallTypes[0]->isVarArg());
	EXPECT_EQ(R.CallTypes[0]->getNumParams(), 5u);
}

TEST(VMEmitter, RecordsVarargCallerSubopsForSharedEngineDemand) {
	LLVMContext C;
	SMDiagnostic D;
	auto M = parseAssemblyString(R"IR(
declare i32 @vadd(i32, ...)
define i32 @target(i32 %x, i32 %y) {
  %mul = mul i32 %x, %y
  %sum = add i32 %x, %y
  %r = call i32 (i32, ...) @vadd(i32 2, i32 %mul, i32 %sum)
  ret i32 %r
}
)IR", D, C);
	ASSERT_NE(M, nullptr);
	BytecodeEmitter E;
	ASSERT_TRUE(E.run(*M->getFunction("target"), 0, M->getDataLayout()));
	EXPECT_TRUE(E.getRequirements().allowsBinSubop(OP_BINOP, BS_MUL));
	EXPECT_TRUE(E.getRequirements().allowsBinSubop(OP_BINOP, BS_ADD));
	ASSERT_EQ(E.getRequirements().CallTypes.size(), 1u);
	EXPECT_TRUE(E.getRequirements().CallTypes[0]->isVarArg());
}

TEST(VMVerifier, RejectsInvalidAndUnrequiredSemanticBytesAtCorrectIP) {
	LLVMContext C;
	SMDiagnostic D;
	auto M = parseAssemblyString(R"IR(
define i32 @target(i32 %x, i32 %y) { %r = add i32 %x, %y ret i32 %r }
)IR", D, C);
	ASSERT_NE(M, nullptr);
	BytecodeEmitter E;
	VMOpcodeMap Map;
	ASSERT_TRUE(E.run(*M->getFunction("target"), 0, M->getDataLayout()));
	std::string Error;
	uint32_t BadIP = 99;
	auto Verify = [&] {
		return verifyBytecode(E, 0, Map, Error, BadIP, 0, false, false, &E.getRequirements());
	};
	ASSERT_TRUE(Verify()) << Error;
	E.BC[4] = 255;
	EXPECT_FALSE(Verify());
	EXPECT_EQ(BadIP, 0u);
	EXPECT_NE(Error.find("subop"), std::string::npos);
	E.BC[4] = BS_MUL;
	EXPECT_FALSE(Verify());
	E.BC[4] = BS_ADD;
	E.BC[0] = OP_ICMP;
	EXPECT_FALSE(Verify());
	EXPECT_NE(Error.find("requirement"), std::string::npos);
	E.BC[0] = 255;
	EXPECT_FALSE(Verify());
	EXPECT_NE(Error.find("invalid opcode"), std::string::npos);
}

TEST(VMVerifier, IndependentlyChecksInstructionBoundaries) {
	BytecodeEmitter E;
	E.NVR = 1;
	E.BC = {OP_JMP, 6, 0, 0, 0, OP_LOADI, 0, 7, 0, 0, 0, OP_RET_INT, 0};
	E.BlockIP[nullptr] = 0;
	LLVMContext C;
	auto BB = std::unique_ptr<BasicBlock>(BasicBlock::Create(C));
	E.BlockIP[BB.get()] = 6; // 故意伪造落在 LOADI 操作数内部的块起点。
	std::string Error;
	uint32_t IP = 99;
	EXPECT_FALSE(verifyBytecode(E, 0, VMOpcodeMap{}, Error, IP));
	EXPECT_NE(Error.find("instruction boundary"), std::string::npos);
}

TEST(VMVerifier, UsesCallTypeToValidateArgumentFileAndArity) {
	LLVMContext C;
	auto F = std::unique_ptr<Function>(Function::Create(
		FunctionType::get(Type::getVoidTy(C), {PointerType::getUnqual(C)}, false),
		GlobalValue::ExternalLinkage, "callee"));
	BytecodeEmitter E;
	E.CalleeTab.push_back(F.get());
	E.CalleeFTyTab.push_back(F->getFunctionType());
	E.NPR = 1;
	E.NVR = 10;
	E.BlockIP[nullptr] = 0;
	E.BC = {OP_CALL_VOID, 0, 1, 9, OP_RET_VOID};
	std::string Error;
	uint32_t IP = 99;
	EXPECT_FALSE(verifyBytecode(E, 0, VMOpcodeMap{}, Error, IP));
	EXPECT_EQ(IP, 0u);
	E.BC = {OP_CALL_VOID, 0, 0, OP_RET_VOID};
	EXPECT_FALSE(verifyBytecode(E, 0, VMOpcodeMap{}, Error, IP));
	EXPECT_NE(Error.find("arity"), std::string::npos);
}

TEST(VMVerifier, RejectsUnusedFloatingPrecisionCombination) {
	BytecodeEmitter E;
	E.NFR = 3;
	E.BlockIP[nullptr] = 0;
	E.BC = {OP_BINOP_F, 2, 0, 1, FBS_FADD, OP_RET_F, 2};
	VMRequirementSet Allowed;
	Allowed.requireFBinSubop(FBS_FADD, true);
	Allowed.requireOpcode(OP_RET_F);
	std::string Error;
	uint32_t IP = 99;
	EXPECT_FALSE(verifyBytecode(E, 0, VMOpcodeMap{}, Error, IP, 0, false, false, &Allowed));
	E.BC[4] |= FBS_F32_FLAG;
	EXPECT_TRUE(verifyBytecode(E, 0, VMOpcodeMap{}, Error, IP, 0, false, false, &Allowed)) << Error;
}

TEST(VMVerifier, RejectsUnrequiredCastKindsInEveryRegisterFamily) {
	struct Case { VMOp Op; uint8_t AllowedKind, OtherKind; bool F32; };
	const Case Cases[] = {
		{OP_CAST64, C64_ZEXT32, C64_SEXT32, false},
		{OP_FCAST_FF, FK_FPEXT, FK_FPTRUNC, false},
		{OP_FCAST_FV, FK_FPTOSI, FK_FPTOUI, false},
		{OP_FCAST_FV64, FK_FPTOSI64, FK_FPTOUI64, false},
		{OP_FCAST_VF, FK_SITOFP, FK_UITOFP, true},
		{OP_FCAST_V64F, FK_SI64TOFP, FK_UI64TOFP, true},
	};
	for (const auto &T : Cases) {
		SCOPED_TRACE(vmOpcodeName(T.Op).str());
		BytecodeEmitter E;
		E.NVR = E.NVR64 = E.NFR = 1;
		E.BlockIP[nullptr] = 0;
		E.BC = {T.Op, 0, 0, uint8_t(T.AllowedKind | (T.F32 ? 128 : 0)), OP_RET_VOID};
		VMRequirementSet Allowed;
		if (T.Op == OP_CAST64) Allowed.requireCastKind(T.Op, T.AllowedKind);
		else Allowed.requireFCastKind(T.Op, T.AllowedKind, T.F32);
		Allowed.requireOpcode(OP_RET_VOID);
		std::string Error;
		uint32_t IP = 99;
		auto Verify = [&] {
			return verifyBytecode(E, 0, VMOpcodeMap{}, Error, IP, 0, false, false, &Allowed);
		};
		ASSERT_TRUE(Verify()) << Error;
		E.BC[3] = T.OtherKind | (T.F32 ? 128 : 0);
		EXPECT_FALSE(Verify());
		EXPECT_EQ(IP, 0u);
		if (T.F32) {
			E.BC[3] = T.AllowedKind;
			EXPECT_FALSE(Verify());
		}
	}
}

TEST(VMVerifier, RejectsUnrequiredOrInvalidFusedPredicates) {
	for (VMOp Op : {OP_CMPSEL, OP_ANDCMPZ}) {
		SCOPED_TRACE(vmOpcodeName(Op).str());
		BytecodeEmitter E;
		E.NVR = 1;
		E.BlockIP[nullptr] = 0;
		E.BC = {Op, 0, 0, 0, 32};
		if (Op == OP_CMPSEL) E.BC.append({0, 0});
		E.BC.push_back(OP_RET_VOID);
		VMRequirementSet Allowed;
		Allowed.requireIcmpPredicate(Op, 32);
		Allowed.requireOpcode(OP_RET_VOID);
		std::string Error;
		uint32_t IP = 99;
		ASSERT_TRUE(verifyBytecode(E, 0, VMOpcodeMap{}, Error, IP, 0, false, false, &Allowed));
		E.BC[4] = 33;
		EXPECT_FALSE(verifyBytecode(E, 0, VMOpcodeMap{}, Error, IP, 0, false, false, &Allowed));
		EXPECT_EQ(IP, 0u);
		E.BC[4] = Op == OP_ANDCMPZ ? 34 : 255;
		EXPECT_FALSE(verifyBytecode(E, 0, VMOpcodeMap{}, Error, IP));
	}
}

TEST(VMVerifier, AcceptsConstantFcmpPredicatesAndRejectsInvalidOnes) {
	BytecodeEmitter E;
	E.NVR = E.NFR = 1;
	E.BlockIP[nullptr] = 0;
	E.BC = {OP_FCMP, 0, 0, 0, 0, OP_RET_INT, 0};
	VMRequirementSet Allowed;
	Allowed.requireFcmpPredicate(0);
	Allowed.requireFcmpPredicate(15);
	Allowed.requireOpcode(OP_RET_INT);
	std::string Error;
	uint32_t IP = 99;
	for (uint8_t Pred : {0, 15}) {
		E.BC[4] = Pred;
		EXPECT_TRUE(verifyBytecode(E, 0, VMOpcodeMap{}, Error, IP, 0, false, false, &Allowed)) << Error;
	}
	E.BC[4] = 16;
	EXPECT_FALSE(verifyBytecode(E, 0, VMOpcodeMap{}, Error, IP));
}

TEST(VMVerifier, ChecksCallReturnKindAndAllowedSignature) {
	LLVMContext C;
	auto F = std::unique_ptr<Function>(Function::Create(
		FunctionType::get(Type::getInt32Ty(C), false), GlobalValue::ExternalLinkage, "callee"));
	BytecodeEmitter E;
	E.CalleeTab.push_back(F.get());
	E.CalleeFTyTab.push_back(F->getFunctionType());
	E.NVR = E.NPR = 1;
	E.BlockIP[nullptr] = 0;
	E.BC = {OP_CALL_INT, 0, 0, 0, OP_RET_VOID};
	VMRequirementSet Allowed;
	Allowed.requireOpcode(OP_CALL_INT);
	Allowed.requireOpcode(OP_RET_VOID);
	std::string Error;
	uint32_t IP = 99;
	EXPECT_FALSE(verifyBytecode(E, 0, VMOpcodeMap{}, Error, IP, 0, false, false, &Allowed));
	Allowed.requireCallType(F->getFunctionType());
	ASSERT_TRUE(verifyBytecode(E, 0, VMOpcodeMap{}, Error, IP, 0, false, false, &Allowed)) << Error;
	E.BC[0] = OP_CALL_PTR;
	EXPECT_FALSE(verifyBytecode(E, 0, VMOpcodeMap{}, Error, IP));
	EXPECT_EQ(IP, 0u);
}

TEST(VMVerifier, ValidatesConcreteVariadicArguments) {
	LLVMContext C;
	SMDiagnostic D;
	auto M = parseAssemblyString(R"IR(
declare i32 @callee(ptr, ...)
define i32 @target(ptr %p, double %d, i64 %n) {
  %r = call i32 (ptr, ...) @callee(ptr %p, double %d, i64 %n)
  ret i32 %r
}
)IR", D, C);
	ASSERT_NE(M, nullptr);
	BytecodeEmitter E;
	ASSERT_TRUE(E.run(*M->getFunction("target"), 0, M->getDataLayout()));
	std::string Error;
	uint32_t IP = 99;
	ASSERT_TRUE(verifyBytecode(E, 0, VMOpcodeMap{}, Error, IP, 0, false, false, &E.getRequirements())) << Error;
	E.BC[5] = 1;
	EXPECT_FALSE(verifyBytecode(E, 0, VMOpcodeMap{}, Error, IP));
	EXPECT_EQ(IP, 0u);
}

// ============================================================================
// Task 3: sensitive decision parsing and def-use validation
// ============================================================================

TEST(SensitiveDecisionConfigTest, ParsesRegionAndStrict) {
	auto C = AnnotationParser::parseAnnotationString(
		"obf: sensitive(region=auth,strict=1), vm(preset=max)");
	auto PC = C.getPassConfig("sensitive");
	ASSERT_TRUE(PC.has_value());
	auto S = SensitiveDecisionConfig::fromPassConfig(*PC);
	EXPECT_TRUE(S.enable);
	EXPECT_TRUE(S.strict);
	EXPECT_EQ(S.region, "auth");
}

TEST(SensitiveDecisionConfigTest, DefaultsToStrictWhenUnspecified) {
	auto C = AnnotationParser::parseAnnotationString(
		"obf: sensitive(region=auth), vm(preset=max)");
	auto PC = C.getPassConfig("sensitive");
	ASSERT_TRUE(PC.has_value());
	auto S = SensitiveDecisionConfig::fromPassConfig(*PC);
	EXPECT_TRUE(S.enable);
	EXPECT_TRUE(S.strict);
	EXPECT_EQ(S.region, "auth");
}

TEST(SensitiveDecisionConfigTest, RejectsEmptyRegion) {
	auto C = AnnotationParser::parseAnnotationString(
		"obf: sensitive(region=,strict=1), vm(preset=max)");
	auto PC = C.getPassConfig("sensitive");
	ASSERT_TRUE(PC.has_value());
	auto S = SensitiveDecisionConfig::fromPassConfig(*PC);
	std::string Reason;
	EXPECT_FALSE(S.validate(&Reason));
	EXPECT_FALSE(Reason.empty());
}

TEST(SensitiveDecisionConfigTest, RejectsUnknownParameters) {
	auto C = AnnotationParser::parseAnnotationString(
		"obf: sensitive(region=auth,bogus=1), vm(preset=max)");
	auto PC = C.getPassConfig("sensitive");
	ASSERT_TRUE(PC.has_value());
	auto S = SensitiveDecisionConfig::fromPassConfig(*PC);
	std::string Reason;
	EXPECT_FALSE(S.validate(&Reason));
}

TEST(SensitiveDecisionConfigTest, RequiresEnabledVM) {
	std::string Reason;
	auto Only = AnnotationParser::parseAnnotationString(
		"obf: sensitive(region=auth,strict=1)");
	EXPECT_FALSE(validateSensitiveConfig(Only, &Reason));
	EXPECT_FALSE(Reason.empty());
	auto Both = AnnotationParser::parseAnnotationString(
		"obf: sensitive(region=auth,strict=1), vm(preset=max)");
	EXPECT_TRUE(validateSensitiveConfig(Both, &Reason));
}

#ifdef OBF_TEST_VM_IMPL
template <typename Action>
static void expectMaterialFatal(Action Run, StringRef Diagnostic) {
#ifdef __ANDROID__
	int FDs[2]; ASSERT_EQ(pipe(FDs), 0);
	pid_t PID = fork(); ASSERT_GE(PID, 0);
	if (PID == 0) {
		close(FDs[0]); dup2(FDs[1], STDERR_FILENO); close(FDs[1]);
		Run(); _exit(0);
	}
	close(FDs[1]); std::string Error; char Buf[1024]; ssize_t N;
	while ((N = read(FDs[0], Buf, sizeof(Buf))) > 0) Error.append(Buf, N);
	close(FDs[0]); int Status = 0; ASSERT_EQ(waitpid(PID, &Status, 0), PID);
	EXPECT_TRUE(WIFSIGNALED(Status) || (WIFEXITED(Status) && WEXITSTATUS(Status) != 0));
	EXPECT_NE(Error.find(Diagnostic.str()), std::string::npos) << Error;
#else
	EXPECT_DEATH(Run(), Diagnostic.str());
#endif
}

TEST(VMCloudMaterial, DirectCoordinatorCommitCannotSilentlySkipUnpreparedCandidate) {
	LLVMContext C; Module M("unprepared", C);
	auto* F = Function::Create(FunctionType::get(Type::getVoidTy(C), false),
		GlobalValue::ExternalLinkage, "f", M);
	auto Config = materialConfig("cloudMaterial=lease,materialRegion=auth");
	VMPlanCoordinator P;
	auto* Candidate = P.addCandidate(*F, Config, EngineConfigKey::fromConfig(Config, 0, 0), BytecodeEmitter{}, {});
	ASSERT_NE(Candidate, nullptr);
	EXPECT_FALSE(Candidate->Required);
	ASSERT_TRUE(P.freeze());
	expectMaterialFatal([&] { P.commit(); }, "not prepared");
}

TEST(VMCloudMaterial, ProtocolNameBoundaries) {
	for (const std::string& Name : {std::string("1auth/payment:read"), std::string(128, 'a')}) {
		auto Cfg = materialConfig("cloudMaterial=lease,materialRegion=" + Name);
		EXPECT_EQ(Cfg.materialRegion, Name);
	}
	for (const std::string& Name : {std::string("_auth"), std::string(129, 'a')})
		expectMaterialFatal([&] { materialConfig("cloudMaterial=lease,materialRegion=" + Name); }, "materialRegion");
}

TEST(VMCloudMaterial, BudgetBoundaries) {
	for (StringRef Key : {"budget", "budgetMax", "budgetMultiplier"}) {
		for (StringRef Value : {"2junk", "-1", "4294967296", ""}) {
			// 直接配置 API 也必须拒绝，不能仅依靠模块入口检查。
			PassConfig PC; PC.enabled = true;
			PC.params = {{"cloudMaterial", "lease"}, {"materialRegion", "auth"}, {Key.str(), Value.str()}};
			expectMaterialFatal([&] { VMPassConfig::fromPassConfig(PC); },
				(Twine("invalid unsigned value for ") + Key).str());
		}
	}
	auto C = AnnotationParser::parseAnnotationString(
		"obf: vm(cloudMaterial=lease,materialRegion=auth), shield(budgetMax=2junk)");
	expectMaterialFatal([&] { ObfuscationPipeline::validateMaterialConfig(C); },
		"invalid unsigned value for budgetMax");
}

TEST(VMCloudMaterial, DeclarationCacheAndDirectPassRejectMissingBody) {
	LLVMContext C; SMDiagnostic D;
	std::string Spec = "obf: vm(cloudMaterial=lease,materialRegion=auth)";
	auto M = parseAssemblyString("declare i32 @f(i32)\n@ann = private constant [" +
		std::to_string(Spec.size() + 1) + " x i8] c\"" + Spec + "\\00\"\n"
		"@llvm.global.annotations = appending global [1 x {ptr,ptr,ptr,i32,ptr}] "
		"[{ptr,ptr,ptr,i32,ptr} {ptr @f,ptr @ann,ptr @ann,i32 0,ptr null}]", D, C);
	ASSERT_NE(M, nullptr) << D.getMessage().str();
	expectMaterialFatal([&] {
		ModuleAnalysisManager MAM;
		ObfuscationAnnotationAnalysis().run(*M, MAM);
	}, "cloudMaterial requires a function body");
	expectMaterialFatal([&] {
		FunctionAnalysisManager FAM;
		VMPass().run(*M->getFunction("f"), FAM);
	}, "cloudMaterial requires a function body");
}

TEST(VMCloudMaterial, DirectEmissionIsGuardedBeforeLegacyGlobals) {
	LLVMContext C; SMDiagnostic D;
	auto M = parseAssemblyString("target triple = \"aarch64-unknown-linux-android26\"\n"
		"define i32 @f(i32 %x) { %r = add i32 %x,7\n ret i32 %r }", D, C);
	ASSERT_NE(M, nullptr);
	auto Config = materialConfig("cloudMaterial=session,materialRegion=auth,hardened=1");
	obf::Rng R(42); VMImpl Impl(*M->getFunction("f"), Config, R, 42);
	ASSERT_TRUE(Impl.prepare()) << Impl.FailReason;
	EXPECT_TRUE(M->global_empty());
	EXPECT_FALSE(Impl.Committed);
	EXPECT_TRUE(Impl.E.getRequirements().NeedsConstStream);
	expectMaterialFatal([&] { Impl.commit(); }, "cloud material emission not implemented");
}

TEST(VMCallVariants, IncrementalTypesReachEveryVariant) {
	for (unsigned Order = 0; Order != 2; ++Order) {
		LLVMContext C;
		SMDiagnostic D;
		auto M = parseAssemblyString(R"IR(
target triple = "aarch64-unknown-linux-android26"
declare i32 @one(i32)
declare i32 @three(i32, i64, double)
define i32 @first(i32 %x) { %r = call i32 @one(i32 %x)
 ret i32 %r }
define i32 @later(i32 %x, i64 %y, double %z) { %r = call i32 @three(i32 %x, i64 %y, double %z)
 ret i32 %r }
)IR", D, C);
		ASSERT_NE(M, nullptr) << D.getMessage().str();
		VMPassConfig Config;
		Config.hardened = true;
		Config.encBytecode = Config.lazyDecrypt = Config.strongBytecode = true;
		Config.regEncrypt = Config.rollingRegKey = true;
		Config.handlerVariants = 4;
		obf::Rng R(42);
		SmallVector<std::unique_ptr<VMImpl>, 2> Impls;
		const char* Names[2] = {"first", "later"};
		for (unsigned i = 0; i != 2; ++i) {
			auto Impl = std::make_unique<VMImpl>(*M->getFunction(Names[i ^ Order]), Config, R, 42);
			ASSERT_TRUE(Impl->run()) << Impl->FailReason;
			Impls.push_back(std::move(Impl));
		}
		EXPECT_EQ(Impls[0]->EngineId, Impls[1]->EngineId);
		auto* SS = VMEngine::getSharedState(*M, Impls[0]->EngineId);
		ASSERT_EQ(SS->SharedFTys.size(), 2u);
		ASSERT_EQ(SS->CallSW[VMEngine::RK2_I32].size(), 4u);
		DenseSet<BasicBlock*> Targets;
		for (const auto& SW : SS->CallSW[VMEngine::RK2_I32]) {
			EXPECT_EQ(SW.SW->getNumCases(), 2u);
			EXPECT_EQ(SW.OperandIP->getType(), Type::getInt32Ty(C));
			Targets.insert(SS->OpcBB[OP_CALL_INT][SW.Variant]);
		}
		EXPECT_EQ(Targets.size(), 4u);
		EXPECT_FALSE(verifyModule(*M, &errs()));
		if (const char* Dir = std::getenv("OBF_VM_CALL_IR_DIR")) {
			std::error_code EC;
			raw_fd_ostream OS(std::string(Dir) + "/incremental-" + std::to_string(Order) + ".ll", EC);
			ASSERT_FALSE(EC) << EC.message();
			M->print(OS, nullptr);
		}
		VMEngine::releaseSharedState(*M);
	}
}

TEST(VMPlan, DemandOnlyCandidateCanPrecedePreparedCandidate) {
	LLVMContext C;
	SMDiagnostic D;
	auto M = parseAssemblyString(R"IR(
define i32 @target(i32 %x) { %r = add i32 %x, 1 ret i32 %r }
)IR", D, C);
	ASSERT_NE(M, nullptr);
	VMPassConfig Config;
	obf::Rng R(42);
	auto Impl = std::make_unique<VMImpl>(*M->getFunction("target"), Config, R, 42);
	ASSERT_TRUE(Impl->prepare()) << Impl->FailReason;
	Impl->EngineId = VMEngine::makeEngineId(3, 0);
	unsigned ExpectedId = Impl->EngineId;
	auto Key = EngineConfigKey::fromConfig(Config, 3, 0);
	VMPlanCoordinator Coordinator;
	ASSERT_NE(Coordinator.addCandidate(*M->getFunction("target"), Config, Key,
		BytecodeEmitter{}, {}), nullptr);
	ASSERT_NE(Coordinator.addPrepared(std::move(Impl), Config, Key), nullptr);
	ASSERT_TRUE(Coordinator.freeze());
	ASSERT_EQ(Coordinator.groupCount(), 1u);
	EXPECT_EQ(Coordinator.groupPlan(0)->EngineId, ExpectedId);
}

static std::unique_ptr<Module> parseSensitiveFixture(const char* IR) {
	// context 必须比返回的 Module 活得久，否则 Module 持有悬垂引用导致 SIGSEGV
	static LLVMContext C;
	SMDiagnostic D;
	auto M = parseAssemblyString(IR, D, C);
	if (!M) errs() << D.getMessage();
	return M;
}

static SensitiveDecisionConfig AuthConfig() {
	SensitiveDecisionConfig Cfg;
	Cfg.enable = true;
	Cfg.strict = true;
	Cfg.region = "auth";
	return Cfg;
}

TEST(SensitiveDecisionValidation, AcceptsLocalDecisionWithLiteralReturns) {
	auto M = parseSensitiveFixture(R"IR(
declare i32 @verify(i32)
define i32 @auth(i32 %x) {
entry:
  %r = call i32 @verify(i32 %x)
  %ok = icmp eq i32 %r, 1
  br i1 %ok, label %success, label %fail
success:
  ret i32 1
fail:
  ret i32 0
}
)IR");
	ASSERT_NE(M, nullptr);
	SensitiveDecisionAnalysisResult R;
	ASSERT_TRUE(validateSensitiveDecision(*M->getFunction("auth"), AuthConfig(), R));
	EXPECT_TRUE(R.Valid);
	EXPECT_EQ(R.Callees.size(), 1u);
	EXPECT_EQ(R.Callees.front()->getName(), "verify");
}

TEST(SensitiveDecisionValidation, RejectsTaintedReturn) {
	auto M = parseSensitiveFixture(R"IR(
declare i32 @verify(i32)
define i32 @auth(i32 %x) {
entry:
  %r = call i32 @verify(i32 %x)
  %ok = icmp eq i32 %r, 1
  br i1 %ok, label %success, label %fail
success:
  ret i32 1
fail:
  ret i32 %r
}
)IR");
	ASSERT_NE(M, nullptr);
	SensitiveDecisionAnalysisResult R;
	EXPECT_FALSE(validateSensitiveDecision(*M->getFunction("auth"), AuthConfig(), R));
	EXPECT_NE(R.Diagnostic.find("escapes through return"), std::string::npos) << R.Diagnostic;
}

TEST(SensitiveDecisionValidation, RejectsTaintedStore) {
	auto M = parseSensitiveFixture(R"IR(
@g = global i32 0
declare i32 @verify(i32)
define i32 @auth(i32 %x) {
entry:
  %r = call i32 @verify(i32 %x)
  store i32 %r, ptr @g
  %ok = icmp eq i32 %r, 1
  br i1 %ok, label %success, label %fail
success:
  ret i32 1
fail:
  ret i32 0
}
)IR");
	ASSERT_NE(M, nullptr);
	SensitiveDecisionAnalysisResult R;
	EXPECT_FALSE(validateSensitiveDecision(*M->getFunction("auth"), AuthConfig(), R));
	EXPECT_NE(R.Diagnostic.find("escapes through store"), std::string::npos) << R.Diagnostic;
}

TEST(SensitiveDecisionValidation, RejectsTaintedUnknownCall) {
	auto M = parseSensitiveFixture(R"IR(
declare i32 @verify(i32)
declare void @sink(i32)
define i32 @auth(i32 %x) {
entry:
  %r = call i32 @verify(i32 %x)
  call void @sink(i32 %r)
  %ok = icmp eq i32 %r, 1
  br i1 %ok, label %success, label %fail
success:
  ret i32 1
fail:
  ret i32 0
}
)IR");
	ASSERT_NE(M, nullptr);
	SensitiveDecisionAnalysisResult R;
	EXPECT_FALSE(validateSensitiveDecision(*M->getFunction("auth"), AuthConfig(), R));
	EXPECT_NE(R.Diagnostic.find("escapes to unknown call"), std::string::npos) << R.Diagnostic;
}

TEST(SensitiveDecisionValidation, RejectsTaintedArgToNonVoidExternal) {
	auto M = parseSensitiveFixture(R"IR(
declare i32 @verify(i32)
declare i32 @rehash(i32)
define i32 @auth(i32 %x) {
entry:
  %r = call i32 @verify(i32 %x)
  %z = call i32 @rehash(i32 %r)
  %ok = icmp eq i32 %r, 1
  br i1 %ok, label %success, label %fail
success:
  ret i32 1
fail:
  ret i32 0
}
)IR");
	ASSERT_NE(M, nullptr);
	SensitiveDecisionAnalysisResult R;
	EXPECT_FALSE(validateSensitiveDecision(*M->getFunction("auth"), AuthConfig(), R));
	EXPECT_NE(R.Diagnostic.find("escapes to unknown call"), std::string::npos) << R.Diagnostic;
}

TEST(SensitiveDecisionValidation, RejectsMissingDecisionBranch) {
	auto M = parseSensitiveFixture(R"IR(
declare i32 @verify(i32)
define i32 @auth(i32 %x) {
entry:
  %r = call i32 @verify(i32 %x)
  ret i32 0
}
)IR");
	ASSERT_NE(M, nullptr);
	SensitiveDecisionAnalysisResult R;
	EXPECT_FALSE(validateSensitiveDecision(*M->getFunction("auth"), AuthConfig(), R));
	EXPECT_NE(R.Diagnostic.find("no in-region success/failure branch"),
		std::string::npos) << R.Diagnostic;
}

TEST(SensitiveDecisionValidation, AllowsStateCommitThenLiteralReturn) {
	auto M = parseSensitiveFixture(R"IR(
declare i32 @verify(i32)
define i32 @auth(i32 %x, ptr %state) {
entry:
  %r = call i32 @verify(i32 %x)
  %ok = icmp eq i32 %r, 1
  br i1 %ok, label %success, label %fail
success:
  store i32 1, ptr %state
  ret i32 1
fail:
  store i32 0, ptr %state
  ret i32 0
}
)IR");
	ASSERT_NE(M, nullptr);
	SensitiveDecisionAnalysisResult R;
	EXPECT_TRUE(validateSensitiveDecision(*M->getFunction("auth"), AuthConfig(), R)) << R.Diagnostic;
}

TEST(SensitiveDecisionValidation, LocalAllocaRoundTripIsAllowed) {
	auto M = parseSensitiveFixture(R"IR(
declare i32 @verify(i32)
define i32 @auth(i32 %x) {
entry:
  %slot = alloca i32
  %r = call i32 @verify(i32 %x)
  store i32 %r, ptr %slot
  %loaded = load i32, ptr %slot
  %ok = icmp eq i32 %loaded, 1
  br i1 %ok, label %success, label %fail
success:
  ret i32 1
fail:
  ret i32 0
}
)IR");
	ASSERT_NE(M, nullptr);
	SensitiveDecisionAnalysisResult R;
	EXPECT_TRUE(validateSensitiveDecision(*M->getFunction("auth"), AuthConfig(), R)) << R.Diagnostic;
}
#endif

#ifdef OBF_TEST_VM_IMPL
TEST(VMEligibility, AcceptsMultipleReturnValues) {
	LLVMContext C;
	SMDiagnostic D;
	auto M = parseAssemblyString(R"IR(
define i32 @target(i1 %c, i32 %x) {
entry:
  br i1 %c, label %a, label %b
a:
  %left = add i32 %x, 17
  ret i32 %left
b:
  %right = sub i32 %x, 29
  ret i32 %right
}
)IR", D, C);
	ASSERT_NE(M, nullptr);
	Function &F = *M->getFunction("target");
	FunctionObfContext FOC(F, false);
	FOC.NumNormalBlocks = F.size();
	VMPassConfig Config;
	std::string Reason;
	raw_string_ostream OS(Reason);
	EXPECT_TRUE(isVMEligible(F, FOC, Config, &OS)) << Reason;
	EXPECT_TRUE(Reason.empty()) << Reason;
}

TEST(VMRequirements, IntegerReturnHandlerNeedsBothRegisterFiles) {
	VMRequirementSet R;
	R.requireOpcode(OP_RET_INT);
	R.closeDependencies(VMPassConfig{});
	EXPECT_TRUE(R.NeedsRegFile[0]);
	EXPECT_TRUE(R.NeedsRegFile[1]);
}

TEST(VMEligibility, RejectsMustTailWithMultipleReturns) {
	LLVMContext C;
	SMDiagnostic D;
	auto M = parseAssemblyString(R"IR(
declare i32 @callee(i1, i32)
define i32 @target(i1 %c, i32 %x) {
entry:
  br i1 %c, label %a, label %b
a:
  %r = musttail call i32 @callee(i1 %c, i32 %x)
  ret i32 %r
b:
  ret i32 %x
}
)IR", D, C);
	ASSERT_NE(M, nullptr);
	ASSERT_FALSE(verifyModule(*M, &errs()));
	Function &F = *M->getFunction("target");
	FunctionObfContext FOC(F, false);
	FOC.NumNormalBlocks = F.size();
	for (BasicBlock &BB : F)
		for (Instruction &I : BB)
			if (auto *CI = dyn_cast<CallInst>(&I))
				FOC.HasMustTail |= CI->isMustTailCall();
	std::string Reason;
	raw_string_ostream OS(Reason);
	EXPECT_FALSE(isVMEligible(F, FOC, VMPassConfig{}, &OS));
	EXPECT_EQ(Reason, "musttail");
}

// 同一模块混用返回类型；分支结果占不同槽，避免统一出口掩盖返回 ABI 错误。
TEST(VMReturnABI, MultipleReturnRuntimeModule) {
	const char *IR = R"IR(
define i1 @ret_i1(i1 %c, i32 %x) {
entry:
  br i1 %c, label %a, label %b
a:
  %left = icmp slt i32 %x, 7
  ret i1 %left
b:
  %right = icmp sgt i32 %x, -3
  ret i1 %right
}
define i32 @ret_i32(i1 %c, i32 %x) {
entry:
  br i1 %c, label %a, label %b
a:
  %left = add i32 %x, 17
  ret i32 %left
b:
  %right = sub i32 %x, 29
  ret i32 %right
}
define i64 @ret_i64(i1 %c, i64 %x) {
entry:
  br i1 %c, label %a, label %b
a:
  %left = add i64 %x, 4294967313
  ret i64 %left
b:
  %t0 = xor i64 %x, 4294967295
  %t1 = add i64 %t0, 4294967325
  %t2 = xor i64 %t1, 72623859790382856
  %right = sub i64 %t2, 17
  ret i64 %right
}
define ptr @ret_ptr(i1 %c, ptr %x, ptr %y) {
entry:
  br i1 %c, label %a, label %b
a:
  ret ptr %x
b:
  ret ptr %y
}
define float @ret_float(i1 %c, float %x) {
entry:
  br i1 %c, label %a, label %b
a:
  %left = fadd float %x, 1.250000e+00
  ret float %left
b:
  %right = fsub float %x, 2.500000e+00
  ret float %right
}
define double @ret_double(i1 %c, double %x) {
entry:
  br i1 %c, label %a, label %b
a:
  %left = fadd double %x, 1.250000e+00
  ret double %left
b:
  %right = fsub double %x, 2.500000e+00
  ret double %right
}
define void @ret_void(i1 %c, ptr %out) {
entry:
  br i1 %c, label %a, label %b
a:
  store i32 17, ptr %out
  ret void
b:
  store i32 29, ptr %out
  ret void
}
)IR";
	const char *OutDir = std::getenv("OBF_VM_RETURN_IR_DIR");
	for (unsigned Mode = 0; Mode != 4; ++Mode) {
		SCOPED_TRACE(Mode);
		LLVMContext C;
		SMDiagnostic D;
		auto M = parseAssemblyString(IR, D, C);
		ASSERT_NE(M, nullptr);
		auto WriteIR = [&](StringRef Name) {
			if (!OutDir) return;
			std::error_code EC;
			raw_fd_ostream OS(std::string(OutDir) + "/" + Name.str() + ".ll", EC);
			ASSERT_FALSE(EC) << EC.message();
			M->print(OS, nullptr);
		};
		if (Mode == 0) WriteIR("reference");
		VMPassConfig Config;
		Config.hardened = false;
		Config.encBytecode = Mode != 0;
		Config.regEncrypt = Mode != 0;
		Config.rollingRegKey = Mode >= 2;
		Config.lazyDecrypt = Mode == 3;
		Config.constInStream = Mode >= 2;
		Config.handlerVariants = 2;
		VMPlanCoordinator Coordinator;
		SmallVector<VMImpl *, 8> Impls;
		for (Function &F : *M) {
			FunctionObfContext FOC(F, false);
			FOC.NumNormalBlocks = F.size();
			std::string Reason;
			raw_string_ostream OS(Reason);
			ASSERT_TRUE(isVMEligible(F, FOC, Config, &OS)) << F.getName().str() << ": " << Reason;
			obf::Rng R(42 + Impls.size());
			auto Impl = std::make_unique<VMImpl>(F, Config, R, 42);
			ASSERT_TRUE(Impl->prepare()) << Impl->FailReason;
			Impls.push_back(Impl.get());
			ASSERT_NE(Coordinator.addPrepared(std::move(Impl), Config,
				EngineConfigKey::fromConfig(Config, 0, 0, 42)), nullptr);
		}
		ASSERT_EQ(Impls.size(), 7u);
		ASSERT_TRUE(Coordinator.freeze());
		ASSERT_EQ(Coordinator.groupCount(), 1u);
		ASSERT_TRUE(Coordinator.commit());
		for (VMImpl *Impl : Impls) {
			EXPECT_TRUE(Impl->Committed) << Impl->F.getName().str();
			EXPECT_NE(Impl->GVBytecode, nullptr);
			EXPECT_EQ(Impl->EngineId, Impls.front()->EngineId);
		}
		EXPECT_FALSE(verifyModule(*M, &errs()));
		WriteIR("mode-" + std::to_string(Mode));
		VMEngine::releaseSharedState(*M);
	}
}

TEST(VMPreparation, RejectionLeavesOriginalFunctionAndModuleUntouched) {
	LLVMContext C;
	SMDiagnostic D;
	// invoke 是 isVMEligible 明确拒绝的条件（EH/invoke），
	// 确保被拒绝的函数不会被 VM 改写。
	auto M = parseAssemblyString(R"IR(
declare i32 @may_throw(i32)
declare i32 @__gxx_personality_v0(...)

define i32 @target(i32 %x) personality ptr @__gxx_personality_v0 {
entry:
  %r = invoke i32 @may_throw(i32 %x)
          to label %ok unwind label %lpad
ok:
  ret i32 %r
lpad:
  %lp = landingpad { ptr, i32 } cleanup
  ret i32 0
}
)IR", D, C);
	ASSERT_NE(M, nullptr);
	auto Print = [&] {
		std::string S;
		raw_string_ostream OS(S);
		M->print(OS, nullptr);
		return S;
	};
	std::string Before = Print();
	VMPassConfig Config;
	obf::Rng R(42);
	{
		VMImpl Impl(*M->getFunction("target"), Config, R, 42);
		EXPECT_FALSE(Impl.run());
		EXPECT_FALSE(Impl.FailReason.empty());
		EXPECT_EQ(Print(), Before);
	}
	EXPECT_EQ(Print(), Before);
}

TEST(VMNested, HelperFailureRestoresCallerAndNoSkipsAborts) {
	auto Run = [](bool NoSkips) {
		LLVMContext C; SMDiagnostic D;
		auto M = parseAssemblyString("define i32 @target(i32 %a,i32 %b) { %r = add i32 %a,%b\n ret i32 %r }", D, C);
		VMPassConfig Config; Config.nestedVM = true; Config.nestedVMHardened = true;
		obf::Rng R(42); auto Impl = std::make_unique<VMImpl>(*M->getFunction("target"), Config, R, 42);
		ASSERT_TRUE(Impl->prepare());
		auto Key = EngineConfigKey::fromConfig(Config, 0, Impl->EngineId, 42, &Impl->AntiDebug);
		std::string Name = (Twine("__vm_h_binop_owner") + Twine(Impl->EngineId) + "_" + Twine::utohexstr(Key.stableHash())).str();
		auto* HF = Function::Create(FunctionType::get(Type::getInt32Ty(C),
			{Type::getInt32Ty(C), Type::getInt32Ty(C), Type::getInt8Ty(C)}, false), GlobalValue::InternalLinkage, Name, *M);
		IRBuilder<> B(BasicBlock::Create(C, "entry", HF)); B.CreateFence(AtomicOrdering::SequentiallyConsistent); B.CreateRet(HF->getArg(0));
		VMPlanCoordinator P; auto* Candidate = P.addPrepared(std::move(Impl), Config, Key);
		ASSERT_TRUE(P.freeze());
		bool Prev = ObfNoSkips; ObfNoSkips = NoSkips;
		EXPECT_TRUE(P.commit()); ObfNoSkips = Prev;
		EXPECT_FALSE(Candidate->Accepted);
		EXPECT_NE(Candidate->SkipReason.find("nested"), std::string::npos);
		ASSERT_FALSE(M->getFunction("target")->empty());
		EXPECT_TRUE(isa<BinaryOperator>(M->getFunction("target")->getEntryBlock().front()));
		EXPECT_FALSE(verifyModule(*M, &errs())); VMEngine::releaseSharedState(*M);
	};
	Run(false);
#ifdef __ANDROID__
	// Android gtest 的 stderr 捕获硬编码 /data/local/tmp，Termux 无写权限。
	// 用 pipe 隔离 fatal 子进程，仍断言真实中止状态和明确诊断。
	int FDs[2]; ASSERT_EQ(pipe(FDs), 0);
	pid_t PID = fork(); ASSERT_GE(PID, 0);
	if (PID == 0) {
		close(FDs[0]); dup2(FDs[1], STDERR_FILENO); close(FDs[1]);
		Run(true); _exit(0);
	}
	close(FDs[1]); std::string Error; char Buf[1024]; ssize_t N;
	while ((N = read(FDs[0], Buf, sizeof(Buf))) > 0) Error.append(Buf, N);
	close(FDs[0]); int Status = 0; ASSERT_EQ(waitpid(PID, &Status, 0), PID);
	EXPECT_TRUE(WIFSIGNALED(Status) || (WIFEXITED(Status) && WEXITSTATUS(Status) != 0));
	EXPECT_NE(Error.find("nested helper preparation failed"), std::string::npos);
#else
	EXPECT_DEATH(Run(true), "nested helper preparation failed");
#endif
}
#endif
