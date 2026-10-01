#include "llvm/Transforms/Obfuscator/ZoneAuth.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include "llvm/Transforms/Obfuscator/ObfuscationOptions.h"
#include "zone_runtime/zone_link_manifest.h"

#include <limits>

using namespace llvm;

static void emitZoneLinkMarker(Module& M) {
	const StringRef mode = ObfZoneLinkMode;
	if (mode != XOLLVM_ZONE_LINK_MODE_BUNDLED &&
		mode != XOLLVM_ZONE_LINK_MODE_EXTERNAL)
		return;
	LLVMContext& C = M.getContext();
	const std::string marker = std::string(XOLLVM_ZONE_LINK_MARKER_PREFIX) +
		"mode=" + mode.str() + ";triple=" + M.getTargetTriple().str();
	Constant* value = ConstantDataArray::getString(C, marker, true);
	auto* global = new GlobalVariable(M, value->getType(), true,
		GlobalValue::PrivateLinkage, value, "__xollvm_zone_link_marker");
	global->setSection(XOLLVM_ZONE_LINK_SECTION);
	global->setAlignment(Align(1));
	appendToCompilerUsed(M, {global});
}

ZoneAuthConfig ZoneAuthConfig::fromPassConfig(const PassConfig& pc) {
	ZoneAuthConfig cfg;
	cfg.enabled = pc.enabled;
	auto get = [&](const char* name, std::string& out) {
		auto it = pc.params.find(name);
		if (it != pc.params.end())
			out = it->second;
	};
	get("capability", cfg.capability);
	get("policy", cfg.policy);
	get("algorithm", cfg.algorithm);
	get("softwareId", cfg.softwareId);
	get("version", cfg.version);
	get("codeManifest", cfg.codeManifest);

	auto getUnsigned = [&](const char* name, uint32_t& out) {
		auto it = pc.params.find(name);
		if (it == pc.params.end())
			return;
		try {
			unsigned long value = std::stoul(it->second);
			if (value <= std::numeric_limits<uint32_t>::max())
				out = static_cast<uint32_t>(value);
		} catch (...) {
			out = 0;
		}
	};
	getUnsigned("heartbeatPeriod", cfg.heartbeatPeriodSec);
	getUnsigned("offlineGrace", cfg.offlineGraceSec);
	return cfg;
}

bool ZoneAuthConfig::validate() const {
	if (!enabled || capability.empty())
		return false;
	if (policy != "fail_closed")
		return false;
	if (heartbeatPeriodSec == 0 || offlineGraceSec == 0)
		return false;
	return true;
}

static bool injectGate(Function& F, StringRef Capability, StringRef CodeManifest) {
	if (F.isDeclaration() || F.empty())
		return false;
	Type* ReturnTy = F.getReturnType();
	if (!ReturnTy->isVoidTy() && !ReturnTy->isIntegerTy() &&
		!ReturnTy->isPointerTy())
		return false;
	LLVMContext& C = F.getContext();
	Module& M = *F.getParent();
	std::string CapName = (Twine("xollvm_zone_cap_") + Capability).str();
	GlobalVariable* Cap = M.getGlobalVariable(CapName);
	if (!Cap) {
		Constant* Value = ConstantDataArray::getString(C, Capability, true);
		Cap = new GlobalVariable(M, Value->getType(), true,
			GlobalValue::PrivateLinkage, Value, CapName);
	}
	BasicBlock& Original = F.getEntryBlock();
	BasicBlock* Authorized = &Original;
	BasicBlock* Gate = BasicBlock::Create(C, "zoneauth.entry", &F, Authorized);
	BasicBlock* Denied = BasicBlock::Create(C, "zoneauth.denied", &F);
	IRBuilder<> Builder(Gate);
	FunctionCallee Require = M.getOrInsertFunction(
		"xollvm_zone_require", Type::getInt32Ty(C),
		PointerType::getUnqual(Type::getInt8Ty(C)));
	Value* CapPtr = Builder.CreateBitCast(Cap, PointerType::getUnqual(Type::getInt8Ty(C)));
	FunctionCallee Begin = M.getOrInsertFunction(
		"xollvm_zone_capability_begin", Type::getInt32Ty(C),
		PointerType::getUnqual(Type::getInt8Ty(C)),
		PointerType::getUnqual(Type::getInt8Ty(C)));
	Value* Payload = ConstantPointerNull::get(
		PointerType::getUnqual(Type::getInt8Ty(C)));
	if (F.arg_size() == 1 && F.getArg(0)->getType()->isIntegerTy()) {
		AllocaInst* PayloadBuffer = Builder.CreateAlloca(
			ArrayType::get(Type::getInt8Ty(C), 32), nullptr, "zoneauth.payload");
		Value* PayloadPtr = Builder.CreateBitCast(PayloadBuffer,
			PointerType::getUnqual(Type::getInt8Ty(C)));
		FunctionCallee Format = M.getOrInsertFunction("snprintf",
			FunctionType::get(Type::getInt32Ty(C),
				{PointerType::getUnqual(Type::getInt8Ty(C)), Type::getInt64Ty(C),
				 PointerType::getUnqual(Type::getInt8Ty(C)),
				 Type::getInt64Ty(C)}, true));
		Constant* FormatString = ConstantDataArray::getString(C, "%lld", true);
		auto* FormatGlobal = new GlobalVariable(M, FormatString->getType(), true,
			GlobalValue::PrivateLinkage, FormatString, "xollvm.zone.payload.format");
		Value* FormatPtr = Builder.CreateBitCast(FormatGlobal,
			PointerType::getUnqual(Type::getInt8Ty(C)));
		Value* Argument = F.getArg(0);
		if (Argument->getType()->getIntegerBitWidth() < 64)
			Argument = Builder.CreateSExt(Argument, Type::getInt64Ty(C));
		Builder.CreateCall(Format, {PayloadPtr, ConstantInt::get(Type::getInt64Ty(C), 32),
			FormatPtr, Argument});
		Payload = PayloadPtr;
	}
	else {
		Constant* Unsupported = ConstantDataArray::getString(C, "unsupported-payload", true);
		auto* UnsupportedGlobal = new GlobalVariable(M, Unsupported->getType(), true,
			GlobalValue::PrivateLinkage, Unsupported, "xollvm.zone.payload.unsupported");
		Payload = Builder.CreateBitCast(UnsupportedGlobal,
			PointerType::getUnqual(Type::getInt8Ty(C)));
	}
	Value* BeginResult = Builder.CreateCall(Begin, {CapPtr, Payload},
		"zoneauth.capability");
	Value* Result = Builder.CreateCall(Require, {CapPtr}, "zoneauth.ok");
	FunctionCallee Seed = M.getOrInsertFunction(
		"xollvm_zone_capability_seed", Type::getInt32Ty(C),
		PointerType::getUnqual(Type::getInt8Ty(C)),
		PointerType::getUnqual(Type::getInt8Ty(C)),
		PointerType::getUnqual(Type::getInt8Ty(C)),
		Type::getInt32Ty(C));
	AllocaInst* SeedBuffer = Builder.CreateAlloca(
		ArrayType::get(Type::getInt8Ty(C), 65), nullptr, "zoneauth.seed");
	Value* SeedPtr = Builder.CreateBitCast(SeedBuffer,
		PointerType::getUnqual(Type::getInt8Ty(C)));
	Constant* Manifest = ConstantDataArray::getString(C, CodeManifest, true);
	auto* ManifestGlobal = new GlobalVariable(M, Manifest->getType(), true,
		GlobalValue::PrivateLinkage, Manifest, "xollvm.zone.manifest");
	Value* ManifestPtr = Builder.CreateBitCast(ManifestGlobal,
		PointerType::getUnqual(Type::getInt8Ty(C)));
	Value* SeedResult = Builder.CreateCall(Seed, {CapPtr, ManifestPtr, SeedPtr,
		ConstantInt::get(Type::getInt32Ty(C), 65)});
	Value* RequireAllowed = Builder.CreateICmpNE(Result,
		ConstantInt::get(Type::getInt32Ty(C), 0));
	Value* SeedAllowed = Builder.CreateICmpNE(SeedResult,
		ConstantInt::get(Type::getInt32Ty(C), 0));
	Value* BeginAllowed = Builder.CreateICmpNE(BeginResult,
		ConstantInt::get(Type::getInt32Ty(C), 0));
	Value* Allowed = Builder.CreateAnd(RequireAllowed,
		Builder.CreateAnd(BeginAllowed, SeedAllowed));
	Builder.CreateCondBr(Allowed, Authorized, Denied);
	IRBuilder<> Reject(Denied);
	if (ReturnTy->isVoidTy())
		Reject.CreateRetVoid();
	else if (ReturnTy->isPointerTy())
		Reject.CreateRet(ConstantPointerNull::get(cast<PointerType>(ReturnTy)));
	else
		Reject.CreateRet(ConstantInt::get(ReturnTy, 0));
	return true;
}

static void injectStartup(Function& F) {
	Module& M = *F.getParent();
	LLVMContext& C = M.getContext();
	FunctionType* InitTy = FunctionType::get(Type::getInt32Ty(C),
		{PointerType::getUnqual(Type::getInt8Ty(C)),
		 PointerType::getUnqual(Type::getInt8Ty(C)),
		 PointerType::getUnqual(Type::getInt8Ty(C)),
		 PointerType::getUnqual(Type::getInt8Ty(C)),
		 PointerType::getUnqual(Type::getInt8Ty(C)),
		 PointerType::getUnqual(Type::getInt8Ty(C)),
		 Type::getInt32Ty(C), Type::getInt32Ty(C)}, false);
	FunctionCallee Init = M.getOrInsertFunction("xollvm_zone_initialize", InitTy);
	FunctionCallee SetShutdownMode = M.getOrInsertFunction(
		"xollvm_zone_set_shutdown_mode", Type::getVoidTy(C),
		Type::getInt32Ty(C));
	FunctionType* LoginTy = FunctionType::get(Type::getInt32Ty(C),
		{PointerType::getUnqual(Type::getInt8Ty(C))}, false);
	FunctionCallee Login = M.getOrInsertFunction("xollvm_zone_login_card", LoginTy);
	FunctionCallee FirstHeartbeat = M.getOrInsertFunction(
		"xollvm_zone_first_heartbeat", FunctionType::get(Type::getInt32Ty(C), false));
	IRBuilder<> B(&*F.getEntryBlock().getFirstInsertionPt());
	B.CreateCall(SetShutdownMode, {ConstantInt::get(Type::getInt32Ty(C),
		ObfZoneShutdownMode == "auto" ? 1 : 0)});
	B.CreateCall(SetShutdownMode, {ConstantInt::get(Type::getInt32Ty(C),
		ObfZoneShutdownMode == "auto" ? 1 : 0)});
	auto Str = [&](StringRef Text, StringRef Name) -> llvm::Value* {
		Constant* S = ConstantDataArray::getString(C, Text, true);
		GlobalVariable* G = new GlobalVariable(M, S->getType(), true,
			GlobalValue::PrivateLinkage, S, Name);
		return B.CreateBitCast(G, PointerType::getUnqual(Type::getInt8Ty(C)));
	};
	B.CreateCall(Init, {Str(ObfZoneSoftwareId, "xollvm.zone.software"),
		Str(ObfZoneVersion, "xollvm.zone.version"),
		Str(ObfZoneEncryptKey, "xollvm.zone.key"),
		Str(ObfZoneEncryptIv, "xollvm.zone.iv"),
		Str(ObfZoneAlgorithm, "xollvm.zone.algorithm"),
		Str(ObfZoneCapabilityKeyId, "xollvm.zone.capability.key_id"),
		ConstantInt::get(Type::getInt32Ty(C), ObfZoneHeartbeatPeriod),
		ConstantInt::get(Type::getInt32Ty(C), ObfZoneOfflineGrace)});
	Constant* NullCard = ConstantPointerNull::get(
		PointerType::getUnqual(Type::getInt8Ty(C)));
	Value* LoginResult = B.CreateCall(Login, {NullCard}, "zone.login.result");
	Value* HeartbeatResult = B.CreateCall(FirstHeartbeat, {}, "zone.heartbeat.result");
	Value* LoginFailed = B.CreateICmpEQ(LoginResult,
		ConstantInt::get(Type::getInt32Ty(C), 0));
	Value* HeartbeatFailed = B.CreateICmpEQ(HeartbeatResult,
		ConstantInt::get(Type::getInt32Ty(C), 0));
	Value* StartupFailed = B.CreateOr(LoginFailed, HeartbeatFailed);
	BasicBlock* StartupBlock = B.GetInsertBlock();
	BasicBlock* ContinueBlock = StartupBlock->splitBasicBlock(B.GetInsertPoint(),
		"zone.startup.continue");
	StartupBlock->getTerminator()->eraseFromParent();
	BasicBlock* FailureBlock = BasicBlock::Create(C, "zone.startup.failure", &F,
		ContinueBlock);
	IRBuilder<> EntryBuilder(StartupBlock);
	EntryBuilder.CreateCondBr(StartupFailed, FailureBlock, ContinueBlock);
	IRBuilder<> FailureBuilder(FailureBlock);
	FunctionType* SyscallTy = FunctionType::get(Type::getVoidTy(C), false);
	InlineAsm* Terminate = InlineAsm::get(SyscallTy,
		"mov x8, #94\nmov x0, #1\nsvc #0", "~{x0},~{x8},~{memory}", true);
	FailureBuilder.CreateCall(Terminate);
	FailureBuilder.CreateUnreachable();
}

PreservedAnalyses ZoneAuthModulePass::run(Module& M, ModuleAnalysisManager& MAM) {
	if (!ObfZoneEnable)
		return PreservedAnalyses::all();
	bool Requested = false;
	for (Function& F : M) {
		ObfuscationConfig Config = AnnotationParser::parseAnnotations(&F);
		auto Pass = Config.getPassConfig("zoneauth");
		if (!Pass)
			continue;
		ZoneAuthConfig Z = ZoneAuthConfig::fromPassConfig(*Pass);
		if (!Z.validate())
			continue;
		Requested = true;
	}
	if (!Requested)
		return PreservedAnalyses::all();
	if (ObfZoneSoftwareId.empty() || ObfZoneVersion.empty() ||
		ObfZoneEncryptKey.empty() || ObfZoneEncryptIv.empty() ||
		ObfZoneAlgorithm.empty())
		return PreservedAnalyses::all();
	if (ObfZoneLinkMode != XOLLVM_ZONE_LINK_MODE_BUNDLED &&
		ObfZoneLinkMode != XOLLVM_ZONE_LINK_MODE_EXTERNAL)
		return PreservedAnalyses::all();
	if (ObfZoneShutdownMode != "auto" && ObfZoneShutdownMode != "manual")
		return PreservedAnalyses::all();
	if (!ObfZoneCapabilityOperation.empty() &&
		(ObfZoneCapabilityPublicKey.empty() || ObfZoneCapabilityBuildId.empty() ||
		 ObfZoneCapabilityCodeManifest.empty()))
		return PreservedAnalyses::all();
	if (ObfZoneShutdownMode != "auto" && ObfZoneShutdownMode != "manual")
		return PreservedAnalyses::all();
	for (Function& F : M)
		if (F.getName() == "main")
			injectStartup(F);
	bool Changed = false;
	for (Function& F : M) {
		ObfuscationConfig Config = AnnotationParser::parseAnnotations(&F);
		auto Pass = Config.getPassConfig("zoneauth");
		if (!Pass)
			continue;
		ZoneAuthConfig Z = ZoneAuthConfig::fromPassConfig(*Pass);
		if (Z.validate())
			Changed |= injectGate(F, Z.capability, Z.codeManifest);
	}
	if (Changed)
		emitZoneLinkMarker(M);
	return Changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
}
