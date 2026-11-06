#include "llvm/Transforms/Obfuscator/ObfuscationOptions.h"
#include "llvm/ADT/SmallString.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/MDBuilder.h"
#include "llvm/IR/Metadata.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/Path.h"
#include <cctype>
#include <cstdlib>

using namespace llvm;

cl::opt<uint64_t> llvm::ObfSeed("obf-seed",
	cl::desc("Base seed for obfuscation (enables reproducible builds)."),
	cl::init(0));

cl::opt<bool> llvm::ObfDeterministic("obf-deterministic",
	cl::desc("If true and -obf-seed is not provided"),
	cl::init(false));

cl::opt<bool> llvm::ObfVerbose("obf-verbose",
	cl::desc("Verbose obfuscator logging."),
	cl::init(false));

cl::opt<bool> llvm::ObfSeedManifest(
	"obf-seed-manifest",
	llvm::cl::desc("Print per-function/per-pass seed manifest (debug)"),
	llvm::cl::init(false));

cl::opt<bool> llvm::ObfSeedManifestMD(
	"obf-seed-manifest-md",
	llvm::cl::desc("Also emit seed manifest into IR metadata"),
	llvm::cl::init(false));

cl::opt<bool> llvm::ObfVerify(
	"obf-verify",
	llvm::cl::desc("Verify IR after each obfuscation pass (fatal on failure)."),
	llvm::cl::init(false));

cl::opt<unsigned> llvm::ObfMaxFunctionInsts(
	"obf-max-function-insts",
	cl::desc("Skip obfuscation for functions with more than N instructions (0=off)"),
	cl::init(0));

cl::opt<unsigned> llvm::ObfMaxFunctionBlocks(
	"obf-max-function-blocks",
	cl::desc("Skip obfuscation for functions with more than N basic blocks (0=off)"),
	cl::init(0));

cl::opt<unsigned> llvm::ObfMaxLoopDepth(
	"obf-max-loop-depth",
	cl::desc("Skip obfuscation for functions with loop nesting deeper than N (0=off)"),
	cl::init(0));

cl::opt<unsigned> llvm::ObfIRBudgetMultiplier(
	"obf-ir-budget-multiplier",
	cl::desc("IR instruction budget: final_insts <= initial_insts * N (0=unlimited)"),
	cl::init(50));

cl::opt<unsigned> llvm::ObfIRBudgetMax(
	"obf-ir-budget-max",
	cl::desc("Absolute IR instruction ceiling per function (0=no hard cap)"),
	cl::init(0));

cl::opt<bool> llvm::ObfShieldAuto(
	"obf-shield-auto",
	cl::desc("Auto-enable AntiOptimizationShield for any function with "
	         "obfuscation passes but no explicit `shield(...)` token. "
	         "Off by default — explicit shield annotations are still honored."),
	cl::init(false));

cl::opt<bool> llvm::ObfNoSkips(
	"obf-no-skips",
	cl::desc("Escalate any pass skip (eligibility bail, budget exhaustion, "
	         "function cap) to a fatal error. For test assertions; off by "
	         "default in production."),
	cl::init(false));

cl::opt<bool> llvm::ObfVMAllowAntiDebugBypass(
	"obf-vm-allow-antidebug-bypass",
	cl::desc("Emit the __OBF_DISABLE_ANTIDEBUG env-var escape hatch in the "
	         "VM anti-debug gate. For CI/testing only; OFF by default so "
	         "shipped binaries carry no kill-switch string."),
	cl::init(false));

cl::opt<std::string> llvm::ObfReportDir(
	"obf-report-dir",
	cl::desc("Directory to emit obfuscation report artifacts (CFG DOT + default JSON). Empty=off"),
	cl::init(""));

cl::opt<std::string> llvm::ObfMaterialExportDir(
	"obf-material-export-dir",
	cl::desc("Optional directory for cloud material export (auto-derived from module if unset)"),
	cl::init(""));

void llvm::validateMaterialExportDirectory() {
	// 当为空时允许 Pass 层自动推导，只验证显式提供的路径。
	if (ObfMaterialExportDir.empty())
		return;
	if (!sys::fs::is_directory(ObfMaterialExportDir))
		report_fatal_error("vm: material export directory does not exist or is not a directory", false);
	// 解析 dir/. 同时检查目录可遍历；LLVM Execute 专门拒绝目录。
	SmallString<256> Searchable(ObfMaterialExportDir.getValue());
	sys::path::append(Searchable, ".");
	if (sys::fs::access(Searchable, sys::fs::AccessMode::Write))
		report_fatal_error("vm: material export directory is not writable/searchable", false);
}

std::string llvm::resolveCloudMaterialExportDir(const llvm::Module& M) {
	// 1. 显式命令行参数
	if (!ObfMaterialExportDir.empty())
		return ObfMaterialExportDir.getValue();

	// 2. 环境变量（测试覆盖）
	if (const char* env = std::getenv("XOLLVM_CLOUD_EXPORT_DIR"))
		if (*env) return env;

	// 3. Module flag（构建系统注入）
	if (auto* MD = M.getModuleFlag("xollvm.material_export_dir"))
		if (auto* MDS = dyn_cast<MDString>(MD))
			return MDS->getString().str();

	// 4. 从 Module 标识自动推导
	StringRef moduleID = M.getModuleIdentifier();
	if (moduleID.empty())
		return "";

	SmallString<256> path(moduleID);
	StringRef filename = sys::path::filename(path);
	StringRef stem = sys::path::stem(filename);

	if (stem.empty())
		return "";

	SmallString<256> dir(sys::path::parent_path(path));
	if (dir.empty())
		dir = ".";

	SmallString<256> materialDir(dir);
	SmallString<128> materialName(stem);
	materialName += ".material";
	sys::path::append(materialDir, materialName);

	return materialDir.str().str();
}

cl::opt<std::string> llvm::ObfReportJson(
	"obf-report-json",
	cl::desc("Write JSON obfuscation map to this path ('-' for stdout). Empty=off"),
	cl::init(""));

cl::opt<std::string> llvm::ObfGraphDir(
	"obf-graph-dir",
	cl::desc("Directory to emit the program call graph and final per-function CFG SVGs. Empty=off"),
	cl::init(""));

cl::opt<std::string> llvm::ObfGraphMode(
	"obf-graph-mode",
	cl::desc("Graph report mode: obfuscated or direct."),
	cl::value_desc("mode"),
	cl::init("obfuscated"));

cl::opt<std::string> llvm::ObfPipelineOrdering(
	"obf-pipeline-ordering",
	cl::desc("Explicit comma-separated pipeline order "
	         "(e.g. \"mba,split,bcf,flattening\"). "
	         "Listed passes go first in this order; "
	         "remaining enabled passes are appended in topo order. "
	         "Unknown names are fatal. Empty=off."),
	cl::init(""));

cl::opt<bool> llvm::ObfPipelineOrderingAnn(
	"obf-pipeline-ordering-ann",
	cl::desc("Use the per-function annotation order verbatim instead of "
	         "topological sort. Ignored when -obf-pipeline-ordering is set."),
	cl::init(false));

std::vector<std::string> llvm::ParsePipelineOrdering(llvm::StringRef raw) {
	std::vector<std::string> out;
	llvm::SmallVector<llvm::StringRef, 16> parts;
	raw.split(parts, ',', /*MaxSplit=*/-1, /*KeepEmpty=*/false);
	out.reserve(parts.size());
	for (auto &p : parts) {
		llvm::StringRef trimmed = p.trim();
		if (trimmed.empty())
			continue;
		std::string s;
		s.reserve(trimmed.size());
		for (char c : trimmed)
			s.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
		out.push_back(std::move(s));
	}
	return out;
}

cl::opt<std::string> llvm::ADecGadgetsFile(
	"adec-gadgets-file",
	cl::desc("Comma-separated list of JSON gadget files merged into the "
	         "global gadget pool. Empty=off (built-ins only)."),
	cl::init(""));

cl::opt<bool> llvm::ADecDisableBuiltinGadgets(
	"adec-disable-builtin-gadgets",
	cl::desc("Suppress the compile-time built-in gadget tables; rely "
	         "entirely on user-supplied files / annotations."),
	cl::init(false));

cl::opt<std::string> llvm::ADecClobbersX86(
	"adec-clobbers-x86",
	cl::desc("Override default inline-asm clobber list for x86_64. "
	         "Comma-separated short register names."),
	cl::init(""));

cl::opt<std::string> llvm::ADecClobbersAArch64(
	"adec-clobbers-aarch64",
	cl::desc("Override default inline-asm clobber list for aarch64. "
	         "Comma-separated short register names."),
	cl::init(""));

cl::opt<std::string> llvm::ADecTechniques(
	"adec-techniques",
	cl::desc("Whitelist of anti-decompiler technique names, comma-separated "
	         "(asmGadgets,indirectBr,deadDecoy,stackPollution,"
	         "callTrampoline,aliasConfusion). Empty=all."),
	cl::init(""));

cl::opt<std::string> llvm::ADecCategories(
	"adec-categories",
	cl::desc("Gadget category filter, comma-separated "
	         "(anti-disasm,anti-trace,desync,...). Empty=all."),
	cl::init(""));

cl::opt<std::string> llvm::ADecBudgetSplit(
	"adec-budget-split",
	cl::desc("Per-technique budget percent split, e.g. "
	         "\"asm:30,ibr:20,decoy:20,call:15,alias:15,"
	         "loop:5,rdtsc:5,clndr:10\". "
	         "Empty=defaults."),
	cl::init(""));

cl::opt<std::string> llvm::ADecPrefix(
	"adec-prefix",
	cl::desc("IR-name prefix for anti-decompiler artifacts. Default 'adec'. "
	         "Override with a per-build random value to defeat signature "
	         "scans against canonical adec.* names."),
	cl::init("adec"));

cl::opt<bool> llvm::ADecRandomizeConsts(
	"adec-randomize-consts",
	cl::desc("Replace hard-coded decoy payload constants with RNG values."),
	cl::init(false));

std::vector<std::string> llvm::ParseAdecCsv(llvm::StringRef raw) {
	std::vector<std::string> out;
	llvm::SmallVector<llvm::StringRef, 16> parts;
	raw.split(parts, ',', /*MaxSplit=*/-1, /*KeepEmpty=*/false);
	out.reserve(parts.size());
	for (auto &p : parts) {
		llvm::StringRef trimmed = p.trim();
		if (trimmed.empty())
			continue;
		out.push_back(trimmed.str());
	}
	return out;
}

std::string llvm::FormatClobberList(llvm::StringRef rawCsv) {
	std::string out;
	bool first = true;
	llvm::SmallVector<llvm::StringRef, 16> parts;
	rawCsv.split(parts, ',', /*MaxSplit=*/-1, /*KeepEmpty=*/false);
	for (auto &p : parts) {
		llvm::StringRef trimmed = p.trim();
		if (trimmed.empty())
			continue;
		if (!first)
			out.push_back(',');
		first = false;
		out += "~{";
		out += trimmed.str();
		out.push_back('}');
	}
	return out;
}
