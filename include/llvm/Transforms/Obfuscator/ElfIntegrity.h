#pragma once

#include "llvm/IR/PassManager.h"

#include <cstdint>
#include <string>

namespace llvm {

	class Function;
	class Module;

	// On-disk / in-memory manifest schema. Packed and endian-stable; the
	// post-link tool patches bytes at fixed offsets, so the layout must not
	// drift between the compiler and the tool (asserted via static_assert in
	// the implementation).
	//
	//   [0..7]    magic "XOLINT01"
	//   [8..11]   version (=1)
	//   [12..15]  range count
	//   [16..23]  manifest virtual address (module base recovery)
	//   [24..151] up to 8 {uint64 vaddr, uint64 file_size} ranges
	//   [152..183] SHA-256 digest
	struct ElfIntegrityRange {
		uint64_t VirtualAddress;
		uint64_t FileSize;
	};

	struct ElfIntegrityManifestV1 {
		uint8_t Magic[8];
		uint32_t Version;
		uint32_t RangeCount;
		uint64_t ManifestVirtualAddress;
		ElfIntegrityRange Ranges[8];
		uint8_t Digest[32];
	};

	static_assert(sizeof(ElfIntegrityRange) == 16, "range layout drift");
	static_assert(sizeof(ElfIntegrityManifestV1) == 184, "manifest layout drift");

	// Symbol / section constants shared with the post-link tool.
	// The section name is prefixed with .text so lld routes it into the
	// executable PT_LOAD (a bare custom section lands in an RW load, where the
	// runtime cannot hash it as part of the code image).
	static constexpr const char* kIntegritySectionName = ".text.xollvm.integrity";
	static constexpr const char* kIntegrityReportSectionName = ".xollvm.integrity";
	static constexpr const char* kIntegrityManifestSymbol = "__xollvm_elf_integrity_manifest";
	static constexpr const char* kIntegrityStateSymbol = "__obf_elf_integrity_state";
	static constexpr const char* kIntegritySha256Symbol = "__xollvm_integrity_sha256";

	// Emits the manifest placeholder + runtime integrity state for any module
	// that contains at least one strict sensitive region. No-op otherwise.
	class ElfIntegrityPass : public PassInfoMixin<ElfIntegrityPass> {
	public:
		PreservedAnalyses run(Module& M, ModuleAnalysisManager& MAM);
		static bool isRequired() { return true; }
	};

} // namespace llvm
