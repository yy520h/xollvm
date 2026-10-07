//===-- xollvm-elf-hardener.cpp - final ELF cave auditor ----------*- C++ -*-===//
//
// `audit` classifies every zero run >= threshold inside each file-backed
// PT_LOAD and fails when a non-allowlisted executable (PF_X) run is found.
//
// Executability is decided ONLY by PT_LOAD.p_flags & PF_X; sections are used
// for ownership reporting and allowlisting, never for the policy decision.
//
// Exit codes: 0 = valid, 2 = malformed/unsupported ELF, 3 = policy violation.
//
//===----------------------------------------------------------------------===//

#include "llvm/BinaryFormat/ELF.h"
#include "llvm/Object/ELFObjectFile.h"
#include "llvm/Object/ObjectFile.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Endian.h"
#include "llvm/Support/Error.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/SHA256.h"
#include "llvm/Support/raw_ostream.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

using namespace llvm;
using namespace llvm::object;

namespace {

	enum ExitCode { Ok = 0, Malformed = 2, PolicyViolation = 3 };

	// Manifest layout (must match ElfIntegrity.h).
	constexpr uint64_t kManifestSize = 184;
	constexpr uint64_t kManifestRangeCountOff = 12;
	constexpr uint64_t kManifestVAOff = 16;
	constexpr uint64_t kManifestRangesOff = 24;
	constexpr uint64_t kManifestDigestOff = 152;
	constexpr unsigned kMaxRanges = 8;

	cl::opt<std::string> Command(cl::Positional,
		cl::desc("<audit|seal|verify>"), cl::Required);
	cl::opt<std::string> Input("input", cl::desc("ELF input path"), cl::Required);
	cl::opt<std::string> Output("output", cl::desc("sealed ELF output path"),
		cl::init(""));
	cl::opt<uint64_t> ZeroThreshold("zero-threshold",
		cl::desc("minimum zero-run size to report (inclusive)"), cl::init(512));
	cl::list<std::string> AllowSections("allow-section",
		cl::desc("exact section name whose zero runs are allowed"));

	struct SectionRange {
		std::string Name;
		uint64_t Offset = 0;
		uint64_t Size = 0;
	};

	struct ZeroRun {
		uint64_t Offset = 0;
		uint64_t Size = 0;
	};

	std::string permissions(uint32_t Flags) {
		std::string P = "---";
		if (Flags & ELF::PF_R) P[0] = 'r';
		if (Flags & ELF::PF_W) P[1] = 'w';
		if (Flags & ELF::PF_X) P[2] = 'x';
		return P;
	}

	// Return the section owning [Offset, Offset+Size) if a single section fully
	// covers it; otherwise an empty name.
	std::string owningSection(const std::vector<SectionRange>& Sections,
		const ZeroRun& Run) {
		for (const SectionRange& S : Sections) {
			if (S.Size == 0) continue;
			if (Run.Offset >= S.Offset && Run.Offset + Run.Size <= S.Offset + S.Size)
				return S.Name;
		}
		return {};
	}

	// A run is allowlisted only when every covered byte belongs to one section
	// whose exact name is in the allow list.
	bool allowlisted(const std::vector<SectionRange>& Sections, const ZeroRun& Run,
		const std::vector<std::string>& Allowed) {
		std::string Owner = owningSection(Sections, Run);
		if (Owner.empty()) return false;
		return std::find(Allowed.begin(), Allowed.end(), Owner) != Allowed.end();
	}

	std::vector<ZeroRun> findZeroRuns(ArrayRef<uint8_t> Data, uint64_t Minimum) {
		std::vector<ZeroRun> Runs;
		uint64_t Start = 0;
		bool In = false;
		for (uint64_t I = 0, E = Data.size(); I != E; ++I) {
			if (Data[I] == 0) {
				if (!In) { Start = I; In = true; }
			}
			else if (In) {
				if (I - Start >= Minimum) Runs.push_back({ Start, I - Start });
				In = false;
			}
		}
		if (In && Data.size() - Start >= Minimum)
			Runs.push_back({ Start, Data.size() - Start });
		return Runs;
	}

} // namespace

int main(int argc, char** argv) {
	cl::ParseCommandLineOptions(argc, argv, "xollvm ELF hardener\n");

	if (Command != "audit" && Command != "seal" && Command != "verify") {
		errs() << "error: unknown command '" << Command
			<< "' (expected audit|seal|verify)\n";
		return Malformed;
	}

	auto BufOrErr = MemoryBuffer::getFile(Input);
	if (!BufOrErr) {
		errs() << "error: cannot read '" << Input << "': "
			<< BufOrErr.getError().message() << "\n";
		return Malformed;
	}
	MemoryBuffer& Buf = *BufOrErr.get();
	ArrayRef<uint8_t> Data(
		reinterpret_cast<const uint8_t*>(Buf.getBufferStart()), Buf.getBufferSize());

	if (Data.size() < sizeof(ELF::Elf64_Ehdr)) {
		errs() << "error: file smaller than an ELF64 header\n";
		return Malformed;
	}
	const auto* Ehdr = reinterpret_cast<const ELF::Elf64_Ehdr*>(Data.data());
	if (!(Ehdr->e_ident[ELF::EI_MAG0] == 0x7f &&
		Ehdr->e_ident[ELF::EI_MAG1] == 'E' &&
		Ehdr->e_ident[ELF::EI_MAG2] == 'L' &&
		Ehdr->e_ident[ELF::EI_MAG3] == 'F')) {
		errs() << "error: not an ELF file\n";
		return Malformed;
	}
	if (Ehdr->e_ident[ELF::EI_CLASS] != ELF::ELFCLASS64) {
		errs() << "error: only ELF64 is supported\n";
		return Malformed;
	}
	if (Ehdr->e_ident[ELF::EI_DATA] != ELF::ELFDATA2LSB) {
		errs() << "error: only little-endian ELF is supported\n";
		return Malformed;
	}
	if (Ehdr->e_machine != ELF::EM_AARCH64) {
		errs() << "error: expected AArch64 ELF (EM_AARCH64)\n";
		return Malformed;
	}

	const uint64_t PhOff = Ehdr->e_phoff;
	const uint64_t PhEnt = Ehdr->e_phentsize;
	const uint64_t PhNum = Ehdr->e_phnum;
	if (PhEnt < sizeof(ELF::Elf64_Phdr) || PhOff + PhEnt * PhNum > Data.size()) {
		errs() << "error: program header table exceeds file bounds\n";
		return Malformed;
	}

	// LLVM Object validates the file and its ELF structure; section ownership
	// is read from the raw section headers so a stripped file still audits.
	{
		auto ObjOrErr = ObjectFile::createObjectFile(Input);
		if (!ObjOrErr) {
			errs() << "error: LLVM Object rejected the input: "
				<< toString(ObjOrErr.takeError()) << "\n";
			return Malformed;
		}
	}

	std::vector<SectionRange> Sections;
	const uint64_t ShOff = Ehdr->e_shoff;
	const uint64_t ShEnt = Ehdr->e_shentsize;
	const uint64_t ShNum = Ehdr->e_shnum;
	const uint64_t ShStrNdx = Ehdr->e_shstrndx;
	const char* ShStr = nullptr;
	uint64_t ShStrSize = 0;
	if (ShOff != 0 && ShEnt >= sizeof(ELF::Elf64_Shdr) &&
		ShOff + ShEnt * ShNum <= Data.size() && ShStrNdx < ShNum) {
		const auto* StrHdr = reinterpret_cast<const ELF::Elf64_Shdr*>(
			Data.data() + ShOff + ShStrNdx * ShEnt);
		if (StrHdr->sh_offset + StrHdr->sh_size <= Data.size()) {
			ShStr = reinterpret_cast<const char*>(Data.data() + StrHdr->sh_offset);
			ShStrSize = StrHdr->sh_size;
		}
	}
	if (ShStr) {
		for (uint64_t I = 0; I != ShNum; ++I) {
			const auto* Shdr = reinterpret_cast<const ELF::Elf64_Shdr*>(
				Data.data() + ShOff + I * ShEnt);
			if (Shdr->sh_type == ELF::SHT_NULL || Shdr->sh_type == ELF::SHT_NOBITS)
				continue;
			SectionRange R;
			R.Offset = Shdr->sh_offset;
			R.Size = Shdr->sh_size;
			if (Shdr->sh_name < ShStrSize)
				R.Name = std::string(ShStr + Shdr->sh_name);
			Sections.push_back(std::move(R));
		}
	}

	// ---- seal / verify -----------------------------------------------------
	if (Command == "seal" || Command == "verify") {
		// Locate the manifest. It lives in .text.xollvm.integrity (merged into
		// .text, the executable load). Accept the legacy bare name too.
		auto isManifestName = [](const char* N) {
			return std::strcmp(N, ".text.xollvm.integrity") == 0 ||
				std::strcmp(N, ".xollvm.integrity") == 0;
		};
		uint64_t ManOff = 0, ManAddr = 0;
		bool ManFound = false;
		// (a) A dedicated section survives only if lld keeps it separate.
		for (uint64_t I = 0; I != ShNum; ++I) {
			const auto* Shdr = reinterpret_cast<const ELF::Elf64_Shdr*>(
				Data.data() + ShOff + I * ShEnt);
			if (!ShStr || Shdr->sh_name >= ShStrSize) continue;
			if (!isManifestName(ShStr + Shdr->sh_name)) continue;
			ManOff = Shdr->sh_offset;
			ManAddr = Shdr->sh_addr;
			ManFound = Shdr->sh_size >= kManifestSize;
			break;
		}
		// (b) Fallback: find the manifest symbol in .symtab/.dynsym and map its
		// vaddr back to a file offset via PT_LOAD. Robust against lld merging
		// `.text.*` sections into `.text`.
		if (!ManFound) {
			for (uint64_t I = 0; I != ShNum && !ManFound; ++I) {
				const auto* Shdr = reinterpret_cast<const ELF::Elf64_Shdr*>(
					Data.data() + ShOff + I * ShEnt);
				if (Shdr->sh_type != ELF::SHT_SYMTAB && Shdr->sh_type != ELF::SHT_DYNSYM)
					continue;
				if (Shdr->sh_entsize < sizeof(ELF::Elf64_Sym)) continue;
				const char* StrTab = nullptr;
				if (Shdr->sh_link < ShNum) {
					const auto* StrHdr = reinterpret_cast<const ELF::Elf64_Shdr*>(
						Data.data() + ShOff + Shdr->sh_link * ShEnt);
					if (StrHdr->sh_offset + StrHdr->sh_size <= Data.size())
						StrTab = reinterpret_cast<const char*>(Data.data() + StrHdr->sh_offset);
				}
				uint64_t Count = Shdr->sh_size / Shdr->sh_entsize;
				for (uint64_t K = 0; K != Count; ++K) {
					const auto* Sym = reinterpret_cast<const ELF::Elf64_Sym*>(
						Data.data() + Shdr->sh_offset + K * Shdr->sh_entsize);
					if (Sym->st_name == 0 || !StrTab) continue;
					if (std::strcmp(StrTab + Sym->st_name,
						"__xollvm_elf_integrity_manifest") != 0)
						continue;
					if (Sym->st_size < kManifestSize) continue;
					ManAddr = Sym->st_value;
					// Map vaddr -> file offset through PT_LOAD.
					for (uint64_t P = 0; P != PhNum; ++P) {
						const auto* Phdr = reinterpret_cast<const ELF::Elf64_Phdr*>(
							Data.data() + PhOff + P * PhEnt);
						if (Phdr->p_type != ELF::PT_LOAD) continue;
						if (ManAddr >= Phdr->p_vaddr &&
							ManAddr + kManifestSize <= Phdr->p_vaddr + Phdr->p_filesz) {
							ManOff = Phdr->p_offset + (ManAddr - Phdr->p_vaddr);
							ManFound = true;
							break;
						}
					}
					if (ManFound) break;
				}
			}
		}
		// (c) Fallback: scan PT_LOADs for the 8-byte magic. Survives stripping
		// (which removes the manifest symbol) and lld section merging.
		if (!ManFound) {
			static const char Magic[8] = { 'X','O','L','I','N','T','0','1' };
			for (uint64_t P = 0; P != PhNum && !ManFound; ++P) {
				const auto* Phdr = reinterpret_cast<const ELF::Elf64_Phdr*>(
					Data.data() + PhOff + P * PhEnt);
				if (Phdr->p_type != ELF::PT_LOAD || Phdr->p_filesz < kManifestSize)
					continue;
				const uint8_t* begin = Data.data() + Phdr->p_offset;
				const uint8_t* end = begin + Phdr->p_filesz - kManifestSize;
				for (const uint8_t* p = begin; p <= end; ++p) {
					if (std::memcmp(p, Magic, 8) != 0) continue;
					ManOff = (uint64_t)(p - Data.data());
					ManAddr = Phdr->p_vaddr + (ManOff - Phdr->p_offset);
					ManFound = true;
					break;
				}
			}
		}
		if (!ManFound) {
			errs() << "error: no xollvm integrity manifest found\n";
			return Malformed;
		}
		if (ManOff > Data.size() || kManifestSize > Data.size() - ManOff) {
			errs() << "error: manifest exceeds file bounds\n";
			return Malformed;
		}

		// Reject dynamic relocation targets inside any PF_X PT_LOAD.
		// Enumerate RELA/REL from section headers.
		for (uint64_t I = 0; I != ShNum; ++I) {
			const auto* Shdr = reinterpret_cast<const ELF::Elf64_Shdr*>(
				Data.data() + ShOff + I * ShEnt);
			bool IsRela = Shdr->sh_type == ELF::SHT_RELA;
			bool IsRel = Shdr->sh_type == ELF::SHT_REL;
			if (!IsRela && !IsRel) continue;
			uint64_t Ent = IsRela ? sizeof(ELF::Elf64_Rela) : sizeof(ELF::Elf64_Rel);
			if (Ent == 0) continue;
			uint64_t Count = Shdr->sh_size / Ent;
			for (uint64_t K = 0; K != Count; ++K) {
				const uint8_t* EP = Data.data() + Shdr->sh_offset + K * Ent;
				uint64_t Target;
				if (IsRela) Target = reinterpret_cast<const ELF::Elf64_Rela*>(EP)->r_offset;
				else Target = reinterpret_cast<const ELF::Elf64_Rel*>(EP)->r_offset;
				for (uint64_t P = 0; P != PhNum; ++P) {
					const auto* Phdr = reinterpret_cast<const ELF::Elf64_Phdr*>(
						Data.data() + PhOff + P * PhEnt);
					if (Phdr->p_type != ELF::PT_LOAD || !(Phdr->p_flags & ELF::PF_X))
						continue;
					if (Target >= Phdr->p_vaddr && Target < Phdr->p_vaddr + Phdr->p_filesz) {
						errs() << "error: dynamic relocation target 0x"
							<< Twine::utohexstr(Target) << " lies in executable segment "
							<< P << "\n";
						return PolicyViolation;
					}
				}
			}
		}

		// Canonical hash: the file-backed bytes of the executable PT_LOAD that
		// contains the manifest, with the manifest bytes zeroed. This matches
		// the runtime checker, which maps that same range and hashes it in
		// place. Private copy so `verify` never mutates the input.
		auto put64 = [&](std::vector<uint8_t>& V, uint64_t Off, uint64_t Val) {
			for (int J = 0; J < 8; ++J) V[Off + J] = (uint8_t)(Val >> (J * 8));
		};

		// Canonical range set = EVERY file-backed executable (PF_X) PT_LOAD,
		// in segment order, up to kMaxRanges. The runtime hashes the identical
		// set, so seal and runtime observe the same bytes. The manifest must
		// live inside one of these ranges (the runtime recovers the base from
		// &manifest - ManifestVirtualAddress).
		struct Range { uint64_t Off, Vaddr, Size; };
		std::vector<Range> Ranges;
		bool ManInRange = false;
		for (uint64_t P = 0; P != PhNum; ++P) {
			const auto* Phdr = reinterpret_cast<const ELF::Elf64_Phdr*>(
				Data.data() + PhOff + P * PhEnt);
			if (Phdr->p_type != ELF::PT_LOAD || !(Phdr->p_flags & ELF::PF_X)) continue;
			if (Phdr->p_filesz == 0) continue;
			Ranges.push_back({ Phdr->p_offset, Phdr->p_vaddr, Phdr->p_filesz });
			if (ManAddr >= Phdr->p_vaddr &&
				ManAddr + kManifestSize <= Phdr->p_vaddr + Phdr->p_filesz)
				ManInRange = true;
		}
		if (!ManInRange) {
			errs() << "error: manifest is not inside an executable PT_LOAD\n";
			return Malformed;
		}
		if (Ranges.size() > kMaxRanges) {
			errs() << "error: more executable PT_LOADs (" << Ranges.size()
				<< ") than the manifest can bind (" << kMaxRanges << ")\n";
			return Malformed;
		}

		std::vector<uint8_t> Out(Data.begin(), Data.end());

		// Hash [EHDR .. end of phdrs) then every executable range, with the
		// ENTIRE manifest window [0,184) zeroed. The comparison computed==stored
		// then detects any change to the stored digest itself (computed stays
		// the same because the window is zeroed), as well as any change to the
		// covered code/data.
		for (uint64_t J = 0; J < kManifestSize; ++J)
			Out[ManOff + J] = 0;
		SHA256 Hasher;
		uint64_t HdrEnd = PhOff + PhEnt * PhNum;
		if (HdrEnd > Data.size()) HdrEnd = Data.size();
		Hasher.update(ArrayRef<uint8_t>(Out.data(), HdrEnd));
		for (const Range& R : Ranges)
			Hasher.update(ArrayRef<uint8_t>(Out.data() + R.Off, R.Size));
		auto Hash = Hasher.final();
		ArrayRef<uint8_t> DigestBytes(Hash.data(), 32);

		if (Command == "verify") {
			const char Want[8] = { 'X','O','L','I','N','T','0','1' };
			if (std::memcmp(Data.data() + ManOff, Want, 8) != 0) {
				errs() << "error: manifest magic mismatch\n";
				return PolicyViolation;
			}
			const uint8_t* Man = Data.data() + ManOff;
			if (support::endian::read32le(Man + 8) != 1) {
				errs() << "error: unsupported manifest version\n";
				return PolicyViolation;
			}
			// manifest 不参与自身哈希，必须独立匹配从 ELF 推导的规范元数据。
			if (support::endian::read32le(Man + kManifestRangeCountOff) != Ranges.size() ||
				support::endian::read64le(Man + kManifestVAOff) != ManAddr) {
				errs() << "error: manifest range count or virtual address mismatch\n";
				return PolicyViolation;
			}
			for (unsigned I = 0; I < kMaxRanges; ++I) {
				uint64_t VA = I < Ranges.size() ? Ranges[I].Vaddr : 0;
				uint64_t Size = I < Ranges.size() ? Ranges[I].Size : 0;
				if (support::endian::read64le(Man + kManifestRangesOff + I * 16) != VA ||
					support::endian::read64le(Man + kManifestRangesOff + I * 16 + 8) != Size) {
					errs() << "error: manifest executable range mismatch at slot " << I << "\n";
					return PolicyViolation;
				}
			}
			ArrayRef<uint8_t> Stored(Data.data() + ManOff + kManifestDigestOff, 32);
			if (DigestBytes != Stored) {
				errs() << "error: integrity digest mismatch\n";
				return PolicyViolation;
			}
			errs() << "verify: digest matches\n";
			return Ok;
		}

		// seal: after hashing the zeroed window, stamp the runtime metadata and
		// digest. These live inside the hashed window, so writing them does not
		// change the digest.
		if (Output.empty()) {
			errs() << "error: seal requires --output\n";
			return Malformed;
		}
		// Write manifest metadata (VA + range table) and digest.
		uint8_t* man = Out.data() + ManOff;
		auto st64 = [&](uint64_t O, uint64_t V) {
			for (int J = 0; J < 8; ++J) man[O + J] = (uint8_t)(V >> (J * 8));
		};
		st64(kManifestVAOff, ManAddr);
		uint32_t RC = (uint32_t)Ranges.size();
		for (int J = 0; J < 4; ++J) man[kManifestRangeCountOff + J] = (uint8_t)(RC >> (J * 8));
		for (uint32_t I = 0; I < RC; ++I) {
			st64(kManifestRangesOff + (uint64_t)I * 16 + 0, Ranges[I].Vaddr);
			st64(kManifestRangesOff + (uint64_t)I * 16 + 8, Ranges[I].Size);
		}
		for (uint64_t J = 0; J < 32; ++J) man[kManifestDigestOff + J] = DigestBytes[J];
		// Magic "XOLINT01" + version 1, written last.
		const char Magic[8] = { 'X','O','L','I','N','T','0','1' };
		for (int J = 0; J < 8; ++J) man[J] = (uint8_t)Magic[J];
		for (int J = 0; J < 4; ++J) man[8 + J] = (uint8_t)(1u >> (J * 8));


		std::error_code EC;
		raw_fd_ostream OS(Output, EC, sys::fs::OF_None);
		if (EC) {
			errs() << "error: cannot write '" << Output << "': " << EC.message() << "\n";
			return Malformed;
		}
		OS.write(reinterpret_cast<const char*>(Out.data()), Out.size());
		errs() << "seal: wrote " << Output << " (" << RC << " executable range(s))\n";
		return Ok;
	}

	std::vector<std::string> Allowed(AllowSections.begin(), AllowSections.end());
	bool Violation = false;
	unsigned SegmentIndex = 0;
	uint64_t Reported = 0;

	for (uint64_t I = 0; I != PhNum; ++I) {
		const auto* Phdr = reinterpret_cast<const ELF::Elf64_Phdr*>(
			Data.data() + PhOff + I * PhEnt);
		if (Phdr->p_type != ELF::PT_LOAD) continue;
		if (Phdr->p_filesz == 0) { ++SegmentIndex; continue; }
		if (Phdr->p_offset + Phdr->p_filesz > Data.size()) {
			errs() << "error: segment " << SegmentIndex
				<< " file range exceeds file bounds\n";
			return Malformed;
		}
		const bool Exec = (Phdr->p_flags & ELF::PF_X) != 0;
		ArrayRef<uint8_t> Seg(Data.data() + Phdr->p_offset, Phdr->p_filesz);
		for (const ZeroRun& Run : findZeroRuns(Seg, ZeroThreshold)) {
			ZeroRun Abs{ Phdr->p_offset + Run.Offset, Run.Size };
			std::string Owner = owningSection(Sections, Abs);
			errs() << "zero-run: segment " << SegmentIndex
				<< " file-offset 0x" << Twine::utohexstr(Abs.Offset)
				<< " vaddr 0x" << Twine::utohexstr(Phdr->p_vaddr + Run.Offset)
				<< " size " << Abs.Size
				<< " permissions " << permissions(Phdr->p_flags)
				<< " section " << (Owner.empty() ? std::string("<none>") : Owner)
				<< "\n";
			++Reported;
			if (Exec && !allowlisted(Sections, Abs, Allowed)) {
				Violation = true;
			}
		}
		++SegmentIndex;
	}

	if (Violation) {
		errs() << "error: non-allowlisted executable zero run >= "
			<< ZeroThreshold << " bytes\n";
		return PolicyViolation;
	}
	if (Reported)
		errs() << "audit: " << Reported
			<< " zero-run(s) reported; no executable policy violation\n";
	return Ok;
}
