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
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/raw_ostream.h"

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

using namespace llvm;
using namespace llvm::object;

namespace {

	enum ExitCode { Ok = 0, Malformed = 2, PolicyViolation = 3 };

	cl::opt<std::string> Command(cl::Positional, cl::desc("<audit>"), cl::Required);
	cl::opt<std::string> Input("input", cl::desc("ELF input path"), cl::Required);
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

	if (Command != "audit") {
		errs() << "error: unknown command '" << Command << "' (expected audit)\n";
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
