#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/BinaryFormat/ELF.h"
#include "llvm/Support/Endian.h"
#include "llvm/Support/Error.h"
#include "llvm/Support/LEB128.h"
#include "llvm/Support/SHA256.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <map>
#include <set>
#include <string>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <vector>

using namespace llvm;
using namespace llvm::support::endian;

namespace llvm {
Expected<unsigned> finalizeMaterialManifest(StringRef InputPath,
	StringRef ManifestPath, StringRef OutputPath);
}

namespace {

constexpr uint64_t MaxManifestSize = 4 * 1024 * 1024;
constexpr uint64_t RecordSize = 120;
constexpr unsigned MaxRegions = 4096;
constexpr StringLiteral MaterialSectionName = ".rodata.xovm.material";

Error bad(const char* Code) {
	return createStringError(inconvertibleErrorCode(), "materials: %s", Code);
}

struct FileContents {
	std::vector<uint8_t> Bytes;
	struct stat Status {};
};

bool sameIdentity(const struct stat& A, const struct stat& B) {
	return A.st_dev == B.st_dev && A.st_ino == B.st_ino && A.st_size == B.st_size &&
		A.st_mode == B.st_mode && A.st_uid == B.st_uid && A.st_nlink == B.st_nlink &&
		A.st_mtim.tv_sec == B.st_mtim.tv_sec && A.st_mtim.tv_nsec == B.st_mtim.tv_nsec &&
		A.st_ctim.tv_sec == B.st_ctim.tv_sec && A.st_ctim.tv_nsec == B.st_ctim.tv_nsec;
}

Expected<FileContents> readFile(StringRef Path, uint64_t Maximum, const char* Code) {
	std::string Name = Path.str();
	int FD = ::open(Name.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (FD < 0) return bad(Code);
	FileContents Result;
	struct stat After {};
	bool Valid = ::fstat(FD, &Result.Status) == 0 && S_ISREG(Result.Status.st_mode) &&
		Result.Status.st_size >= 0 &&
		static_cast<uint64_t>(Result.Status.st_size) <= Maximum &&
		static_cast<uint64_t>(Result.Status.st_size) <= SIZE_MAX;
	if (Valid) {
		Result.Bytes.resize(static_cast<size_t>(Result.Status.st_size));
		size_t Offset = 0;
		while (Offset < Result.Bytes.size()) {
			ssize_t Count = ::pread(FD, Result.Bytes.data() + Offset,
				Result.Bytes.size() - Offset, static_cast<off_t>(Offset));
			if (Count < 0 && errno == EINTR) continue;
			if (Count <= 0) { Valid = false; break; }
			Offset += static_cast<size_t>(Count);
		}
		Valid = Valid && ::fstat(FD, &After) == 0 && sameIdentity(Result.Status, After);
	}
	if (::close(FD) != 0) Valid = false;
	if (!Valid) return bad(Code);
	return Result;
}

bool isHash(StringRef Value) {
	return Value.size() == 64 && llvm::all_of(Value, [](char C) {
		return (C >= '0' && C <= '9') || (C >= 'a' && C <= 'f');
	});
}

bool isId(StringRef Value) {
	if (Value.empty() || Value.size() > 64 ||
		!((Value[0] >= 'A' && Value[0] <= 'Z') ||
		  (Value[0] >= 'a' && Value[0] <= 'z') ||
		  (Value[0] >= '0' && Value[0] <= '9'))) return false;
	return llvm::all_of(Value.drop_front(), [](char C) {
		return (C >= 'A' && C <= 'Z') || (C >= 'a' && C <= 'z') ||
			(C >= '0' && C <= '9') || C == '.' || C == '_' || C == '-';
	});
}

bool isName(StringRef Value) {
	if (Value.empty() || Value.size() > 128 ||
		!((Value[0] >= 'A' && Value[0] <= 'Z') ||
		  (Value[0] >= 'a' && Value[0] <= 'z') ||
		  (Value[0] >= '0' && Value[0] <= '9'))) return false;
	return llvm::all_of(Value.drop_front(), [](char C) {
		return (C >= 'A' && C <= 'Z') || (C >= 'a' && C <= 'z') ||
			(C >= '0' && C <= '9') || C == '.' || C == '_' || C == ':' ||
			C == '/' || C == '-';
	});
}

bool decodeHash(StringRef Text, std::array<uint8_t, 32>& Bytes) {
	if (!isHash(Text)) return false;
	for (unsigned I = 0; I < Bytes.size(); ++I) {
		auto Digit = [](char C) -> unsigned {
			return C <= '9' ? static_cast<unsigned>(C - '0') :
				static_cast<unsigned>(C - 'a' + 10);
		};
		Bytes[I] = static_cast<uint8_t>((Digit(Text[I * 2]) << 4) |
			Digit(Text[I * 2 + 1]));
	}
	return true;
}

struct PublicRegion {
	std::string CallABIHash;
	std::string EngineABIHash;
	std::string LayoutHash;
	std::string ModeText;
	std::string RegionContentHash;
	std::string RegionIDText;
	std::string RegionName;
	std::array<uint8_t, 32> RegionID{};
	std::array<uint8_t, 32> EngineABI{};
	uint32_t Mode = 0;
};

struct PublicManifest {
	std::string BuildIDText;
	std::array<uint8_t, 32> BuildID{};
	std::string SoftwareID;
	std::vector<PublicRegion> Regions;
};

class ManifestParser {
public:
	explicit ManifestParser(ArrayRef<uint8_t> Input) : Input(Input) {}

	bool parse(PublicManifest& Manifest) {
		if (!literal("{\"build_id\":") ||
			!string(Manifest.BuildIDText, 64) ||
			!decodeHash(Manifest.BuildIDText, Manifest.BuildID) ||
			!literal(",\"format_version\":") || !u32(1) ||
			!literal(",\"protocol_version\":") || !u32(2) ||
			!literal(",\"regions\":[")) return false;
		std::set<std::string> Names;
		std::string PreviousID;
		while (true) {
			if (Manifest.Regions.size() == MaxRegions) return false;
			PublicRegion Region;
			if (!region(Region) ||
				(!PreviousID.empty() && Region.RegionIDText <= PreviousID) ||
				!Names.insert(Region.RegionName).second) return false;
			PreviousID = Region.RegionIDText;
			Manifest.Regions.push_back(std::move(Region));
			if (take(']')) break;
			if (!take(',')) return false;
		}
		if (Manifest.Regions.empty() || !literal(",\"software_id\":") ||
			!string(Manifest.SoftwareID, 64) || !isId(Manifest.SoftwareID) ||
			!literal(",\"target_triple\":\"aarch64-linux-android26\"") ||
			!literal(",\"vm_format_version\":") || !u32(1) || !take('}'))
			return false;
		return Position == Input.size();
	}

private:
	bool take(uint8_t Value) {
		if (Position == Input.size() || Input[Position] != Value) return false;
		++Position;
		return true;
	}

	bool literal(StringRef Value) {
		if (Value.size() > Input.size() - Position ||
			std::memcmp(Input.data() + Position, Value.data(), Value.size()) != 0)
			return false;
		Position += Value.size();
		return true;
	}

	bool string(std::string& Value, size_t Limit) {
		if (!take('"')) return false;
		while (Position < Input.size() && Input[Position] != '"') {
			uint8_t C = Input[Position++];
			if (C < 0x20 || C > 0x7e || Value.size() == Limit) return false;
			if (C == '\\') {
				if (Position == Input.size()) return false;
				C = Input[Position++];
				if (C != '"' && C != '\\') return false;
			}
			Value.push_back(static_cast<char>(C));
		}
		return take('"');
	}

	bool hash(std::string& Text, std::array<uint8_t, 32>* Bytes = nullptr) {
		std::array<uint8_t, 32> Decoded{};
		if (!string(Text, 64) || !decodeHash(Text, Decoded)) return false;
		if (Bytes) *Bytes = Decoded;
		return true;
	}

	bool u32(uint32_t Expected) {
		if (Position == Input.size() || Input[Position] < '0' || Input[Position] > '9')
			return false;
		size_t Start = Position;
		uint64_t Value = 0;
		while (Position < Input.size() && Input[Position] >= '0' && Input[Position] <= '9') {
			if (Position - Start == 10) return false;
			Value = Value * 10 + Input[Position++] - '0';
		}
		if (Position - Start > 1 && Input[Start] == '0') return false;
		return Value <= UINT32_MAX && Value == Expected;
	}

	bool region(PublicRegion& Region) {
		if (!literal("{\"call_abi_hash\":") || !hash(Region.CallABIHash) ||
			!literal(",\"engine_abi_hash\":") ||
			!hash(Region.EngineABIHash, &Region.EngineABI) ||
			!literal(",\"layout_hash\":") || !hash(Region.LayoutHash) ||
			!literal(",\"mode\":") || !string(Region.ModeText, 9)) return false;
		if (Region.ModeText == "session") Region.Mode = 1;
		else if (Region.ModeText == "lease") Region.Mode = 2;
		else if (Region.ModeText == "operation") Region.Mode = 3;
		else return false;
		if (!literal(",\"region_content_hash\":") ||
			!hash(Region.RegionContentHash) ||
			!literal(",\"region_id\":") ||
			!hash(Region.RegionIDText, &Region.RegionID) ||
			!literal(",\"region_name\":") ||
			!string(Region.RegionName, 128) || !isName(Region.RegionName) ||
			!take('}')) return false;
		return true;
	}

	ArrayRef<uint8_t> Input;
	size_t Position = 0;
};

void appendQuoted(std::string& Output, StringRef Value) {
	Output.push_back('"');
	Output.append(Value.data(), Value.size());
	Output.push_back('"');
}

std::string encodePublicCore(const PublicManifest& Manifest) {
	std::string Core = "{\"format_version\":1,\"protocol_version\":2,\"regions\":[";
	for (unsigned I = 0; I < Manifest.Regions.size(); ++I) {
		if (I) Core.push_back(',');
		const PublicRegion& Region = Manifest.Regions[I];
		Core += "{\"call_abi_hash\":"; appendQuoted(Core, Region.CallABIHash);
		Core += ",\"engine_abi_hash\":"; appendQuoted(Core, Region.EngineABIHash);
		Core += ",\"layout_hash\":"; appendQuoted(Core, Region.LayoutHash);
		Core += ",\"mode\":"; appendQuoted(Core, Region.ModeText);
		Core += ",\"region_content_hash\":"; appendQuoted(Core, Region.RegionContentHash);
		Core += ",\"region_id\":"; appendQuoted(Core, Region.RegionIDText);
		Core += ",\"region_name\":"; appendQuoted(Core, Region.RegionName);
		Core.push_back('}');
	}
	Core += "],\"software_id\":"; appendQuoted(Core, Manifest.SoftwareID);
	Core += ",\"target_triple\":\"aarch64-linux-android26\",\"vm_format_version\":1}";
	return Core;
}

bool validBuildID(const PublicManifest& Manifest) {
	std::string Core = encodePublicCore(Manifest);
	SHA256 Digest;
	static constexpr char Label[] = "XOVM2/build-id";
	Digest.update(StringRef(Label, sizeof(Label)));
	uint8_t Length[4] = {
		static_cast<uint8_t>(Core.size() >> 24),
		static_cast<uint8_t>(Core.size() >> 16),
		static_cast<uint8_t>(Core.size() >> 8),
		static_cast<uint8_t>(Core.size()),
	};
	Digest.update(ArrayRef<uint8_t>(Length));
	Digest.update(StringRef(Core));
	return Digest.final() == Manifest.BuildID;
}

struct Section {
	uint32_t Name = 0;
	uint32_t Type = 0;
	uint64_t Flags = 0;
	uint64_t Address = 0;
	uint64_t Offset = 0;
	uint64_t Size = 0;
	uint64_t Alignment = 0;
	uint64_t EntrySize = 0;
	uint32_t Link = 0;
	uint32_t Info = 0;
	std::string TextName;
};

struct Segment {
	uint32_t Type = 0;
	uint32_t Flags = 0;
	uint64_t Offset = 0;
	uint64_t Address = 0;
	uint64_t FileSize = 0;
	uint64_t MemorySize = 0;
};

bool range(ArrayRef<uint8_t> Data, uint64_t Offset, uint64_t Size) {
	return Offset <= Data.size() && Size <= Data.size() - Offset;
}

bool contains(uint64_t OuterOffset, uint64_t OuterSize,
	uint64_t InnerOffset, uint64_t InnerSize) {
	return InnerOffset >= OuterOffset && InnerOffset - OuterOffset <= OuterSize &&
		InnerSize <= OuterSize - (InnerOffset - OuterOffset);
}

bool overlaps(uint64_t A, uint64_t ASize, uint64_t B, uint64_t BSize) {
	return ASize && BSize && (A <= B ? B - A < ASize : A - B < BSize);
}

Expected<uint64_t> fileOffset(ArrayRef<Segment> Segments, uint64_t Address,
	uint64_t Size) {
	unsigned Matches = 0;
	uint64_t Offset = 0;
	for (const Segment& Current : Segments) {
		if (Current.Type != ELF::PT_LOAD ||
			!contains(Current.Address, Current.FileSize, Address, Size)) continue;
		Offset = Current.Offset + Address - Current.Address;
		++Matches;
	}
	if (Matches != 1) return bad("relocation_address_not_file_backed");
	return Offset;
}

Expected<unsigned> relocationWidth(uint32_t Type) {
	switch (Type) {
	case 0: return 0;
	case ELF::R_AARCH64_COPY:
		return bad("unsupported_aarch64_copy_relocation");
	case 0x103:
	case 0x106:
		return 2;
	case 0x102:
	case 0x105:
		return 4;
	case 0x101:
	case 0x104:
	case 0x401:
	case 0x402:
	case 0x403:
	case 0x404:
	case 0x405:
	case 0x406:
	case 0x408:
	case 0x411:
	case 0x412:
	case 0x414:
		return 8;
	case 0x407:
	case 0x413:
		return 16;
	default:
		return bad("unsupported_aarch64_relocation");
	}
}

Error validateRelocationTarget(uint64_t Target, uint64_t Info,
	ArrayRef<Segment> Segments, uint64_t MaterialAddress,
	uint64_t MaterialSize) {
	auto Width = relocationWidth(static_cast<uint32_t>(Info));
	if (!Width) return Width.takeError();
	if (!*Width) return Error::success();
	if (Target > UINT64_MAX - *Width)
		return bad("relocation_target_overflow");
	unsigned Loads = 0;
	for (const Segment& Current : Segments)
		if (Current.Type == ELF::PT_LOAD &&
			contains(Current.Address, Current.MemorySize, Target, *Width))
			++Loads;
	if (Loads != 1) return bad("relocation_target_not_loaded");
	if (overlaps(Target, *Width, MaterialAddress, MaterialSize))
		return bad("relocation_targets_material");
	return Error::success();
}

Error validateRelocations(ArrayRef<uint8_t> Data, uint64_t Offset, uint64_t Size,
	bool Rela, ArrayRef<Segment> Segments, uint64_t MaterialAddress,
	uint64_t MaterialSize, uint64_t RelativeCount = 0) {
	const uint64_t EntrySize = Rela ? 24 : 16;
	if (!range(Data, Offset, Size) || Size % EntrySize ||
		RelativeCount > Size / EntrySize)
		return bad("malformed_relocation_block");
	uint64_t Index = 0;
	for (uint64_t Relative = 0; Relative < Size;
		 Relative += EntrySize, ++Index) {
		const uint8_t* Entry = Data.data() + Offset + Relative;
		uint64_t Target = read64le(Entry);
		uint32_t Type = static_cast<uint32_t>(read64le(Entry + 8));
		if (Index < RelativeCount && Type != ELF::R_AARCH64_RELATIVE)
			return bad("malformed_dynamic_relocation_count");
		if (Error E = validateRelocationTarget(Target, Type, Segments,
			MaterialAddress, MaterialSize)) return E;
	}
	return Error::success();
}

Expected<int64_t> readPackedSLEB(const uint8_t*& Cursor, const uint8_t* End) {
	const char* Message = nullptr;
	unsigned Used = 0;
	int64_t Value = decodeSLEB128(Cursor, &Used, End, &Message);
	if (Message || !Used) return bad("malformed_android_packed_relocations");
	uint8_t Canonical[16];
	unsigned CanonicalSize = encodeSLEB128(Value, Canonical);
	if (CanonicalSize != Used || std::memcmp(Cursor, Canonical, Used) != 0)
		return bad("malformed_android_packed_relocations");
	Cursor += Used;
	return Value;
}

bool addPackedOffset(uint64_t& Value, int64_t Delta) {
	if (Delta < 0 || static_cast<uint64_t>(Delta) > UINT64_MAX - Value)
		return false;
	Value += static_cast<uint64_t>(Delta);
	return true;
}

bool addPackedAddend(int64_t& Value, int64_t Delta) {
	int64_t Result = 0;
	if (__builtin_add_overflow(Value, Delta, &Result)) return false;
	Value = Result;
	return true;
}

Error validateAndroidPackedRelocations(ArrayRef<uint8_t> Data, uint64_t Offset,
	uint64_t Size, ArrayRef<Segment> Segments, uint64_t MaterialAddress,
	uint64_t MaterialSize) {
	if (!range(Data, Offset, Size) || Size < 4 ||
		std::memcmp(Data.data() + Offset, "APS2", 4) != 0)
		return bad("malformed_android_packed_relocations");
	const uint8_t* Cursor = Data.data() + Offset + 4;
	const uint8_t* End = Data.data() + Offset + Size;
	auto CountValue = readPackedSLEB(Cursor, End);
	if (!CountValue) return CountValue.takeError();
	auto OffsetValue = readPackedSLEB(Cursor, End);
	if (!OffsetValue) return OffsetValue.takeError();
	if (*CountValue < 0 || static_cast<uint64_t>(*CountValue) > Data.size() / 2 ||
		*OffsetValue < 0)
		return bad("malformed_android_packed_relocations");
	uint64_t Remaining = static_cast<uint64_t>(*CountValue);
	uint64_t Target = static_cast<uint64_t>(*OffsetValue);
	int64_t Addend = 0;
	while (Remaining) {
		auto GroupCountValue = readPackedSLEB(Cursor, End);
		if (!GroupCountValue) return GroupCountValue.takeError();
		auto FlagsValue = readPackedSLEB(Cursor, End);
		if (!FlagsValue) return FlagsValue.takeError();
		if (*GroupCountValue <= 0 ||
			static_cast<uint64_t>(*GroupCountValue) > Remaining ||
			*FlagsValue < 0 || *FlagsValue > 15 ||
			((*FlagsValue & ELF::RELOCATION_GROUPED_BY_ADDEND_FLAG) &&
			 !(*FlagsValue & ELF::RELOCATION_GROUP_HAS_ADDEND_FLAG)))
			return bad("malformed_android_packed_relocations");
		uint64_t GroupCount = static_cast<uint64_t>(*GroupCountValue);
		uint64_t Flags = static_cast<uint64_t>(*FlagsValue);
		int64_t GroupOffsetDelta = 0;
		int64_t GroupInfo = 0;
		if (Flags & ELF::RELOCATION_GROUPED_BY_OFFSET_DELTA_FLAG) {
			auto Value = readPackedSLEB(Cursor, End);
			if (!Value || *Value < 0) {
				if (!Value) consumeError(Value.takeError());
				return bad("malformed_android_packed_relocations");
			}
			GroupOffsetDelta = *Value;
		}
		if (Flags & ELF::RELOCATION_GROUPED_BY_INFO_FLAG) {
			auto Value = readPackedSLEB(Cursor, End);
			if (!Value || *Value < 0) {
				if (!Value) consumeError(Value.takeError());
				return bad("malformed_android_packed_relocations");
			}
			GroupInfo = *Value;
		}
		if ((Flags & ELF::RELOCATION_GROUP_HAS_ADDEND_FLAG) &&
			(Flags & ELF::RELOCATION_GROUPED_BY_ADDEND_FLAG)) {
			auto Value = readPackedSLEB(Cursor, End);
			if (!Value) return Value.takeError();
			if (!addPackedAddend(Addend, *Value))
				return bad("malformed_android_packed_relocations");
		}
		if (!(Flags & ELF::RELOCATION_GROUP_HAS_ADDEND_FLAG)) Addend = 0;
		for (uint64_t I = 0; I < GroupCount; ++I) {
			int64_t Delta = GroupOffsetDelta;
			if (!(Flags & ELF::RELOCATION_GROUPED_BY_OFFSET_DELTA_FLAG)) {
				auto Value = readPackedSLEB(Cursor, End);
				if (!Value) return Value.takeError();
				Delta = *Value;
			}
			if (!addPackedOffset(Target, Delta))
				return bad("malformed_android_packed_relocations");
			int64_t Info = GroupInfo;
			if (!(Flags & ELF::RELOCATION_GROUPED_BY_INFO_FLAG)) {
				auto Value = readPackedSLEB(Cursor, End);
				if (!Value) return Value.takeError();
				Info = *Value;
			}
			if (Info < 0) return bad("malformed_android_packed_relocations");
			if ((Flags & ELF::RELOCATION_GROUP_HAS_ADDEND_FLAG) &&
				!(Flags & ELF::RELOCATION_GROUPED_BY_ADDEND_FLAG)) {
				auto Value = readPackedSLEB(Cursor, End);
				if (!Value) return Value.takeError();
				if (!addPackedAddend(Addend, *Value))
					return bad("malformed_android_packed_relocations");
			}
			if (Error E = validateRelocationTarget(Target,
				static_cast<uint64_t>(Info), Segments, MaterialAddress,
				MaterialSize)) return E;
		}
		Remaining -= GroupCount;
	}
	if (Cursor != End) return bad("malformed_android_packed_relocations");
	return Error::success();
}

struct MaterialELF {
	uint64_t SectionOffset = 0;
	uint64_t SectionSize = 0;
	unsigned RecordCount = 0;
};

Expected<MaterialELF> parseELF(ArrayRef<uint8_t> Data) {
	if (!range(Data, 0, 64) || read32le(Data.data()) != 0x464c457f ||
		Data[ELF::EI_CLASS] != ELF::ELFCLASS64 ||
		Data[ELF::EI_DATA] != ELF::ELFDATA2LSB ||
		Data[ELF::EI_VERSION] != ELF::EV_CURRENT ||
		(read16le(Data.data() + 16) != ELF::ET_DYN &&
		 read16le(Data.data() + 16) != ELF::ET_EXEC) ||
		read16le(Data.data() + 18) != ELF::EM_AARCH64 ||
		read32le(Data.data() + 20) != ELF::EV_CURRENT ||
		read16le(Data.data() + 52) != 64)
		return bad("unsupported_elf");

	uint64_t ProgramOffset = read64le(Data.data() + 32);
	uint64_t SectionOffset = read64le(Data.data() + 40);
	uint16_t ProgramEntrySize = read16le(Data.data() + 54);
	uint16_t ProgramCount = read16le(Data.data() + 56);
	uint16_t SectionEntrySize = read16le(Data.data() + 58);
	uint16_t SectionCount = read16le(Data.data() + 60);
	uint16_t StringIndex = read16le(Data.data() + 62);
	if (!ProgramCount || ProgramCount == ELF::PN_XNUM || ProgramEntrySize != 56 ||
		ProgramCount > (Data.size() - std::min<uint64_t>(ProgramOffset, Data.size())) /
			ProgramEntrySize || !range(Data, ProgramOffset,
			static_cast<uint64_t>(ProgramCount) * ProgramEntrySize) ||
		!SectionCount || SectionEntrySize != 64 || StringIndex == ELF::SHN_XINDEX ||
		StringIndex == ELF::SHN_UNDEF || StringIndex >= SectionCount ||
		SectionCount > (Data.size() - std::min<uint64_t>(SectionOffset, Data.size())) /
			SectionEntrySize || !range(Data, SectionOffset,
			static_cast<uint64_t>(SectionCount) * SectionEntrySize))
		return bad("malformed_elf_tables");

	std::vector<Segment> Segments;
	for (unsigned I = 0; I < ProgramCount; ++I) {
		const uint8_t* Header = Data.data() + ProgramOffset + I * ProgramEntrySize;
		Segment Current{read32le(Header), read32le(Header + 4), read64le(Header + 8),
			read64le(Header + 16), read64le(Header + 32), read64le(Header + 40)};
		uint64_t Alignment = read64le(Header + 48);
		if (!range(Data, Current.Offset, Current.FileSize) ||
			Current.FileSize > Current.MemorySize ||
			Current.Address > UINT64_MAX - Current.MemorySize ||
			(Alignment && (Alignment & (Alignment - 1))) ||
			(Alignment > 1 && Current.Offset % Alignment != Current.Address % Alignment))
			return bad("malformed_elf_segment");
		Segments.push_back(Current);
	}
	for (unsigned I = 0; I < Segments.size(); ++I) if (Segments[I].Type == ELF::PT_LOAD)
		for (unsigned J = I + 1; J < Segments.size(); ++J) if (Segments[J].Type == ELF::PT_LOAD)
			if (overlaps(Segments[I].Offset, Segments[I].FileSize,
					Segments[J].Offset, Segments[J].FileSize) ||
				overlaps(Segments[I].Address, Segments[I].MemorySize,
					Segments[J].Address, Segments[J].MemorySize))
				return bad("overlapping_elf_segments");

	std::vector<Section> Sections;
	Sections.reserve(SectionCount);
	for (unsigned I = 0; I < SectionCount; ++I) {
		const uint8_t* Header = Data.data() + SectionOffset + I * SectionEntrySize;
		Section Current{read32le(Header), read32le(Header + 4), read64le(Header + 8),
			read64le(Header + 16), read64le(Header + 24), read64le(Header + 32),
			read64le(Header + 48), read64le(Header + 56), read32le(Header + 40),
			read32le(Header + 44), {}};
		if (Current.Address > UINT64_MAX - Current.Size ||
			(Current.Alignment && (Current.Alignment & (Current.Alignment - 1))) ||
			(Current.Type != ELF::SHT_NOBITS && Current.Type != ELF::SHT_NULL &&
			 (!range(Data, Current.Offset, Current.Size) ||
			  (Current.Alignment > 1 && Current.Offset % Current.Alignment))))
			return bad("malformed_elf_section");
		Sections.push_back(std::move(Current));
	}
	if (Sections[0].Type != ELF::SHT_NULL || Sections[StringIndex].Type != ELF::SHT_STRTAB ||
		!range(Data, Sections[StringIndex].Offset, Sections[StringIndex].Size))
		return bad("malformed_elf_strings");
	ArrayRef<uint8_t> Strings(Data.data() + Sections[StringIndex].Offset,
		Sections[StringIndex].Size);
	for (Section& Current : Sections) {
		if (Current.Name >= Strings.size()) return bad("malformed_elf_strings");
		const uint8_t* Start = Strings.data() + Current.Name;
		const void* End = std::memchr(Start, 0, Strings.size() - Current.Name);
		if (!End) return bad("malformed_elf_strings");
		Current.TextName.assign(reinterpret_cast<const char*>(Start),
			reinterpret_cast<const char*>(End));
	}

	struct FileRange { uint64_t Offset, Size; };
	std::vector<FileRange> FileRanges;
	for (const Section& Current : Sections)
		if (Current.Type != ELF::SHT_NULL && Current.Type != ELF::SHT_NOBITS && Current.Size)
			FileRanges.push_back({Current.Offset, Current.Size});
	std::sort(FileRanges.begin(), FileRanges.end(), [](const auto& A, const auto& B) {
		return A.Offset < B.Offset;
	});
	for (unsigned I = 1; I < FileRanges.size(); ++I)
		if (overlaps(FileRanges[I - 1].Offset, FileRanges[I - 1].Size,
			FileRanges[I].Offset, FileRanges[I].Size))
			return bad("overlapping_elf_sections");

	const Section* Material = nullptr;
	for (const Section& Current : Sections) {
		if (Current.TextName != MaterialSectionName) continue;
		if (Material) return bad("multiple_material_sections");
		Material = &Current;
	}
	if (!Material) return bad("missing_material_section");
	if (Material->Type != ELF::SHT_PROGBITS || !(Material->Flags & ELF::SHF_ALLOC) ||
		(Material->Flags & (ELF::SHF_WRITE | ELF::SHF_EXECINSTR)) ||
		!range(Data, Material->Offset, Material->Size) ||
		Material->Size < RecordSize || Material->Size % RecordSize ||
		Material->Size / RecordSize > MaxRegions ||
		overlaps(Material->Offset, Material->Size, 0, 64) ||
		overlaps(Material->Offset, Material->Size, ProgramOffset,
			static_cast<uint64_t>(ProgramCount) * ProgramEntrySize) ||
		overlaps(Material->Offset, Material->Size, SectionOffset,
			static_cast<uint64_t>(SectionCount) * SectionEntrySize))
		return bad("malformed_material_section");

	unsigned Loads = 0;
	for (const Segment& Current : Segments) {
		if (Current.Type != ELF::PT_LOAD ||
			!contains(Current.Offset, Current.FileSize, Material->Offset, Material->Size) ||
			!contains(Current.Address, Current.MemorySize, Material->Address, Material->Size) ||
			Material->Offset - Current.Offset != Material->Address - Current.Address)
			continue;
		if (!(Current.Flags & ELF::PF_R) || (Current.Flags & (ELF::PF_W | ELF::PF_X)))
			return bad("material_section_not_read_only");
		++Loads;
	}
	if (Loads != 1) return bad("material_section_not_file_backed");

	auto fileRangeAliasesMaterial = [&](uint64_t Offset, uint64_t Size) {
		if (overlaps(Offset, Size, Material->Offset, Material->Size)) return true;
		for (const Segment& Current : Segments) {
			if (Current.Type != ELF::PT_LOAD || !Current.FileSize || !Size) continue;
			uint64_t Start = std::max(Offset, Current.Offset);
			uint64_t End = std::min(Offset + Size,
				Current.Offset + Current.FileSize);
			if (Start >= End) continue;
			uint64_t Address = Current.Address + Start - Current.Offset;
			if (overlaps(Address, End - Start, Material->Address, Material->Size))
				return true;
		}
		return false;
	};
	if (fileRangeAliasesMaterial(0, 64) ||
		fileRangeAliasesMaterial(ProgramOffset,
			static_cast<uint64_t>(ProgramCount) * ProgramEntrySize) ||
		fileRangeAliasesMaterial(SectionOffset,
			static_cast<uint64_t>(SectionCount) * SectionEntrySize))
		return bad("material_aliases_elf_headers");
	for (const Segment& Current : Segments) {
		if (Current.Type == ELF::PT_NULL || Current.Type == ELF::PT_LOAD) continue;
		if (overlaps(Current.Offset, Current.FileSize,
				Material->Offset, Material->Size) ||
			overlaps(Current.Address, Current.MemorySize,
				Material->Address, Material->Size))
			return bad("material_aliases_loader_metadata");
	}

	for (const Section& Current : Sections) {
		bool PackedRela = Current.Type == ELF::SHT_ANDROID_RELA;
		bool Unsupported = Current.Type == ELF::SHT_RELR ||
			Current.Type == ELF::SHT_CREL ||
			Current.Type == ELF::SHT_ANDROID_REL ||
			Current.Type == ELF::SHT_ANDROID_RELR ||
			Current.Type == ELF::SHT_AARCH64_AUTH_RELR;
		bool Rela = Current.Type == ELF::SHT_RELA;
		bool Rel = Current.Type == ELF::SHT_REL;
		if (!PackedRela && !Unsupported && !Rela && !Rel) continue;
		if (fileRangeAliasesMaterial(Current.Offset, Current.Size) ||
			overlaps(Current.Address, Current.Size,
				Material->Address, Material->Size))
			return bad("relocation_block_aliases_material");
		if (overlaps(Current.Offset, Current.Size, 0, 64) ||
			overlaps(Current.Offset, Current.Size, ProgramOffset,
				static_cast<uint64_t>(ProgramCount) * ProgramEntrySize) ||
			overlaps(Current.Offset, Current.Size, SectionOffset,
				static_cast<uint64_t>(SectionCount) * SectionEntrySize))
			return bad("relocation_block_aliases_elf_headers");
		if (Unsupported) {
			if (Current.Flags & ELF::SHF_ALLOC)
				return bad("unsupported_relocation_format");
			continue;
		}
		if (PackedRela) {
			if (Current.EntrySize != 1 || Current.Link >= Sections.size() ||
				(Sections[Current.Link].Type != ELF::SHT_SYMTAB &&
				 Sections[Current.Link].Type != ELF::SHT_DYNSYM) ||
				(Current.Info && Current.Info >= Sections.size()))
				return bad("malformed_relocation_section");
			if (Current.Flags & ELF::SHF_ALLOC)
				if (Error E = validateAndroidPackedRelocations(Data, Current.Offset,
					Current.Size, Segments, Material->Address, Material->Size)) return E;
			continue;
		}
		uint64_t ExpectedEntrySize = Rela ? 24 : 16;
		if (Current.EntrySize != ExpectedEntrySize ||
			Current.Size % ExpectedEntrySize || Current.Link >= Sections.size() ||
			(Sections[Current.Link].Type != ELF::SHT_SYMTAB &&
			 Sections[Current.Link].Type != ELF::SHT_DYNSYM) ||
			(Current.Info && Current.Info >= Sections.size()))
			return bad("malformed_relocation_section");
		if ((Current.Flags & ELF::SHF_ALLOC))
			if (Error E = validateRelocations(Data, Current.Offset, Current.Size,
				Rela, Segments, Material->Address, Material->Size)) return std::move(E);
	}

	std::map<uint64_t, uint64_t> DynamicTags;
	const auto isRelocationTag = [](uint64_t Tag) {
		switch (Tag) {
		case ELF::DT_PLTRELSZ: case ELF::DT_RELA: case ELF::DT_RELASZ:
		case ELF::DT_RELAENT: case ELF::DT_REL: case ELF::DT_RELSZ:
		case ELF::DT_RELENT: case ELF::DT_RELACOUNT: case ELF::DT_RELCOUNT:
		case 20: case 23: case 35: case 36: case 37:
		case ELF::DT_CREL:
		case 0x6000000f: case 0x60000010: case 0x60000011:
		case 0x60000012: case 0x6fffe000: case 0x6fffe001:
		case 0x6fffe003: case 0x70000011: case 0x70000012:
		case 0x70000013:
			return true;
		default:
			return false;
		}
	};
	unsigned DynamicSegments = 0;
	for (const Segment& Current : Segments) {
		if (Current.Type != ELF::PT_DYNAMIC) continue;
		if (++DynamicSegments != 1 || Current.FileSize % 16)
			return bad("malformed_dynamic_segment");
		bool Terminated = false;
		for (uint64_t Relative = 0; Relative < Current.FileSize; Relative += 16) {
			const uint8_t* Entry = Data.data() + Current.Offset + Relative;
			uint64_t Tag = read64le(Entry);
			if (!Tag) { Terminated = true; break; }
			if (isRelocationTag(Tag) &&
				!DynamicTags.emplace(Tag, read64le(Entry + 8)).second)
				return bad("duplicate_dynamic_relocation_tag");
		}
		if (!Terminated) return bad("unterminated_dynamic_segment");
	}
	static constexpr std::array<uint64_t, 12> UnsupportedDynamicRelocations = {
		ELF::DT_CREL, 35, 36, 37, 0x6000000f, 0x60000010,
		0x6fffe000, 0x6fffe001, 0x6fffe003, 0x70000011,
		0x70000012, 0x70000013,
	};
	for (uint64_t Tag : UnsupportedDynamicRelocations)
		if (DynamicTags.count(Tag)) return bad("unsupported_relocation_format");

	struct RelocationBlock { uint64_t Offset, Address, Size; };
	std::vector<RelocationBlock> DynamicBlocks;
	auto dynamicBlock = [&](uint64_t AddressTag, uint64_t SizeTag,
		uint64_t EntryTag, uint64_t CountTag, uint64_t ExpectedEntrySize,
		bool Rela) -> Error {
		bool Any = DynamicTags.count(AddressTag) || DynamicTags.count(SizeTag) ||
			(CountTag && DynamicTags.count(CountTag));
		if (!Any) return Error::success();
		if (!DynamicTags.count(AddressTag) || !DynamicTags.count(SizeTag) ||
			!DynamicTags.count(EntryTag) || DynamicTags[EntryTag] != ExpectedEntrySize)
			return bad("incomplete_dynamic_relocation_tags");
		uint64_t Address = DynamicTags[AddressTag];
		uint64_t Size = DynamicTags[SizeTag];
		if (Size % ExpectedEntrySize) return bad("malformed_relocation_block");
		auto Offset = fileOffset(Segments, Address, Size);
		if (!Offset) return Offset.takeError();
		if (fileRangeAliasesMaterial(*Offset, Size) ||
			overlaps(Address, Size, Material->Address, Material->Size))
			return bad("relocation_block_aliases_material");
		if (overlaps(*Offset, Size, 0, 64) ||
			overlaps(*Offset, Size, ProgramOffset,
				static_cast<uint64_t>(ProgramCount) * ProgramEntrySize) ||
			overlaps(*Offset, Size, SectionOffset,
				static_cast<uint64_t>(SectionCount) * SectionEntrySize))
			return bad("relocation_block_aliases_elf_headers");
		for (const RelocationBlock& Other : DynamicBlocks)
			if (overlaps(*Offset, Size, Other.Offset, Other.Size) ||
				overlaps(Address, Size, Other.Address, Other.Size))
				return bad("overlapping_dynamic_relocation_blocks");
		uint64_t RelativeCount = CountTag && DynamicTags.count(CountTag) ?
			DynamicTags[CountTag] : 0;
		if (Error E = validateRelocations(Data, *Offset, Size, Rela, Segments,
			Material->Address, Material->Size, RelativeCount)) return E;
		DynamicBlocks.push_back({*Offset, Address, Size});
		return Error::success();
	};
	if (Error E = dynamicBlock(7, 8, 9, ELF::DT_RELACOUNT, 24, true))
		return std::move(E);
	if (Error E = dynamicBlock(17, 18, 19, ELF::DT_RELCOUNT, 16, false))
		return std::move(E);
	bool AnyAndroidRela = DynamicTags.count(0x60000011) ||
		DynamicTags.count(0x60000012);
	if (AnyAndroidRela) {
		if (!DynamicTags.count(0x60000011) || !DynamicTags.count(0x60000012))
			return bad("incomplete_dynamic_relocation_tags");
		uint64_t Address = DynamicTags[0x60000011];
		uint64_t Size = DynamicTags[0x60000012];
		auto Offset = fileOffset(Segments, Address, Size);
		if (!Offset) return Offset.takeError();
		if (fileRangeAliasesMaterial(*Offset, Size) ||
			overlaps(Address, Size, Material->Address, Material->Size))
			return bad("relocation_block_aliases_material");
		if (overlaps(*Offset, Size, 0, 64) ||
			overlaps(*Offset, Size, ProgramOffset,
				static_cast<uint64_t>(ProgramCount) * ProgramEntrySize) ||
			overlaps(*Offset, Size, SectionOffset,
				static_cast<uint64_t>(SectionCount) * SectionEntrySize))
			return bad("relocation_block_aliases_elf_headers");
		for (const RelocationBlock& Other : DynamicBlocks)
			if (overlaps(*Offset, Size, Other.Offset, Other.Size) ||
				overlaps(Address, Size, Other.Address, Other.Size))
				return bad("overlapping_dynamic_relocation_blocks");
		if (Error E = validateAndroidPackedRelocations(Data, *Offset, Size,
			Segments, Material->Address, Material->Size)) return E;
		DynamicBlocks.push_back({*Offset, Address, Size});
	}
	bool AnyPLT = DynamicTags.count(23) || DynamicTags.count(2) ||
		DynamicTags.count(20);
	if (AnyPLT) {
		if (!DynamicTags.count(23) || !DynamicTags.count(2) ||
			!DynamicTags.count(20)) return bad("incomplete_dynamic_relocation_tags");
		uint64_t Kind = DynamicTags[20];
		if (Kind == 7) {
			if (Error E = dynamicBlock(23, 2, 9, 0, 24, true)) return std::move(E);
		} else if (Kind == 17) {
			if (Error E = dynamicBlock(23, 2, 19, 0, 16, false)) return std::move(E);
		} else {
			return bad("unsupported_plt_relocation_format");
		}
	}
	return MaterialELF{Material->Offset, Material->Size,
		static_cast<unsigned>(Material->Size / RecordSize)};
}

Error validateRecords(ArrayRef<uint8_t> Input, MutableArrayRef<uint8_t> Output,
	const MaterialELF& ELFInfo, const PublicManifest& Manifest) {
	if (ELFInfo.RecordCount != Manifest.Regions.size()) return bad("descriptor_set_mismatch");
	std::map<std::array<uint8_t, 32>, const PublicRegion*> Regions;
	for (const PublicRegion& Region : Manifest.Regions)
		if (!Regions.emplace(Region.RegionID, &Region).second)
			return bad("duplicate_manifest_region");
	std::set<std::array<uint8_t, 32>> Seen;
	unsigned Pending = 0;
	unsigned Finalized = 0;
	static constexpr uint8_t Magic[8] = {'X','O','V','M','M','A','T',0};
	for (unsigned I = 0; I < ELFInfo.RecordCount; ++I) {
		uint64_t Offset = ELFInfo.SectionOffset + static_cast<uint64_t>(I) * RecordSize;
		const uint8_t* Record = Input.data() + Offset;
		if (std::memcmp(Record, Magic, sizeof(Magic)) != 0 ||
			read16le(Record + 8) != 1 || read16le(Record + 10) != 16 ||
			read32le(Record + 12) != RecordSize || read32le(Record + 16) != 1)
			return bad("invalid_material_record_header");
		uint32_t Mode = read32le(Record + 20);
		if (Mode < 1 || Mode > 3) return bad("invalid_material_record_mode");
		std::array<uint8_t, 32> RegionID{};
		std::copy(Record + 56, Record + 88, RegionID.begin());
		if (!Seen.insert(RegionID).second) return bad("duplicate_material_record");
		auto It = Regions.find(RegionID);
		if (It == Regions.end() || It->second->Mode != Mode ||
			!std::equal(It->second->EngineABI.begin(), It->second->EngineABI.end(),
				Record + 88)) return bad("descriptor_set_mismatch");
		bool Zero = llvm::all_of(ArrayRef<uint8_t>(Record + 24, 32),
			[](uint8_t Byte) { return Byte == 0; });
		bool Same = std::equal(Manifest.BuildID.begin(), Manifest.BuildID.end(), Record + 24);
		if (!Zero && !Same) return bad("invalid_material_build_id");
		Pending += Zero;
		Finalized += Same;
	}
	if (!((Pending == ELFInfo.RecordCount && Finalized == 0) ||
		(Pending == 0 && Finalized == ELFInfo.RecordCount)))
		return bad("mixed_material_build_ids");
	if (Pending) {
		for (unsigned I = 0; I < ELFInfo.RecordCount; ++I) {
			uint64_t Offset = ELFInfo.SectionOffset + static_cast<uint64_t>(I) * RecordSize + 24;
			std::copy(Manifest.BuildID.begin(), Manifest.BuildID.end(), Output.begin() + Offset);
		}
	}
	return Error::success();
}

int renameNoReplace(int Directory, const char* Source, const char* Destination) {
#if defined(SYS_renameat2)
	return static_cast<int>(::syscall(SYS_renameat2, Directory, Source,
		Directory, Destination, 1));
#else
	errno = ENOTSUP;
	return -1;
#endif
}

bool randomStageName(std::string& Name) {
	std::array<uint8_t, 16> Random{};
	size_t Offset = 0;
	while (Offset < Random.size()) {
		ssize_t Count = static_cast<ssize_t>(::syscall(SYS_getrandom,
			Random.data() + Offset, Random.size() - Offset, 0));
		if (Count < 0 && errno == EINTR) continue;
		if (Count <= 0) return false;
		Offset += static_cast<size_t>(Count);
	}
	static constexpr char Hex[] = "0123456789abcdef";
	Name = ".xollvm-material-";
	for (uint8_t Byte : Random) {
		Name.push_back(Hex[Byte >> 4]);
		Name.push_back(Hex[Byte & 15]);
	}
	Name += ".tmp";
	return true;
}

bool sameStage(int Directory, StringRef Name, int FD, mode_t Mode,
	uint64_t Size) {
	struct stat Opened {}, Named {};
	return ::fstat(FD, &Opened) == 0 &&
		::fstatat(Directory, Name.str().c_str(), &Named,
			AT_SYMLINK_NOFOLLOW) == 0 &&
		S_ISREG(Opened.st_mode) && S_ISREG(Named.st_mode) &&
		Opened.st_uid == ::geteuid() && Named.st_uid == ::geteuid() &&
		Opened.st_nlink == 1 && Named.st_nlink == 1 &&
		Opened.st_dev == Named.st_dev && Opened.st_ino == Named.st_ino &&
		(Opened.st_mode & 07777u) == Mode &&
		(Named.st_mode & 07777u) == Mode && Opened.st_size >= 0 &&
		static_cast<uint64_t>(Opened.st_size) == Size &&
		Named.st_size == Opened.st_size;
}

bool stageMatchesBytes(int FD, ArrayRef<uint8_t> Expected) {
	std::array<uint8_t, 16384> Buffer{};
	size_t Offset = 0;
	while (Offset < Expected.size()) {
		size_t Requested = std::min(Buffer.size(), Expected.size() - Offset);
		ssize_t Count = ::pread(FD, Buffer.data(), Requested,
			static_cast<off_t>(Offset));
		if (Count < 0 && errno == EINTR) continue;
		if (Count <= 0 || !std::equal(Buffer.begin(), Buffer.begin() + Count,
			Expected.begin() + Offset)) return false;
		Offset += static_cast<size_t>(Count);
	}
	uint8_t Extra = 0;
	return ::pread(FD, &Extra, 1, static_cast<off_t>(Offset)) == 0;
}

Error publishNoReplace(StringRef OutputPath, ArrayRef<uint8_t> Bytes, mode_t Mode) {
	std::string Path = OutputPath.str();
	size_t Slash = Path.rfind('/');
	std::string Parent = Slash == std::string::npos ? "." :
		(Slash == 0 ? "/" : Path.substr(0, Slash));
	std::string Name = Slash == std::string::npos ? Path : Path.substr(Slash + 1);
	if (Name.empty() || Name == "." || Name == "..") return bad("invalid_output_path");
	int Directory = ::open(Parent.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
	if (Directory < 0) return bad("output_parent_unavailable");
	struct stat ParentStatus {};
	if (::fstat(Directory, &ParentStatus) != 0 || !S_ISDIR(ParentStatus.st_mode)) {
		::close(Directory);
		return bad("output_parent_unavailable");
	}
	if (ParentStatus.st_uid != ::geteuid() ||
		(ParentStatus.st_mode & (S_IWGRP | S_IWOTH))) {
		::close(Directory);
		return bad("output_parent_untrusted");
	}
	struct stat Existing {};
	if (::fstatat(Directory, Name.c_str(), &Existing, AT_SYMLINK_NOFOLLOW) == 0) {
		::close(Directory);
		return bad("output_exists");
	}
	if (errno != ENOENT) {
		::close(Directory);
		return bad("output_path_unavailable");
	}
	std::string StageName;
	int FD = -1;
	for (unsigned Attempt = 0; Attempt < 16 && FD < 0; ++Attempt) {
		if (!randomStageName(StageName)) break;
		FD = ::openat(Directory, StageName.c_str(),
			O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
		if (FD < 0 && errno != EEXIST) break;
	}
	if (FD < 0) {
		::close(Directory);
		return bad("output_staging_unavailable");
	}
	auto UnlinkOwnedStage = [&]() {
		struct stat Opened {};
		if (::fstat(FD, &Opened) != 0) return;
		struct stat Named {};
		if (::fstatat(Directory, StageName.c_str(), &Named,
			AT_SYMLINK_NOFOLLOW) == 0 && S_ISREG(Named.st_mode) &&
			Opened.st_dev == Named.st_dev && Opened.st_ino == Named.st_ino)
			(void)::unlinkat(Directory, StageName.c_str(), 0);
	};
	auto Cleanup = [&](bool RemoveStage) {
		if (FD >= 0) {
			if (RemoveStage) UnlinkOwnedStage();
			(void)::close(FD);
			FD = -1;
		}
		(void)::close(Directory);
	};
	struct stat Initial {};
	bool Valid = ::fchmod(FD, 0600) == 0 && ::fstat(FD, &Initial) == 0 &&
		S_ISREG(Initial.st_mode) && Initial.st_uid == ::geteuid() &&
		Initial.st_nlink == 1 && (Initial.st_mode & 07777u) == 0600;
	for (size_t Offset = 0; Valid && Offset < Bytes.size();) {
		ssize_t Count = ::write(FD, Bytes.data() + Offset, Bytes.size() - Offset);
		if (Count < 0 && errno == EINTR) continue;
		if (Count <= 0) { Valid = false; break; }
		Offset += static_cast<size_t>(Count);
	}
	const char* Fault = std::getenv("XOVM_TEST_MATERIAL_PUBLISH_FAULT");
	Valid = Valid && ::fsync(FD) == 0;
	Valid = Valid && sameStage(Directory, StageName, FD, 0600, Bytes.size()) &&
		stageMatchesBytes(FD, Bytes);
	// 禁止向可见 staging inode 传播组/其他用户写权限；特殊位也不保留。
	mode_t FinalMode = Mode & 0755u;
	Valid = Valid && ::fchmod(FD, FinalMode) == 0 && ::fsync(FD) == 0;
	if (Valid && Fault && std::strcmp(Fault, "substitute_stage") == 0) {
		if (::unlinkat(Directory, StageName.c_str(), 0) == 0) {
			int Replacement = ::openat(Directory, StageName.c_str(),
				O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
			if (Replacement >= 0) {
				(void)::write(Replacement, "substituted", 11);
				(void)::close(Replacement);
			}
		}
	}
	if (Valid && Fault && std::strcmp(Fault, "mutate_stage_content") == 0 &&
		!Bytes.empty()) {
		uint8_t Mutated = Bytes.front() ^ 0xffu;
		if (::pwrite(FD, &Mutated, 1, 0) != 1) Valid = false;
	}
	if (Valid && Fault && std::strcmp(Fault, "require_safe_stage_mode") == 0) {
		struct stat BeforeRename {};
		if (::fstat(FD, &BeforeRename) != 0 || (BeforeRename.st_mode & 0022u))
			Valid = false;
	}
	if (Fault && std::strcmp(Fault, "before_rename") == 0) Valid = false;
	Valid = Valid && sameStage(Directory, StageName, FD, FinalMode, Bytes.size()) &&
		stageMatchesBytes(FD, Bytes);
	if (!Valid) {
		Cleanup(true);
		return bad("output_precommit_failed");
	}
	if (renameNoReplace(Directory, StageName.c_str(), Name.c_str()) != 0) {
		int Failure = errno;
		Cleanup(true);
		if (Failure == EEXIST) return bad("output_exists");
		if (Failure == EINVAL || Failure == ENOSYS || Failure == EOPNOTSUPP)
			return bad("output_noreplace_commit_unavailable");
		return bad("output_commit_failed");
	}
	bool Synced = !(Fault && std::strcmp(Fault, "after_rename_sync") == 0) &&
		::fsync(Directory) == 0;
	if (::close(FD) != 0) Synced = false;
	FD = -1;
	if (!Synced) { Cleanup(false); return bad("output_committed_sync_failed"); }
	Cleanup(false);
	return Error::success();
}

} // namespace

Expected<unsigned> llvm::finalizeMaterialManifest(StringRef InputPath,
	StringRef ManifestPath, StringRef OutputPath) {
	auto ManifestFile = readFile(ManifestPath, MaxManifestSize, "manifest_read_failed");
	if (!ManifestFile) return ManifestFile.takeError();
	PublicManifest Manifest;
	ManifestParser Parser(ManifestFile->Bytes);
	if (!Parser.parse(Manifest) || !validBuildID(Manifest))
		return bad("invalid_public_manifest");
	auto InputFile = readFile(InputPath, UINT64_MAX, "input_read_failed");
	if (!InputFile) return InputFile.takeError();
	auto ELFInfo = parseELF(InputFile->Bytes);
	if (!ELFInfo) return ELFInfo.takeError();
	std::vector<uint8_t> Output = InputFile->Bytes;
	if (Error E = validateRecords(InputFile->Bytes, Output, *ELFInfo, Manifest))
		return std::move(E);
	if (Error E = publishNoReplace(OutputPath, Output, InputFile->Status.st_mode))
		return std::move(E);
	return ELFInfo->RecordCount;
}
