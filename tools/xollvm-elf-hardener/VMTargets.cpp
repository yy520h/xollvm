#include "VMTargets.h"
#include "llvm/Transforms/Obfuscator/VMTargetEncoding.h"
#include "llvm/Support/Endian.h"
#include "llvm/Support/LEB128.h"
#include <algorithm>
#include <map>
#include <set>
#include <vector>

using namespace llvm;
using namespace llvm::support::endian;
using namespace llvm::VMTargetFormat;

namespace {
Error bad(const char* Message) { return createStringError(inconvertibleErrorCode(), "VM targets: %s", Message); }
struct Segment { uint32_t Type, Flags; uint64_t Off, VA, Size; };
struct Reloc { uint64_t Slot, Info, Add; };
struct Block { uint64_t Off, Size, SizeField; unsigned Kind; std::vector<Reloc> Relocs; };
struct Descriptor { uint64_t Off, VA; uint32_t Count, State; };

class Parser {
public:
	ArrayRef<uint8_t> Data;
	std::vector<Segment> Segments;
	std::vector<Descriptor> Descriptors;
	std::vector<Block> Blocks;
	std::map<uint64_t, uint64_t> Dynamic;
	std::vector<uint64_t> RelaCounts;
	uint64_t ShOff = 0, ShSize = 0, ShNum = 0;
	bool UnsupportedRelocations = false;
	explicit Parser(ArrayRef<uint8_t> D) : Data(D) {}
	bool range(uint64_t Off, uint64_t Size) const { return Off <= Data.size() && Size <= Data.size() - Off; }
	Expected<uint64_t> fileOffset(uint64_t VA, uint64_t Size) const {
		for (auto S : Segments) if (S.Type == 1 && VA >= S.VA && VA - S.VA <= S.Size && Size <= S.Size - (VA - S.VA))
			return S.Off + VA - S.VA;
		return bad("address not file-backed");
	}
	bool executable(uint64_t VA) const {
		for (auto S : Segments) if (S.Type == 1 && (S.Flags & 1) && VA >= S.VA && VA - S.VA < S.Size) return true;
		return false;
	}
	Error parse() {
		if (!range(0, 64) || read32le(Data.data()) != 0x464c457f || Data[4] != 2 || Data[5] != 1 ||
			read16le(Data.data() + 18) != 183) return bad("requires AArch64 LE ELF64");
		uint64_t PO = read64le(Data.data() + 32), PN = read16le(Data.data() + 56), PE = read16le(Data.data() + 54);
		if (PE < 56 || !range(PO, PN * PE)) return bad("program headers out of bounds");
		for (unsigned i = 0; i < PN; ++i) {
			const uint8_t* P = Data.data() + PO + i * PE;
			Segment S{read32le(P), read32le(P + 4), read64le(P + 8), read64le(P + 16), read64le(P + 32)};
			if (!range(S.Off, S.Size) || S.Size > read64le(P + 40) || S.VA > UINT64_MAX - S.Size)
				return bad("segment out of bounds");
			Segments.push_back(S);
		}
		ShOff = read64le(Data.data() + 40); ShSize = read16le(Data.data() + 58); ShNum = read16le(Data.data() + 60);
		if (ShNum && (ShSize < 64 || !range(ShOff, ShSize * ShNum))) return bad("section headers out of bounds");
		for (auto S : Segments) {
			if (S.Type == 2) {
				if (S.Size % 16) return bad("bad dynamic size");
				for (uint64_t O = S.Off; O < S.Off + S.Size; O += 16) {
					uint64_t Tag = read64le(Data.data() + O);
					if (!Tag) break;
					if (Tag == 17 || Tag == 18 || Tag == 19 || Tag == 0x6000000f || Tag == 0x60000010)
						UnsupportedRelocations = true;
					if (Tag == 0x6ffffff9) RelaCounts.push_back(O + 8);
					if (Tag == 7 || Tag == 8 || Tag == 9 || Tag == 23 || Tag == 2 || Tag == 20 || Tag == 36 || Tag == 35 ||
						Tag == 0x60000011 || Tag == 0x60000012 || Tag == 0x6fffe000 || Tag == 0x6fffe001)
						if (!Dynamic.emplace(Tag, O + 8).second) return bad("duplicate dynamic relocation tag");
				}
			}
			if (S.Type != 1 || (S.Flags & 1)) continue;
			for (uint64_t O = S.Off; O + 8 <= S.Off + S.Size; O += 8) {
				if (read64le(Data.data() + O) != Magic) continue;
				if (!range(O, HeaderSize) || HeaderSize > S.Size - (O - S.Off)) return bad("truncated descriptor");
				const uint8_t* D = Data.data() + O;
				uint32_t Count = read32le(D + CountOffset), State = read32le(D + StateOffset), Role = read32le(D + RoleOffset);
				uint64_t Size = HeaderSize + uint64_t(Count) * RecordSize;
				if (read32le(D + 8) != Version || State > 1 || !Count || (Role != HandlerRole && Role != EngineRole) ||
					(Role == EngineRole && Count != 1) || read64le(D + 24) || Size > S.Size - (O - S.Off)) return bad("invalid descriptor version/state/range");
				Descriptors.push_back({O, S.VA + O - S.Off, Count, State});
				unsigned Targets = 0;
				for (unsigned i = 0; i < Count; ++i) {
					const uint8_t* R = D + HeaderSize + i * RecordSize;
					uint32_t Rot = read32le(R + RotateOffset), Kind = read32le(R + KindOffset);
					if (!Rot || Rot > 63 || Kind > 1) return bad("invalid slot parameters");
					Targets += Kind;
				}
				if (!Targets) return bad("descriptor has no encoded target");
				O += Size - 8;
			}
		}
		if (Descriptors.empty()) return Error::success();
		if (UnsupportedRelocations) return bad("unsupported REL/Android REL relocation format");
		if (Dynamic.count(20) && read64le(Data.data() + Dynamic[20]) != 7)
			return bad("PLT relocations require RELA");
		if (read16le(Data.data() + 16) != 3) return bad("encoded targets require PIE");
		auto Overlap = [](uint64_t A, uint64_t AN, uint64_t B, uint64_t BN) {
			return AN && BN && (A <= B ? B - A < AN : A - B < BN);
		};
		// 同一文件范围或 VA 不能被多份 PT_LOAD 解释成不同 descriptor 地址。
		for (unsigned i = 0; i < Segments.size(); ++i) if (Segments[i].Type == 1)
			for (unsigned j = i + 1; j < Segments.size(); ++j) if (Segments[j].Type == 1)
				if (Overlap(Segments[i].Off, Segments[i].Size, Segments[j].Off, Segments[j].Size) ||
					Overlap(Segments[i].VA, Segments[i].Size, Segments[j].VA, Segments[j].Size))
					return bad("ambiguous overlapping load segments");
		std::sort(Descriptors.begin(), Descriptors.end(), [](auto A, auto B) { return A.Off < B.Off; });
		for (unsigned i = 1; i < Descriptors.size(); ++i)
			if (Descriptors[i].Off < Descriptors[i-1].Off + HeaderSize + uint64_t(Descriptors[i-1].Count) * RecordSize)
				return bad("overlapping descriptors");
		if (auto E = block(7, 8, 0)) return E;
		if (auto E = block(0x60000011, 0x60000012, 1)) return E;
		if (auto E = block(36, 35, 2)) return E;
		if (auto E = block(0x6fffe000, 0x6fffe001, 2)) return E;
		if (auto E = block(23, 2, 0)) return E;
		// 改写重定位表/元数据不得反过来覆盖 descriptor 或控制 ELF 装载的头部。
		for (auto D : Descriptors) {
			uint64_t Size = HeaderSize + uint64_t(D.Count) * RecordSize;
			if (Overlap(D.Off, Size, 0, 64) || Overlap(D.Off, Size, PO, PN * PE) ||
				Overlap(D.Off, Size, ShOff, ShSize * ShNum)) return bad("descriptor overlaps ELF headers");
			for (auto S : Segments) if (S.Type == 2 && Overlap(D.Off, Size, S.Off, S.Size))
				return bad("descriptor overlaps dynamic metadata");
			for (auto B : Blocks) if (Overlap(D.Off, Size, B.Off, B.Size))
				return bad("relocation block overlaps descriptor");
		}
		for (auto B : Blocks) {
			if (Overlap(B.Off, B.Size, 0, 64) || Overlap(B.Off, B.Size, PO, PN * PE) ||
				Overlap(B.Off, B.Size, ShOff, ShSize * ShNum)) return bad("relocation block overlaps ELF headers");
			for (auto S : Segments) if (S.Type == 2 && Overlap(B.Off, B.Size, S.Off, S.Size))
				return bad("relocation block overlaps dynamic metadata");
		}
		return Error::success();
	}
	Error block(uint64_t AddressTag, uint64_t SizeTag, unsigned Kind) {
		if (!Dynamic.count(AddressTag) && !Dynamic.count(SizeTag)) return Error::success();
		if (!Dynamic.count(AddressTag) || !Dynamic.count(SizeTag)) return bad("incomplete relocation tags");
		uint64_t Size = read64le(Data.data() + Dynamic[SizeTag]);
		if (!Size) return Error::success();
		auto Off = fileOffset(read64le(Data.data() + Dynamic[AddressTag]), Size);
		if (!Off) return Off.takeError();
		for (auto B : Blocks) if (*Off < B.Off + B.Size && B.Off < *Off + Size) return bad("overlapping relocation blocks");
		Block B{*Off, Size, Dynamic[SizeTag], Kind, {}};
		const uint8_t* P = Data.data() + *Off, *End = P + Size;
		if (Kind == 0) {
			if (Size % 24) return bad("invalid RELA size");
			for (; P < End; P += 24) B.Relocs.push_back({read64le(P), read64le(P + 8), read64le(P + 16)});
		} else if (Kind == 1) {
			if (Size < 4 || std::memcmp(P, "APS2", 4)) return bad("invalid APS2 header");
			P += 4; const char* Error = nullptr;
			auto Read = [&]() { unsigned N = 0; int64_t V = decodeSLEB128(P, &N, End, &Error); if (!Error) P += N; return V; };
			int64_t Count = Read(); uint64_t Slot = Read(), Add = 0;
			if (Error || Count < 0 || uint64_t(Count) > Data.size() / 8) return bad("invalid APS2 count");
			while (Count > 0 && !Error) {
				int64_t N = Read(), Flags = Read();
				if (Error || N <= 0 || N > Count || Flags < 0 || Flags > 15 || ((Flags & 4) && !(Flags & 8))) return bad("invalid APS2 group");
				uint64_t Delta = (Flags & 2) ? Read() : 0, Info = (Flags & 1) ? Read() : 0;
				if ((Flags & 12) == 12) Add += Read();
				for (int64_t i = 0; i < N && !Error; ++i) {
					Slot += (Flags & 2) ? Delta : uint64_t(Read());
					uint64_t RI = (Flags & 1) ? Info : uint64_t(Read());
					if ((Flags & 8) && !(Flags & 4)) Add += Read();
					if (!(Flags & 8)) Add = 0;
					B.Relocs.push_back({Slot, RI, Add});
				}
				Count -= N;
			}
			if (Error || P != End) return bad("truncated or trailing APS2 data");
		} else {
			if (Size % 8) return bad("invalid RELR size");
			uint64_t Where = 0;
			auto AddSlot = [&](uint64_t Slot) -> Error {
				auto O = fileOffset(Slot, 8); if (!O) return O.takeError();
				B.Relocs.push_back({Slot, 1027, read64le(Data.data() + *O)}); return Error::success();
			};
			for (; P < End; P += 8) {
				uint64_t V = read64le(P);
				if (!(V & 1)) { if (V % 8) return bad("unaligned RELR address"); if (auto E = AddSlot(V)) return E; Where = V + 8; }
				else {
					if (!Where || Where > UINT64_MAX - 63 * 8) return bad("invalid RELR bitmap");
					for (unsigned i = 0; i < 63; ++i) if (V & (uint64_t(1) << (i + 1))) if (auto E = AddSlot(Where + i * 8)) return E;
					Where += 63 * 8;
				}
			}
		}
		Blocks.push_back(std::move(B)); return Error::success();
	}
};

std::vector<uint8_t> serialize(const Block& B, ArrayRef<Reloc> Rs) {
	std::vector<uint8_t> V;
	auto Put = [&](uint64_t X) { for (unsigned i = 0; i < 8; ++i) V.push_back(X >> (8 * i)); };
	auto Sleb = [&](uint64_t X) { uint8_t T[16]; unsigned N = encodeSLEB128(int64_t(X), T); V.insert(V.end(), T, T + N); };
	if (B.Kind == 0) for (auto R : Rs) { Put(R.Slot); Put(R.Info); Put(R.Add); }
	else if (B.Kind == 1) {
		V = {'A','P','S','2'}; Sleb(Rs.size()); Sleb(0);
		uint64_t Slot = 0, Add = 0;
		auto DeltaRun = [&](unsigned I, uint64_t Previous) {
			uint64_t Delta = Rs[I].Slot - Previous;
			unsigned N = 1;
			while (I + N < Rs.size() && Rs[I + N].Info == Rs[I].Info &&
				Rs[I + N].Slot - Rs[I + N - 1].Slot == Delta) ++N;
			return N;
		};
		for (unsigned i = 0; i < Rs.size();) {
			uint64_t Delta = Rs[i].Slot - Slot, Info = Rs[i].Info;
			unsigned N = DeltaRun(i, Slot);
			bool GroupOffsets = N >= 8;
			if (!GroupOffsets) {
				// 不等间隔仍可共享 Info，避免为每条重定位重复写四个组头字段。
				N = 1;
				while (i + N < Rs.size() && Rs[i + N].Info == Info &&
					DeltaRun(i + N, Rs[i + N - 1].Slot) < 8) ++N;
			}
			uint64_t AddDelta = Rs[i].Add - Add;
			bool GroupAddends = true;
			for (unsigned j = 1; j < N; ++j)
				// APS2 共享的是整组的最终 addend，而不是逐项递增的 delta。
				if (Rs[i + j].Add != Rs[i].Add) GroupAddends = false;
			Sleb(N); Sleb(9 | (GroupOffsets ? 2 : 0) | (GroupAddends ? 4 : 0));
			if (GroupOffsets) Sleb(Delta);
			Sleb(Info);
			if (GroupAddends) Sleb(AddDelta);
			for (unsigned j = 0; j < N; ++j) {
				if (!GroupOffsets) Sleb(Rs[i + j].Slot - Slot);
				if (!GroupAddends) Sleb(Rs[i + j].Add - Add);
				Slot = Rs[i + j].Slot; Add = Rs[i + j].Add;
			}
			Slot = Rs[i + N - 1].Slot; i += N;
		}
	} else {
		unsigned i = 0;
		while (i < Rs.size()) {
			uint64_t Where = Rs[i++].Slot; Put(Where); Where += 8;
			while (i < Rs.size() && Rs[i].Slot >= Where && Rs[i].Slot - Where < 63 * 8) {
				uint64_t Bitmap = 1;
				while (i < Rs.size() && Rs[i].Slot >= Where && Rs[i].Slot - Where < 63 * 8) {
					Bitmap |= uint64_t(1) << (1 + (Rs[i++].Slot - Where) / 8);
				}
				Put(Bitmap); Where += 63 * 8;
			}
		}
	}
	return V;
}

Expected<unsigned> process(ArrayRef<uint8_t> In, MutableArrayRef<uint8_t> Out, bool Finalize) {
	Parser P(In); if (auto E = P.parse()) return std::move(E);
	if (P.Descriptors.empty()) return 0;
	std::map<uint64_t, Reloc> Relocations;
	for (auto& B : P.Blocks) for (auto R : B.Relocs)
		if (!Relocations.emplace(R.Slot, R).second) return bad("duplicate relocation address");
	std::set<uint64_t> Remove;
	struct Change { uint64_t Off, Word; };
	std::vector<Change> Changes;
	for (auto D : P.Descriptors) {
		if (!Finalize && !D.State) return bad("pending descriptor; run targets before verify/audit");
		std::set<uint64_t> Allowed;
		for (unsigned i = 0; i < D.Count; ++i) {
			uint64_t Off = D.Off + HeaderSize + i * RecordSize, VA = D.VA + HeaderSize + i * RecordSize;
			const uint8_t* R = In.data() + Off;
			if (!read32le(R + KindOffset)) continue;
			uint64_t Target;
			if (!D.State) {
				auto It = Relocations.find(VA);
				if (It == Relocations.end() || It->second.Info != 1027) return bad("slot lacks symbol-free AArch64 RELATIVE relocation");
				Target = It->second.Add; Allowed.insert(VA); Remove.insert(VA);
				Changes.push_back({Off, encode(Target - VA, read64le(R + KeyOffset), read64le(R + AddOffset), read32le(R + RotateOffset))});
			} else {
				if (Relocations.count(VA)) return bad("processed slot still has relocation");
				Target = VA + decode(read64le(R), read64le(R + KeyOffset), read64le(R + AddOffset), read32le(R + RotateOffset));
			}
			if (!P.executable(Target)) return bad("decoded target outside executable segment");
		}
		for (auto It = Relocations.lower_bound(D.VA >= 7 ? D.VA - 7 : 0); It != Relocations.end() && It->first < D.VA + HeaderSize + uint64_t(D.Count) * RecordSize; ++It)
			if (!Allowed.count(It->first)) return bad("relocation overlaps descriptor metadata/non-target");
	}
	if (!Finalize || Remove.empty()) return P.Descriptors.size();
	// 先完成全部改写计算和空间检查，之后才复制提交。
	std::vector<std::pair<Block, std::vector<uint8_t>>> NewBlocks;
	for (auto& B : P.Blocks) {
		std::vector<Reloc> Keep;
		for (auto R : B.Relocs) if (!Remove.count(R.Slot)) Keep.push_back(R);
		if (Keep.size() == B.Relocs.size()) continue;
		if (B.Kind == 2) std::sort(Keep.begin(), Keep.end(), [](auto A, auto B) { return A.Slot < B.Slot; });
		auto Bytes = serialize(B, Keep);
		if (Bytes.size() > B.Size) return bad("filtered relocation encoding exceeds original space");
		NewBlocks.push_back({B, std::move(Bytes)});
	}
	std::copy(In.begin(), In.end(), Out.begin());
	for (auto& Entry : NewBlocks) {
		auto& B = Entry.first; auto& V = Entry.second;
		std::fill(Out.begin() + B.Off, Out.begin() + B.Off + B.Size, 0);
		std::copy(V.begin(), V.end(), Out.begin() + B.Off);
		write64le(Out.data() + B.SizeField, V.size());
		for (unsigned i = 0; i < P.ShNum; ++i) {
			uint8_t* S = Out.data() + P.ShOff + i * P.ShSize;
			if (read64le(S + 24) == B.Off && read64le(S + 32) == B.Size) write64le(S + 32, V.size());
		}
	}
	for (uint64_t Off : P.RelaCounts) write64le(Out.data() + Off, 0);
	for (auto C : Changes) write64le(Out.data() + C.Off, C.Word);
	for (auto D : P.Descriptors) write32le(Out.data() + D.Off + StateOffset, 1);
	return P.Descriptors.size();
}
} // namespace

Expected<unsigned> llvm::finalizeVMTargets(MutableArrayRef<uint8_t> Image) {
	std::vector<uint8_t> Result(Image.size());
	auto R = process(Image, Result, true);
	if (!R) return R.takeError();
	if (*R) {
		// 幂等处理时 process 不写 output。
		Parser P(Image); if (auto E = P.parse()) return std::move(E);
		bool Pending = std::any_of(P.Descriptors.begin(), P.Descriptors.end(), [](auto D) { return !D.State; });
		if (Pending) std::copy(Result.begin(), Result.end(), Image.begin());
	}
	return *R;
}
Expected<unsigned> llvm::verifyVMTargets(ArrayRef<uint8_t> Image) { return process(Image, {}, false); }
