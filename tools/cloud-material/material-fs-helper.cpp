#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <dirent.h>
#include <fcntl.h>
#include <set>
#include <string>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <vector>

namespace {

constexpr const char* LockName = ".xovm-publish.lock";

struct LockedRoot {
	std::string Path;
	int Argument = -1;
	int Directory = -1;
	int Lock = -1;
	dev_t Device = 0;
	ino_t Inode = 0;
};

struct WitnessEntry {
	std::string Name;
	mode_t Mode = 0;
	uid_t Owner = 0;
	nlink_t LinkCount = 0;
	uint64_t Size = 0;
	std::string Hash;
};

uint32_t rotateRight(uint32_t Value, unsigned Count) {
	return (Value >> Count) | (Value << (32 - Count));
}

class SHA256 {
public:
	void update(const uint8_t* Data, size_t Size) {
		Length += Size;
		while (Size) {
			size_t Count = std::min(Size, Buffer.size() - Used);
			std::copy(Data, Data + Count, Buffer.begin() + Used);
			Data += Count;
			Size -= Count;
			Used += Count;
			if (Used == Buffer.size()) { transform(Buffer.data()); Used = 0; }
		}
	}

	std::string final() {
		uint64_t Bits = Length * 8;
		Buffer[Used++] = 0x80;
		if (Used > 56) {
			std::fill(Buffer.begin() + Used, Buffer.end(), 0);
			transform(Buffer.data());
			Used = 0;
		}
		std::fill(Buffer.begin() + Used, Buffer.begin() + 56, 0);
		for (unsigned I = 0; I < 8; ++I)
			Buffer[63 - I] = static_cast<uint8_t>(Bits >> (I * 8));
		transform(Buffer.data());
		static constexpr char Hex[] = "0123456789abcdef";
		std::string Result;
		Result.reserve(64);
		for (uint32_t Value : State)
			for (int Shift : {28, 24, 20, 16, 12, 8, 4, 0})
				Result.push_back(Hex[(Value >> Shift) & 15]);
		return Result;
	}

private:
	void transform(const uint8_t* Block) {
		static constexpr uint32_t K[64] = {
			0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
			0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
			0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
			0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
			0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
			0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
			0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
			0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
		};
		uint32_t W[64];
		for (unsigned I = 0; I < 16; ++I)
			W[I] = static_cast<uint32_t>(Block[I * 4]) << 24 |
				static_cast<uint32_t>(Block[I * 4 + 1]) << 16 |
				static_cast<uint32_t>(Block[I * 4 + 2]) << 8 | Block[I * 4 + 3];
		for (unsigned I = 16; I < 64; ++I) {
			uint32_t S0 = rotateRight(W[I - 15], 7) ^ rotateRight(W[I - 15], 18) ^ (W[I - 15] >> 3);
			uint32_t S1 = rotateRight(W[I - 2], 17) ^ rotateRight(W[I - 2], 19) ^ (W[I - 2] >> 10);
			W[I] = W[I - 16] + S0 + W[I - 7] + S1;
		}
		uint32_t A = State[0], B = State[1], C = State[2], D = State[3];
		uint32_t E = State[4], F = State[5], G = State[6], H = State[7];
		for (unsigned I = 0; I < 64; ++I) {
			uint32_t S1 = rotateRight(E, 6) ^ rotateRight(E, 11) ^ rotateRight(E, 25);
			uint32_t Choice = (E & F) ^ (~E & G);
			uint32_t T1 = H + S1 + Choice + K[I] + W[I];
			uint32_t S0 = rotateRight(A, 2) ^ rotateRight(A, 13) ^ rotateRight(A, 22);
			uint32_t Majority = (A & B) ^ (A & C) ^ (B & C);
			uint32_t T2 = S0 + Majority;
			H = G; G = F; F = E; E = D + T1; D = C; C = B; B = A; A = T1 + T2;
		}
		State[0] += A; State[1] += B; State[2] += C; State[3] += D;
		State[4] += E; State[5] += F; State[6] += G; State[7] += H;
	}

	std::array<uint32_t, 8> State{0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
		0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
	std::array<uint8_t, 64> Buffer{};
	uint64_t Length = 0;
	size_t Used = 0;
};

[[noreturn]] void fail(const char* Code) {
	std::printf("ERR %s\n", Code);
	std::fflush(stdout);
	std::exit(1);
}

bool sameNamedLock(const LockedRoot& Root) {
	struct stat Opened {}, Named {};
	return ::fstat(Root.Lock, &Opened) == 0 &&
		::fstatat(Root.Directory, LockName, &Named, AT_SYMLINK_NOFOLLOW) == 0 &&
		S_ISREG(Named.st_mode) && (Named.st_mode & 0777u) == 0600u &&
		Named.st_uid == ::geteuid() && Named.st_nlink == 1 &&
		Opened.st_dev == Named.st_dev && Opened.st_ino == Named.st_ino;
}

LockedRoot openRoot(const char* Path, int Argument) {
	LockedRoot Root;
	Root.Path = Path;
	Root.Argument = Argument;
	Root.Directory = ::open(Path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
	if (Root.Directory < 0) fail("lock_open");
	struct stat Directory {};
	if (::fstat(Root.Directory, &Directory) != 0 || !S_ISDIR(Directory.st_mode) ||
		Directory.st_uid != ::geteuid()) fail("lock_owner");
	Root.Device = Directory.st_dev;
	Root.Inode = Directory.st_ino;
	Root.Lock = ::openat(Root.Directory, LockName,
		O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
	if (Root.Lock < 0) fail("lock_open");
	return Root;
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

bool decodeHex(const char* Input, std::string& Output) {
	size_t Length = std::strlen(Input);
	if (!Length || Length % 2 || Length > 510) return false;
	Output.clear();
	for (size_t I = 0; I < Length; I += 2) {
		auto Digit = [](char Value) -> int {
			if (Value >= '0' && Value <= '9') return Value - '0';
			if (Value >= 'a' && Value <= 'f') return Value - 'a' + 10;
			return -1;
		};
		int High = Digit(Input[I]);
		int Low = Digit(Input[I + 1]);
		if (High < 0 || Low < 0) return false;
		char Value = static_cast<char>((High << 4) | Low);
		if (!Value || Value == '/') return false;
		Output.push_back(Value);
	}
	return Output != "." && Output != "..";
}

bool validHash(const std::string& Value) {
	return Value.size() == 64 && std::all_of(Value.begin(), Value.end(), [](char C) {
		return (C >= '0' && C <= '9') || (C >= 'a' && C <= 'f');
	});
}

bool sameStatIdentity(const struct stat& A, const struct stat& B) {
	return A.st_dev == B.st_dev && A.st_ino == B.st_ino && A.st_size == B.st_size &&
		A.st_mode == B.st_mode && A.st_uid == B.st_uid && A.st_nlink == B.st_nlink &&
		A.st_mtim.tv_sec == B.st_mtim.tv_sec && A.st_mtim.tv_nsec == B.st_mtim.tv_nsec &&
		A.st_ctim.tv_sec == B.st_ctim.tv_sec && A.st_ctim.tv_nsec == B.st_ctim.tv_nsec;
}

bool hashFile(int FD, std::string& Hash) {
	if (::lseek(FD, 0, SEEK_SET) < 0) return false;
	SHA256 Digest;
	std::array<uint8_t, 65536> Buffer{};
	for (;;) {
		ssize_t Count = ::read(FD, Buffer.data(), Buffer.size());
		if (Count < 0 && errno == EINTR) continue;
		if (Count < 0) return false;
		if (Count == 0) break;
		Digest.update(Buffer.data(), static_cast<size_t>(Count));
	}
	Hash = Digest.final();
	return true;
}

bool copyFile(int Source, int Directory, const std::string& Name) {
	if (::lseek(Source, 0, SEEK_SET) < 0) return false;
	int Destination = ::openat(Directory, Name.c_str(),
		O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
	if (Destination < 0) return false;
	std::array<char, 65536> Buffer{};
	bool Success = true;
	for (;;) {
		ssize_t Count = ::read(Source, Buffer.data(), Buffer.size());
		if (Count < 0 && errno == EINTR) continue;
		if (Count < 0) { Success = false; break; }
		if (!Count) break;
		for (ssize_t Offset = 0; Offset < Count;) {
			ssize_t Written = ::write(Destination, Buffer.data() + Offset, Count - Offset);
			if (Written < 0 && errno == EINTR) continue;
			if (Written <= 0) { Success = false; break; }
			Offset += Written;
		}
		if (!Success) break;
	}
	return ::close(Destination) == 0 && Success;
}

bool verifyDirectory(int Directory, mode_t DirectoryMode, uid_t DirectoryOwner,
	const std::vector<WitnessEntry>& Witness,
	bool InjectFault) {
	struct stat DirectoryBefore {}, DirectoryAfter {};
	if (::fstat(Directory, &DirectoryBefore) != 0 || !S_ISDIR(DirectoryBefore.st_mode) ||
		(DirectoryBefore.st_mode & 0777u) != DirectoryMode ||
		DirectoryBefore.st_uid != DirectoryOwner) return false;
	std::set<std::string> Expected;
	for (const WitnessEntry& Entry : Witness)
		if (!Expected.insert(Entry.Name).second) return false;
	if (::lseek(Directory, 0, SEEK_SET) < 0) return false;
	DIR* Stream = ::fdopendir(::dup(Directory));
	if (!Stream) return false;
	bool Valid = true;
	while (dirent* Entry = ::readdir(Stream)) {
		std::string Name = Entry->d_name;
		if (Name == "." || Name == "..") continue;
		if (!Expected.erase(Name)) { Valid = false; break; }
	}
	::closedir(Stream);
	if (!Valid || !Expected.empty()) return false;
	struct OpenedMember { const WitnessEntry* Expected; int FD; struct stat Before; };
	std::vector<OpenedMember> Members;
	for (const WitnessEntry& Entry : Witness) {
		int FD = ::openat(Directory, Entry.Name.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
		struct stat Before {};
		if (FD < 0 || ::fstat(FD, &Before) != 0 || !S_ISREG(Before.st_mode) ||
			(Before.st_mode & 0777u) != Entry.Mode || Before.st_uid != Entry.Owner ||
			Before.st_nlink != Entry.LinkCount ||
			static_cast<uint64_t>(Before.st_size) != Entry.Size) {
			if (FD >= 0) ::close(FD);
			Valid = false;
			break;
		}
		Members.push_back({&Entry, FD, Before});
	}
	for (OpenedMember& Member : Members) {
		std::string Hash;
		if (!hashFile(Member.FD, Hash) || Hash != Member.Expected->Hash) Valid = false;
	}
	if (Valid && InjectFault && !Members.empty() &&
		std::getenv("XOVM_HELPER_FAULT_MEMBER_CONTENT")) {
		int FD = ::openat(Directory, Members.front().Expected->Name.c_str(),
			O_WRONLY | O_TRUNC | O_CLOEXEC | O_NOFOLLOW);
		Valid = FD >= 0 && ::write(FD, "x", 1) == 1 && ::close(FD) == 0;
	}
	if (Valid && InjectFault && !Members.empty() &&
		std::getenv("XOVM_HELPER_FAULT_MEMBER_SWAP")) {
		const std::string& Name = Members.front().Expected->Name;
		std::string Displaced = Name + ".displaced";
		Valid = ::renameat(Directory, Name.c_str(), Directory, Displaced.c_str()) == 0 &&
			copyFile(Members.front().FD, Directory, Name);
	}
	for (OpenedMember& Member : Members) {
		struct stat After {}, Named {};
		if (::fstat(Member.FD, &After) != 0 ||
			!sameStatIdentity(Member.Before, After) ||
			::fstatat(Directory, Member.Expected->Name.c_str(), &Named,
				AT_SYMLINK_NOFOLLOW) != 0 || !sameStatIdentity(After, Named))
			Valid = false;
		::close(Member.FD);
	}
	return Valid && ::fstat(Directory, &DirectoryAfter) == 0 &&
		sameStatIdentity(DirectoryBefore, DirectoryAfter);
}

bool verifyNamedDirectory(int Root, const std::string& Name,
	mode_t DirectoryMode, uid_t DirectoryOwner,
	const std::vector<WitnessEntry>& Witness,
	const struct stat* Expected,
	bool InjectFault) {
	int Directory = ::openat(Root, Name.c_str(),
		O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
	if (Directory < 0) return false;
	struct stat Opened {}, Named {};
	bool Valid = ::fstat(Directory, &Opened) == 0 &&
		(!Expected || (Opened.st_dev == Expected->st_dev && Opened.st_ino == Expected->st_ino)) &&
		verifyDirectory(Directory, DirectoryMode, DirectoryOwner, Witness, InjectFault);
	if (Valid && InjectFault && std::getenv("XOVM_HELPER_FAULT_SWAP_DURING_COMPARE")) {
		std::string Displaced = Name + ".displaced";
		Valid = ::renameat(Root, Name.c_str(), Root, Displaced.c_str()) == 0 &&
			::mkdirat(Root, Name.c_str(), DirectoryMode) == 0;
	}
	Valid = Valid &&
		::fstatat(Root, Name.c_str(), &Named, AT_SYMLINK_NOFOLLOW) == 0 &&
		sameStatIdentity(Opened, Named);
	::close(Directory);
	return Valid;
}

} // namespace

int main(int ArgumentCount, char** Arguments) {
	if (ArgumentCount < 2) return 2;
	std::vector<LockedRoot> Roots;
	for (int I = 1; I < ArgumentCount; ++I) Roots.push_back(openRoot(Arguments[I], I - 1));
	std::sort(Roots.begin(), Roots.end(), [](const LockedRoot& Left, const LockedRoot& Right) {
		return std::tie(Left.Device, Left.Inode) < std::tie(Right.Device, Right.Inode);
	});
	Roots.erase(std::unique(Roots.begin(), Roots.end(), [](const LockedRoot& Left,
		const LockedRoot& Right) {
		return Left.Device == Right.Device && Left.Inode == Right.Inode;
	}), Roots.end());
	for (LockedRoot& Root : Roots) {
		if (::flock(Root.Lock, LOCK_EX) != 0 || ::flock(Root.Directory, LOCK_EX) != 0 ||
			!sameNamedLock(Root)) fail("lock_invalid");
	}
	std::printf("READY\n");
	std::fflush(stdout);
	int Stage = -1;
	int StageRoot = -1;
	std::string StageName;
	std::vector<WitnessEntry> Witness;
	mode_t WitnessDirectoryMode = 0;
	uid_t WitnessDirectoryOwner = 0;
	bool WitnessReady = false;
	int InheritedStage = -1;
	if (const char* Value = std::getenv("XOVM_HELPER_STAGE_FD"))
		InheritedStage = std::atoi(Value);

	char Line[8192];
	while (std::fgets(Line, sizeof(Line), stdin)) {
		char Command[32] = {}, SourceHex[511] = {}, DestinationHex[511] = {};
		unsigned long long ExpectedDevice = 0;
		unsigned long long ExpectedInode = 0;
		int RootIndex = -1;
		if (std::sscanf(Line, "%31s %d %510s %510s %llu %llu", Command, &RootIndex,
			SourceHex, DestinationHex, &ExpectedDevice, &ExpectedInode) < 1)
			fail("protocol");
		for (const LockedRoot& Root : Roots)
			if (!sameNamedLock(Root)) fail("lock_replaced");
		if (std::strcmp(Command, "WITNESS_DIR") == 0) {
			unsigned Mode = 0, Owner = 0;
			if (WitnessReady || WitnessDirectoryMode ||
				std::sscanf(Line, "%*s %u %u", &Mode, &Owner) != 2 ||
				Mode != 0700 || Owner != ::geteuid())
				fail("witness_invalid");
			WitnessDirectoryMode = static_cast<mode_t>(Mode);
			WitnessDirectoryOwner = static_cast<uid_t>(Owner);
			std::printf("WITNESS_DIR_OK\n");
			std::fflush(stdout);
			continue;
		}
		if (std::strcmp(Command, "WITNESS") == 0) {
			char NameHex[511] = {}, Type[16] = {}, Hash[65] = {};
			unsigned Mode = 0, Owner = 0, LinkCount = 0;
			unsigned long long Size = 0;
			std::string Name;
			if (WitnessReady || !WitnessDirectoryMode || Witness.size() >= 2 ||
				std::sscanf(Line, "%*s %510s %15s %u %u %u %llu %64s",
					NameHex, Type, &Mode, &Owner, &LinkCount, &Size, Hash) != 7 ||
				!decodeHex(NameHex, Name) ||
				std::strcmp(Type, "file") != 0 || Mode != 0600 ||
				Owner != ::geteuid() || LinkCount != 1 ||
				(Name != "public-manifest.json" && Name != "registration.private.json") ||
				!validHash(Hash) || std::any_of(Witness.begin(), Witness.end(), [&](const WitnessEntry& Entry) {
					return Entry.Name == Name;
				})) fail("witness_invalid");
			Witness.push_back({std::move(Name), static_cast<mode_t>(Mode),
				static_cast<uid_t>(Owner), static_cast<nlink_t>(LinkCount), Size, Hash});
			std::printf("WITNESS_OK\n");
			std::fflush(stdout);
			continue;
		}
		if (std::strcmp(Command, "WITNESS_DONE") == 0) {
			if (WitnessReady || WitnessDirectoryMode != 0700 || Witness.size() != 2)
				fail("witness_invalid");
			WitnessReady = true;
			std::printf("WITNESS_READY\n");
			std::fflush(stdout);
			continue;
		}
		if (std::strcmp(Command, "VERIFY") == 0) {
			std::printf("OK\n");
			std::fflush(stdout);
			continue;
		}
		auto It = std::find_if(Roots.begin(), Roots.end(), [&](const LockedRoot& Root) {
			return Root.Argument == RootIndex;
		});
		std::string Source;
		std::string Destination;
		if (It == Roots.end() || !WitnessReady || !decodeHex(SourceHex, Source)) fail("protocol");
		if (std::strcmp(Command, "OPEN") == 0) {
			if (Stage >= 0) fail("protocol");
			Stage = ::openat(It->Directory, Source.c_str(),
				O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
			if (Stage < 0) fail("source_invalid");
			struct stat Opened {};
			if (::fstat(Stage, &Opened) != 0 || Opened.st_dev != ExpectedDevice ||
				Opened.st_ino != ExpectedInode ||
				!verifyDirectory(Stage, WitnessDirectoryMode, WitnessDirectoryOwner,
					Witness, false))
				fail("source_replaced");
			StageRoot = RootIndex;
			StageName = Source;
			std::printf("OPENED\n");
			std::fflush(stdout);
			continue;
		}
		if (std::strcmp(Command, "OPENFD") == 0) {
			if (Stage >= 0 || InheritedStage < 0) fail("protocol");
			Stage = ::dup(InheritedStage);
			struct stat Opened {};
			if (Stage < 0 || ::fstat(Stage, &Opened) != 0 ||
				Opened.st_dev != ExpectedDevice || Opened.st_ino != ExpectedInode ||
				!verifyDirectory(Stage, WitnessDirectoryMode, WitnessDirectoryOwner,
					Witness, false))
				fail("source_replaced");
			StageRoot = RootIndex;
			std::printf("OPENED\n");
			std::fflush(stdout);
			continue;
		}
		if (std::strcmp(Command, "RECONCILE") == 0) {
			if (Stage < 0 || StageRoot != RootIndex ||
				!decodeHex(DestinationHex, Destination)) fail("protocol");
			struct stat Held {};
			if (::fstat(Stage, &Held) != 0 ||
				!verifyNamedDirectory(It->Directory, Destination, WitnessDirectoryMode,
					WitnessDirectoryOwner, Witness, &Held, true)) {
				std::printf("NOT_SAME\n");
				std::fflush(stdout);
				continue;
			}
			bool LocksValid = true;
			for (const LockedRoot& Root : Roots)
				LocksValid &= sameNamedLock(Root);
			if (!LocksValid) {
				std::printf("INDETERMINATE\n");
				std::fflush(stdout);
				continue;
			}
			std::printf(::fsync(It->Directory) == 0 ?
				"EXISTS_SAME\n" : "EXISTS_SAME_UNKNOWN\n");
			std::fflush(stdout);
			continue;
		}
		if (std::strcmp(Command, "COMMIT") != 0 || Stage < 0 ||
			StageRoot != RootIndex || StageName != Source ||
			!decodeHex(DestinationHex, Destination)) fail("protocol");
		struct stat SourceStat {}, DestinationStat {};
		struct stat HeldStat {};
		if (::fstat(Stage, &HeldStat) != 0 ||
			!verifyDirectory(Stage, WitnessDirectoryMode, WitnessDirectoryOwner,
				Witness, false) ||
			::fstatat(It->Directory, Source.c_str(), &SourceStat, AT_SYMLINK_NOFOLLOW) != 0 ||
			!S_ISDIR(SourceStat.st_mode) || HeldStat.st_dev != SourceStat.st_dev ||
			HeldStat.st_ino != SourceStat.st_ino) fail("source_invalid");
		if (::fsync(It->Directory) != 0) fail("precommit_sync");
		if (renameNoReplace(It->Directory, Source.c_str(), Destination.c_str()) != 0) {
			if (errno == EEXIST) {
				if (!verifyNamedDirectory(It->Directory, Destination, WitnessDirectoryMode,
					WitnessDirectoryOwner, Witness, nullptr, true)) {
					std::printf("EXISTS\n");
					std::fflush(stdout);
					continue;
				}
				std::printf(::fsync(It->Directory) == 0 ?
					"EXISTS_SAME\n" : "EXISTS_SAME_UNKNOWN\n");
				std::fflush(stdout);
				continue;
			}
			fail("rename_failed");
		}
		if (std::getenv("XOVM_HELPER_FAULT_EXIT_AFTER_COMMIT")) ::_exit(86);
		errno = 0;
		if (::fstatat(It->Directory, Source.c_str(), &DestinationStat, AT_SYMLINK_NOFOLLOW) == 0 ||
			errno != ENOENT ||
			::fstatat(It->Directory, Destination.c_str(), &DestinationStat,
				AT_SYMLINK_NOFOLLOW) != 0 ||
			HeldStat.st_dev != DestinationStat.st_dev ||
			HeldStat.st_ino != DestinationStat.st_ino) {
			std::printf("COMMITTED INDETERMINATE\n");
			std::fflush(stdout);
			continue;
		}
		for (const LockedRoot& Root : Roots) {
			if (!sameNamedLock(Root)) {
				std::printf("COMMITTED INDETERMINATE\n");
				std::fflush(stdout);
				goto NextCommand;
			}
		}
		if (std::getenv("XOVM_HELPER_FAULT_AFTER_COMMIT")) {
			std::printf("COMMITTED UNKNOWN\n");
			std::fflush(stdout);
			continue;
		}
		if (!verifyNamedDirectory(It->Directory, Destination, WitnessDirectoryMode,
			WitnessDirectoryOwner, Witness, &HeldStat, false)) {
			std::printf("COMMITTED INDETERMINATE\n");
			std::fflush(stdout);
			continue;
		}
		if (::fsync(It->Directory) != 0) {
			std::printf("COMMITTED UNKNOWN\n");
			std::fflush(stdout);
			continue;
		}
		std::printf("COMMITTED DURABLE\n");
		std::fflush(stdout);
	NextCommand:
		continue;
	}
	if (Stage >= 0) ::close(Stage);
	return std::getenv("XOVM_HELPER_FAULT_CLOSE") ? 9 : 0;
}
