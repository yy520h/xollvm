#include "llvm/Transforms/Obfuscator/VMWhiteBoxAES.h"
#include "llvm/Transforms/Obfuscator/Rng.h"
#include <algorithm>

using namespace llvm;
namespace {
using Nibble = std::array<uint8_t, 16>;
using ByteEncoding = std::array<Nibble, 2>;
Nibble permutation(obf::Rng& R) {
	Nibble P; for (unsigned i = 0; i < 16; ++i) P[i] = i;
	for (unsigned i = 15; i; --i) std::swap(P[i], P[R.range(i + 1)]);
	return P;
}
uint8_t inverse(const Nibble& P, uint8_t V) { return std::find(P.begin(), P.end(), V) - P.begin(); }
uint8_t encode(const ByteEncoding& P, uint8_t V) { return P[0][V & 15] | (P[1][V >> 4] << 4); }
uint8_t decode(const ByteEncoding& P, uint8_t V) { return inverse(P[0], V & 15) | (inverse(P[1], V >> 4) << 4); }
uint8_t mul(uint8_t A, uint8_t B) {
	uint8_t R = 0;
	while (B) { if (B & 1) R ^= A; A = (A << 1) ^ ((A >> 7) * 0x1b); B >>= 1; }
	return R;
}
uint8_t sbox(uint8_t X) {
	uint8_t I = 1, A = X; unsigned N = 254;
	while (N) { if (N & 1) I = mul(I, A); A = mul(A, A); N >>= 1; }
	uint8_t R = I ^ 0x63;
	for (unsigned i = 1; i < 5; ++i) R ^= uint8_t((I << i) | (I >> (8 - i)));
	return R;
}
std::array<uint8_t, 176> expand(ArrayRef<uint8_t> K) {
	std::array<uint8_t, 176> RK; std::copy(K.begin(), K.end(), RK.begin());
	uint8_t RC = 1;
	for (unsigned w = 4; w < 44; ++w) {
		std::array<uint8_t, 4> T;
		for (unsigned j = 0; j < 4; ++j) T[j] = RK[(w - 1) * 4 + j];
		if (!(w % 4)) { std::rotate(T.begin(), T.begin() + 1, T.end()); for (auto& V : T) V = sbox(V); T[0] ^= RC; RC = mul(RC, 2); }
		for (unsigned j = 0; j < 4; ++j) RK[w * 4 + j] = RK[(w - 4) * 4 + j] ^ T[j];
	}
	return RK;
}
}

Expected<VMWhiteBoxTables> llvm::VMWhiteBoxAES::generate(ArrayRef<uint8_t> Key, uint64_t Seed) {
	if (Key.size() != 16) return createStringError(inconvertibleErrorCode(), "whitebox AES requires 16-byte key");
	VMWhiteBoxTables T; T.Bytes.resize(VMWhiteBoxTables::Size);
	auto RK = expand(Key); obf::Rng R(Seed);
	std::array<std::array<ByteEncoding, 16>, 10> State;
	for (unsigned r = 0; r < 10; ++r) for (auto& B : State[r]) for (auto& N : B) {
		if (r) N = permutation(R); else for (unsigned i = 0; i < 16; ++i) N[i] = i;
	}
	constexpr unsigned MC[4][4] = {{2,3,1,1}, {1,2,3,1}, {1,1,2,3}, {3,1,1,2}};
	for (unsigned r = 0; r < 9; ++r) for (unsigned c = 0; c < 4; ++c) {
		std::array<std::array<ByteEncoding, 4>, 4> Contribution;
		for (auto& Row : Contribution) for (auto& B : Row) for (auto& N : B) N = permutation(R);
		// 每个输入表输出一列贡献；首轮 key 和后续轮 key 均融合到实际表值。
		for (unsigned row = 0; row < 4; ++row) {
			unsigned Source = ((c + row) % 4) * 4 + row;
			for (unsigned x = 0; x < 256; ++x) {
				uint8_t V = sbox(decode(State[r][Source], x) ^ (r ? 0 : RK[Source]));
				for (unsigned out = 0; out < 4; ++out) {
					uint8_t Y = mul(V, MC[out][row]) ^ (row ? 0 : RK[(r + 1) * 16 + c * 4 + out]);
					T.Bytes[r * VMWhiteBoxTables::RoundBytes + (c * 4 + row) * 1024 + x * 4 + out] = encode(Contribution[row][out], Y);
				}
			}
		}
		// 编码的 nibble XOR 网络；运行时没有逆编码表或标准轮密钥。
		for (unsigned out = 0; out < 4; ++out) for (unsigned n = 0; n < 2; ++n) {
			Nibble Middle[2] = {permutation(R), permutation(R)};
			for (unsigned stage = 0; stage < 3; ++stage) {
				const Nibble& A = stage == 2 ? Middle[0] : Contribution[stage * 2][out][n];
				const Nibble& B = stage == 2 ? Middle[1] : Contribution[stage * 2 + 1][out][n];
				const Nibble& O = stage == 2 ? State[r + 1][c * 4 + out][n] : Middle[stage];
				unsigned Base = VMWhiteBoxTables::XorOffset + r * VMWhiteBoxTables::XorRoundBytes + ((c * 4 + out) * 6 + n * 3 + stage) * 256;
				for (unsigned a = 0; a < 16; ++a) for (unsigned b = 0; b < 16; ++b)
					T.Bytes[Base + a * 16 + b] = O[inverse(A, a) ^ inverse(B, b)];
			}
		}
	}
	for (unsigned p = 0; p < 16; ++p) {
		unsigned Source = (((p / 4) + p % 4) % 4) * 4 + p % 4;
		for (unsigned x = 0; x < 256; ++x) T.Bytes[VMWhiteBoxTables::LastOffset + p * 256 + x] = sbox(decode(State[9][Source], x)) ^ RK[160 + p];
	}
	return T;
}

std::array<uint8_t, 16> llvm::VMWhiteBoxAES::evaluate(const VMWhiteBoxTables& T, ArrayRef<uint8_t> Input) {
	assert(Input.size() == 16 && T.Bytes.size() == VMWhiteBoxTables::Size);
	std::array<uint8_t, 16> S, Next; std::copy(Input.begin(), Input.end(), S.begin());
	for (unsigned r = 0; r < 9; ++r) for (unsigned c = 0; c < 4; ++c) {
		uint8_t V[4][4];
		for (unsigned row = 0; row < 4; ++row) {
			unsigned X = S[((c + row) % 4) * 4 + row];
			for (unsigned out = 0; out < 4; ++out) V[row][out] = T.Bytes[r * VMWhiteBoxTables::RoundBytes + (c * 4 + row) * 1024 + X * 4 + out];
		}
		for (unsigned out = 0; out < 4; ++out) {
			unsigned Byte = 0;
			for (unsigned n = 0; n < 2; ++n) {
				unsigned Base = VMWhiteBoxTables::XorOffset + r * VMWhiteBoxTables::XorRoundBytes + ((c * 4 + out) * 6 + n * 3) * 256;
				auto Xor = [&](unsigned Stage, unsigned A, unsigned B) { return T.Bytes[Base + Stage * 256 + A * 16 + B]; };
				unsigned A = Xor(0, (V[0][out] >> (n * 4)) & 15, (V[1][out] >> (n * 4)) & 15);
				unsigned B = Xor(1, (V[2][out] >> (n * 4)) & 15, (V[3][out] >> (n * 4)) & 15);
				Byte |= Xor(2, A, B) << (n * 4);
			}
			Next[c * 4 + out] = Byte;
		}
		if (c == 3) S = Next;
	}
	for (unsigned p = 0; p < 16; ++p) Next[p] = T.Bytes[VMWhiteBoxTables::LastOffset + p * 256 + S[(((p / 4) + p % 4) % 4) * 4 + p % 4]];
	return Next;
}
