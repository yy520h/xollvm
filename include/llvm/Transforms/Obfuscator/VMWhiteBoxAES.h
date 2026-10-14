#pragma once
#include "llvm/ADT/ArrayRef.h"
#include "llvm/Support/Error.h"
#include <array>
#include <vector>

namespace llvm {
class Module; class Function; class GlobalVariable;
struct VMWhiteBoxTables {
	static constexpr unsigned RoundBytes = 16 * 256 * 4;
	static constexpr unsigned XorRoundBytes = 16 * 2 * 3 * 256;
	static constexpr unsigned XorOffset = 9 * RoundBytes;
	static constexpr unsigned LastOffset = XorOffset + 9 * XorRoundBytes;
	static constexpr unsigned Size = LastOffset + 16 * 256;
	std::vector<uint8_t> Bytes;
};
namespace VMWhiteBoxAES {
Expected<VMWhiteBoxTables> generate(ArrayRef<uint8_t> Key, uint64_t Seed);
std::array<uint8_t, 16> evaluate(const VMWhiteBoxTables& Tables, ArrayRef<uint8_t> Input);
}
GlobalVariable* emitVMWhiteBoxInstance(Module& M, const VMWhiteBoxTables& T);
Function* getVMWhiteBoxBlockFunction(Module& M);
Function* getVMWhiteBoxCTRFunction(Module& M);
} // namespace llvm
