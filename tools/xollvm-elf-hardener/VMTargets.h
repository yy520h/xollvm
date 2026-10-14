#pragma once
#include "llvm/ADT/ArrayRef.h"
#include "llvm/Support/Error.h"
namespace llvm {
Expected<unsigned> finalizeVMTargets(MutableArrayRef<uint8_t> Image);
Expected<unsigned> verifyVMTargets(ArrayRef<uint8_t> Image);
}
