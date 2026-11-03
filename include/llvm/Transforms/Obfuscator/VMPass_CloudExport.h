//===-- VMPass_CloudExport.h - Cloud material window export -----*- C++ -*-===//
//
// Task 3/8: Export VM bytecode as cloud material windows
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_TRANSFORMS_OBFUSCATOR_VMPASS_CLOUDEXPORT_H
#define LLVM_TRANSFORMS_OBFUSCATOR_VMPASS_CLOUDEXPORT_H

#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/StringRef.h"
#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace llvm {

/// Metadata for a single cloud window
struct CloudWindowMetadata {
  std::string material_id;
  uint32_t window_id;
  uint32_t shard_id;
  std::vector<uint8_t> data;
  std::array<uint8_t, 32> commitment; // SHA256 hash
};

/// Cloud material exporter - handles splitting bytecode into windows
/// and writing them to the export directory
class CloudMaterialExporter {
public:
  /// Split bytecode into fixed-size windows
  static std::vector<CloudWindowMetadata> splitBytecodeIntoWindows(
      ArrayRef<uint8_t> bytecode,
      StringRef materialID,
      uint32_t windowSize);

  /// Write a single window file to disk
  static bool writeWindowFile(
      const CloudWindowMetadata& window,
      StringRef exportDir);

  /// Generate/update metadata.json file
  static bool writeMetadataFile(
      ArrayRef<CloudWindowMetadata> windows,
      StringRef exportDir,
      StringRef appID);

  /// Main export function - call this from VMImpl::commit()
  /// Returns true on success
  static bool exportBytecode(
      ArrayRef<uint8_t> bytecode,
      StringRef functionName,
      StringRef materialRegion,
      uint32_t windowSize,
      StringRef exportDir,
      StringRef appID);
};

} // namespace llvm

#endif // LLVM_TRANSFORMS_OBFUSCATOR_VMPASS_CLOUDEXPORT_H
