//===-- VMPass_CloudExport.cpp - Cloud material window export ---*- C++ -*-===//
//
// Task 3/8: Export VM bytecode as cloud material windows
//
// This module handles the export of VM bytecode to the cloud material directory
// when cloudMaterial mode is enabled. It splits bytecode into windows, generates
// metadata, and writes window files to the export directory.
//
//===----------------------------------------------------------------------===//

#include "llvm/Transforms/Obfuscator/VMPass_CloudExport.h"
#include "llvm/Transforms/Obfuscator/ObfuscationOptions.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/SHA256.h"
#include "llvm/Support/JSON.h"
#include <fstream>
#include <random>

using namespace llvm;

namespace llvm {

// Split bytecode into fixed-size windows
std::vector<CloudWindowMetadata>
CloudMaterialExporter::splitBytecodeIntoWindows(
    ArrayRef<uint8_t> bytecode,
    StringRef materialID,
    uint32_t windowSize) {

  std::vector<CloudWindowMetadata> windows;

  if (bytecode.empty()) {
    return windows;
  }

  uint32_t totalSize = bytecode.size();
  uint32_t numWindows = (totalSize + windowSize - 1) / windowSize;

  for (uint32_t i = 0; i < numWindows; i++) {
    CloudWindowMetadata window;
    window.material_id = materialID.str();
    window.window_id = i;
    window.shard_id = 0; // Single shard for now

    uint32_t offset = i * windowSize;
    uint32_t size = std::min(windowSize, totalSize - offset);

    // Copy bytecode slice
    window.data.assign(bytecode.begin() + offset,
                       bytecode.begin() + offset + size);

    // Pad to window size if needed
    if (window.data.size() < windowSize) {
      window.data.resize(windowSize, 0);
    }

    // Compute SHA256 commitment
    auto hash = SHA256::hash(ArrayRef<uint8_t>(window.data));
    std::memcpy(window.commitment.data(), hash.data(), 32);

    windows.push_back(std::move(window));
  }

  return windows;
}

// Write a single window file
bool CloudMaterialExporter::writeWindowFile(
    const CloudWindowMetadata& window,
    StringRef exportDir) {

  SmallString<256> path(exportDir);
  sys::path::append(path, "windows");

  // Create windows subdirectory if needed
  if (auto EC = sys::fs::create_directories(path)) {
    errs() << "Failed to create windows directory: " << EC.message() << "\n";
    return false;
  }

  // Build filename: material_id_wN_sM.bin
  std::string filename = window.material_id + "_w" +
                        std::to_string(window.window_id) + "_s" +
                        std::to_string(window.shard_id) + ".bin";
  sys::path::append(path, filename);

  // Write binary data
  std::error_code EC;
  raw_fd_ostream outFile(path, EC, sys::fs::OF_None);
  if (EC) {
    errs() << "Failed to create window file " << path << ": "
           << EC.message() << "\n";
    return false;
  }

  outFile.write(reinterpret_cast<const char*>(window.data.data()),
                window.data.size());
  outFile.flush();

  return true;
}

// Generate metadata JSON file
bool CloudMaterialExporter::writeMetadataFile(
    ArrayRef<CloudWindowMetadata> windows,
    StringRef exportDir,
    StringRef appID) {

  if (windows.empty()) {
    return true;
  }

  SmallString<256> path(exportDir);
  sys::path::append(path, "metadata.json");

  // Build JSON structure
  json::Object root;
  root["app_id"] = appID.str();
  root["version"] = "1.0.0";

  json::Object materials;

  // Group windows by material_id
  std::map<std::string, std::vector<const CloudWindowMetadata*>> grouped;
  for (const auto& w : windows) {
    grouped[w.material_id].push_back(&w);
  }

  for (const auto& [matID, matWindows] : grouped) {
    json::Object material;
    material["id"] = matID;

    uint32_t totalSize = 0;
    for (const auto* w : matWindows) {
      totalSize += w->data.size();
    }

    material["total_size"] = static_cast<int64_t>(totalSize);
    material["window_count"] = static_cast<int64_t>(matWindows.size());
    material["shard_count"] = 1; // Single shard for now

    // For single-window materials, use the window's commitment directly
    // For multi-window materials, compute hash of all window hashes
    std::array<uint8_t, 32> finalHash;
    if (matWindows.size() == 1) {
      finalHash = matWindows[0]->commitment;
    } else {
      SHA256 hasher;
      for (const auto* w : matWindows) {
        hasher.update(ArrayRef<uint8_t>(w->commitment.data(), 32));
      }
      auto hash = hasher.final();
      std::memcpy(finalHash.data(), hash.data(), 32);
    }

    std::string commitmentHex = "sha256:";
    for (size_t i = 0; i < 32; i++) {
      char buf[3];
      snprintf(buf, sizeof(buf), "%02x", finalHash[i]);
      commitmentHex += buf;
    }
    material["commitment"] = commitmentHex;

    materials[matID] = std::move(material);
  }

  root["materials"] = std::move(materials);

  // Write JSON file
  std::error_code EC;
  raw_fd_ostream outFile(path, EC, sys::fs::OF_Text);
  if (EC) {
    errs() << "Failed to create metadata file " << path << ": "
           << EC.message() << "\n";
    return false;
  }

  outFile << formatv("{0:2}", json::Value(std::move(root))) << "\n";
  outFile.flush();

  return true;
}

// Main export function called from VMImpl::commit()
bool CloudMaterialExporter::exportBytecode(
    ArrayRef<uint8_t> bytecode,
    StringRef functionName,
    StringRef materialRegion,
    uint32_t windowSize,
    StringRef exportDir,
    StringRef appID) {

  if (bytecode.empty()) {
    errs() << "[CloudExport] Warning: empty bytecode for "
           << functionName << "\n";
    return false;
  }

  for (char c : materialRegion)
    if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
          (c >= '0' && c <= '9') || c == '_' || c == '-')) {
      errs() << "[CloudExport] invalid cloud material ID region: "
             << materialRegion << "\n";
      return false;
    }

  // Generate material ID from function name and region
  std::string materialID = materialRegion.empty()
      ? functionName.str()
      : (materialRegion.str() + "__" + functionName.str());
  for (char c : materialID)
    if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
          (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.')) {
      errs() << "[CloudExport] invalid cloud material ID: " << materialID << "\n";
      return false;
    }

  outs() << "[CloudExport] Exporting " << bytecode.size()
         << " bytes for " << materialID << "\n";

  // Split into windows
  auto windows = splitBytecodeIntoWindows(bytecode, materialID, windowSize);

  outs() << "[CloudExport] Generated " << windows.size()
         << " windows (" << windowSize << " bytes each)\n";

  // Write window files
  for (const auto& window : windows) {
    if (!writeWindowFile(window, exportDir)) {
      return false;
    }
  }

  // Update or create metadata file
  // TODO: Support incremental updates (read existing, merge, write)
  if (!writeMetadataFile(windows, exportDir, appID)) {
    return false;
  }

  outs() << "[CloudExport] Successfully exported to " << exportDir << "\n";

  return true;
}

} // namespace llvm
