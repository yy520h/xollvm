#ifndef XOVM_MATERIAL_PACKAGE_H
#define XOVM_MATERIAL_PACKAGE_H

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <variant>
#include <vector>
#include <nlohmann/json.hpp>

namespace xovm::material {

inline constexpr size_t kMaxPlaintext = 11250348;
inline constexpr size_t kMaxBytecode = 8388608;
inline constexpr size_t kMaxBase64 = 11184812;
inline constexpr size_t kMaxOverhead = 65536;

struct PackageError {
    std::string code; // 固定非秘密错误码；不包含输入值或 JSON 异常消息。
};
template<class T> using ParseResult = std::variant<T, PackageError>;

struct MaterialBinding {
    std::string build_id;
    std::string region_id;
    std::string session_id;
    uint64_t generation = 0;
    std::string request_hash;
    std::string mode;
    uint32_t lease_ms = 0;
    std::string engine_abi_hash;
    std::string package_hash;
    bool operator==(const MaterialBinding &) const = default;
};

struct DecodeDescriptor {
    uint32_t decode_salt;
    uint32_t isa_version;
    std::string layout_hash;
    std::string operand_encoding_hash;
};

// 不代表认证或可执行能力；后续私有 VerifiedPackage 与本类型严格分离。
struct ParsedPackage {
    MaterialBinding binding;
    std::vector<uint8_t> bytecode;
    std::array<uint16_t, 256> decode_map;
    DecodeDescriptor static_decode_descriptor;
};

// 执行包 profile：预扫描限额/ASCII/canonical 后才分配 nlohmann DOM。
ParseResult<nlohmann::json> decodeCanonical(std::span<const uint8_t> bytes);
ParseResult<MaterialBinding> parseMaterialBinding(const nlohmann::json &value);
ParseResult<ParsedPackage> parseExecutionPackage(std::span<const uint8_t> bytes,
                                                const MaterialBinding &expectedBinding);

} // namespace xovm::material
#endif
