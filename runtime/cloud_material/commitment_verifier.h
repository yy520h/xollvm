#ifndef XOLLVM_RUNTIME_CLOUD_MATERIAL_COMMITMENT_VERIFIER_H
#define XOLLVM_RUNTIME_CLOUD_MATERIAL_COMMITMENT_VERIFIER_H

#include <vector>
#include <array>
#include <cstdint>
#include <openssl/sha.h>
#include <cstring>

namespace xovm {
namespace material {

/**
 * 窗口数据 Commitment 验证器
 * 使用 SHA256 验证窗口数据完整性
 */
class CommitmentVerifier {
public:
    /**
     * 计算数据的 SHA256 哈希
     * @param data 输入数据
     * @return SHA256 哈希值（32 字节）
     */
    static std::array<uint8_t, 32> computeSHA256(const std::vector<uint8_t>& data) {
        std::array<uint8_t, 32> hash;
        SHA256(data.data(), data.size(), hash.data());
        return hash;
    }

    /**
     * 验证窗口数据的 commitment
     * @param data 窗口数据
     * @param expected_commitment 期望的 commitment 哈希
     * @return 验证是否通过
     */
    static bool verify(const std::vector<uint8_t>& data,
                      const std::array<uint8_t, 32>& expected_commitment) {
        if (data.empty()) {
            return false;
        }

        auto actual_hash = computeSHA256(data);
        return std::memcmp(actual_hash.data(), expected_commitment.data(), 32) == 0;
    }

    /**
     * 将十六进制字符串转换为字节数组
     * @param hex 十六进制字符串（64 字符）
     * @return 字节数组（32 字节），如果格式错误则返回空数组
     */
    static std::array<uint8_t, 32> fromHexString(const std::string& hex) {
        std::array<uint8_t, 32> result = {0};

        if (hex.length() != 64) {
            return result;
        }

        for (size_t i = 0; i < 32; i++) {
            unsigned int byte;
            if (sscanf(hex.c_str() + i * 2, "%2x", &byte) != 1) {
                return result;
            }
            result[i] = static_cast<uint8_t>(byte);
        }

        return result;
    }

    /**
     * 将字节数组转换为十六进制字符串
     * @param bytes 字节数组
     * @return 十六进制字符串
     */
    static std::string toHexString(const std::array<uint8_t, 32>& bytes) {
        char hex[65];
        for (size_t i = 0; i < 32; i++) {
            snprintf(hex + i * 2, 3, "%02x", bytes[i]);
        }
        hex[64] = '\0';
        return std::string(hex);
    }
};

} // namespace material
} // namespace xovm

#endif // XOLLVM_RUNTIME_CLOUD_MATERIAL_COMMITMENT_VERIFIER_H
