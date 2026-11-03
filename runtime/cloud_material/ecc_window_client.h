#ifndef XOLLVM_RUNTIME_CLOUD_MATERIAL_ECC_WINDOW_CLIENT_H
#define XOLLVM_RUNTIME_CLOUD_MATERIAL_ECC_WINDOW_CLIENT_H

#include <string>
#include <vector>
#include <array>
#include <cstdint>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <openssl/sha.h>

namespace xovm {
namespace material {

/**
 * ECC 窗口客户端
 * 使用 ECDH 密钥协商动态解密窗口数据
 */
class ECCWindowClient {
public:
    /**
     * 构造函数
     * @param server_pubkey_hex 服务器公钥（十六进制，压缩格式）
     */
    explicit ECCWindowClient(const std::string& server_pubkey_hex);
    ~ECCWindowClient();

    /**
     * 生成临时密钥对并获取临时公钥
     * 每次请求窗口时调用，生成新的临时密钥
     * @return 临时公钥（十六进制，压缩格式）
     */
    std::string generateEphemeralKey();

    /**
     * 解密窗口数据
     * @param encrypted 加密的窗口数据
     * @return 解密后的窗口数据
     */
    std::vector<uint8_t> decryptWindow(const std::vector<uint8_t>& encrypted);

    /**
     * 获取当前临时公钥（上次调用 generateEphemeralKey 生成的）
     */
    std::string getCurrentEphemeralPublicKey() const;

    /**
     * 验证客户端是否正确初始化
     */
    bool isValid() const { return server_pubkey_ != nullptr && group_ != nullptr; }

private:
    // 计算共享密钥
    std::array<uint8_t, 32> computeSharedSecret();

    // 十六进制转字节数组
    static std::vector<uint8_t> hexToBytes(const std::string& hex);

    // 字节数组转十六进制
    static std::string bytesToHex(const uint8_t* bytes, size_t len);

private:
    int curve_nid_;                    // 曲线 NID
    EC_GROUP* group_;                  // 椭圆曲线群
    EC_POINT* server_pubkey_;          // 服务器公钥点
    EC_KEY* ephemeral_key_;            // 当前临时密钥对
    std::string current_ephemeral_pubkey_hex_;  // 当前临时公钥（十六进制）
};

} // namespace material
} // namespace xovm

#endif // XOLLVM_RUNTIME_CLOUD_MATERIAL_ECC_WINDOW_CLIENT_H
