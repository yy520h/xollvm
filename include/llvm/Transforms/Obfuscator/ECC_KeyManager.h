// ============================================================================
// ECC_KeyManager.h - 椭圆曲线密钥管理
// ============================================================================

#ifndef LLVM_TRANSFORMS_OBFUSCATOR_ECC_KEYMANAGER_H
#define LLVM_TRANSFORMS_OBFUSCATOR_ECC_KEYMANAGER_H

#include <string>
#include <vector>
#include <array>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>

namespace llvm {

/**
 * ECC 密钥对
 * 用于窗口动态加密
 */
class ECCKeyPair {
public:
    ECCKeyPair();
    ~ECCKeyPair();

    // 生成新的密钥对（使用 secp256k1 曲线）
    bool generate();

    // 导出私钥（十六进制）- 用于服务器
    std::string exportPrivateKeyHex() const;

    // 导出公钥（十六进制压缩格式）- 用于客户端
    std::string exportPublicKeyHex() const;

    // 导出公钥点坐标
    bool exportPublicKeyCoordinates(std::string& x_hex, std::string& y_hex) const;

    // 从十六进制导入密钥
    bool importPrivateKeyHex(const std::string& hex);
    bool importPublicKeyHex(const std::string& hex);

    // 计算共享密钥（ECDH）
    std::array<uint8_t, 32> computeSharedSecret(const std::string& peer_pubkey_hex) const;

    // 验证密钥是否有效
    bool isValid() const { return key_ != nullptr; }

private:
    EC_KEY* key_;
    const EC_GROUP* group_;
};

/**
 * ECC 密钥管理器
 * 管理编译时的密钥生成和分发
 */
class ECCKeyManager {
public:
    ECCKeyManager();

    // 生成服务器和客户端密钥对
    bool generateKeys();

    // 保存服务器私钥到配置文件
    bool saveServerPrivateKey(const std::string& config_path) const;

    // 生成客户端公钥头文件
    bool generateClientConfigHeader(const std::string& output_path) const;

    // 导出密钥信息（用于日志）
    std::string getKeyInfo() const;

    // 获取服务器私钥（十六进制）
    std::string getServerPrivateKeyHex() const {
        return server_key_.exportPrivateKeyHex();
    }

    // 获取客户端公钥（十六进制）
    std::string getClientPublicKeyHex() const {
        return server_key_.exportPublicKeyHex();
    }

private:
    ECCKeyPair server_key_;  // 服务器持有私钥
};

} // namespace llvm

#endif // LLVM_TRANSFORMS_OBFUSCATOR_ECC_KEYMANAGER_H
