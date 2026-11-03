#ifndef XOLLVM_RUNTIME_CLOUD_MATERIAL_HMAC_CLIENT_H
#define XOLLVM_RUNTIME_CLOUD_MATERIAL_HMAC_CLIENT_H

#include <string>
#include <cstdint>
#include <chrono>
#include <random>
#include <sstream>
#include <iomanip>
#include <openssl/hmac.h>
#include <openssl/sha.h>

namespace xovm {
namespace material {

/**
 * HMAC 认证客户端
 * 用于 Direct 模式下与后端服务器进行安全认证
 */
class HMACClient {
public:
    explicit HMACClient(const std::string& secret, const std::string& device_id)
        : secret_(secret), device_id_(device_id) {}

    /**
     * 生成 Authorization 头
     * @param payload 请求体内容（JSON 字符串）
     * @return Authorization 头的值，格式: "HMAC device_id:timestamp:nonce:signature"
     */
    std::string generateAuthHeader(const std::string& payload) {
        // 1. 生成时间戳（当前时间，秒）
        int64_t timestamp = std::chrono::system_clock::now().time_since_epoch().count() / 1000000000;

        // 2. 生成随机 nonce（32 字节十六进制）
        std::string nonce = generateNonce();

        // 3. 构造消息: device_id|timestamp|nonce|payload
        std::ostringstream message;
        message << device_id_ << "|" << timestamp << "|" << nonce << "|" << payload;
        std::string msg_str = message.str();

        // 4. 计算 HMAC-SHA256
        unsigned char hmac_result[EVP_MAX_MD_SIZE];
        unsigned int hmac_len = 0;

        HMAC(EVP_sha256(),
             secret_.c_str(), secret_.length(),
             reinterpret_cast<const unsigned char*>(msg_str.c_str()), msg_str.length(),
             hmac_result, &hmac_len);

        // 5. 转换为十六进制字符串
        std::string signature = bytesToHex(hmac_result, hmac_len);

        // 6. 构造 Authorization 头
        std::ostringstream auth_header;
        auth_header << "HMAC " << device_id_ << ":" << timestamp << ":" << nonce << ":" << signature;

        return auth_header.str();
    }

    /**
     * 获取设备 ID
     */
    const std::string& getDeviceID() const {
        return device_id_;
    }

private:
    std::string secret_;      // HMAC 密钥
    std::string device_id_;   // 设备 ID

    /**
     * 生成随机 nonce（32 字节十六进制）
     */
    std::string generateNonce() {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 255);

        unsigned char nonce_bytes[16];
        for (int i = 0; i < 16; i++) {
            nonce_bytes[i] = static_cast<unsigned char>(dis(gen));
        }

        return bytesToHex(nonce_bytes, 16);
    }

    /**
     * 字节数组转十六进制字符串
     */
    std::string bytesToHex(const unsigned char* bytes, size_t len) {
        std::ostringstream oss;
        for (size_t i = 0; i < len; i++) {
            oss << std::hex << std::setw(2) << std::setfill('0')
                << static_cast<int>(bytes[i]);
        }
        return oss.str();
    }
};

} // namespace material
} // namespace xovm

#endif // XOLLVM_RUNTIME_CLOUD_MATERIAL_HMAC_CLIENT_H
