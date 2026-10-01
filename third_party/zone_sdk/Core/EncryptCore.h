#pragma once

#include <iostream>
#include <string>
#include <vector>
#include <stdexcept>
#include "ZoneLib.h"
#include "Cryption.hpp"

#include "md5.h"

//#pragma comment(lib, "libcrypto.lib")
//#pragma comment(lib, "libssl.lib")


struct EncryptCore {

public:
    // 构造函数，初始化CRC表
    EncryptCore();

    // 计算CRC8并返回十六进制字符串
    std::string CalculateCRC8(const std::string& input);

    // 计算CRC16_CCITTFALSE并返回十六进制字符串
    std::string CalculateCRC16(const std::string& input);

    // 计算CRC32并返回十六进制字符串
    std::string CalculateCRC32(const std::string& input);

private:
    // CRC8 相关变量和方法
    static const uint8_t _crc8Polynomial;
    uint8_t _crc8Table[256];
    void InitializeCrc8Table();

    // CRC16_CCITTFALSE 相关变量和方法
    static const uint16_t _crc16Polynomial;
    static const uint16_t _crc16FinalXor;
    uint16_t _crc16Table[256];
    void InitializeCrc16Table();

    // CRC32 相关变量和方法
    static const uint32_t _crc32Polynomial;
    uint32_t _crc32Table[256];
    void InitializeCrc32Table();

    // 辅助函数：将字符串转换为UTF8字节
    std::vector<uint8_t> StringToUtf8Bytes(const std::string& input);
public:
	std::string StringToHex(const std::string& input);
	std::string HexToString(const std::string& hexString);
	std::string CalculateMD5Hash(const std::string& input);

	std::string ToEncrypt(const std::string& plainText, const std::string& key, const std::string& iv, eum_EncryptType arg_encryptType);
	std::string ToDecrypt(const std::string& cipherText, const std::string& key, const std::string& iv, eum_EncryptType arg_encryptType);

};