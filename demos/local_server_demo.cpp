// 本地云提供商服务端Demo - 在Termux运行
#include <iostream>
#include <vector>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

constexpr uint32_t kWireProtocolMagic = 0xDEADBEEF;
constexpr uint16_t kServerPort = 8080;

struct MessageHeader {
    uint32_t magic;
    uint16_t message_id;
    uint16_t payload_size;
    uint32_t checksum;
};

// 简单的CRC32实现
uint32_t computeCRC32(const std::vector<uint8_t>& data) {
    uint32_t crc = 0xFFFFFFFF;
    for (uint8_t byte : data) {
        crc ^= byte;
        for (int i = 0; i < 8; i++) {
            crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1));
        }
    }
    return ~crc;
}

int main() {
    std::cout << "=== 云提供商本地服务端Demo ===" << std::endl;
    std::cout << "监听端口: " << kServerPort << std::endl;
    
    // 创建socket
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        std::cerr << "创建socket失败" << std::endl;
        return 1;
    }
    
    // 设置地址重用
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    // 绑定地址
    struct sockaddr_in server_addr;
    std::memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(kServerPort);
    
    if (bind(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        std::cerr << "绑定失败" << std::endl;
        close(server_fd);
        return 1;
    }
    
    // 监听
    if (listen(server_fd, 5) < 0) {
        std::cerr << "监听失败" << std::endl;
        close(server_fd);
        return 1;
    }
    
    std::cout << "服务端启动成功，等待连接..." << std::endl;
    
    while (true) {
        // 接受连接
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
        
        if (client_fd < 0) {
            std::cerr << "接受连接失败" << std::endl;
            continue;
        }
        
        std::cout << "\n新连接来自: " << inet_ntoa(client_addr.sin_addr) << std::endl;
        
        // 接收消息头
        MessageHeader header;
        ssize_t bytes_read = recv(client_fd, &header, sizeof(header), 0);
        
        if (bytes_read != sizeof(header)) {
            std::cerr << "接收消息头失败" << std::endl;
            close(client_fd);
            continue;
        }
        
        // 验证魔数
        if (header.magic != kWireProtocolMagic) {
            std::cerr << "无效的魔数: 0x" << std::hex << header.magic << std::endl;
            close(client_fd);
            continue;
        }
        
        std::cout << "收到消息 - ID: " << header.message_id 
                  << ", 负载大小: " << header.payload_size << std::endl;
        
        // 接收负载
        std::vector<uint8_t> payload(header.payload_size);
        bytes_read = recv(client_fd, payload.data(), header.payload_size, 0);
        
        if (bytes_read != header.payload_size) {
            std::cerr << "接收负载失败" << std::endl;
            close(client_fd);
            continue;
        }
        
        // 验证校验和
        uint32_t computed_checksum = computeCRC32(payload);
        if (computed_checksum != header.checksum) {
            std::cerr << "校验和验证失败" << std::endl;
            close(client_fd);
            continue;
        }
        
        std::cout << "校验和验证通过 ✓" << std::endl;
        std::cout << "负载内容: ";
        for (uint8_t byte : payload) {
            std::cout << std::hex << (int)byte << " ";
        }
        std::cout << std::dec << std::endl;
        
        // 发送回复
        std::vector<uint8_t> response = {0xAA, 0xBB, 0xCC, 0xDD};
        MessageHeader response_header;
        response_header.magic = kWireProtocolMagic;
        response_header.message_id = header.message_id + 1;
        response_header.payload_size = response.size();
        response_header.checksum = computeCRC32(response);
        
        send(client_fd, &response_header, sizeof(response_header), 0);
        send(client_fd, response.data(), response.size(), 0);
        
        std::cout << "已发送回复" << std::endl;
        
        close(client_fd);
    }
    
    close(server_fd);
    return 0;
}
