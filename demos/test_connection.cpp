// 测试基本连接
#include <iostream>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <errno.h>

int main() {
    std::cout << "测试连接到 127.0.0.1:9999..." << std::endl;
    
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        std::cerr << "创建socket失败: " << strerror(errno) << std::endl;
        return 1;
    }
    std::cout << "✓ Socket创建成功 (fd: " << sock << ")" << std::endl;
    
    struct sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(9999);
    
    // 使用inet_addr而不是直接赋值
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    
    std::cout << "尝试连接..." << std::endl;
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        std::cerr << "✗ 连接失败: " << strerror(errno) << std::endl;
        close(sock);
        return 1;
    }
    
    std::cout << "✓ 连接成功！" << std::endl;
    close(sock);
    return 0;
}
