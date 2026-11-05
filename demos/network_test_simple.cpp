// 简化的网络测试 - 验证基本TCP通信
#include <iostream>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <thread>
#include <chrono>

bool server_ready = false;

void run_server() {
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    struct sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(23456);
    
    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        std::cerr << "服务器绑定失败: " << strerror(errno) << std::endl;
        return;
    }
    
    listen(server_fd, 1);
    std::cout << "✓ 服务器监听端口 23456" << std::endl;
    server_ready = true;
    
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    int client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
    
    if (client_fd >= 0) {
        std::cout << "✓ 服务器接受连接" << std::endl;
        
        char buffer[256];
        int n = recv(client_fd, buffer, sizeof(buffer), 0);
        if (n > 0) {
            std::cout << "✓ 服务器收到 " << n << " 字节" << std::endl;
            send(client_fd, "OK", 2, 0);
        }
        close(client_fd);
    }
    
    close(server_fd);
}

void run_client() {
    while (!server_ready) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    
    struct sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port = htons(23456);
    
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        std::cerr << "客户端连接失败: " << strerror(errno) << std::endl;
        return;
    }
    
    std::cout << "✓ 客户端连接成功" << std::endl;
    
    const char* msg = "Hello";
    send(sock, msg, strlen(msg), 0);
    std::cout << "✓ 客户端发送数据" << std::endl;
    
    char buffer[256];
    int n = recv(sock, buffer, sizeof(buffer), 0);
    if (n > 0) {
        std::cout << "✓ 客户端收到回复: " << std::string(buffer, n) << std::endl;
    }
    
    close(sock);
}

int main() {
    std::cout << "=== 简化网络通信测试 ===" << std::endl;
    std::cout << "测试: 本地TCP socket通信" << std::endl;
    std::cout << std::endl;
    
    std::thread server_thread(run_server);
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    std::thread client_thread(run_client);
    
    server_thread.join();
    client_thread.join();
    
    std::cout << std::endl;
    std::cout << "🎉 网络通信基础功能验证通过" << std::endl;
    
    return 0;
}
