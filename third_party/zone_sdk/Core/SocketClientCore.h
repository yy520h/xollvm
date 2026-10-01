#pragma once
#include "ZoneLib.h"
#include <iostream>
#include <string>
#include <thread>
#include <mutex>
#include <vector>
#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <fcntl.h>
#include <errno.h>
using SOCKET = int;
#endif

class SocketClientCore {
public:
    SocketClientCore();
    SocketClientCore(const std::string& arg_address, int arg_port, SocketReadMsgContainer& arg_SocketReadMsgContainer);
    ~SocketClientCore();

    std::string SendMessageS(const std::string& message);
    std::string DisconnectFromServer();
    bool con_status;

private:
    std::string m_address;
    int m_port;
    SOCKET client;

    // Method to connect to the server with retry logic
    bool connectToServer(const std::string& address, int port);

    // Method to keep the connection alive
    void KeepAlive();

    // Method to find a character in a string
    size_t find_c(const std::string& str, char ch, size_t startPos = 0);

    // Method to receive messages from the server
    void ReceiveMessages(SocketReadMsgContainer& m_SocketReadMsgContainer);

    // Convert narrow string to wide string
    std::wstring stringToWideString(const std::string& narrowStr);
};
