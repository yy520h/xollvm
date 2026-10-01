#include "SocketClientCore.h"

#define _WINSOCK_DEPRECATED_NO_WARNINGS

#if !defined(_WIN32)
SocketClientCore::SocketClientCore(const std::string&, int, SocketReadMsgContainer&) {
	con_status = false;
}
SocketClientCore::~SocketClientCore() = default;
std::string SocketClientCore::SendMessageS(const std::string&) { return "0"; }
std::string SocketClientCore::DisconnectFromServer() { return "Disconnected"; }
void SocketClientCore::KeepAlive() {}
std::wstring SocketClientCore::stringToWideString(const std::string&) { return {}; }
bool SocketClientCore::connectToServer(const std::string&, int) { return false; }
size_t SocketClientCore::find_c(const std::string&, char, size_t) { return std::string::npos; }
void SocketClientCore::ReceiveMessages(SocketReadMsgContainer&) {}
#else

SocketClientCore::SocketClientCore() {
}

std::wstring SocketClientCore::stringToWideString(const std::string& narrowStr) {
	int bufferSize = MultiByteToWideChar(CP_UTF8, 0, narrowStr.c_str(), -1, nullptr, 0);
	if (bufferSize == 0) {
		return L"";
	}

	std::wstring wideStr(bufferSize, 0);
	if (MultiByteToWideChar(CP_UTF8, 0, narrowStr.c_str(), -1, &wideStr[0], bufferSize) == 0) {
		return L"";
	}

	return wideStr;
}

bool SocketClientCore::connectToServer(const std::string& address, int port) {
	int maxRetries = 999;
	for (int attempt = 0; attempt < maxRetries; ++attempt) {
		try {
			this->m_address = address;
			this->m_port = port;
			WSADATA wsaData;
			int iResult;

			iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
			if (iResult != 0) {
				throw std::runtime_error("WSAStartup failed");
			}

			client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
			if (client == INVALID_SOCKET) {
				throw std::runtime_error("Error at socket()");
			}

			sockaddr_in clientService;
			clientService.sin_family = AF_INET;
			std::wstring wideAddress = stringToWideString(m_address);
			if (InetPton(AF_INET, wideAddress.c_str(), &clientService.sin_addr) != 1) {
				throw std::runtime_error("Invalid address");
			}
			clientService.sin_port = htons(m_port);

			iResult = connect(client, (SOCKADDR*)&clientService, sizeof(clientService));
			if (iResult == SOCKET_ERROR) {
				closesocket(client);
				client = INVALID_SOCKET;
				std::cerr << "Connection failed, retrying... (" << (attempt + 1) << "/" << maxRetries << ")" << std::endl;
				std::this_thread::sleep_for(std::chrono::seconds(2)); // Wait before retrying
				continue; // Retry connection
			}

			return true; // Successfully connected
		}
		catch (const std::exception& e) {
			std::cerr << e.what() << std::endl;
			return false; // Connection failed
		}
	}
	return false; // Failed after max retries
}

SocketClientCore::SocketClientCore(const std::string& arg_address, int arg_port, SocketReadMsgContainer& arg_SocketReadMsgContainer) {
	if (!connectToServer(arg_address, arg_port)) {
		std::cerr << "Failed to connect to server after multiple attempts." << std::endl;
		return;
	}

	// Create a thread for receiving messages
	std::thread recvThread(&SocketClientCore::ReceiveMessages, this, std::ref(arg_SocketReadMsgContainer));
	recvThread.detach();

	con_status = true;

	// Start a thread for keep-alive
	std::thread keepAliveThread(&SocketClientCore::KeepAlive, this);
	keepAliveThread.detach();
}

SocketClientCore::~SocketClientCore() {
	closesocket(client);
	WSACleanup();
}

std::string SocketClientCore::SendMessageS(const std::string& message) {
	try {
		int iResult = send(client, message.c_str(), message.length(), 0);
		if (iResult == SOCKET_ERROR) {
			return "0"; // Error sending message
		}
		return "1"; // Message sent successfully
	}
	catch (const std::exception& e) {
		return "0"; // Error sending message
	}
}

std::string SocketClientCore::DisconnectFromServer() {
	try {
		closesocket(client);
		return "Disconnected from server";
	}
	catch (const std::exception& e) {
		return "Error disconnecting from server: " + std::string(e.what());
	}
}

void SocketClientCore::KeepAlive() {
	while (true) {
		std::this_thread::sleep_for(std::chrono::seconds(9)); // Keep alive every 9 seconds
		if (SendMessageS("zone") == "0") {
			std::cerr << "Keep-alive message failed, attempting to reconnect..." << std::endl;
			if (connectToServer(m_address, m_port)) {
				std::cout << "Reconnected successfully." << std::endl;
			}
			else {
				std::cerr << "Reconnection failed." << std::endl;
			}
		}
	}
}
size_t SocketClientCore::find_c(const std::string& str, char ch, size_t startPos) {
	for (size_t i = startPos; i < str.length(); ++i) {
		if (str[i] == ch) {
			return i;
		}
	}
	return std::string::npos; // If not found, return npos
}
//void SocketClientCore::ReceiveMessages(SocketReadMsgContainer& m_SocketReadMsgContainer) {
//	std::string all_receivedMessage;
//	try {
//		while (true) {
//			char* recvbuf = new char[1024 * 1];
//			int recvbuflen = 1024 * 1;
//
//			int iResult = recv(client, recvbuf, recvbuflen, 0);
//			if (iResult > 0) {
//				for (int i = 0; i < iResult; ++i) {
//					if (recvbuf[i] != '\0') { // Check for valid characters
//						all_receivedMessage += recvbuf[i];
//					}
//				}
//
//				size_t pos_i = all_receivedMessage.find("<~end~>");
//
//				if (pos_i != std::string::npos) {
//					std::cout << "read_comp[" << all_receivedMessage << "]" << std::endl;
//					std::lock_guard<std::mutex> lock(m_SocketReadMsgContainer.lockObject);
//					m_SocketReadMsgContainer.read_msg.push_back(all_receivedMessage.substr(0, pos_i));
//					all_receivedMessage = all_receivedMessage.substr(pos_i + 1); // Keep remaining data
//					//std::cout << all_receivedMessage;
//				}
//
//				delete[] recvbuf; // Deallocate the memory
//			}
//			else if (iResult == 0) {
//				std::cout << "Connection closed by server" << std::endl;
//				delete[] recvbuf; // Deallocate the memory
//				break; // Exit loop on connection closure
//			}
//			else {
//				std::cout << "recv failed with error: " << WSAGetLastError() << std::endl;
//				delete[] recvbuf; // Deallocate the memory
//				break; // Exit loop on error
//			}
//		}
//	}
//	catch (const std::exception& ex) {
//		std::cerr << "Error receiving messages: " << ex.what() << std::endl;
//	}
//
//	// Attempt to reconnect if the loop exits
//	std::cerr << "Attempting to reconnect..." << std::endl;
//	if (connectToServer(m_address, m_port)) {
//		std::cout << "Reconnected successfully." << std::endl;
//		ReceiveMessages(m_SocketReadMsgContainer); // Restart receiving messages
//	}
//	else {
//		std::cerr << "Reconnection failed." << std::endl;
//	}
//}
//

void SocketClientCore::ReceiveMessages(SocketReadMsgContainer& m_SocketReadMsgContainer) {
	std::string all_receivedMessage;
	try {
		while (true) {
			char buffer[1024]; // Use a stack-allocated buffer
			int recvbuflen = sizeof(buffer);

			int iResult = recv(client, buffer, recvbuflen, 0);
			if (iResult > 0) {
				// Convert the received bytes to a string
				std::string receivedMessage(buffer, iResult);
				all_receivedMessage += receivedMessage;

				size_t pos_i = all_receivedMessage.find("<~end~>");
				if (pos_i != std::string::npos) {
					//std::cout << "read_comp[" << all_receivedMessage << "]" << std::endl;
					std::lock_guard<std::mutex> lock(m_SocketReadMsgContainer.lockObject);
					m_SocketReadMsgContainer.read_msg.push_back(all_receivedMessage.substr(0, pos_i));
					all_receivedMessage = all_receivedMessage.substr(pos_i + 7); // Keep remaining data after "<~end~>"
				}
			}
			else if (iResult == 0) {
				std::cout << "Connection closed by server" << std::endl;
				break; // Exit loop on connection closure
			}
			else {
				std::cout << "recv failed with error: " << WSAGetLastError() << std::endl;
				break; // Exit loop on error
			}
		}
	}
	catch (const std::exception& ex) {
		std::cerr << "Error receiving messages: " << ex.what() << std::endl;
	}

	// Attempt to reconnect if the loop exits
	std::cerr << "Attempting to reconnect..." << std::endl;
	if (connectToServer(m_address, m_port)) {
		std::cout << "Reconnected successfully." << std::endl;
		ReceiveMessages(m_SocketReadMsgContainer); // Restart receiving messages
	}
	else {
		std::cerr << "Reconnection failed." << std::endl;
	}
}
#endif
