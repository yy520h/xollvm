#pragma once
#include <mutex>
#include <list>
#include <string>
#include <thread>
#include <chrono>

#pragma region libhv
//
//
//#include "hv/WebSocketClient.h"
//#include "hv/htime.h"
//class WebSocketReadMsgContainer {
//public:
//	std::mutex lockMutex;
//	std::list<std::string> read_msg;
//};
//
//class ZoneWebSocketClient {
//private:
//	hv::WebSocketClient* webSocket;
//	std::thread* keepAliveThread;
//	bool keepAliveRunning;
//
//public:
//	bool con_status = false;
//	std::string m_address;
//	WebSocketReadMsgContainer msgContainer;
//
//	ZoneWebSocketClient(const std::string& arg_address) : m_address(arg_address), keepAliveThread(nullptr), keepAliveRunning(false) {
//		con_status = ConnectToServer(arg_address);
//	}
//
//	~ZoneWebSocketClient() {
//		StopKeepAlive();
//		DisconnectFromServer();
//	}
//
//	void StartKeepAlive() {
//		if (keepAliveThread) return;
//
//		keepAliveRunning = true;
//		keepAliveThread = new std::thread([this]() {
//			while (keepAliveRunning) {
//				SendMessageWs("ping");
//				std::this_thread::sleep_for(std::chrono::seconds(9));
//			}
//			});
//	}
//
//	void StopKeepAlive() {
//		if (keepAliveThread) {
//			keepAliveRunning = false;
//			if (keepAliveThread->joinable()) {
//				keepAliveThread->join();
//			}
//			delete keepAliveThread;
//			keepAliveThread = nullptr;
//		}
//	}
//
//	bool ConnectToServer(const std::string& arg_address) {
//		try {
//			webSocket = new hv::WebSocketClient();
//
//			// Set callbacks
//			webSocket->onopen = [this]() {
//				//std::cout << "连接成功" << std::endl;
//			};
//
//			webSocket->onmessage = [this](const std::string& msg) {
//				std::lock_guard<std::mutex> lock(msgContainer.lockMutex);
//				msgContainer.read_msg.push_back(msg);
//				//std::cout << "收到消息: " << msg << std::endl;
//			};
//
//			webSocket->onclose = []() {
//				//std::cout << "连接关闭" << std::endl;
//			};
//
//			//webSocket->onerror = [](const std::string& error) {
//			//    std::cout << "错误: " << error << std::endl;
//			//};
//
//			// Open connection
//			http_headers headers;
//			int ret = webSocket->open(arg_address.c_str(), headers);
//
//			if (ret == 0) {
//				//StartKeepAlive();
//				return true;
//			}
//			return false;
//		}
//		catch (const std::exception& ex) {
//			//std::cout << "连接错误: " << ex.what() << std::endl;
//			return false;
//		}
//	}
//
//	int SendMessageWs(const std::string& message) {
//		if (webSocket && webSocket->isConnected()) {
//			try {
//				webSocket->send(message);
//				return 1;
//			}
//			catch (const std::exception& ex) {
//				//std::cout << "发送消息时出错: " << ex.what() << std::endl;
//				return 0;
//			}
//		}
//		else
//		{
//			//std::cout << "WebSocket未连接" << std::endl;
//			return 0;
//		}
//	}
//
//	void DisconnectFromServer() {
//		StopKeepAlive();
//		if (webSocket) {
//			webSocket->close();
//			delete webSocket;
//			webSocket = nullptr;
//		}
//	}
//
//	// Optional: Method to retrieve messages
//	std::list<std::string> GetMessages() {
//		std::lock_guard<std::mutex> lock(msgContainer.lockMutex);
//		std::list<std::string> messages = msgContainer.read_msg;
//		msgContainer.read_msg.clear();
//		return messages;
//	}
//};
//
#pragma endregion

#pragma region noTLS

#include "ZoneWsDebugLog.h"
#if defined(ZoneDebug)
#include <string>
static inline std::string zone_ws_msg_preview(const std::string& s, size_t maxLen = 256) {
	if (s.size() <= maxLen) return s;
	return s.substr(0, maxLen) + "... (total " + std::to_string(s.size()) + " bytes)";
}
#endif

#include "cyanray/WebSocketClient.h"

class WebSocketReadMsgContainer {
public:
	std::mutex lockMutex;
	std::list<std::string> read_msg;
};

class ZoneWebSocketClient {
private:
	cyanray::WebSocketClient* webSocket;
	std::thread* keepAliveThread;
	bool keepAliveRunning;

public:
	bool con_status = false;
	std::string m_address;
	WebSocketReadMsgContainer msgContainer;

	ZoneWebSocketClient(const std::string& arg_address) : m_address(arg_address), keepAliveThread(nullptr), keepAliveRunning(false) {
		con_status = ConnectToServer(arg_address);
	}

	~ZoneWebSocketClient() {
		StopKeepAlive();
		DisconnectFromServer();
	}

	void StartKeepAlive() {
		if (keepAliveThread) return;

		keepAliveRunning = true;
		keepAliveThread = new std::thread([this]() {
			while (keepAliveRunning) {
				SendMessageWs("ping");
				std::this_thread::sleep_for(std::chrono::seconds(9));
			}
			});
	}

	void StopKeepAlive() {
		if (keepAliveThread) {
			keepAliveRunning = false;
			if (keepAliveThread->joinable()) {
				keepAliveThread->join();
			}
			delete keepAliveThread;
			keepAliveThread = nullptr;
		}
	}

	bool ConnectToServer(const std::string& arg_address) {
		ZONE_WS_LOG("ZoneWebSocketClient::ConnectToServer url=\"" << arg_address << "\"");
		try {
			webSocket = new cyanray::WebSocketClient();

			webSocket->OnError([](cyanray::WebSocketClient& client, std::string err)
				{
					(void)client;
					ZONE_WS_LOG("cyanray OnError: " << err);
				});

			webSocket->OnTextReceived([this](cyanray::WebSocketClient& client, string text)
				{
#if defined(ZoneDebug)
					(void)client;
					ZONE_WS_LOG("ZoneWebSocketClient OnText len=" << text.size() << " preview=\"" << zone_ws_msg_preview(text) << "\"");
#endif
					std::lock_guard<std::mutex> lock(msgContainer.lockMutex);
					msgContainer.read_msg.push_back(text);
				});

			webSocket->OnLostConnection([arg_address](cyanray::WebSocketClient& client, int code)
				{
					ZONE_WS_LOG("ZoneWebSocketClient OnLostConnection code=" << code << " reconnect uri=\"" << arg_address << "\"");
					while (true)
					{
						try
						{
							client.Connect(arg_address);
							ZONE_WS_LOG("ZoneWebSocketClient reconnect OK");
							break;
						}
						catch (const std::exception& ex)
						{
#if defined(ZoneDebug)
							ZONE_WS_LOG("ZoneWebSocketClient reconnect error: " << ex.what());
#else
							std::cout << ex.what() << std::endl;
#endif
						}
					}
				});

			webSocket->Connect(arg_address.c_str());
			ZONE_WS_LOG("ZoneWebSocketClient connected GetStatus=" << (int)webSocket->GetStatus());
		}
		catch (const std::exception& ex) {
			ZONE_WS_LOG("ZoneWebSocketClient::ConnectToServer failed: " << ex.what());
			return false;
		}
		return true;
	}

	int SendMessageWs(const std::string& message) {
		if (webSocket && cyanray::WebSocketClient::Status::Open == webSocket->GetStatus()) {
			try {
				ZONE_WS_LOG("ZoneWebSocketClient::SendMessageWs len=" << message.size());
				webSocket->SendText(message);
				return 1;
			}
			catch (const std::exception& ex) {
				ZONE_WS_LOG("ZoneWebSocketClient::SendMessageWs error: " << ex.what());
				return 0;
			}
		}
		else
		{
			ZONE_WS_LOG("ZoneWebSocketClient::SendMessageWs skipped (not Open) ptr=" << (void*)webSocket
				<< " status=" << (webSocket ? (int)webSocket->GetStatus() : -1));
			return 0;
		}
	}

	void DisconnectFromServer() {
		StopKeepAlive();
		if (webSocket) {
			webSocket->Close();
			delete webSocket;
			webSocket = nullptr;
		}
	}

	// Optional: Method to retrieve messages
	std::list<std::string> GetMessages() {
		std::lock_guard<std::mutex> lock(msgContainer.lockMutex);
		std::list<std::string> messages = msgContainer.read_msg;
		msgContainer.read_msg.clear();
		return messages;
	}
};

#pragma endregion
