#include <cstring>
#include <string>
#include <vector>
#include <array>
#include <limits>
#include <thread>
#include <cctype>
#include <algorithm>
#include <stdexcept>
#include "WebSocketClient.h"
#include "../base64.h"
#include "../ZoneWsDebugLog.h"

#if defined(_WIN32)

#include <WS2tcpip.h>
#include <wincrypt.h>
#include <winhttp.h>
#pragma comment (lib, "ws2_32.lib")
#pragma comment (lib, "advapi32.lib")
#pragma comment (lib, "winhttp.lib")

#if defined(ZoneDebug)
static const char* zone_ws_winhttp_buf_type_str(WINHTTP_WEB_SOCKET_BUFFER_TYPE bt)
{
	switch (bt) {
	case WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE: return "BINARY_MESSAGE";
	case WINHTTP_WEB_SOCKET_BINARY_FRAGMENT_BUFFER_TYPE: return "BINARY_FRAGMENT";
	case WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE: return "UTF8_MESSAGE";
	case WINHTTP_WEB_SOCKET_UTF8_FRAGMENT_BUFFER_TYPE: return "UTF8_FRAGMENT";
	case WINHTTP_WEB_SOCKET_CLOSE_BUFFER_TYPE: return "CLOSE";
	default: return "?";
	}
}
#endif

#else

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <netdb.h>

#endif

typedef unsigned char byte_t;

#if defined(_WIN32)
typedef SOCKET socket_t;
#else
typedef int socket_t;
#ifndef INVALID_SOCKET
#define INVALID_SOCKET (-1)
#endif
#ifndef SOCKET_ERROR
#define SOCKET_ERROR   (-1)
#endif
#define closesocket(s) ::close(s)
#endif

using namespace std;

namespace cyanray
{
	static bool ws_uri_parse(const string& uri, bool& secure, string& host, int& port, string& path)
	{
		secure = false;
		port = 80;
		const char* p = uri.c_str();
		if (uri.size() >= 6 && uri.compare(0, 6, "wss://") == 0) {
			secure = true;
			port = 443;
			p += 6;
		}
		else if (uri.size() >= 5 && uri.compare(0, 5, "ws://") == 0) {
			secure = false;
			port = 80;
			p += 5;
		}
		else
			return false;

		string rest(p);
		if (rest.empty())
			return false;

		size_t slash = rest.find('/');
		string authority = (slash == string::npos) ? rest : rest.substr(0, slash);
		if (authority.empty())
			return false;

		if (slash == string::npos)
			path = "/";
		else
			path = rest.substr(slash);
		if (path.empty())
			path = "/";

		size_t colon = authority.rfind(':');
		if (colon != string::npos && colon > 0) {
			bool digits = true;
			for (size_t i = colon + 1; i < authority.size(); ++i) {
				if (!isdigit((unsigned char)authority[i])) { digits = false; break; }
			}
			if (digits && colon + 1 < authority.size()) {
				host = authority.substr(0, colon);
				try {
					port = stoi(authority.substr(colon + 1));
				}
				catch (...) {
					return false;
				}
			}
			else
				host = authority;
		}
		else
			host = authority;

		return !host.empty();
	}

#if defined(_WIN32)
	static wstring utf8_to_wide(const string& s)
	{
		if (s.empty())
			return L"";
		int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
		if (n <= 0)
			return L"";
		vector<wchar_t> buf((size_t)n);
		MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, buf.data(), n);
		return wstring(buf.data());
	}

	static bool sha1_bytes(const void* data, size_t len, unsigned char out20[20])
	{
		HCRYPTPROV prov = 0;
		HCRYPTHASH hash = 0;
		bool ok = CryptAcquireContextA(&prov, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) != FALSE;
		if (ok)
			ok = CryptCreateHash(prov, CALG_SHA1, 0, 0, &hash) != FALSE;
		if (ok)
			ok = CryptHashData(hash, static_cast<const BYTE*>(data), (DWORD)len, 0) != FALSE;
		DWORD cb = 20;
		if (ok)
			ok = CryptGetHashParam(hash, HP_HASHVAL, out20, &cb, 0) != FALSE;
		if (hash)
			CryptDestroyHash(hash);
		if (prov)
			CryptReleaseContext(prov, 0);
		return ok;
	}

	static string sec_websocket_accept_for_key(const string& sec_key)
	{
		static const char kMagic[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
		string input = sec_key + kMagic;
		unsigned char h[20];
		if (!sha1_bytes(input.data(), input.size(), h))
			return {};
		return base64_encode(h, 20);
	}

	static string make_sec_websocket_key()
	{
		unsigned char rnd[16];
		HCRYPTPROV prov = 0;
		if (!CryptAcquireContextA(&prov, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
			throw runtime_error("CryptAcquireContext failed");
		if (!CryptGenRandom(prov, 16, rnd)) {
			CryptReleaseContext(prov, 0);
			throw runtime_error("CryptGenRandom failed");
		}
		CryptReleaseContext(prov, 0);
		return base64_encode(rnd, 16);
	}

	static void trim_inplace(string& s)
	{
		while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r' || s.back() == '\n'))
			s.pop_back();
		size_t i = 0;
		while (i < s.size() && (s[i] == ' ' || s[i] == '\t')) ++i;
		if (i > 0) s.erase(0, i);
	}

	static bool extract_header_value(const string& headers, const char* name, string& outVal)
	{
		string nameLower(name);
		for (char& c : nameLower) {
			if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
		}
		size_t pos = 0;
		while (pos < headers.size()) {
			size_t lineEnd = headers.find("\r\n", pos);
			if (lineEnd == string::npos)
				break;
			string line = headers.substr(pos, lineEnd - pos);
			pos = lineEnd + 2;
			size_t colon = line.find(':');
			if (colon == string::npos)
				continue;
			string hname = line.substr(0, colon);
			for (char& c : hname) {
				if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
			}
			if (hname == nameLower) {
				outVal = line.substr(colon + 1);
				trim_inplace(outVal);
				return true;
			}
		}
		return false;
	}

	static bool recv_http_header_block(socket_t sock, string& out)
	{
		out.clear();
		char buf[2048];
		while (out.size() < 65536u) {
			int n = recv(sock, buf, (int)sizeof(buf), 0);
			if (n <= 0)
				return false;
			out.append(buf, (size_t)n);
			if (out.find("\r\n\r\n") != string::npos)
				return true;
		}
		return false;
	}

	static bool validate_ws_handshake(const string& response, const string& expected_accept)
	{
		if (response.size() < 12)
			return false;
		if (response.compare(0, 7, "HTTP/1.") != 0)
			return false;
		size_t sp = response.find(' ');
		if (sp == string::npos)
			return false;
		size_t sp2 = response.find(' ', sp + 1);
		if (sp2 == string::npos)
			return false;
		string code = response.substr(sp + 1, sp2 - sp - 1);
		if (code != "101")
			return false;
		string acc;
		if (!extract_header_value(response, "Sec-WebSocket-Accept", acc))
			return false;
		trim_inplace(acc);
		return acc == expected_accept;
	}
#endif

	socket_t hostname_connect(const std::string& hostname, int port) {
		struct addrinfo* result;

		struct addrinfo hints;
		memset(&hints, 0, sizeof(hints));
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;

		int ret = getaddrinfo(hostname.c_str(), to_string(port).c_str(), &hints, &result);
		if (ret != 0)
		{
			throw std::runtime_error("getaddrinfo failed.");
		}

		socket_t sockfd = INVALID_SOCKET;
		for (struct addrinfo* p = result; p != NULL; p = p->ai_next)
		{
			sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
			if (sockfd == INVALID_SOCKET) { continue; }
			if (connect(sockfd, p->ai_addr, (int)p->ai_addrlen) != SOCKET_ERROR)
			{
				break;
			}
			closesocket(sockfd);
			sockfd = INVALID_SOCKET;
		}
		freeaddrinfo(result);
		return sockfd;
	}

	enum class WebSocketOpcode
	{
		Continuation = 0x00,
		Text = 0x01,
		Binary = 0x02,
		Close = 0x08,
		Ping = 0x09,
		Pong = 0x0A
	};

	struct WebSocketClient::pimpl
	{
		socket_t wsSocket = INVALID_SOCKET;
		bool use_winhttp = false;
#if defined(_WIN32)
		HINTERNET hSession = nullptr;
		HINTERNET hConnect = nullptr;
		HINTERNET hWebSocket = nullptr;
#endif
		std::thread recvLoop;

		void close_tcp()
		{
			if (wsSocket != INVALID_SOCKET) {
				closesocket(wsSocket);
				wsSocket = INVALID_SOCKET;
			}
		}

#if defined(_WIN32)
		void close_winhttp()
		{
			if (hWebSocket) {
				WinHttpWebSocketClose(hWebSocket, WINHTTP_WEB_SOCKET_SUCCESS_CLOSE_STATUS, nullptr, 0);
				WinHttpCloseHandle(hWebSocket);
				hWebSocket = nullptr;
			}
			if (hConnect) {
				WinHttpCloseHandle(hConnect);
				hConnect = nullptr;
			}
			if (hSession) {
				WinHttpCloseHandle(hSession);
				hSession = nullptr;
			}
		}

		void connect_winhttp(const string& host, int port, const string& path, bool secure)
		{
			ZONE_WS_LOG("WinHTTP begin host=\"" << host << "\" port=" << port << " path=\"" << path << "\" tls=" << (secure ? "yes" : "no"));
			wstring whost = utf8_to_wide(host);
			wstring wpath = utf8_to_wide(path);
			if (wpath.empty())
				wpath = L"/";

			hSession = WinHttpOpen(L"ZoneCore-WebSocket/1.0",
				WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
				WINHTTP_NO_PROXY_NAME,
				WINHTTP_NO_PROXY_BYPASS, 0);
			if (!hSession) {
				ZONE_WS_LOG("WinHttpOpen failed, GetLastError=" << GetLastError());
				throw runtime_error("WinHttpOpen failed");
			}

			hConnect = WinHttpConnect(hSession, whost.c_str(), (INTERNET_PORT)port, 0);
			if (!hConnect) {
				ZONE_WS_LOG("WinHttpConnect failed, GetLastError=" << GetLastError());
				close_winhttp();
				throw runtime_error("WinHttpConnect failed");
			}

			DWORD openFlags = secure ? WINHTTP_FLAG_SECURE : 0;
			HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", wpath.c_str(), nullptr,
				WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, openFlags);
			if (!hRequest) {
				ZONE_WS_LOG("WinHttpOpenRequest failed, GetLastError=" << GetLastError());
				close_winhttp();
				throw runtime_error("WinHttpOpenRequest failed");
			}

			// MSDN: lpBuffer 必须为 NULL，dwBufferLength 必须为 0，否则会返回 ERROR_INVALID_PARAMETER (87)
			if (!WinHttpSetOption(hRequest, WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET, nullptr, 0)) {
				ZONE_WS_LOG("WinHttpSetOption UPGRADE_TO_WEB_SOCKET failed, GetLastError=" << GetLastError());
				WinHttpCloseHandle(hRequest);
				close_winhttp();
				throw runtime_error("WinHttpSetOption UPGRADE_TO_WEB_SOCKET failed");
			}

			if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
				WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
				ZONE_WS_LOG("WinHttpSendRequest failed, GetLastError=" << GetLastError());
				WinHttpCloseHandle(hRequest);
				close_winhttp();
				throw runtime_error("WinHttpSendRequest failed");
			}

			if (!WinHttpReceiveResponse(hRequest, nullptr)) {
				ZONE_WS_LOG("WinHttpReceiveResponse failed, GetLastError=" << GetLastError());
				WinHttpCloseHandle(hRequest);
				close_winhttp();
				throw runtime_error("WinHttpReceiveResponse failed");
			}

			hWebSocket = WinHttpWebSocketCompleteUpgrade(hRequest, (DWORD_PTR)0);
			WinHttpCloseHandle(hRequest);
			if (!hWebSocket) {
				ZONE_WS_LOG("WinHttpWebSocketCompleteUpgrade failed, GetLastError=" << GetLastError());
				close_winhttp();
				throw runtime_error("WinHttpWebSocketCompleteUpgrade failed");
			}

			use_winhttp = true;
			ZONE_WS_LOG("WinHTTP WebSocket upgrade OK");
		}
#endif

		static bool random_mask_key(byte_t out4[4])
		{
#if defined(_WIN32)
			HCRYPTPROV prov = 0;
			if (!CryptAcquireContextA(&prov, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
				return false;
			BOOL ok = CryptGenRandom(prov, 4, out4);
			CryptReleaseContext(prov, 0);
			return ok != FALSE;
#else
			for (int i = 0; i < 4; ++i) out4[i] = (byte_t)(rand() & 0xFF);
			return true;
#endif
		}

		void Send(WebSocketOpcode opcode)
		{
			if (use_winhttp)
				return;
			array<byte_t, 6> frame_data = { 0x00, 0x80, 0x00, 0x00, 0x00, 0x00 };
			frame_data[0] = 0x80 | (byte_t)opcode;
			int sendResult = send(wsSocket, (char*)frame_data.data(), 2, 0);
			if (sendResult == SOCKET_ERROR)
			{
				throw std::runtime_error("socket error (send).");
			}
		}

		template<class Iterator>
		void Send(WebSocketOpcode opcode, Iterator begin, Iterator end)
		{
			if (use_winhttp) {
#if defined(_WIN32)
				size_t length = (size_t)(end - begin);
				if (opcode == WebSocketOpcode::Text) {
					DWORD err = WinHttpWebSocketSend(hWebSocket, WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE,
						(PVOID)&*begin, (DWORD)length);
					if (err != ERROR_SUCCESS)
						throw std::runtime_error("WinHttpWebSocketSend failed");
				}
				else {
					DWORD err = WinHttpWebSocketSend(hWebSocket, WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE,
						(PVOID)&*begin, (DWORD)length);
					if (err != ERROR_SUCCESS)
						throw std::runtime_error("WinHttpWebSocketSend failed");
				}
#endif
				return;
			}

			size_t length = (size_t)(end - begin);
			vector<byte_t> frame_data;
			frame_data.reserve(length + 16);
			frame_data.push_back(0x80 | (byte_t)opcode);
			if (length <= 125)
			{
				frame_data.push_back(0x80 | (byte_t)length);
			}
			else if (length <= (std::numeric_limits<uint16_t>::max)())
			{
				uint16_t t = (uint16_t)length;
				frame_data.push_back(0x80 | 126);
				frame_data.push_back((t >> 8) & 0xFF);
				frame_data.push_back((t >> 0) & 0xFF);
			}
			else if (length <= 0x7FFFFFFFFFFFFFFFULL)
			{
				uint64_t t = (uint64_t)length;
				frame_data.push_back(0x80 | 127);
				for (int i = 7; i >= 0; --i)
					frame_data.push_back((byte_t)((t >> (i * 8)) & 0xFF));
			}
			else
			{
				throw std::runtime_error("Data is too large. Does not support fragmentation.");
			}

			std::array<byte_t, 4> mask_key{};
			if (!random_mask_key(mask_key.data()))
				throw std::runtime_error("random_mask_key failed");
			frame_data.insert(frame_data.end(), mask_key.begin(), mask_key.end());

			int i = 0;
			for (auto it = begin; it != end; ++it)
			{
				frame_data.push_back((byte_t)(*it ^ mask_key[i++ % 4]));
			}

			int sendResult = send(wsSocket, (char*)frame_data.data(), (int)frame_data.size(), 0);
			if (sendResult == SOCKET_ERROR)
			{
				throw std::runtime_error("socket error (send).");
			}
		}
	};

	struct FrameInfo
	{
		bool Fin = false;
		bool Mask = false;
		WebSocketOpcode Opcode = WebSocketOpcode::Text;
		byte_t MaskKey[4] = { };
		uint64_t PayloadLength = 0;
	};

	int TryParseFrame(FrameInfo* frame_info, const byte_t* frame_data, size_t len)
	{
		if (len < 2) return -1;
		int offset = 2;
		FrameInfo& info = *frame_info;
		info.Fin = (frame_data[0] & 0x80) == 0x80;
		info.Mask = (frame_data[1] & 0x80) == 0x80;
		info.Opcode = static_cast<WebSocketOpcode>(frame_data[0] & 0x0F);
		info.PayloadLength = frame_data[1] & 0x7F;
		if (info.PayloadLength == 126)
		{
			if (len < 4) return -1;
			info.PayloadLength = ((uint64_t)frame_data[2] << 8) | frame_data[3];
			offset = 4;
		}
		else if (info.PayloadLength == 127)
		{
			if (len < 10) return -1;
			uint64_t v = 0;
			for (int i = 0; i < 8; ++i)
				v = (v << 8) | frame_data[2 + i];
			if (v >> 63)
				return -1;
			info.PayloadLength = v;
			offset = 10;
		}
		if (info.Mask)
		{
			if (len < (size_t)offset + 4) return -1;
			memcpy(&info.MaskKey, &frame_data[offset], sizeof(info.MaskKey));
			offset += 4;
		}
		return offset;
	}

	WebSocketClient::WebSocketClient() : PrivateMembers(new pimpl()), status(Status::Closed)
	{
#if defined(_WIN32)
		WSAData data;
		int WsResult = WSAStartup(MAKEWORD(2, 2), &data);
		if (WsResult != 0)
		{
			throw std::runtime_error("Can't start winsock.");
		}
#endif
	}
	
	WebSocketClient::~WebSocketClient()
	{
		delete PrivateMembers;
#if defined(_WIN32)
		WSACleanup();
#endif
	}

	void WebSocketClient::Connect(const string& ws_uri)
	{
		ZONE_WS_LOG("Connect(uri) \"" << ws_uri << "\"");
#if defined(_WIN32)
		PrivateMembers->close_winhttp();
		PrivateMembers->close_tcp();
		PrivateMembers->use_winhttp = false;
#endif
		bool secure = false;
		string host;
		int port = 80;
		string path;
		if (!ws_uri_parse(ws_uri, secure, host, port, path)) {
			ZONE_WS_LOG("URI parse failed");
			throw std::runtime_error("Unable to parse websocket uri (expected ws:// or wss://).");
		}
		ZONE_WS_LOG("URI ok secure=" << (secure ? "wss" : "ws") << " host=\"" << host << "\" port=" << port << " path=\"" << path << "\"");

#if defined(_WIN32)
		if (secure) {
			PrivateMembers->connect_winhttp(host, port, path, true);
			status = Status::Open;
			ZONE_WS_LOG("status=Open, starting RecvLoop (WinHTTP wss)");
			PrivateMembers->recvLoop = std::thread([this]() {RecvLoop(); });
			PrivateMembers->recvLoop.detach();
			return;
		}
		PrivateMembers->connect_winhttp(host, port, path, false);
		status = Status::Open;
		ZONE_WS_LOG("status=Open, starting RecvLoop (WinHTTP ws)");
		PrivateMembers->recvLoop = std::thread([this]() {RecvLoop(); });
		PrivateMembers->recvLoop.detach();
#else
		if (secure)
			throw std::runtime_error("wss:// is not supported on this platform (build on Windows with WinHTTP or add TLS).");
		Connect(host, port, path);
#endif
	}

	void WebSocketClient::Connect(const string& hostname, int port, const string& path)
	{
		ZONE_WS_LOG("Connect(host,port) host=\"" << hostname << "\" port=" << port << " path=\"" << path << "\"");
#if defined(_WIN32)
		PrivateMembers->close_tcp();
		PrivateMembers->close_winhttp();
		PrivateMembers->use_winhttp = false;
#endif

		PrivateMembers->wsSocket = hostname_connect(hostname, port);
		if (PrivateMembers->wsSocket == INVALID_SOCKET)
		{
			ZONE_WS_LOG("TCP connect failed host=\"" << hostname << "\" port=" << port);
			throw std::runtime_error("Unable to connect to " + hostname);
		}
		ZONE_WS_LOG("TCP connected");

		string hostHeader = hostname;
		if (!(port == 80 || port == 443))
			hostHeader += ":" + to_string(port);

		string handshakingWords;
		handshakingWords.append("GET ").append(path).append(" HTTP/1.1").append("\r\n");
		handshakingWords.append("Host: ").append(hostHeader).append("\r\n");
		handshakingWords.append("Connection: Upgrade").append("\r\n");
		handshakingWords.append("Upgrade: websocket").append("\r\n");
		handshakingWords.append("Sec-WebSocket-Version: 13").append("\r\n");

#if defined(_WIN32)
		string secKey = make_sec_websocket_key();
		string expectAccept = sec_websocket_accept_for_key(secKey);
		if (expectAccept.empty()) {
			PrivateMembers->close_tcp();
			throw std::runtime_error("Sec-WebSocket-Accept derivation failed.");
		}
		handshakingWords.append("Sec-WebSocket-Key: ").append(secKey).append("\r\n");
#else
		handshakingWords.append("Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==").append("\r\n");
#endif
		handshakingWords.append("\r\n");

		int sendResult = send(PrivateMembers->wsSocket, handshakingWords.c_str(), (int)handshakingWords.size(), 0);
		if (sendResult == SOCKET_ERROR)
		{
			ZONE_WS_LOG("handshake send failed");
			PrivateMembers->close_tcp();
			throw std::runtime_error("An error occurred during the handshake.");
		}

#if defined(_WIN32)
		string response;
		if (!recv_http_header_block(PrivateMembers->wsSocket, response)) {
			ZONE_WS_LOG("handshake response read failed");
			PrivateMembers->close_tcp();
			throw std::runtime_error("Handshake response read failed.");
		}
		if (!validate_ws_handshake(response, expectAccept)) {
			ZONE_WS_LOG("handshake validate failed (not 101 or bad Accept), first line: "
				<< (response.size() > 120 ? response.substr(0, 120) + "..." : response));
			PrivateMembers->close_tcp();
			throw std::runtime_error("WebSocket handshake failed (expected HTTP 101 and valid Sec-WebSocket-Accept).");
		}
		ZONE_WS_LOG("TCP handshake OK (HTTP 101)");
#else
		char response_buffer[4096] = { 0 };
		int bytesReceived = recv(PrivateMembers->wsSocket, response_buffer, 4096, 0);
		if (bytesReceived <= 0) {
			PrivateMembers->close_tcp();
			throw std::runtime_error("Handshake response read failed.");
		}
#endif

		status = Status::Open;
		ZONE_WS_LOG("status=Open, starting RecvLoop (raw TCP)");
		PrivateMembers->recvLoop = std::thread([this]() {RecvLoop(); });
		PrivateMembers->recvLoop.detach();
	}

	void WebSocketClient::Shutdown()
	{
		if (status == Status::Closed) return;
		ZONE_WS_LOG("Shutdown()");
		status = Status::Closed;
#if defined(_WIN32)
		if (PrivateMembers->use_winhttp)
			PrivateMembers->close_winhttp();
		else
#endif
			PrivateMembers->close_tcp();
	}

	void WebSocketClient::OnTextReceived(Callback<string> callback)
	{
		TextReceivedCallback = callback;
	}

	void WebSocketClient::OnBinaryReceived(Callback<vector<uint8_t>> callback)
	{
		BinaryReceivedCallback = callback;
	}

	void WebSocketClient::OnError(Callback<string> callback)
	{
		ErrorCallback = callback;
	}

	void WebSocketClient::OnLostConnection(Callback<int> callback)
	{
		LostConnectionCallback = callback;
	}

	void WebSocketClient::SendText(const string& text)
	{
		if (status == Status::Closed) {
			ZONE_WS_LOG("SendText rejected: closed, len=" << text.size());
			throw std::runtime_error("WebSocket is closed.");
		}
		ZONE_WS_LOG("SendText len=" << text.size() << (PrivateMembers->use_winhttp ? " (WinHTTP)" : " (TCP)"));
		PrivateMembers->Send(WebSocketOpcode::Text, text.begin(), text.end());
	}

	void WebSocketClient::SendBinary(const char* data, size_t length)
	{
		if (status == Status::Closed)
			throw std::runtime_error("WebSocket is closed.");
		PrivateMembers->Send(WebSocketOpcode::Binary, data, data + length);
	}

	void WebSocketClient::SendBinary(const uint8_t* data, size_t length)
	{
		if (status == Status::Closed)
			throw std::runtime_error("WebSocket is closed.");
		PrivateMembers->Send(WebSocketOpcode::Binary, data, data + length);
	}

	void WebSocketClient::Ping()
	{
		if (status == Status::Closed) return;
#if defined(_WIN32)
		if (PrivateMembers->use_winhttp)
			return;
#endif
		PrivateMembers->Send(WebSocketOpcode::Ping);
	}

	void WebSocketClient::Pong()
	{
		if (status == Status::Closed) return;
#if defined(_WIN32)
		if (PrivateMembers->use_winhttp)
			return;
#endif
		PrivateMembers->Send(WebSocketOpcode::Pong);
	}

	void WebSocketClient::Pong(const vector<uint8_t>& data)
	{
		if (status == Status::Closed) return;
		PrivateMembers->Send(WebSocketOpcode::Pong, data.begin(), data.end());
	}

	void WebSocketClient::Close()
	{
		if (status == Status::Closed) return;
		ZONE_WS_LOG("Close()");
		status = Status::Closing;
#if defined(_WIN32)
		if (PrivateMembers->use_winhttp && PrivateMembers->hWebSocket) {
			WinHttpWebSocketClose(PrivateMembers->hWebSocket, WINHTTP_WEB_SOCKET_SUCCESS_CLOSE_STATUS, nullptr, 0);
			return;
		}
#endif
		PrivateMembers->Send(WebSocketOpcode::Close);
	}

	void WebSocketClient::RecvLoop()
	{
#if defined(_WIN32)
		if (PrivateMembers->use_winhttp) {
			string utf8Accum;
			vector<uint8_t> binAccum;
			while (status == Status::Open)
			{
				BYTE buf[8192];
				DWORD read = 0;
				WINHTTP_WEB_SOCKET_BUFFER_TYPE bt = WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE;
				DWORD r = WinHttpWebSocketReceive(PrivateMembers->hWebSocket, buf, sizeof(buf), &read, &bt);
				if (r != ERROR_SUCCESS)
				{
					ZONE_WS_LOG("WinHttpWebSocketReceive failed err=" << r << " GetLastError=" << GetLastError());
					if (status == Status::Open)
					{
						Shutdown();
						if (LostConnectionCallback != nullptr)
							LostConnectionCallback(*this, 1006);
					}
					return;
				}
#if defined(ZoneDebug)
				ZONE_WS_LOG("WinHTTP recv type=" << zone_ws_winhttp_buf_type_str(bt) << " bytes=" << read);
#endif
				if (bt == WINHTTP_WEB_SOCKET_CLOSE_BUFFER_TYPE)
				{
					ZONE_WS_LOG("peer close frame");
					if (status == Status::Open || status == Status::Closing)
					{
						Shutdown();
						if (LostConnectionCallback != nullptr)
							LostConnectionCallback(*this, 1000);
					}
					return;
				}
				if (bt == WINHTTP_WEB_SOCKET_UTF8_FRAGMENT_BUFFER_TYPE)
				{
					utf8Accum.append((char*)buf, read);
					continue;
				}
				if (bt == WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE)
				{
					utf8Accum.append((char*)buf, read);
					if (TextReceivedCallback != nullptr && !utf8Accum.empty()) {
						ZONE_WS_LOG("on text (WinHTTP) len=" << utf8Accum.size());
						TextReceivedCallback(*this, utf8Accum);
					}
					utf8Accum.clear();
					continue;
				}
				if (bt == WINHTTP_WEB_SOCKET_BINARY_FRAGMENT_BUFFER_TYPE)
				{
					binAccum.insert(binAccum.end(), buf, buf + read);
					continue;
				}
				if (bt == WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE)
				{
					binAccum.insert(binAccum.end(), buf, buf + read);
					if (BinaryReceivedCallback != nullptr && !binAccum.empty())
						BinaryReceivedCallback(*this, binAccum);
					binAccum.clear();
					continue;
				}
			}
			return;
		}
#endif

		socket_t sock = PrivateMembers->wsSocket;
		vector<byte_t> buffer;
		buffer.reserve(8192);

		while (status == Status::Open)
		{
			struct timeval tv;
			tv.tv_sec = 0;
			tv.tv_usec = 200 * 1000;

			fd_set fds_read;
			FD_ZERO(&fds_read);
			FD_SET(sock, &fds_read);
			int ret = select((int)(sock + 1), &fds_read, NULL, NULL, &tv);
			if (ret < 0)
			{
				ZONE_WS_LOG("select error ret=" << ret);
				if (ErrorCallback != nullptr)
				{
					ErrorCallback(*this, "select error.");
				}
			}
			if (ret != 0 && FD_ISSET(sock, &fds_read))
			{
				array<char, 2048>  buf = {};
				int bytesReceived = recv(sock, buf.data(), (int)buf.size(), 0);
				if (bytesReceived > 0)
				{
					ZONE_WS_LOG("TCP recv " << bytesReceived << " bytes, buffer_total=" << (buffer.size() + (size_t)bytesReceived));
					buffer.insert(buffer.end(), buf.begin(), buf.begin() + bytesReceived);
				}
				else
				{
					ZONE_WS_LOG("TCP recv closed or error bytesReceived=" << bytesReceived);
					if (status == Status::Open)
					{
						this->Shutdown();
						if (LostConnectionCallback != nullptr)
						{
							LostConnectionCallback(*this, 1006);
						}
					}
					break;
				}
			}

			while (buffer.size())
			{
				FrameInfo info;
				int offset = TryParseFrame(&info, buffer.data(), buffer.size());
				if (offset < 0)
				{
					ZONE_WS_LOG("parse frame failed, buffer_len=" << buffer.size());
					if (ErrorCallback != nullptr)
					{
						ErrorCallback(*this, "Failed to parse frame.");
					}
					break;
				}
				else
				{
					if (buffer.size() >= (size_t)offset + info.PayloadLength)
					{
						auto payload_start = buffer.begin() + offset;
						auto payload_end = buffer.begin() + (offset + (ptrdiff_t)info.PayloadLength);
						if (info.Mask)
						{
							int i = 0;
							for (auto it = payload_start; it != payload_end; ++it)
							{
								*it = *it ^ info.MaskKey[i++ % 4];
							}
						}
						if (info.Opcode == WebSocketOpcode::Text)
						{
							string text = string(payload_start, payload_end);
							ZONE_WS_LOG("on text (TCP) len=" << text.size());
							if (TextReceivedCallback != nullptr)
							{
								TextReceivedCallback(*this, text);
							}
						}
						else if (info.Opcode == WebSocketOpcode::Binary)
						{
							if (BinaryReceivedCallback != nullptr)
							{
								BinaryReceivedCallback(*this, vector<uint8_t>(payload_start, payload_end));
							}
						}
						else if (info.Opcode == WebSocketOpcode::Ping)
						{
							try
							{
								Pong(vector<uint8_t>(payload_start, payload_end));
							}
							catch (const std::exception& ex)
							{
								if (ErrorCallback != nullptr)
								{
									ErrorCallback(*this, string("An error occurs on sending pong frame. error: ")+ ex.what());
								}
							}
						}
						else if (info.Opcode == WebSocketOpcode::Close)
						{
							if (status == Status::Closing)
							{
								Shutdown();
							}
							else if (status == Status::Open)
							{
								Close();
								Shutdown();
								if (LostConnectionCallback != nullptr)
								{
									LostConnectionCallback(*this, 1000);
								}
							}
							return;
						}
						else
						{
							ZONE_WS_LOG("unsupported opcode " << (int)info.Opcode);
							if (ErrorCallback != nullptr)
							{
								ErrorCallback(*this, 
									string("The opcode #")
										.append(to_string((int)info.Opcode))
										.append(" is not supported.") );
							}
						}
						buffer.erase(buffer.begin(), buffer.begin() + (offset + (ptrdiff_t)info.PayloadLength));
					}
					else
					{
						break;
					}
				}
			}
		}

	}


}

