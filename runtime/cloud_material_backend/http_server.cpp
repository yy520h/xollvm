#include "http_server.h"
#include "http_contract.h"
#include "protocol_service.h"

#include <nlohmann/json.hpp>

#include <arpa/inet.h>
#include <charconv>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <fcntl.h>
#include <netinet/in.h>
#include <sstream>
#include <sys/socket.h>
#include <unistd.h>

namespace xovm::cloud_material {
namespace {

const char *reasonPhrase(unsigned code) {
    switch (code) {
    case 200: return "OK";
    case 400: return "Bad Request";
    case 401: return "Unauthorized";
    case 404: return "Not Found";
    case 405: return "Method Not Allowed";
    case 413: return "Payload Too Large";
    case 415: return "Unsupported Media Type";
    case 503: return "Service Unavailable";
    default: return "Internal Server Error";
    }
}

std::string base64(std::span<const std::byte> bytes) {
    constexpr char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string result;
    result.reserve(((bytes.size() + 2) / 3) * 4);
    for (std::size_t index = 0; index < bytes.size(); index += 3) {
        const auto left = std::to_integer<unsigned char>(bytes[index]);
        const auto middle = index + 1 < bytes.size()
            ? std::to_integer<unsigned char>(bytes[index + 1]) : 0;
        const auto right = index + 2 < bytes.size()
            ? std::to_integer<unsigned char>(bytes[index + 2]) : 0;
        result.push_back(alphabet[left >> 2]);
        result.push_back(alphabet[((left & 3) << 4) | (middle >> 4)]);
        result.push_back(index + 1 < bytes.size()
            ? alphabet[((middle & 15) << 2) | (right >> 6)] : '=');
        result.push_back(index + 2 < bytes.size() ? alphabet[right & 63] : '=');
    }
    return result;
}

std::string lower(std::string value) {
    for (char &character : value)
        if (character >= 'A' && character <= 'Z') character = static_cast<char>(character + 32);
    return value;
}

std::string trim(std::string value) {
    const auto first = value.find_first_not_of(" \t");
    if (first == std::string::npos) return {};
    const auto last = value.find_last_not_of(" \t");
    return value.substr(first, last - first + 1);
}

bool sendAll(int fd, std::string_view value) {
    std::size_t offset = 0;
    while (offset < value.size()) {
        const auto count = ::send(fd, value.data() + offset, value.size() - offset, MSG_NOSIGNAL);
        if (count <= 0) return false;
        offset += static_cast<std::size_t>(count);
    }
    return true;
}

bool validPathSegment(std::string_view value) {
    if (value.empty() || value.size() > 128) return false;
    return std::all_of(value.begin(), value.end(), [](char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
    });
}

} // namespace

HttpServer::HttpServer(HttpServerConfig config) : config_(std::move(config)) {}

HttpServer::~HttpServer() {
    stop();
}

std::variant<std::monostate, BackendError> HttpServer::start() {
    if (config_.bind_address != "127.0.0.1")
        return BackendError{"http_bind_must_be_loopback"};
    if (config_.relay_token.empty() || config_.admin_token.empty())
        return BackendError{"http_missing_relay_credential"};
    if (config_.max_body_bytes == 0 || config_.max_header_bytes == 0 ||
        config_.max_response_bytes == 0 ||
        config_.max_concurrent_requests == 0 ||
        config_.idle_timeout_ms == 0)
        return BackendError{"http_invalid_limits"};
    if (listen_fd_ >= 0) return BackendError{"http_already_started"};
    const int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return BackendError{"http_socket_failed"};
    int reuse = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(config_.port);
    if (::inet_pton(AF_INET, config_.bind_address.c_str(), &address.sin_addr) != 1 ||
        ::bind(fd, reinterpret_cast<sockaddr *>(&address), sizeof(address)) != 0 ||
        ::listen(fd, 64) != 0) {
        ::close(fd);
        return BackendError{"http_bind_failed"};
    }
    sockaddr_in bound{};
    socklen_t length = sizeof(bound);
    if (::getsockname(fd, reinterpret_cast<sockaddr *>(&bound), &length) != 0) {
        ::close(fd);
        return BackendError{"http_port_failed"};
    }
    listen_fd_.store(fd);
    bound_port_ = ntohs(bound.sin_port);
    stopping_ = false;
    accept_thread_ = std::thread(&HttpServer::acceptLoop, this);
    return std::monostate{};
}

void HttpServer::stop() {
    stopping_ = true;
    const int fd = listen_fd_.exchange(-1);
    if (fd >= 0) {
        ::shutdown(fd, SHUT_RDWR);
        ::close(fd);
    }
    if (accept_thread_.joinable()) accept_thread_.join();
    std::lock_guard lock(workers_mutex_);
    for (auto &worker : workers_)
        if (worker.joinable()) worker.join();
    workers_.clear();
}

void HttpServer::setReady(bool ready) {
    ready_ = ready;
}

void HttpServer::setRelayHandler(RelayHandler handler) {
    std::lock_guard lock(handler_mutex_);
    relay_handler_ = std::move(handler);
}

void HttpServer::setProtocolService(ProtocolService *service) {
    if (service == nullptr) {
        setRelayHandler({});
        return;
    }
    setRelayHandler([service](std::span<const std::byte> request,
                              const std::string &credential) {
        return service->handle(request, credential);
    });
}

void HttpServer::setAdminHandler(AdminHandler handler) {
    std::lock_guard lock(handler_mutex_);
    admin_handler_ = std::move(handler);
}

void HttpServer::setTrustHandler(TrustHandler handler) {
    std::lock_guard lock(handler_mutex_);
    trust_handler_ = std::move(handler);
}

void HttpServer::acceptLoop() {
    while (!stopping_) {
        const int fd = ::accept4(listen_fd_.load(), nullptr, nullptr, SOCK_CLOEXEC);
        if (fd < 0) {
            if (stopping_) break;
            continue;
        }
        if (active_requests_.fetch_add(1) >= config_.max_concurrent_requests) {
            active_requests_.fetch_sub(1);
            ::close(fd);
            continue;
        }
        std::lock_guard lock(workers_mutex_);
        workers_.emplace_back([this, fd] {
            handleConnection(fd);
            active_requests_.fetch_sub(1);
        });
    }
}

std::string HttpServer::response(unsigned status, std::string_view body,
                                 std::string_view contentType) const {
    std::ostringstream output;
    output << "HTTP/1.1 " << status << ' ' << reasonPhrase(status) << "\r\n"
           << "Content-Type: " << contentType << "\r\n"
           << "Content-Length: " << body.size() << "\r\n"
           << "Connection: close\r\n"
           << "Cache-Control: no-store\r\n\r\n" << body;
    return output.str();
}

void HttpServer::handleConnection(int fd) {
    timeval timeout{};
    timeout.tv_sec = static_cast<time_t>(config_.idle_timeout_ms / 1000);
    timeout.tv_usec = static_cast<suseconds_t>((config_.idle_timeout_ms % 1000) * 1000);
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    std::string request;
    char buffer[4096];
    std::size_t headerEnd = std::string::npos;
    while (request.size() <= config_.max_header_bytes) {
        const auto count = ::recv(fd, buffer, sizeof(buffer), 0);
        if (count <= 0) break;
        request.append(buffer, static_cast<std::size_t>(count));
        headerEnd = request.find("\r\n\r\n");
        if (headerEnd != std::string::npos) break;
    }
    auto sendError = [&](unsigned status) {
        const auto body = std::string("{\"error\":\"request_failed\"}");
        sendAll(fd, response(status, body));
    };
    if (headerEnd == std::string::npos || headerEnd + 4 > config_.max_header_bytes) {
        sendError(request.size() > config_.max_header_bytes ? 413 : 400);
        ::close(fd);
        return;
    }
    const auto header = request.substr(0, headerEnd);
    const auto firstEnd = header.find("\r\n");
    if (firstEnd == std::string::npos) {
        sendError(400);
        ::close(fd);
        return;
    }
    std::istringstream first(header.substr(0, firstEnd));
    std::string method;
    std::string path;
    std::string version;
    first >> method >> path >> version;
    if (version != "HTTP/1.1") {
        sendError(400);
        ::close(fd);
        return;
    }
    std::size_t contentLength = 0;
    std::string contentType;
    std::string contentEncoding;
    std::string transferEncoding;
    std::string authorization;
    bool contentLengthSeen = false;
    bool authorizationSeen = false;
    bool contentTypeSeen = false;
    bool contentEncodingSeen = false;
    bool transferEncodingSeen = false;
    std::size_t offset = firstEnd + 2;
    while (offset < header.size()) {
        const auto end = header.find("\r\n", offset);
        const auto line = header.substr(offset, end == std::string::npos ? end : end - offset);
        const auto colon = line.find(':');
        if (colon == std::string::npos) {
            sendError(400);
            ::close(fd);
            return;
        }
        const auto name = lower(line.substr(0, colon));
        const auto value = trim(line.substr(colon + 1));
        if (name == "content-length") {
            if (contentLengthSeen) {
                sendError(400);
                ::close(fd);
                return;
            }
            contentLengthSeen = true;
            std::uint64_t parsed = 0;
            const auto result = std::from_chars(value.data(), value.data() + value.size(), parsed);
            if (result.ec != std::errc{} || result.ptr != value.data() + value.size()) {
                sendError(400);
                ::close(fd);
                return;
            }
            contentLength = parsed;
        } else if (name == "content-type") {
            if (contentTypeSeen) {
                sendError(400);
                ::close(fd);
                return;
            }
            contentTypeSeen = true;
            contentType = lower(value);
        } else if (name == "content-encoding") {
            if (contentEncodingSeen) {
                sendError(400);
                ::close(fd);
                return;
            }
            contentEncodingSeen = true;
            contentEncoding = lower(value);
        } else if (name == "transfer-encoding") {
            if (transferEncodingSeen) {
                sendError(400);
                ::close(fd);
                return;
            }
            transferEncodingSeen = true;
            transferEncoding = lower(value);
        } else if (name == "authorization") {
            if (authorizationSeen) {
                sendError(400);
                ::close(fd);
                return;
            }
            authorizationSeen = true;
            authorization = value;
        }
        if (end == std::string::npos) break;
        offset = end + 2;
    }
    const bool adminBodyRoute = path == "/v2/admin/builds/import" ||
        path.rfind("/v2/admin/builds/", 0) == 0;
    const auto bodyLimit = adminBodyRoute ? config_.max_admin_body_bytes : config_.max_body_bytes;
    if (contentLength > bodyLimit) {
        sendError(413);
        ::close(fd);
        return;
    }
    if (!transferEncoding.empty()) {
        sendError(400);
        ::close(fd);
        return;
    }
    while (request.size() < headerEnd + 4 + contentLength) {
        const auto count = ::recv(fd, buffer, sizeof(buffer), 0);
        if (count <= 0) {
            sendError(400);
            ::close(fd);
            return;
        }
        request.append(buffer, static_cast<std::size_t>(count));
        if (request.size() > headerEnd + 4 + contentLength) break;
    }
    if (request.size() < headerEnd + 4 + contentLength) {
        sendError(400);
        ::close(fd);
        return;
    }
    if (path == "/healthz" && method == "GET") {
        const auto status = ready_.load() ? 200 : 503;
        sendAll(fd, response(status, ready_.load() ? "{\"ready\":true}" : "{\"ready\":false}"));
        ::close(fd);
        return;
    }
    const std::string_view trustPrefix = "/v2/trust/";
    if (path.rfind(trustPrefix, 0) == 0 && method == "GET") {
        const auto softwareId = std::string_view(path).substr(trustPrefix.size());
        TrustHandler handler;
        {
            std::lock_guard lock(handler_mutex_);
            handler = trust_handler_;
        }
        if (!handler || !validPathSegment(softwareId)) {
            sendError(404);
            ::close(fd);
            return;
        }
        auto result = handler(softwareId);
        if (const auto *error = std::get_if<BackendError>(&result)) {
            (void)error;
            sendError(500);
        } else {
            const auto &body = std::get<std::vector<std::byte>>(result);
            if (body.size() > config_.max_response_bytes) sendError(500);
            else sendAll(fd, response(200, std::string_view(
                reinterpret_cast<const char *>(body.data()), body.size()),
                "application/octet-stream"));
        }
        ::close(fd);
        return;
    }
    const std::string_view adminPrefix = "/v2/admin/builds/";
    const bool isImport = path == "/v2/admin/builds/import";
    const bool isRevoke = path.rfind(adminPrefix, 0) == 0 &&
        path.size() > adminPrefix.size() + std::string_view("/revoke").size() &&
        path.ends_with("/revoke") &&
        validPathSegment(std::string_view(path).substr(
            adminPrefix.size(), path.size() - adminPrefix.size() - std::string_view("/revoke").size()));
    const bool isEnable = path.rfind(adminPrefix, 0) == 0 &&
        path.size() > adminPrefix.size() + std::string_view("/enable").size() &&
        path.ends_with("/enable") &&
        validPathSegment(std::string_view(path).substr(
            adminPrefix.size(), path.size() - adminPrefix.size() - std::string_view("/enable").size()));
    const bool isAdmin = isImport || isRevoke || isEnable;
    if (isAdmin) {
        if (contentLength > config_.max_admin_body_bytes) {
            sendError(413);
            ::close(fd);
            return;
        }
        if (method != "POST" || contentType != "application/json" ||
            (!contentEncoding.empty() && contentEncoding != "identity") ||
            authorization != "Bearer " + config_.admin_token) {
            sendError(401);
            ::close(fd);
            return;
        }
        AdminHandler handler;
        {
            std::lock_guard lock(handler_mutex_);
            handler = admin_handler_;
        }
        if (!handler) {
            sendError(503);
            ::close(fd);
            return;
        }
        const auto bodyStart = headerEnd + 4;
        auto result = handler(path, std::span<const std::byte>(
            reinterpret_cast<const std::byte *>(request.data() + bodyStart), contentLength), authorization);
        if (const auto *error = std::get_if<BackendError>(&result)) {
            (void)error;
            sendError(500);
        } else {
            const auto &body = std::get<std::vector<std::byte>>(result);
            if (body.size() > config_.max_response_bytes) sendError(500);
            else sendAll(fd, response(200, std::string_view(
                reinterpret_cast<const char *>(body.data()), body.size())));
        }
        ::close(fd);
        return;
    }
    if (path != "/v2/relay") {
        sendError(404);
        ::close(fd);
        return;
    }
    if (method != "POST") {
        sendError(405);
        ::close(fd);
        return;
    }
    if (contentType != "application/json" || (!contentEncoding.empty() && contentEncoding != "identity")) {
        sendError(415);
        ::close(fd);
        return;
    }
    const std::string expected = "Bearer " + config_.relay_token;
    if (authorization != expected) {
        sendError(401);
        ::close(fd);
        return;
    }
    const auto bodyStart = headerEnd + 4;
    auto parsed = parseRelayEnvelope(std::span<const std::byte>(
        reinterpret_cast<const std::byte *>(request.data() + bodyStart), contentLength));
    if (const auto *error = std::get_if<BackendError>(&parsed)) {
        (void)error;
        sendError(400);
        ::close(fd);
        return;
    }
    RelayHandler handler;
    {
        std::lock_guard lock(handler_mutex_);
        handler = relay_handler_;
    }
    if (!handler) {
        sendError(503);
        ::close(fd);
        return;
    }
    auto result = handler(std::span<const std::byte>(
        std::get<RelayRequest>(parsed).request_bytes.data(),
        std::get<RelayRequest>(parsed).request_bytes.size()), authorization);
    if (const auto *error = std::get_if<BackendError>(&result)) {
        (void)error;
        sendError(500);
    } else {
        const auto &responseBytes = std::get<std::vector<std::byte>>(result);
        const auto responseEncoded = base64(responseBytes);
        nlohmann::json envelope{{"protocol", "xovm2_relay"},
                                {"response_b64", responseEncoded}};
        const auto body = envelope.dump();
        if (body.size() > config_.max_response_bytes) sendError(500);
        else sendAll(fd, response(200, body));
    }
    ::close(fd);
}

} // namespace xovm::cloud_material
