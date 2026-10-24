#ifndef XOVM_CLOUD_MATERIAL_BACKEND_HTTP_SERVER_H
#define XOVM_CLOUD_MATERIAL_BACKEND_HTTP_SERVER_H

#include "canonical_json.h"

#include <atomic>
#include <cstdint>
#include <functional>
#include <mutex>
#include <span>
#include <string>
#include <thread>
#include <variant>
#include <vector>

namespace xovm::cloud_material {

class ProtocolService;

struct HttpServerConfig {
    std::string bind_address = "127.0.0.1";
    std::uint16_t port = 8080;
    std::string relay_token;
    std::string admin_token;
    std::size_t max_body_bytes = 1024 * 1024;
    std::size_t max_admin_body_bytes = 64 * 1024 * 1024;
    std::size_t max_response_bytes = 16 * 1024 * 1024;
    std::size_t max_header_bytes = 16 * 1024;
    std::uint32_t max_concurrent_requests = 128;
    std::uint64_t idle_timeout_ms = 10000;
};

class HttpServer {
public:
    using RelayHandler = std::function<std::variant<std::vector<std::byte>, BackendError>(
        std::span<const std::byte>, const std::string &)>;
    using AdminHandler = std::function<std::variant<std::vector<std::byte>, BackendError>(
        std::string_view, std::span<const std::byte>, const std::string &)>;
    using TrustHandler = std::function<std::variant<std::vector<std::byte>, BackendError>(
        std::string_view)>;

    explicit HttpServer(HttpServerConfig config);
    ~HttpServer();
    HttpServer(const HttpServer &) = delete;
    HttpServer &operator=(const HttpServer &) = delete;

    std::variant<std::monostate, BackendError> start();
    void stop();
    void setReady(bool ready);
    void setRelayHandler(RelayHandler handler);
    void setProtocolService(ProtocolService *service);
    void setAdminHandler(AdminHandler handler);
    void setTrustHandler(TrustHandler handler);
    std::uint16_t port() const { return bound_port_; }

private:
    void acceptLoop();
    void handleConnection(int fd);
    std::string response(unsigned status, std::string_view body,
                         std::string_view contentType = "application/json") const;

    HttpServerConfig config_;
    RelayHandler relay_handler_;
    AdminHandler admin_handler_;
    TrustHandler trust_handler_;
    std::mutex handler_mutex_;
    std::atomic<bool> ready_{false};
    std::atomic<bool> stopping_{false};
    std::atomic<int> listen_fd_{-1};
    std::uint16_t bound_port_ = 0;
    std::thread accept_thread_;
    std::mutex workers_mutex_;
    std::vector<std::thread> workers_;
    std::atomic<std::uint32_t> active_requests_{0};
};

} // namespace xovm::cloud_material

#endif
