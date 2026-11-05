#ifndef XOVM_CLOUD_MATERIAL_BACKEND_RAW_SERVER_H
#define XOVM_CLOUD_MATERIAL_BACKEND_RAW_SERVER_H

#include "../cloud_material/raw_protocol.h"
#include "raw_session.h"

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <mutex>
#include <span>
#include <string>
#include <thread>
#include <unordered_set>
#include <variant>
#include <vector>

namespace xovm::cloud_material {

struct RawServerConfig {
    std::string bind_address = "127.0.0.1";
    std::uint16_t port = 0;
    std::uint32_t backlog = 16;
    std::uint32_t max_active_connections = 16;
    std::uint64_t idle_timeout_ms = 30000;
};

struct RawServerError {
    std::string code;
};

class RawServer {
public:
    using HelloHandler = std::function<xovm::material::RawServerHello(
        const xovm::material::RawHello &)>;
    using FrameHandler = std::function<std::variant<std::vector<uint8_t>, RawSessionError>(
        const AuthenticatedRawContext &, const xovm::material::RawFrameHeader &,
        std::span<const uint8_t>)>;
    using SessionConfigFactory = std::function<std::variant<RawSessionConfig, RawServerError>()>;
    using SessionFactory = std::function<std::variant<RawSession, RawServerError>(
        const xovm::material::RawHello &)>;

    explicit RawServer(RawServerConfig config);
    ~RawServer();
    RawServer(const RawServer &) = delete;
    RawServer &operator=(const RawServer &) = delete;

    void setHelloHandler(HelloHandler handler);
    void setFrameHandler(FrameHandler handler);
    void setSessionConfig(RawSessionConfig config);
    void setSessionConfigFactory(SessionConfigFactory factory);
    void setSessionFactory(SessionFactory factory);
    std::variant<std::monostate, RawServerError> start();
    // Must be called outside server callbacks; callback re-entry is rejected.
    void stop();
    std::uint16_t port() const { return bound_port_; }

private:
    void acceptLoop();
    void workerLoop();
    void handleClient(int client);
    void closeClient(int client);

    RawServerConfig config_;
    std::mutex lifecycle_mutex_;
    std::mutex callbacks_mutex_;
    HelloHandler hello_handler_;
    FrameHandler frame_handler_;
    SessionConfigFactory session_config_factory_;
    SessionFactory session_factory_;
    std::atomic<bool> stopping_{false};
    std::atomic<int> listen_fd_{-1};
    std::uint16_t bound_port_ = 0;
    std::thread accept_thread_;
    std::mutex clients_mutex_;
    std::condition_variable clients_ready_;
    std::deque<int> pending_clients_;
    std::unordered_set<int> client_fds_;
    std::vector<std::thread> workers_;
};

} // namespace xovm::cloud_material

#endif
