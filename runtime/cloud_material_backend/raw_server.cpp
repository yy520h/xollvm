#include "raw_server.h"

#include "../cloud_material/raw_frame.h"

#include <arpa/inet.h>
#include <openssl/crypto.h>
#include <cerrno>
#include <cstring>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

namespace xovm::cloud_material {
namespace {

constexpr size_t kMaxErrorCode = 64;
thread_local const RawServer *active_server_worker = nullptr;

class WorkerScope final {
public:
    explicit WorkerScope(const RawServer *server) : previous_(active_server_worker) {
        active_server_worker = server;
    }
    ~WorkerScope() { active_server_worker = previous_; }

private:
    const RawServer *previous_;
};

class CleansedBuffer final {
public:
    explicit CleansedBuffer(std::vector<uint8_t> bytes) : bytes_(std::move(bytes)) {}
    ~CleansedBuffer() {
        if (!bytes_.empty()) OPENSSL_cleanse(bytes_.data(), bytes_.size());
    }
    CleansedBuffer(const CleansedBuffer &) = delete;
    CleansedBuffer &operator=(const CleansedBuffer &) = delete;

    std::vector<uint8_t> &bytes() { return bytes_; }
    const std::vector<uint8_t> &bytes() const { return bytes_; }

private:
    std::vector<uint8_t> bytes_;
};

std::vector<uint8_t> encodeErrorPayload(std::string_view code) {
    if (code.empty() || code.size() > kMaxErrorCode) code = "internal_error";
    std::vector<uint8_t> result{0xff, 0xff,
        static_cast<uint8_t>(code.size() >> 8), static_cast<uint8_t>(code.size())};
    result.insert(result.end(), code.begin(), code.end());
    return result;
}

bool readExact(int fd, void *target, size_t size) {
    auto *bytes = static_cast<uint8_t *>(target);
    size_t offset = 0;
    while (offset < size) {
        const ssize_t count = ::recv(fd, bytes + offset, size - offset, 0);
        if (count > 0) {
            offset += static_cast<size_t>(count);
            continue;
        }
        if (count < 0 && errno == EINTR) continue;
        return false;
    }
    return true;
}

bool setSocketTimeouts(int fd, uint64_t timeoutMs) {
    if (timeoutMs == 0) return false;
    const timeval timeout{
        static_cast<time_t>(timeoutMs / 1000),
        static_cast<suseconds_t>((timeoutMs % 1000) * 1000)};
    return ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0 &&
           ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0;
}

bool writeExact(int fd, const void *source, size_t size) {
    const auto *bytes = static_cast<const uint8_t *>(source);
    size_t offset = 0;
    while (offset < size) {
        const ssize_t count = ::send(fd, bytes + offset, size - offset, MSG_NOSIGNAL);
        if (count > 0) {
            offset += static_cast<size_t>(count);
            continue;
        }
        if (count < 0 && errno == EINTR) continue;
        return false;
    }
    return true;
}

} // namespace

RawServer::RawServer(RawServerConfig config) : config_(std::move(config)) {}

RawServer::~RawServer() { stop(); }

void RawServer::setHelloHandler(HelloHandler handler) {
    std::lock_guard<std::mutex> lock(callbacks_mutex_);
    if (listen_fd_.load() >= 0 || accept_thread_.joinable()) return;
    hello_handler_ = std::move(handler);
}

void RawServer::setFrameHandler(FrameHandler handler) {
    std::lock_guard<std::mutex> lock(callbacks_mutex_);
    if (listen_fd_.load() >= 0 || accept_thread_.joinable()) return;
    frame_handler_ = std::move(handler);
}

void RawServer::setSessionConfig(RawSessionConfig config) {
    setSessionConfigFactory([config = std::move(config)]() { return config; });
}

void RawServer::setSessionConfigFactory(SessionConfigFactory factory) {
    std::lock_guard<std::mutex> lock(callbacks_mutex_);
    if (listen_fd_.load() >= 0 || accept_thread_.joinable()) return;
    session_config_factory_ = std::move(factory);
}

void RawServer::setSessionFactory(SessionFactory factory) {
    std::lock_guard<std::mutex> lock(callbacks_mutex_);
    if (listen_fd_.load() >= 0 || accept_thread_.joinable()) return;
    session_factory_ = std::move(factory);
}

std::variant<std::monostate, RawServerError> RawServer::start() {
    std::unique_lock<std::mutex> lifecycleLock(lifecycle_mutex_);
    std::unique_lock<std::mutex> callbacksLock(callbacks_mutex_);
    const unsigned modes = static_cast<unsigned>(static_cast<bool>(hello_handler_)) +
                           static_cast<unsigned>(static_cast<bool>(session_config_factory_)) +
                           static_cast<unsigned>(static_cast<bool>(session_factory_));
    const bool authenticated = session_config_factory_ || session_factory_;
    if (config_.idle_timeout_ms == 0 || config_.max_active_connections == 0 ||
        listen_fd_.load() >= 0 || accept_thread_.joinable() || !workers_.empty() ||
        modes != 1 || (authenticated && !frame_handler_) || (!authenticated && frame_handler_))
        return RawServerError{"invalid_start"};
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return RawServerError{"socket_failed"};
    int reuse = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(config_.port);
    if (::inet_pton(AF_INET, config_.bind_address.c_str(), &address.sin_addr) != 1 ||
        ::bind(fd, reinterpret_cast<const sockaddr *>(&address), sizeof(address)) != 0 ||
        ::listen(fd, static_cast<int>(config_.backlog)) != 0) {
        ::close(fd);
        return RawServerError{"bind_failed"};
    }
    sockaddr_in bound{};
    socklen_t length = sizeof(bound);
    if (::getsockname(fd, reinterpret_cast<sockaddr *>(&bound), &length) != 0) {
        ::close(fd);
        return RawServerError{"getsockname_failed"};
    }
    bound_port_ = ntohs(bound.sin_port);
    stopping_.store(false);
    listen_fd_.store(fd);
    try {
        workers_.reserve(config_.max_active_connections);
        for (uint32_t index = 0; index < config_.max_active_connections; ++index)
            workers_.emplace_back(&RawServer::workerLoop, this);
        accept_thread_ = std::thread(&RawServer::acceptLoop, this);
    } catch (...) {
        callbacksLock.unlock();
        lifecycleLock.unlock();
        stop();
        return RawServerError{"thread_start_failed"};
    }
    return std::monostate{};
}

void RawServer::stop() {
    if (active_server_worker == this) return;
    std::lock_guard<std::mutex> lifecycleLock(lifecycle_mutex_);
    stopping_.store(true);
    const int fd = listen_fd_.exchange(-1);
    if (fd >= 0) {
        ::shutdown(fd, SHUT_RDWR);
        ::close(fd);
    }
    {
        std::lock_guard<std::mutex> lock(clients_mutex_);
        for (const int client : client_fds_) ::shutdown(client, SHUT_RDWR);
    }
    clients_ready_.notify_all();
    if (accept_thread_.joinable()) accept_thread_.join();
    for (auto &worker : workers_) {
        if (worker.joinable()) worker.join();
    }
    workers_.clear();
    {
        std::lock_guard<std::mutex> lock(clients_mutex_);
        pending_clients_.clear();
        client_fds_.clear();
    }
    bound_port_ = 0;
}

void RawServer::closeClient(int client) {
    {
        std::lock_guard<std::mutex> lock(clients_mutex_);
        client_fds_.erase(client);
    }
    ::close(client);
}

void RawServer::acceptLoop() {
    while (!stopping_.load()) {
        const int listenFd = listen_fd_.load();
        if (listenFd < 0) break;
        const int client = ::accept(listenFd, nullptr, nullptr);
        if (client < 0) {
            if (!stopping_.load() && errno == EINTR) continue;
            break;
        }
        if (!setSocketTimeouts(client, config_.idle_timeout_ms)) {
            ::close(client);
            continue;
        }
        bool accepted = false;
        {
            std::lock_guard<std::mutex> lock(clients_mutex_);
            if (!stopping_.load() && client_fds_.size() < config_.max_active_connections) {
                client_fds_.insert(client);
                pending_clients_.push_back(client);
                accepted = true;
            }
        }
        if (!accepted) {
            ::shutdown(client, SHUT_RDWR);
            ::close(client);
            continue;
        }
        clients_ready_.notify_one();
    }
}

void RawServer::workerLoop() {
    WorkerScope workerScope(this);
    while (true) {
        int client = -1;
        {
            std::unique_lock<std::mutex> lock(clients_mutex_);
            clients_ready_.wait(lock, [this] {
                return stopping_.load() || !pending_clients_.empty();
            });
            if (pending_clients_.empty()) {
                if (stopping_.load()) return;
                continue;
            }
            client = pending_clients_.front();
            pending_clients_.pop_front();
        }
        if (!stopping_.load()) handleClient(client);
        closeClient(client);
    }
}

void RawServer::handleClient(int client) {
    std::array<uint8_t, 2> lengthBytes{};
    if (!readExact(client, lengthBytes.data(), lengthBytes.size())) return;
    const size_t length = (static_cast<size_t>(lengthBytes[0]) << 8) | lengthBytes[1];
    if (length == 0 || length > 4096) return;
    std::vector<uint8_t> helloBytes(length);
    if (!readExact(client, helloBytes.data(), helloBytes.size())) return;
    auto parsed = xovm::material::decodeRawHello(helloBytes);
    if (std::holds_alternative<xovm::material::RawProtocolError>(parsed)) return;
    const auto hello = std::get<xovm::material::RawHello>(std::move(parsed));
    xovm::material::RawServerHello response;
    if (session_factory_ || session_config_factory_) {
        std::variant<RawSession, RawServerError> session =
            RawServerError{"session_unavailable"};
        try {
            if (session_factory_) {
                session = session_factory_(hello);
            } else {
                auto config = session_config_factory_();
                if (std::holds_alternative<RawServerError>(config)) return;
                auto accepted = RawSession::accept(
                    hello, std::get<RawSessionConfig>(std::move(config)));
                if (std::holds_alternative<RawSessionError>(accepted)) return;
                session = std::get<RawSession>(std::move(accepted));
            }
        } catch (...) {
            return;
        }
        if (std::holds_alternative<RawServerError>(session)) return;
        auto authenticated = std::get<RawSession>(std::move(session));
        response = authenticated.serverHello();
        const auto encoded = xovm::material::encodeRawServerHello(response);
        const std::array<uint8_t, 2> responseLength = {
            static_cast<uint8_t>(encoded.size() >> 8), static_cast<uint8_t>(encoded.size())};
        if (encoded.size() > UINT16_MAX ||
            !writeExact(client, responseLength.data(), responseLength.size()) ||
            !writeExact(client, encoded.data(), encoded.size()))
            return;
        std::array<uint8_t, xovm::material::kRawFrameHeaderSize> headerBytes{};
        while (!stopping_.load() &&
               readExact(client, headerBytes.data(), headerBytes.size())) {
            auto decoded = xovm::material::decodeRawFrameHeader(headerBytes);
            if (std::holds_alternative<xovm::material::RawProtocolError>(decoded)) break;
            auto header = std::get<xovm::material::RawFrameHeader>(std::move(decoded));
            if (header.payload_length < 16 ||
                header.payload_length > xovm::material::kRawMaxFramePayload)
                break;
            std::vector<uint8_t> payload(header.payload_length);
            if (!readExact(client, payload.data(), payload.size())) break;
            const auto ciphertext =
                std::span<const uint8_t>(payload.data(), payload.size() - 16);
            const auto tag = std::span<const uint8_t, 16>(
                payload.data() + payload.size() - 16, 16);
            auto decrypted = authenticated.decrypt(header, ciphertext, tag);
            if (std::holds_alternative<RawSessionError>(decrypted)) break;
            CleansedBuffer plaintext(std::get<std::vector<uint8_t>>(std::move(decrypted)));
            std::variant<std::vector<uint8_t>, RawSessionError> reply =
                RawSessionError{"dispatch_failed"};
            try {
                reply = frame_handler_(authenticated.authenticatedContext(), header,
                                       plaintext.bytes());
            } catch (...) {
                break;
            }
            // Dispatch may cross the lease boundary. Never emit a response after that point.
            if (std::holds_alternative<RawSessionError>(authenticated.checkFresh())) break;
            auto responseHeader = header;
            if (std::holds_alternative<RawSessionError>(reply)) {
                responseHeader.type = xovm::material::RawFrameType::Error;
                const auto &error = std::get<RawSessionError>(reply);
                reply = encodeErrorPayload(error.code);
            }
            CleansedBuffer replyBytes(std::get<std::vector<uint8_t>>(std::move(reply)));
            responseHeader.payload_length =
                static_cast<uint32_t>(replyBytes.bytes().size() + 16);
            auto encryptedReply = authenticated.encrypt(responseHeader, replyBytes.bytes());
            if (std::holds_alternative<RawSessionError>(encryptedReply)) break;
            const auto frame = xovm::material::encodeRawFrame(
                responseHeader, std::get<std::vector<uint8_t>>(std::move(encryptedReply)));
            if (frame.empty() || !writeExact(client, frame.data(), frame.size())) break;
        }
        return;
    }

    try {
        response = hello_handler_(hello);
    } catch (...) {
        return;
    }
    const auto encoded = xovm::material::encodeRawServerHello(response);
    if (encoded.size() > UINT16_MAX) return;
    const std::array<uint8_t, 2> responseLength = {
        static_cast<uint8_t>(encoded.size() >> 8), static_cast<uint8_t>(encoded.size())};
    if (!writeExact(client, responseLength.data(), responseLength.size())) return;
    writeExact(client, encoded.data(), encoded.size());
}

} // namespace xovm::cloud_material
