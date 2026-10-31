#include "http_server.h"

#include "http_contract.h"
#include "protocol_service.h"

#include <nlohmann/json.hpp>

#include <arpa/inet.h>
#include <cstdio>
#include <cstring>
#include <netinet/in.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

namespace {
using namespace xovm::cloud_material;

struct TestState {
    unsigned assertions = 0;
    unsigned failures = 0;
    const char *test_name = "";
};

TestState state;

bool expect(bool condition, const char *expression, int line) {
    ++state.assertions;
    if (condition) return true;
    ++state.failures;
    std::fprintf(stderr, "line %d: %s failed in %s\n", line, expression, state.test_name);
    return false;
}

#define EXPECT_TRUE(expression) expect(static_cast<bool>(expression), #expression, __LINE__)
#define EXPECT_FALSE(expression) expect(!static_cast<bool>(expression), "! (" #expression ")", __LINE__)
#define TEST(name) static void name()

std::string base64(const std::vector<std::byte> &input) {
    constexpr char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string result;
    for (size_t index = 0; index < input.size(); index += 3) {
        const uint32_t a = std::to_integer<uint8_t>(input[index]);
        const uint32_t b = index + 1 < input.size()
                               ? std::to_integer<uint8_t>(input[index + 1]) : 0;
        const uint32_t c = index + 2 < input.size()
                               ? std::to_integer<uint8_t>(input[index + 2]) : 0;
        const uint32_t bits = (a << 16) | (b << 8) | c;
        result += alphabet[(bits >> 18) & 63];
        result += alphabet[(bits >> 12) & 63];
        result += index + 1 < input.size() ? alphabet[(bits >> 6) & 63] : '=';
        result += index + 2 < input.size() ? alphabet[bits & 63] : '=';
    }
    return result;
}

std::vector<std::byte> validRequest() {
    const nlohmann::json value = {
        {"build_id", std::string(64, '1')},
        {"client_ephemeral_key", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},
        {"client_nonce", std::string(64, '2')},
        {"final_artifact_hash", std::string(64, '3')},
        {"protocol_version", 2},
        {"request_id", std::string(64, '4')},
        {"software_id", "test.software"},
        {"suite", kProtocolSuite},
        {"type", "session.open"},
    };
    const auto text = value.dump();
    std::vector<std::byte> result;
    for (const auto byte : text) result.push_back(static_cast<std::byte>(byte));
    return result;
}

std::string relayBody(const std::vector<std::byte> &request) {
    return nlohmann::json{{"protocol", "xovm2_relay"},
                          {"request_b64", base64(request)}}.dump();
}

int connectTo(std::uint16_t port) {
    const int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    ::inet_pton(AF_INET, "127.0.0.1", &address.sin_addr);
    if (::connect(fd, reinterpret_cast<sockaddr *>(&address), sizeof(address)) != 0) {
        ::close(fd);
        return -1;
    }
    return fd;
}

std::string exchange(std::uint16_t port, std::string request) {
    const int fd = connectTo(port);
    if (fd < 0) return {};
    size_t written = 0;
    while (written < request.size()) {
        const auto count = ::send(fd, request.data() + written, request.size() - written, 0);
        if (count <= 0) break;
        written += static_cast<size_t>(count);
    }
    ::shutdown(fd, SHUT_WR);
    std::string response;
    char buffer[4096];
    for (;;) {
        const auto count = ::recv(fd, buffer, sizeof(buffer), 0);
        if (count <= 0) break;
        response.append(buffer, static_cast<size_t>(count));
    }
    ::close(fd);
    return response;
}

HttpServerConfig config(std::uint16_t port) {
    HttpServerConfig result;
    result.bind_address = "127.0.0.1";
    result.port = port;
    result.relay_token = "relay-http-secret-long-enough";
    result.admin_token = "admin-http-secret-long-enough";
    result.max_body_bytes = 1024;
    result.max_header_bytes = 4096;
    result.idle_timeout_ms = 1000;
    return result;
}

TEST(http_rejects_non_post_and_unknown_route) {
    HttpServer server(config(0));
    EXPECT_TRUE(std::holds_alternative<std::monostate>(server.start()));
    const auto port = server.port();
    auto get = exchange(port, "GET /v2/relay HTTP/1.1\r\nHost: localhost\r\n\r\n");
    EXPECT_TRUE(get.find("400") != std::string::npos || get.find("405") != std::string::npos);
    auto unknown = exchange(port, "POST /unknown HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n");
    EXPECT_TRUE(unknown.find("404") != std::string::npos);
    server.stop();
}

TEST(http_rejects_wrong_content_type_and_encoding) {
    HttpServer server(config(0));
    EXPECT_TRUE(std::holds_alternative<std::monostate>(server.start()));
    const auto port = server.port();
    auto type = exchange(port, "POST /v2/relay HTTP/1.1\r\nHost: localhost\r\n"
                              "Content-Type: text/plain\r\nContent-Length: 2\r\n\r\n{}");
    EXPECT_TRUE(type.find("415") != std::string::npos);
    auto encoding = exchange(port, "POST /v2/relay HTTP/1.1\r\nHost: localhost\r\n"
                                  "Content-Type: application/json\r\nContent-Encoding: gzip\r\n"
                                  "Content-Length: 2\r\n\r\n{}");
    EXPECT_TRUE(encoding.find("415") != std::string::npos);
    server.stop();
}

TEST(http_requires_relay_credential_and_hides_internal_errors) {
    HttpServer server(config(0));
    EXPECT_TRUE(std::holds_alternative<std::monostate>(server.start()));
    const auto request = "POST /v2/relay HTTP/1.1\r\nHost: localhost\r\n"
                         "Content-Type: application/json\r\nContent-Length: 2\r\n\r\n{}";
    auto missing = exchange(server.port(), request);
    EXPECT_TRUE(missing.find("401") != std::string::npos);
    EXPECT_TRUE(missing.find("relay-http-secret") == std::string::npos);
    server.stop();
}

TEST(http_rejects_oversized_body_and_reports_health) {
    HttpServer server(config(0));
    server.setReady(true);
    EXPECT_TRUE(std::holds_alternative<std::monostate>(server.start()));
    const auto health = exchange(server.port(), "GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n");
    EXPECT_TRUE(health.find("200") != std::string::npos);
    std::string oversized(1025, 'x');
    auto request = "POST /v2/relay HTTP/1.1\r\nHost: localhost\r\n"
        "Content-Type: application/json\r\nContent-Length: 1025\r\n\r\n" + oversized;
    auto response = exchange(server.port(), std::move(request));
    EXPECT_TRUE(response.find("413") != std::string::npos);
    server.stop();
}

TEST(http_returns_exact_handler_bytes_in_relay_envelope) {
    HttpServer server(config(0));
    const auto request = validRequest();
    server.setRelayHandler([request](std::span<const std::byte> body, const std::string &credential)
        -> std::variant<std::vector<std::byte>, BackendError> {
        if (credential != "Bearer relay-http-secret-long-enough")
            return BackendError{"wrong_credential"};
        if (std::vector<std::byte>(body.begin(), body.end()) != request)
            return BackendError{"wrong_body"};
        return std::vector<std::byte>{std::byte{'\x01'}, std::byte{'\x02'}, std::byte{'\xff'}};
    });
    EXPECT_TRUE(std::holds_alternative<std::monostate>(server.start()));
    const auto body = relayBody(request);
    auto response = exchange(server.port(), "POST /v2/relay HTTP/1.1\r\nHost: localhost\r\n"
        "Authorization: Bearer relay-http-secret-long-enough\r\n"
        "Content-Type: application/json\r\nContent-Length: " + std::to_string(body.size()) +
        "\r\n\r\n" + body);
    EXPECT_TRUE(response.find("200") != std::string::npos);
    EXPECT_TRUE(response.find("\"protocol\":\"xovm2_relay\"") != std::string::npos);
    EXPECT_TRUE(response.find("\"response_b64\":\"AQL/\"") != std::string::npos);
    server.stop();
}

TEST(http_rejects_unsupported_transfer_encoding) {
    HttpServer server(config(0));
    EXPECT_TRUE(std::holds_alternative<std::monostate>(server.start()));
    auto response = exchange(server.port(), "POST /v2/relay HTTP/1.1\r\nHost: localhost\r\n"
        "Authorization: Bearer relay-http-secret-long-enough\r\n"
        "Content-Type: application/json\r\nTransfer-Encoding: chunked\r\n"
        "Content-Length: 0\r\n\r\n");
    EXPECT_TRUE(response.find("400") != std::string::npos);
    server.stop();
}

TEST(http_rejects_malformed_relay_envelope_before_handler) {
    HttpServer server(config(0));
    bool called = false;
    server.setRelayHandler([&called](std::span<const std::byte>, const std::string &)
        -> std::variant<std::vector<std::byte>, BackendError> {
        called = true;
        return std::vector<std::byte>{};
    });
    EXPECT_TRUE(std::holds_alternative<std::monostate>(server.start()));
    const std::string body = "{\"protocol\":\"wrong\",\"request_b64\":\"AA==\"}";
    auto response = exchange(server.port(), "POST /v2/relay HTTP/1.1\r\nHost: localhost\r\n"
        "Authorization: Bearer relay-http-secret-long-enough\r\n"
        "Content-Type: application/json\r\nContent-Length: " + std::to_string(body.size()) +
        "\r\n\r\n" + body);
    EXPECT_TRUE(response.find("400") != std::string::npos);
    EXPECT_FALSE(called);
    server.stop();
}

TEST(http_rejects_oversized_handler_response) {
    auto serverConfig = config(0);
    serverConfig.max_response_bytes = 2;
    HttpServer server(serverConfig);
    const auto request = validRequest();
    server.setRelayHandler([](std::span<const std::byte>, const std::string &)
        -> std::variant<std::vector<std::byte>, BackendError> {
        return std::vector<std::byte>{std::byte{'a'}, std::byte{'b'}, std::byte{'c'}};
    });
    EXPECT_TRUE(std::holds_alternative<std::monostate>(server.start()));
    const auto body = relayBody(request);
    auto response = exchange(server.port(), "POST /v2/relay HTTP/1.1\r\nHost: localhost\r\n"
        "Authorization: Bearer relay-http-secret-long-enough\r\n"
        "Content-Type: application/json\r\nContent-Length: " + std::to_string(body.size()) +
        "\r\n\r\n" + body);
    EXPECT_TRUE(response.find("500") != std::string::npos);
    server.stop();
}

TEST(http_rejects_duplicate_security_headers) {
    HttpServer server(config(0));
    EXPECT_TRUE(std::holds_alternative<std::monostate>(server.start()));
    auto response = exchange(server.port(), "POST /v2/relay HTTP/1.1\r\nHost: localhost\r\n"
        "Authorization: Bearer relay-http-secret-long-enough\r\n"
        "Content-Type: application/json\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}");
    EXPECT_TRUE(response.find("400") != std::string::npos);
    server.stop();
}

TEST(http_rejects_empty_relay_credential_at_start) {
    auto serverConfig = config(0);
    serverConfig.relay_token.clear();
    HttpServer server(serverConfig);
    auto result = server.start();
    EXPECT_TRUE(std::holds_alternative<BackendError>(result));
    if (std::holds_alternative<BackendError>(result))
        EXPECT_TRUE(std::get<BackendError>(result).code == "http_missing_relay_credential");
}

TEST(http_can_bind_protocol_service_handler) {
    HttpServer server(config(0));
    ProtocolService service;
    server.setProtocolService(&service);
    const auto request = validRequest();
    const auto body = relayBody(request);
    EXPECT_TRUE(std::holds_alternative<std::monostate>(server.start()));
    auto response = exchange(server.port(), "POST /v2/relay HTTP/1.1\r\nHost: localhost\r\n"
        "Authorization: Bearer relay-http-secret-long-enough\r\n"
        "Content-Type: application/json\r\nContent-Length: " + std::to_string(body.size()) +
        "\r\n\r\n" + body);
    EXPECT_TRUE(response.find("500") != std::string::npos);
    EXPECT_TRUE(response.find("authority_unavailable") == std::string::npos);
    server.stop();
}

TEST(http_health_is_not_ready_by_default) {
    HttpServer server(config(0));
    EXPECT_TRUE(std::holds_alternative<std::monostate>(server.start()));
    const auto health = exchange(server.port(), "GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n");
    EXPECT_TRUE(health.find("503") != std::string::npos);
    server.stop();
}

TEST(http_uses_independent_admin_and_trust_routes) {
    HttpServer server(config(0));
    bool adminCalled = false;
    bool trustCalled = false;
    server.setAdminHandler([&adminCalled](std::string_view path,
                                           std::span<const std::byte> body,
                                           const std::string &credential)
        -> std::variant<std::vector<std::byte>, BackendError> {
        adminCalled = path == "/v2/admin/builds/import" &&
            credential == "Bearer admin-http-secret-long-enough" && body.size() == 2;
        return std::vector<std::byte>{std::byte{'o'}, std::byte{'k'}};
    });
    server.setTrustHandler([&trustCalled](std::string_view softwareId)
        -> std::variant<std::vector<std::byte>, BackendError> {
        trustCalled = softwareId == "test.software";
        return std::vector<std::byte>{std::byte{'t'}, std::byte{'r'}, std::byte{'u'}, std::byte{'s'}, std::byte{'t'}};
    });
    EXPECT_TRUE(std::holds_alternative<std::monostate>(server.start()));
    const std::string admin = "POST /v2/admin/builds/import HTTP/1.1\r\nHost: localhost\r\n"
        "Authorization: Bearer admin-http-secret-long-enough\r\nContent-Type: application/json\r\n"
        "Content-Length: 2\r\n\r\n{}";
    const auto adminResponse = exchange(server.port(), admin);
    EXPECT_TRUE(adminResponse.find("200") != std::string::npos);
    EXPECT_TRUE(adminCalled);
    const auto relayCredentialOnAdmin = exchange(server.port(),
        "POST /v2/admin/builds/import HTTP/1.1\r\nHost: localhost\r\n"
        "Authorization: Bearer relay-http-secret-long-enough\r\nContent-Type: application/json\r\n"
        "Content-Length: 0\r\n\r\n");
    EXPECT_TRUE(relayCredentialOnAdmin.find("401") != std::string::npos);
    const auto trustResponse = exchange(server.port(),
        "GET /v2/trust/test.software HTTP/1.1\r\nHost: localhost\r\n\r\n");
    EXPECT_TRUE(trustResponse.find("200") != std::string::npos);
    EXPECT_TRUE(trustResponse.find("trust") != std::string::npos);
    EXPECT_TRUE(trustCalled);
    server.stop();
}

template <typename Test>
void run(const char *name, Test test) {
    const unsigned before = state.failures;
    state.test_name = name;
    test();
    std::fprintf(state.failures == before ? stdout : stderr, "[%s] %s\n",
                 state.failures == before ? "PASS" : "FAIL", name);
}
} // namespace

int main() {
    run("http_rejects_non_post_and_unknown_route", http_rejects_non_post_and_unknown_route);
    run("http_rejects_wrong_content_type_and_encoding",
        http_rejects_wrong_content_type_and_encoding);
    run("http_requires_relay_credential_and_hides_internal_errors",
        http_requires_relay_credential_and_hides_internal_errors);
    run("http_rejects_oversized_body_and_reports_health",
        http_rejects_oversized_body_and_reports_health);
    run("http_returns_exact_handler_bytes_in_relay_envelope",
        http_returns_exact_handler_bytes_in_relay_envelope);
    run("http_rejects_unsupported_transfer_encoding", http_rejects_unsupported_transfer_encoding);
    run("http_rejects_malformed_relay_envelope_before_handler",
        http_rejects_malformed_relay_envelope_before_handler);
    run("http_rejects_oversized_handler_response", http_rejects_oversized_handler_response);
    run("http_rejects_duplicate_security_headers", http_rejects_duplicate_security_headers);
    run("http_rejects_empty_relay_credential_at_start",
        http_rejects_empty_relay_credential_at_start);
    run("http_can_bind_protocol_service_handler", http_can_bind_protocol_service_handler);
    run("http_health_is_not_ready_by_default", http_health_is_not_ready_by_default);
    run("http_uses_independent_admin_and_trust_routes",
        http_uses_independent_admin_and_trust_routes);
    std::fprintf(stdout, "13 tests, %u assertions, %u failures\n",
                 state.assertions, state.failures);
    return state.failures == 0 ? 0 : 1;
}
