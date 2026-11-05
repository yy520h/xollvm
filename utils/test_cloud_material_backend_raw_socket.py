"""Raw TCP server handshake boundary tests."""

from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]


def test_raw_server_accepts_bounded_hello_and_returns_server_hello(tmp_path):
    source = tmp_path / "raw_server_probe.cpp"
    source.write_text(
        '#include "runtime/cloud_material_backend/raw_server.h"\n'
        '#include <cassert>\n'
        '#include <chrono>\n'
        '#include <future>\n'
        '#include <arpa/inet.h>\n'
        '#include <sys/socket.h>\n'
         '#include <unistd.h>\n'
         '#include <thread>\n'
         '#include <variant>\n'
         '#include <vector>\n'
        'int main() {\n'
        '  xovm::cloud_material::RawServerConfig config;\n'
        '  config.bind_address = "127.0.0.1"; config.port = 0;\n'
        '  xovm::cloud_material::RawServer server(config);\n'
        '  server.setHelloHandler([](const xovm::material::RawHello &) {\n'
        '    xovm::material::RawServerHello hello{}; hello.counter = 1;\n'
        '    hello.server_nonce[0] = 2; return hello;\n'
        '  });\n'
         '  auto started = server.start(); assert(std::holds_alternative<std::monostate>(started));\n'
        '  assert(server.port() != 0);\n'
        '  const int fd = ::socket(AF_INET, SOCK_STREAM, 0); assert(fd >= 0);\n'
        '  sockaddr_in address{}; address.sin_family = AF_INET; address.sin_port = htons(server.port());\n'
        '  assert(::inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) == 1);\n'
        '  assert(::connect(fd, reinterpret_cast<sockaddr *>(&address), sizeof(address)) == 0);\n'
        '  xovm::material::RawHello hello{}; hello.software_id = "test"; hello.build_id = "build";\n'
        '  const auto bytes = xovm::material::encodeRawHello(hello);\n'
        '  const unsigned char length[] = {static_cast<unsigned char>(bytes.size() >> 8), static_cast<unsigned char>(bytes.size())};\n'
        '  assert(::send(fd, length, sizeof(length), 0) == 2); assert(::send(fd, bytes.data(), bytes.size(), 0) == static_cast<ssize_t>(bytes.size()));\n'
        '  unsigned char response_length[2]{}; assert(::recv(fd, response_length, 2, MSG_WAITALL) == 2);\n'
        '  const size_t response_size = (static_cast<size_t>(response_length[0]) << 8) | response_length[1];\n'
         '  std::vector<unsigned char> response(response_size); assert(::recv(fd, response.data(), response.size(), MSG_WAITALL) == static_cast<ssize_t>(response.size()));\n'
         '  ::close(fd); server.stop();\n'
         '  xovm::cloud_material::RawServer concurrent(config); concurrent.setHelloHandler([](const xovm::material::RawHello &) { return xovm::material::RawServerHello{}; }); assert(std::holds_alternative<std::monostate>(concurrent.start()));\n'
         '  const int idle = ::socket(AF_INET, SOCK_STREAM, 0); assert(idle >= 0); address.sin_port = htons(concurrent.port()); assert(::connect(idle, reinterpret_cast<sockaddr *>(&address), sizeof(address)) == 0);\n'
         '  auto second_handshake = std::async(std::launch::async, [&]() { const int second = ::socket(AF_INET, SOCK_STREAM, 0); assert(second >= 0); assert(::connect(second, reinterpret_cast<sockaddr *>(&address), sizeof(address)) == 0); assert(::send(second, length, sizeof(length), 0) == 2); assert(::send(second, bytes.data(), bytes.size(), 0) == static_cast<ssize_t>(bytes.size())); unsigned char reply_length[2]{}; const bool ok = ::recv(second, reply_length, 2, MSG_WAITALL) == 2; ::close(second); return ok; });\n'
         '  assert(second_handshake.wait_for(std::chrono::seconds(2)) == std::future_status::ready && second_handshake.get());\n'
         '  auto stopped = std::async(std::launch::async, [&]() { concurrent.stop(); return true; }); assert(stopped.wait_for(std::chrono::seconds(2)) == std::future_status::ready && stopped.get()); ::close(idle);\n'
         '  xovm::cloud_material::RawServer authenticated(config);\n'
         '  xovm::cloud_material::RawSessionConfig session_config;\n'
         '  session_config.expires_at_ms = 1000;\n'
         '  session_config.trusted_now = []() { return std::variant<uint64_t, xovm::cloud_material::RawSessionError>(uint64_t{100}); };\n'
         '  session_config.random_bytes = [](size_t size) { return std::variant<std::vector<unsigned char>, xovm::cloud_material::RawSessionError>(std::vector<unsigned char>(size, 1)); };\n'
         '  session_config.sign = [](std::span<const unsigned char>) { return std::variant<std::array<unsigned char, 64>, xovm::cloud_material::RawSessionError>(std::array<unsigned char, 64>{}); };\n'
         '  authenticated.setSessionConfig(std::move(session_config));\n'
         '  authenticated.setFrameHandler([](const xovm::cloud_material::AuthenticatedRawContext &, const xovm::material::RawFrameHeader &, std::span<const unsigned char>) { return std::variant<std::vector<unsigned char>, xovm::cloud_material::RawSessionError>(std::vector<unsigned char>{}); });\n'
         '  auto authenticated_started = authenticated.start(); assert(std::holds_alternative<std::monostate>(authenticated_started));\n'
         '  authenticated.stop(); return 0;\n'
         '}\n', encoding="ascii")
    exe = tmp_path / "probe"
    result = subprocess.run(
        ["c++", "-std=c++20", "-Wall", "-Wextra", "-Werror", "-I", str(ROOT),
         str(source), str(ROOT / "runtime/cloud_material/raw_protocol.cpp"),
         str(ROOT / "runtime/cloud_material/raw_frame.cpp"),
         str(ROOT / "runtime/cloud_material_backend/raw_server.cpp"),
         str(ROOT / "runtime/cloud_material_backend/raw_session.cpp"),
         "-lcrypto", "-pthread", "-o", str(exe)],
        capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert subprocess.run([str(exe)], capture_output=True, text=True).returncode == 0
