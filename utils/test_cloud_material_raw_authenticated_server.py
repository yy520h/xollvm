"""End-to-end authenticated raw TCP handshake and one encrypted frame."""

from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]


def test_authenticated_raw_server_dispatches_one_encrypted_frame(tmp_path):
    source = tmp_path / "authenticated_raw_server_probe.cpp"
    source.write_text(
        '#include "runtime/cloud_material/raw_client_session.h"\n'
        '#include "runtime/cloud_material/raw_client_transport.h"\n'
        '#include "runtime/cloud_material/raw_frame.h"\n'
        '#include "runtime/cloud_material_backend/raw_server.h"\n'
        '#include <openssl/evp.h>\n'
        '#include <arpa/inet.h>\n'
        '#include <array>\n'
        '#include <atomic>\n'
        '#include <cassert>\n'
        '#include <span>\n'
        '#include <sys/socket.h>\n'
        '#include <unistd.h>\n'
        '#include <variant>\n'
        '#include <vector>\n'
        'static long host_socket(int domain, int type, int protocol) { return ::socket(domain, type, protocol); }\n'
        'static long host_connect(int fd, const void *address, unsigned length) { return ::connect(fd, static_cast<const sockaddr *>(address), length); }\n'
        'static long host_send(int fd, const void *data, size_t length, int flags) { return ::send(fd, data, length, flags); }\n'
        'static long host_recv(int fd, void *data, size_t length, int flags) { return ::recv(fd, data, length, flags); }\n'
        'static long host_close(int fd) { return ::close(fd); }\n'
        'static std::array<unsigned char, 32> public_key(const std::array<unsigned char, 32> &private_key, const char *type) {\n'
        '  EVP_PKEY *key = EVP_PKEY_new_raw_private_key_ex(nullptr, type, nullptr, private_key.data(), 32);\n'
        '  std::array<unsigned char, 32> result{}; size_t size = result.size();\n'
        '  assert(key && EVP_PKEY_get_raw_public_key(key, result.data(), &size) == 1 && size == result.size());\n'
        '  EVP_PKEY_free(key); return result;\n'
        '}\n'
        'int main() {\n'
        '  using namespace xovm; using namespace xovm::cloud_material;\n'
        '  std::array<unsigned char, 32> signing_private{}; signing_private[0] = 9;\n'
        '  EVP_PKEY *signing_key = EVP_PKEY_new_raw_private_key_ex(nullptr, "ED25519", nullptr, signing_private.data(), 32); assert(signing_key);\n'
        '  RawServerConfig server_config; server_config.bind_address = "127.0.0.1"; server_config.port = 0;\n'
        '  RawServer server(server_config); RawSessionConfig session_config; session_config.key_version = 5; session_config.expires_at_ms = 900;\n'
        '  std::atomic<unsigned> trusted_time_calls{0}; session_config.trusted_now = [&trusted_time_calls]() { const auto call = trusted_time_calls.fetch_add(1); return std::variant<uint64_t, RawSessionError>(call == 4 ? uint64_t{900} : uint64_t{100}); };\n'
        '  session_config.random_bytes = [](size_t size) { return std::variant<std::vector<unsigned char>, RawSessionError>(std::vector<unsigned char>(size, 8)); };\n'
        '  session_config.sign = [signing_key](std::span<const unsigned char> bytes) {\n'
        '    std::array<unsigned char, 64> signature{}; size_t size = signature.size(); EVP_MD_CTX *context = EVP_MD_CTX_new();\n'
        '    const bool ok = context && EVP_DigestSignInit(context, nullptr, nullptr, nullptr, signing_key) == 1 && EVP_DigestSign(context, signature.data(), &size, bytes.data(), bytes.size()) == 1;\n'
        '    EVP_MD_CTX_free(context); assert(ok && size == signature.size()); return std::variant<std::array<unsigned char, 64>, RawSessionError>(signature);\n'
        '  };\n'
        '  unsigned factory_calls = 0;\n'
        '  server.setSessionConfigFactory([&session_config, &factory_calls]() { auto fresh = session_config; fresh.expires_at_ms = 900 + factory_calls++; return std::variant<RawSessionConfig, RawServerError>(std::move(fresh)); });\n'
        '  std::array<unsigned char, 32> observed_grant_key{}; std::vector<uint64_t> observed_expiries; std::atomic<unsigned> dispatch_calls{0};\n'
        '  server.setFrameHandler([&observed_grant_key, &observed_expiries, &dispatch_calls](const AuthenticatedRawContext &context, const material::RawFrameHeader &header, std::span<const unsigned char> payload) {\n'
        '    dispatch_calls.fetch_add(1);\n'
        '    assert(header.type == material::RawFrameType::AlgorithmAcquire && payload.size() == 3 && payload[0] == 1);\n'
        '    assert(context.softwareId() == "test" && context.buildId() == "build");\n'
        '    assert(context.sessionId() == header.session_id && context.keyVersion() == 5); observed_expiries.push_back(context.expiresAtMs());\n'
        '    assert((context.initialStateCommitment() != context.transcriptHash() && context.initialStateCommitment() != std::array<unsigned char, 32>{}));\n'
        '    std::array<unsigned char, 32> request_commitment{}; request_commitment[0] = payload[0];\n'
        '    auto first = context.deriveGrantKey(request_commitment); auto second = context.deriveGrantKey(request_commitment);\n'
        '    assert((std::holds_alternative<std::array<unsigned char, 32>>(first) && std::get<std::array<unsigned char, 32>>(first) == std::get<std::array<unsigned char, 32>>(second)));\n'
        '    observed_grant_key = std::get<std::array<unsigned char, 32>>(first);\n'
        '    return std::variant<std::vector<unsigned char>, RawSessionError>(RawSessionError{"provider_rejected"});\n'
        '  });\n'
        '  assert(std::holds_alternative<std::monostate>(server.start()));\n'
        '  cloud_material::RawClientSessionConfig client_config; client_config.hello.software_id = "test"; client_config.hello.build_id = "build"; client_config.server_signing_public_key = public_key(signing_private, "ED25519");\n'
        '  client_config.random_bytes = [](size_t size) { return std::variant<std::vector<unsigned char>, RawClientSessionError>(std::vector<unsigned char>(size, 3)); };\n'
        '  const material::RawSyscallTable host_syscalls{host_socket, host_connect, host_send, host_recv, host_close};\n'
        '  auto client_result = cloud_material::RawClientTransport::connectAndHandshake(htonl(INADDR_LOOPBACK), htons(server.port()), client_config, host_syscalls); assert(std::holds_alternative<cloud_material::RawClientTransport>(client_result)); auto client = std::get<cloud_material::RawClientTransport>(std::move(client_result));\n'
        '  material::RawFrameHeader request{}; request.type = material::RawFrameType::AlgorithmAcquire; request.session_id = client.sessionId(); request.flags = client.keyVersion(); request.sequence = 0; const unsigned char request_payload[] = {1, 2, 3};\n'
        '  auto opened = client.request(request, request_payload); assert(std::holds_alternative<std::vector<unsigned char>>(opened));\n'
        '  const auto &error_bytes = std::get<std::vector<unsigned char>>(opened); assert(error_bytes.size() == 21 && error_bytes[0] == 0xff && error_bytes[1] == 0xff);\n'
        '  request.sequence = 1; auto expired_request = client.request(request, request_payload); assert(std::holds_alternative<cloud_material::RawClientTransportError>(expired_request)); assert(dispatch_calls.load() == 1);\n'
        '  client.close();\n'
        '  auto second_result = cloud_material::RawClientTransport::connectAndHandshake(htonl(INADDR_LOOPBACK), htons(server.port()), client_config, host_syscalls); assert(std::holds_alternative<cloud_material::RawClientTransport>(second_result)); auto second = std::get<cloud_material::RawClientTransport>(std::move(second_result)); request.session_id = second.sessionId(); request.sequence = 0; opened = second.request(request, request_payload); assert(std::holds_alternative<std::vector<unsigned char>>(opened)); second.close();\n'
        '  server.stop(); assert(factory_calls == 2 && observed_expiries == std::vector<uint64_t>({900, 901})); assert((observed_grant_key != std::array<unsigned char, 32>{}));\n'
        '  RawServer failing(server_config); unsigned failures = 0; failing.setSessionConfigFactory([&failures]() -> std::variant<RawSessionConfig, RawServerError> { ++failures; return RawServerError{"clock_failed"}; }); failing.setFrameHandler([](const AuthenticatedRawContext &, const material::RawFrameHeader &, std::span<const unsigned char>) { return std::variant<std::vector<unsigned char>, RawSessionError>(std::vector<unsigned char>{}); }); assert(std::holds_alternative<std::monostate>(failing.start())); auto rejected = cloud_material::RawClientTransport::connectAndHandshake(htonl(INADDR_LOOPBACK), htons(failing.port()), client_config, host_syscalls); assert(std::holds_alternative<cloud_material::RawClientTransportError>(rejected)); failing.stop(); assert(failures == 1);\n'
         '  RawServer admission(server_config); std::atomic<unsigned> admission_calls{0}; admission.setSessionFactory([&admission_calls](const material::RawHello &candidate) -> std::variant<RawSession, RawServerError> { ++admission_calls; assert(candidate.software_id == "test" && candidate.build_id == "build"); return RawServerError{"admission_rejected"}; }); admission.setFrameHandler([](const AuthenticatedRawContext &, const material::RawFrameHeader &, std::span<const unsigned char>) { return std::variant<std::vector<unsigned char>, RawSessionError>(std::vector<unsigned char>{}); }); assert(std::holds_alternative<std::monostate>(admission.start())); auto admission_rejected = cloud_material::RawClientTransport::connectAndHandshake(htonl(INADDR_LOOPBACK), htons(admission.port()), client_config, host_syscalls); assert(std::holds_alternative<cloud_material::RawClientTransportError>(admission_rejected)); admission.stop(); assert(admission_calls.load() == 1);\n'
         '  std::atomic<uint64_t> boundary_now{100}; RawSessionConfig boundary_config = session_config; boundary_config.expires_at_ms = 900; boundary_config.trusted_now = [&boundary_now]() { return std::variant<uint64_t, RawSessionError>(boundary_now.load()); }; RawServer boundary(server_config); boundary.setSessionConfig(std::move(boundary_config)); boundary.setFrameHandler([&boundary_now](const AuthenticatedRawContext &, const material::RawFrameHeader &, std::span<const unsigned char>) { boundary_now.store(900); return std::variant<std::vector<unsigned char>, RawSessionError>(std::vector<unsigned char>{1}); }); assert(std::holds_alternative<std::monostate>(boundary.start())); auto boundary_client_result = cloud_material::RawClientTransport::connectAndHandshake(htonl(INADDR_LOOPBACK), htons(boundary.port()), client_config, host_syscalls); assert(std::holds_alternative<cloud_material::RawClientTransport>(boundary_client_result)); auto boundary_client = std::get<cloud_material::RawClientTransport>(std::move(boundary_client_result)); request.session_id = boundary_client.sessionId(); request.flags = boundary_client.keyVersion(); request.sequence = 0; auto boundary_reply = boundary_client.request(request, request_payload); assert(std::holds_alternative<cloud_material::RawClientTransportError>(boundary_reply)); boundary_client.close(); boundary.stop();\n'
        '  EVP_PKEY_free(signing_key); return 0;\n'
        '}\n',
        encoding="ascii",
    )
    exe = tmp_path / "probe"
    result = subprocess.run(
        ["c++", "-std=c++20", "-Wall", "-Wextra", "-Werror", "-I", str(ROOT),
         str(source), str(ROOT / "runtime/cloud_material/raw_protocol.cpp"),
         str(ROOT / "runtime/cloud_material/raw_frame.cpp"),
         str(ROOT / "runtime/cloud_material/raw_client_session.cpp"),
         str(ROOT / "runtime/cloud_material/raw_client_transport.cpp"),
         str(ROOT / "runtime/cloud_material/raw_socket_transport.cpp"),
         str(ROOT / "runtime/cloud_material/raw_socket_syscall_aarch64.cpp"),
         str(ROOT / "runtime/cloud_material_backend/raw_session.cpp"),
         str(ROOT / "runtime/cloud_material_backend/raw_server.cpp"),
         "-lcrypto", "-pthread", "-o", str(exe)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert subprocess.run([str(exe)], capture_output=True, text=True).returncode == 0
