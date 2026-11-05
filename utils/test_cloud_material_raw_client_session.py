"""Client-side raw handshake, signature, and encrypted-frame coverage."""

from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]


def test_raw_client_verifies_server_and_round_trips_frames(tmp_path):
    source = tmp_path / "raw_client_session_probe.cpp"
    source.write_text(
        '#include "runtime/cloud_material/raw_client_session.h"\n'
        '#include "runtime/cloud_material_backend/raw_session.h"\n'
        '#include <openssl/evp.h>\n'
        '#include <array>\n'
        '#include <cassert>\n'
        '#include <span>\n'
        '#include <variant>\n'
        '#include <vector>\n'
        'static std::array<unsigned char, 32> public_key(const std::array<unsigned char, 32> &private_key, const char *type) {\n'
        '  EVP_PKEY *key = EVP_PKEY_new_raw_private_key_ex(nullptr, type, nullptr, private_key.data(), 32);\n'
        '  std::array<unsigned char, 32> result{}; size_t size = result.size();\n'
        '  assert(key && EVP_PKEY_get_raw_public_key(key, result.data(), &size) == 1 && size == result.size());\n'
        '  EVP_PKEY_free(key); return result;\n'
        '}\n'
        'int main() {\n'
        '  using namespace xovm;\n'
        '  std::array<unsigned char, 32> signing_private{}; signing_private[0] = 9;\n'
        '  EVP_PKEY *signing_key = EVP_PKEY_new_raw_private_key_ex(nullptr, "ED25519", nullptr, signing_private.data(), 32);\n'
        '  assert(signing_key);\n'
        '  const auto signing_public = public_key(signing_private, "ED25519");\n'
        '  cloud_material::RawClientSessionConfig client_config;\n'
        '  client_config.hello.software_id = "test"; client_config.hello.build_id = "build";\n'
        '  client_config.server_signing_public_key = signing_public;\n'
        '  client_config.random_bytes = [](size_t size) { return std::variant<std::vector<unsigned char>, cloud_material::RawClientSessionError>(std::vector<unsigned char>(size, 3)); };\n'
        '  auto client_result = cloud_material::RawClientSession::create(client_config);\n'
        '  assert(std::holds_alternative<cloud_material::RawClientSession>(client_result));\n'
        '  auto client = std::get<cloud_material::RawClientSession>(std::move(client_result));\n'
        '  cloud_material::RawSessionConfig server_config; server_config.counter = 3; server_config.key_version = 5; server_config.expires_at_ms = 900;\n'
        '  server_config.trusted_now = []() { return std::variant<uint64_t, cloud_material::RawSessionError>(uint64_t{100}); };\n'
        '  server_config.random_bytes = [](size_t size) { return std::variant<std::vector<unsigned char>, cloud_material::RawSessionError>(std::vector<unsigned char>(size, 8)); };\n'
        '  server_config.sign = [signing_key](std::span<const unsigned char> bytes) {\n'
        '    std::array<unsigned char, 64> signature{}; size_t size = signature.size(); EVP_MD_CTX *context = EVP_MD_CTX_new();\n'
        '    const bool ok = context && EVP_DigestSignInit(context, nullptr, nullptr, nullptr, signing_key) == 1 && EVP_DigestSign(context, signature.data(), &size, bytes.data(), bytes.size()) == 1;\n'
        '    EVP_MD_CTX_free(context); if (!ok || size != signature.size()) return std::variant<std::array<unsigned char, 64>, cloud_material::RawSessionError>(cloud_material::RawSessionError{"sign_failed"});\n'
        '    return std::variant<std::array<unsigned char, 64>, cloud_material::RawSessionError>(signature);\n'
        '  };\n'
        '  auto server_result = cloud_material::RawSession::accept(client.hello(), server_config);\n'
        '  assert(std::holds_alternative<cloud_material::RawSession>(server_result));\n'
        '  auto server = std::get<cloud_material::RawSession>(std::move(server_result));\n'
        '  assert(client.acceptServerHello(server.serverHello()));\n'
        '  material::RawFrameHeader request{}; request.type = material::RawFrameType::AlgorithmAcquire; request.session_id = server.serverHello().session_id; request.flags = 5; request.sequence = 0; request.payload_length = 19;\n'
        '  const unsigned char request_bytes[] = {1, 2, 3};\n'
        '  auto sealed_request = client.encrypt(request, request_bytes); assert(std::holds_alternative<std::vector<unsigned char>>(sealed_request));\n'
        '  const auto &request_blob = std::get<std::vector<unsigned char>>(sealed_request);\n'
        '  auto request_ciphertext = std::span<const unsigned char>(request_blob.data(), request_blob.size() - 16);\n'
        '  auto request_tag = std::span<const unsigned char, 16>(request_blob.data() + request_blob.size() - 16, 16);\n'
        '  auto opened_request = server.decrypt(request, request_ciphertext, request_tag); assert(std::holds_alternative<std::vector<unsigned char>>(opened_request));\n'
        '  material::RawFrameHeader response = request; response.type = material::RawFrameType::Error; response.payload_length = 19;\n'
        '  auto sealed_response = server.encrypt(response, request_bytes); assert(std::holds_alternative<std::vector<unsigned char>>(sealed_response));\n'
        '  const auto &response_blob = std::get<std::vector<unsigned char>>(sealed_response);\n'
        '  auto response_ciphertext = std::span<const unsigned char>(response_blob.data(), response_blob.size() - 16);\n'
        '  auto response_tag = std::span<const unsigned char, 16>(response_blob.data() + response_blob.size() - 16, 16);\n'
        '  auto opened_response = client.decrypt(response, response_ciphertext, response_tag); assert(std::holds_alternative<std::vector<unsigned char>>(opened_response));\n'
        '  material::RawFrameHeader wrong_direction = response; wrong_direction.type = material::RawFrameType::AlgorithmAcquire;\n'
        '  assert(std::holds_alternative<cloud_material::RawClientSessionError>(client.decrypt(wrong_direction, response_ciphertext, response_tag)));\n'
        '  auto bad_client_result = cloud_material::RawClientSession::create(client_config); assert(std::holds_alternative<cloud_material::RawClientSession>(bad_client_result));\n'
        '  auto bad_client = std::get<cloud_material::RawClientSession>(std::move(bad_client_result));\n'
        '  auto tampered = server.serverHello(); tampered.signature[0] ^= 1; assert(!bad_client.acceptServerHello(tampered));\n'
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
         str(ROOT / "runtime/cloud_material_backend/raw_session.cpp"),
         "-lcrypto", "-o", str(exe)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert subprocess.run([str(exe)], capture_output=True, text=True).returncode == 0
