"""Bounded binary dispatch for the six raw cloud operations."""

from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]


def test_raw_api_dispatch_uses_closed_schemas(tmp_path):
    source = tmp_path / "raw_api_dispatch_probe.cpp"
    source.write_text(
        '#include "runtime/cloud_material_backend/raw_api_dispatch.h"\n'
        '#include <openssl/evp.h>\n'
        '#include <array>\n'
        '#include <cassert>\n'
        '#include <cstdint>\n'
        '#include <span>\n'
        '#include <variant>\n'
        '#include <vector>\n'
        'static std::array<unsigned char, 32> public_key(const std::array<unsigned char, 32> &private_key) {\n'
        '  EVP_PKEY *key = EVP_PKEY_new_raw_private_key_ex(nullptr, "X25519", nullptr, private_key.data(), private_key.size());\n'
        '  std::array<unsigned char, 32> result{}; size_t size = result.size();\n'
        '  assert(key && EVP_PKEY_get_raw_public_key(key, result.data(), &size) == 1 && size == result.size());\n'
        '  EVP_PKEY_free(key); return result;\n'
        '}\n'
        'int main() {\n'
        '  using namespace xovm::cloud_material;\n'
        '  xovm::material::RawHello hello{}; hello.software_id = "test"; hello.build_id = "build";\n'
        '  std::array<unsigned char, 32> client_private{}; client_private[0] = 7;\n'
        '  hello.client_ephemeral_public = public_key(client_private);\n'
        '  RawSessionConfig session_config; session_config.key_version = 5; session_config.expires_at_ms = 900;\n'
        '  session_config.trusted_now = []() { return std::variant<uint64_t, RawSessionError>(uint64_t{100}); };\n'
        '  session_config.random_bytes = [](size_t size) { return std::variant<std::vector<unsigned char>, RawSessionError>(std::vector<unsigned char>(size, 8)); };\n'
        '  session_config.sign = [](std::span<const unsigned char>) { return std::variant<std::array<unsigned char, 64>, RawSessionError>(std::array<unsigned char, 64>{}); };\n'
        '  auto accepted = RawSession::accept(hello, session_config); assert(std::holds_alternative<RawSession>(accepted));\n'
        '  auto session = std::get<RawSession>(std::move(accepted));\n'
        '  const auto &context = session.authenticatedContext();\n'
        '  unsigned calls = 0; unsigned algorithm_calls = 0;\n'
        '  CloudApiProviders providers;\n'
        '  providers.announcement = [&] { ++calls; AnnouncementResponse result; result.announcement_id = "a1"; result.version = 2; result.content = "hello"; return std::variant<AnnouncementResponse, CloudApiError>(result); };\n'
        '  providers.update = [&](std::string_view version) { ++calls; UpdateResponse result; result.version = std::string(version); result.size = 4; return std::variant<UpdateResponse, CloudApiError>(result); };\n'
        '  providers.algorithm = [&](const AuthenticatedRawContext &authenticated, const xovm::material::WindowAcquireRequest &request) { ++calls; ++algorithm_calls; assert(&authenticated == &context); assert(request.request_id[0] == 6); xovm::material::WindowGrant result; result.build_id = request.build_id; result.region_id = request.region_id; result.session_id = authenticated.sessionId(); result.generation = request.generation; result.window_id = request.window_id; result.previous_state_hash = request.previous_state_hash; result.next_state_hash[0] = 4; result.issued_at_ms = 10; result.expires_at_ms = 20; result.key_version = authenticated.keyVersion(); result.encrypted_window_material.assign(xovm::material::kEncryptedWindowMaterialSize, 9); return std::variant<xovm::material::WindowGrant, CloudApiError>(result); };\n'
        '  providers.variables = [&](std::string_view) { ++calls; RemoteVariablesResponse result; result.version = 1; result.canonical_variables = {7}; return std::variant<RemoteVariablesResponse, CloudApiError>(result); };\n'
        '  providers.account_login = [&](std::string_view account, std::span<const uint8_t> proof) { ++calls; assert(account == "user" && proof.size() == 2); return std::variant<LoginResponse, CloudApiError>(LoginResponse{}); };\n'
        '  providers.card_login = [&](std::span<const uint8_t> card, std::span<const uint8_t> binding) { ++calls; assert(card.size() == 2 && binding.size() == 2); return std::variant<LoginResponse, CloudApiError>(LoginResponse{}); };\n'
        '  RawApiDispatch dispatch{CloudApi(providers)};\n'
        '  xovm::material::RawFrameHeader header{};\n'
        '  header.type = xovm::material::RawFrameType::Announcement;\n'
        '  auto announcement = dispatch.handle(context, header, {}); assert(std::holds_alternative<std::vector<uint8_t>>(announcement));\n'
        '  header.type = xovm::material::RawFrameType::Update;\n'
        '  const uint8_t version[] = {0, 3, 118, 49, 48};\n'
        '  auto update = dispatch.handle(context, header, version); assert(std::holds_alternative<std::vector<uint8_t>>(update));\n'
        '  header.type = static_cast<xovm::material::RawFrameType>(99);\n'
        '  auto unknown = dispatch.handle(context, header, {}); assert(std::holds_alternative<RawApiDispatchError>(unknown)); assert(std::get<RawApiDispatchError>(unknown).code == "unknown_operation");\n'
        '  header.type = xovm::material::RawFrameType::AlgorithmAcquire;\n'
        '  auto empty_algorithm = dispatch.handle(context, header, {}); assert(std::holds_alternative<RawApiDispatchError>(empty_algorithm)); assert(algorithm_calls == 0);\n'
        '  xovm::material::WindowAcquireRequest request{}; request.request_id[0] = 6; request.build_id[0] = 1; request.region_id[0] = 2; request.generation = 3; request.window_id = 4; request.previous_state_hash[0] = 5;\n'
        '  const auto request_bytes = xovm::material::encodeWindowAcquireRequest(request); assert(!request_bytes.empty());\n'
        '  auto trailing_bytes = request_bytes; trailing_bytes.push_back(0);\n'
        '  auto trailing_algorithm = dispatch.handle(context, header, trailing_bytes); assert(std::holds_alternative<RawApiDispatchError>(trailing_algorithm)); assert(algorithm_calls == 0);\n'
        '  auto malformed_bytes = request_bytes; malformed_bytes[0] = 0; malformed_bytes[1] = 0;\n'
        '  auto malformed_algorithm = dispatch.handle(context, header, malformed_bytes); assert(std::holds_alternative<RawApiDispatchError>(malformed_algorithm)); assert(algorithm_calls == 0);\n'
        '  auto algorithm = dispatch.handle(context, header, request_bytes); assert(std::holds_alternative<std::vector<uint8_t>>(algorithm)); assert(algorithm_calls == 1);\n'
        '  header.type = xovm::material::RawFrameType::RemoteVariables; const uint8_t session_name[] = {0, 2, 115, 49};\n'
        '  auto variables = dispatch.handle(context, header, session_name); assert(std::holds_alternative<std::vector<uint8_t>>(variables));\n'
        '  header.type = xovm::material::RawFrameType::LoginAccount; const uint8_t account[] = {0, 4, 117, 115, 101, 114, 0, 0, 0, 2, 1, 2};\n'
        '  auto login = dispatch.handle(context, header, account); assert(std::holds_alternative<std::vector<uint8_t>>(login));\n'
        '  header.type = xovm::material::RawFrameType::LoginCard; const uint8_t card[] = {0, 2, 1, 2, 0, 2, 3, 4};\n'
        '  auto card_login = dispatch.handle(context, header, card); assert(std::holds_alternative<std::vector<uint8_t>>(card_login));\n'
        '  assert(calls == 6);\n'
        '  const std::vector<uint8_t> oversized(64 * 1024 + 1);\n'
        '  header.type = xovm::material::RawFrameType::Update;\n'
        '  auto rejected = dispatch.handle(context, header, oversized); assert(std::holds_alternative<RawApiDispatchError>(rejected));\n'
        '  assert(!RawApiDispatch::encodeError(std::get<RawApiDispatchError>(rejected)).empty());\n'
        '  header.type = xovm::material::RawFrameType::Announcement; const uint8_t malformed[] = {1};\n'
        '  auto malformed_result = dispatch.handle(context, header, malformed); assert(std::holds_alternative<RawApiDispatchError>(malformed_result));\n'
        '  RawApiDispatchError long_error{std::string(100, \'x\')}; auto encoded_error = RawApiDispatch::encodeError(long_error); assert(encoded_error.size() == 17);\n'
        '  assert(calls == 6);\n'
        '  return 0;\n'
        '}\n',
        encoding="ascii",
    )
    exe = tmp_path / "probe"
    result = subprocess.run(
        ["c++", "-std=c++20", "-Wall", "-Wextra", "-Werror", "-I", str(ROOT),
         str(source), str(ROOT / "runtime/cloud_material/raw_protocol.cpp"),
         str(ROOT / "runtime/cloud_material/dynamic_vm_schema.cpp"),
         str(ROOT / "runtime/cloud_material_backend/raw_session.cpp"),
         str(ROOT / "runtime/cloud_material_backend/cloud_api.cpp"),
         str(ROOT / "runtime/cloud_material_backend/raw_api_dispatch.cpp"),
         "-lcrypto", "-o", str(exe)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    run = subprocess.run([str(exe)], capture_output=True, text=True)
    assert run.returncode == 0, run.stderr
