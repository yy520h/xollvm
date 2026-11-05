"""Authenticated raw-session crypto and sequence-boundary coverage."""

from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]


def test_raw_session_binds_transcript_and_rejects_sequence_replay(tmp_path):
    source = tmp_path / "raw_session_probe.cpp"
    source.write_text(
        '#include "runtime/cloud_material_backend/raw_session.h"\n'
        '#include <openssl/evp.h>\n'
        '#include <cassert>\n'
         '#include <array>\n'
         '#include <cstring>\n'
         '#include <type_traits>\n'
         '#include <vector>\n'
        'static std::array<unsigned char, 32> public_key(const std::array<unsigned char, 32> &private_key) {\n'
        '  EVP_PKEY *key = EVP_PKEY_new_raw_private_key_ex(nullptr, "X25519", nullptr, private_key.data(), 32);\n'
        '  std::array<unsigned char, 32> result{}; size_t size = result.size();\n'
        '  assert(key && EVP_PKEY_get_raw_public_key(key, result.data(), &size) == 1 && size == 32);\n'
        '  EVP_PKEY_free(key); return result;\n'
        '}\n'
        'int main() {\n'
        '  using namespace xovm; using namespace xovm::cloud_material;\n'
        '  material::RawHello hello{}; hello.software_id = "test"; hello.build_id = "build";\n'
        '  std::array<unsigned char, 32> client_private{}; client_private[0] = 7;\n'
        '  hello.client_ephemeral_public = public_key(client_private);\n'
         '  std::array<unsigned char, 32> signing_private{}; signing_private[0] = 9;\n'
         '  EVP_PKEY *signing_key = EVP_PKEY_new_raw_private_key_ex(nullptr, "ED25519", nullptr, signing_private.data(), 32);\n'
         '  std::array<unsigned char, 32> signing_public{}; size_t signing_public_size = signing_public.size();\n'
         '  assert(signing_key && EVP_PKEY_get_raw_public_key(signing_key, signing_public.data(), &signing_public_size) == 1);\n'
         '  RawSessionConfig config; config.counter = 3; config.key_version = 5; config.expires_at_ms = 900;\n'
         '  uint64_t trusted_now = 100; config.trusted_now = [&trusted_now]() { return std::variant<uint64_t, RawSessionError>(trusted_now); };\n'
         '  config.random_bytes = [](size_t size) { return std::variant<std::vector<unsigned char>, RawSessionError>(std::vector<unsigned char>(size, 8)); };\n'
         '  config.sign = [signing_key](std::span<const unsigned char> bytes) {\n'
         '    std::array<unsigned char, 64> signature{}; size_t signature_size = signature.size();\n'
         '    EVP_MD_CTX *context = EVP_MD_CTX_new();\n'
         '    const bool ok = context && EVP_DigestSignInit(context, nullptr, nullptr, nullptr, signing_key) == 1 &&\n'
         '      EVP_DigestSign(context, signature.data(), &signature_size, bytes.data(), bytes.size()) == 1;\n'
         '    EVP_MD_CTX_free(context); if (!ok || signature_size != signature.size()) return std::variant<std::array<unsigned char, 64>, RawSessionError>(RawSessionError{"sign_failed"});\n'
         '    return std::variant<std::array<unsigned char, 64>, RawSessionError>(signature);\n'
         '  };\n'
         '  auto expired_config = config; expired_config.expires_at_ms = trusted_now; auto expired = RawSession::accept(hello, expired_config); assert(std::holds_alternative<RawSessionError>(expired) && std::get<RawSessionError>(expired).code == "session_expired");\n'
         '  auto throwing_config = config; throwing_config.sign = [](std::span<const unsigned char>) -> std::variant<std::array<unsigned char, 64>, RawSessionError> { throw 7; }; auto thrown = RawSession::accept(hello, throwing_config); assert(std::holds_alternative<RawSessionError>(thrown) && std::get<RawSessionError>(thrown).code == "sign_failed");\n'
         '  auto accepted = RawSession::accept(hello, config); assert(std::holds_alternative<RawSession>(accepted));\n'
         '  static_assert(!std::is_copy_constructible_v<RawSession> && std::is_nothrow_move_constructible_v<RawSession>);\n'
         '  auto session = std::get<RawSession>(std::move(accepted));\n'
         '  const auto &context = session.authenticatedContext();\n'
         '  assert(context.softwareId() == hello.software_id && context.buildId() == hello.build_id);\n'
         '  assert(context.sessionId() == session.serverHello().session_id && context.keyVersion() == 5 && context.expiresAtMs() == 900);\n'
         '  assert(context.transcriptHash() == material::hashRawTranscript(session.transcript()));\n'
         '  assert((context.initialStateCommitment() != context.transcriptHash() && context.initialStateCommitment() != std::array<unsigned char, 32>{}));\n'
         '  std::array<unsigned char, 32> request_a{}; request_a[0] = 1; std::array<unsigned char, 32> request_b{}; request_b[0] = 2;\n'
         '  auto grant_a1 = context.deriveGrantKey(request_a); auto grant_a2 = context.deriveGrantKey(request_a); auto grant_b = context.deriveGrantKey(request_b);\n'
         '  assert((std::holds_alternative<std::array<unsigned char, 32>>(grant_a1) && std::get<std::array<unsigned char, 32>>(grant_a1) == std::get<std::array<unsigned char, 32>>(grant_a2)));\n'
         '  assert((std::get<std::array<unsigned char, 32>>(grant_a1) != std::get<std::array<unsigned char, 32>>(grant_b)));\n'
         '  material::RawSessionTranscript transcript = session.transcript();\n'
         '  assert(material::verifyRawServerHello(transcript, signing_public));\n'
         '  transcript.hello.build_id = "tampered"; assert(!material::verifyRawServerHello(transcript, signing_public));\n'
         '  EVP_PKEY_free(signing_key);\n'
        '  assert(session.serverHello().counter == 3 && session.serverHello().key_version == 5);\n'
         '  material::RawFrameHeader header{}; header.session_id = session.serverHello().session_id; header.flags = 5; header.sequence = 0; header.payload_length = 19;\n'
         '  const unsigned char payload[] = {1, 2, 3}; auto encrypted = session.encrypt(header, payload); assert(std::holds_alternative<std::vector<unsigned char>>(encrypted));\n'
         '  const auto &blob = std::get<std::vector<unsigned char>>(encrypted);\n'
         '  auto ciphertext = std::span<const unsigned char>(blob.data(), blob.size() - 16);\n'
         '  auto tag = std::span<const unsigned char, 16>(blob.data() + blob.size() - 16, 16);\n'
         '  header.payload_length = 18; auto malformed = session.decrypt(header, ciphertext, tag);\n'
         '  assert(std::holds_alternative<RawSessionError>(malformed));\n'
         '  assert(std::get<RawSessionError>(malformed).code == "invalid_frame_length");\n'
         '  header.payload_length = 19; header.sequence = 0; auto replay = session.encrypt(header, payload); assert(std::holds_alternative<RawSessionError>(replay));\n'
         '  trusted_now = 900; header.sequence = 1; auto stale_encrypt = session.encrypt(header, payload); assert(std::holds_alternative<RawSessionError>(stale_encrypt) && std::get<RawSessionError>(stale_encrypt).code == "session_expired");\n'
         '  header.sequence = 0; auto stale_decrypt = session.decrypt(header, ciphertext, tag); assert(std::holds_alternative<RawSessionError>(stale_decrypt) && std::get<RawSessionError>(stale_decrypt).code == "session_expired");\n'
        '  return 0;\n'
        '}\n', encoding="ascii")
    exe = tmp_path / "probe"
    result = subprocess.run(
        ["c++", "-std=c++20", "-Wall", "-Wextra", "-Werror", "-I", str(ROOT),
         str(source), str(ROOT / "runtime/cloud_material/raw_protocol.cpp"),
         str(ROOT / "runtime/cloud_material_backend/raw_session.cpp"), "-lcrypto", "-o", str(exe)],
        capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert subprocess.run([str(exe)], capture_output=True, text=True).returncode == 0
