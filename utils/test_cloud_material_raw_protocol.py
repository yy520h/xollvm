"""Red tests for the raw socket protocol schema."""

from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]


def test_raw_protocol_schema_harness_is_not_yet_available(tmp_path):
    source = tmp_path / "raw_protocol_probe.cpp"
    source.write_text(
        '#include "runtime/cloud_material/raw_protocol.h"\n'
        '#include <cassert>\n'
        '#include <array>\n'
        '#include <variant>\n'
        'int main() {\n'
        '  using namespace xovm::material;\n'
        '  RawFrameHeader header{};\n'
        '  header.type = RawFrameType::AlgorithmAcquire;\n'
        '  header.payload_length = 7;\n'
        '  const auto encoded = encodeRawFrameHeader(header);\n'
        '  assert(encoded.size() == kRawFrameHeaderSize);\n'
        '  auto decoded = decodeRawFrameHeader(encoded);\n'
        '  assert(std::holds_alternative<RawFrameHeader>(decoded));\n'
        '  assert(std::get<RawFrameHeader>(decoded).payload_length == 7);\n'
        '  header.payload_length = kRawMaxFramePayload + 1;\n'
        '  assert(encodeRawFrameHeader(header).empty());\n'
        '  auto invalid = encoded; invalid[6] = 0; invalid[7] = 99;\n'
        '  assert(std::holds_alternative<RawProtocolError>(decodeRawFrameHeader(invalid)));\n'
        '  RawSessionTranscript transcript{};\n'
        '  transcript.hello.software_id = "test.software";\n'
        '  transcript.hello.build_id = "build";\n'
        '  transcript.server_hello.counter = 1;\n'
        '  std::array<unsigned char, 32> secret{}; secret[0] = 1;\n'
        '  auto keys = deriveRawSessionKeys(transcript, secret);\n'
        '  assert(std::holds_alternative<RawSessionKeys>(keys));\n'
        '  const auto &k = std::get<RawSessionKeys>(keys);\n'
        '  assert(k.client_to_server != k.server_to_client);\n'
        '  assert(k.client_to_server != k.material);\n'
        '  transcript.server_hello.signature[0] = 1;\n'
        '  std::array<unsigned char, 32> signing_key{};\n'
        '  assert(!verifyRawServerHello(transcript, signing_key));\n'
        '  RawServerHello server{}; server.session_id[0] = 1; server.server_nonce[0] = 2; server.server_ephemeral_public[0] = 3; server.signature[0] = 4;\n'
        '  const auto server_bytes = encodeRawServerHello(server);\n'
        '  auto decoded_server = decodeRawServerHello(server_bytes);\n'
        '  assert(std::holds_alternative<RawServerHello>(decoded_server));\n'
        '  auto malformed_server = server_bytes; malformed_server.push_back(0);\n'
        '  assert(std::holds_alternative<RawProtocolError>(decodeRawServerHello(malformed_server)));\n'
        '  return 0;\n'
        '}\n',
        encoding="ascii",
    )
    result = subprocess.run(
        ["c++", "-std=c++20", "-I", str(ROOT), str(source),
         str(ROOT / "runtime/cloud_material/raw_protocol.cpp"),
         str(ROOT / "runtime/cloud_material/raw_frame.cpp"), "-lcrypto",
         "-o", str(tmp_path / "probe")],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
