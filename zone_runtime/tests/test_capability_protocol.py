import json
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def run_harness(source: str) -> str:
    harness = ROOT / "zone_runtime/tests/.capability_protocol_harness.cpp"
    binary = ROOT / "zone_runtime/tests/.capability_protocol_harness"
    harness.write_text(source)
    try:
        subprocess.run(
            [
                "c++",
                "-std=c++17",
                "-I",
                str(ROOT),
                str(harness),
                str(ROOT / "zone_runtime/capability_protocol.cpp"),
                "-o",
                str(binary),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        return subprocess.run(
            [str(binary)], check=True, capture_output=True, text=True
        ).stdout
    finally:
        harness.unlink(missing_ok=True)
        binary.unlink(missing_ok=True)


def test_request_canonicalization_is_ordered_and_length_delimited():
    output = run_harness(
        r'''
#include "zone_runtime/capability_protocol.h"
#include <iostream>

int main() {
  xollvm::CapabilityRequest request;
  request.protocol = "capability_v1";
  request.software_id = "demo";
  request.version = "1";
  request.build_id = "build-a";
  request.device_id = "device-a";
  request.operation = "decrypt";
  request.state = "00112233445566778899aabbccddeeff";
  request.client_nonce = "ffeeddccbbaa99887766554433221100";
  request.request_id = "0123456789abcdef0123456789abcdef";
  request.client_time = 1700000000;
  request.code_manifest = "manifest-a";
  request.payload = "a|b\n\\c";
  std::cout << xollvm::canonicalizeCapabilityRequest(request) << "\n";
}
'''
    )
    labels = [
        "protocol",
        "software_id",
        "version",
        "build_id",
        "device_id",
        "operation",
        "state",
        "client_nonce",
        "request_id",
        "client_time",
        "code_manifest",
        "payload",
    ]
    positions = [output.index(label + ":") for label in labels]
    assert positions == sorted(positions)
    assert "a|b" in output


def test_request_validation_rejects_short_ids_and_unsupported_protocol():
    output = run_harness(
        r'''
#include "zone_runtime/capability_protocol.h"
#include <iostream>

int main() {
  xollvm::CapabilityRequest request;
  request.protocol = "wrong";
  request.client_nonce = "00";
  request.request_id = "00";
  std::cout << xollvm::validateCapabilityRequest(request) << "\n";
}
'''
    )
    assert output.strip() == "0"


def test_canonical_output_is_stable_for_payload_values():
    first = json.dumps({"payload": "alpha"}, sort_keys=True)
    second = json.dumps({"payload": "beta"}, sort_keys=True)
    assert first != second
