import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_signed_capability_is_verified_before_state_commit(tmp_path):
    source = tmp_path / "capability_client_harness.cpp"
    binary = tmp_path / "capability_client_harness"
    source.write_text(
        r'''
#include "zone_runtime/capability_client.h"
#include <iostream>

int main(int argc, char** argv) {
  xollvm::CapabilityClientConfig config;
  config.build_manifest = "manifest-a";
  config.operation = "decrypt";
  config.policy_version = 1;
  config.server_time = 1700000010;
  config.state_path = argv[1];
  xollvm::CapabilityClient client(config);
  xollvm::CapabilityResponse response;
  response.protocol = 1;
  response.ok = true;
  response.operation = "decrypt";
  response.request_hash = std::string(64, 'a');
  response.device_id_hash = std::string(64, 'b');
  response.next_state = std::string(64, 'c');
  response.vm_value = std::string(64, 'd');
  response.server_time = 1700000000;
  response.issued_at = 1700000000;
  response.expires_at = 1700000100;
  response.policy_version = 1;
  response.key_id = "key-1";
  if (!client.signTestResponse(&response)) return 2;
  std::cout << client.acceptResponse(response, std::string(64, 'a')) << "\n";
  std::cout << client.hasState() << "\n";
  response.vm_value[0] = 'e';
  std::cout << client.acceptResponse(response, std::string(64, 'a')) << "\n";
}
'''
    )
    result = subprocess.run(
        [
            "c++", "-std=c++17", "-I", str(ROOT), str(source),
            str(ROOT / "zone_runtime/capability_protocol.cpp"),
            str(ROOT / "zone_runtime/capability_client.cpp"), "-lcrypto",
            "-o", str(binary),
        ], check=False, capture_output=True, text=True
    )
    assert result.returncode == 0, result.stderr
    result = subprocess.run(
        [str(binary), str(tmp_path / "state")],
        check=True,
        capture_output=True,
        text=True,
    )
    assert result.stdout.splitlines() == ["1", "1", "0"]
