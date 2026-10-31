"""Task 5 fixed public protocol vectors and native rejection paths."""

import os
import json
from pathlib import Path
import subprocess

import pytest

from cloud_material_support import build_material_harness, run_material_case


REPO = Path(__file__).resolve().parents[1]


def fixture_bytes(case):
    generated = subprocess.run([
        "node", REPO / "cloud/material_v2/test/protocol.test.mjs",
        "--native-fixture", case,
    ], capture_output=True, check=True, timeout=30)
    value = json.loads(generated.stdout)
    assert isinstance(value, dict) and value["installed"]["software_id"] == "test.software"
    return generated.stdout


@pytest.fixture(scope="module")
def protocol_exe(tmp_path_factory):
    return build_material_harness(tmp_path_factory.mktemp("material-protocol"),
                                  sources=("material_protocol.cpp",))


def test_fixed_public_node_openssl_vector(protocol_exe):
    result = run_material_case(protocol_exe, "valid", input_bytes=fixture_bytes("valid"))
    assert result["accepted"] is True
    assert result["published_generations"] == 1


def test_native_authentication_consumes_pending_request(protocol_exe):
    result = run_material_case(protocol_exe, "pending_reuse",
                               input_bytes=fixture_bytes("valid"))
    assert result["first_accepted"] is True
    assert result["accepted"] is False
    assert result["code"] == "invalid_pending_request"
    assert result["published_generations"] == 1


@pytest.mark.parametrize("case", [
    "wrong_signature", "wrong_aad", "wrong_request_hash", "wrong_ephemeral_key",
    "wrong_region", "bad_tag", "truncated_envelope", "zero_shared_secret",
    "noncanonical_x25519", "unknown_key_id", "short_auth_window",
    "wrong_lease_binding",
])
def test_authentication_rejects_mismatched_material(protocol_exe, case):
    result = run_material_case(protocol_exe, case, input_bytes=fixture_bytes(case))
    assert result["accepted"] is False
    assert result["published_generations"] == 0


def test_native_protocol_delivery_is_static(protocol_exe):
    root = Path(os.environ["XOLLVM_PROJECT_ROOT"])
    readelf = (root.parent / "android-ndk-r30-ollvm-r23-beta3/toolchains/llvm/prebuilt/"
                "linux-arm64/bin/llvm-readelf")
    result = subprocess.run([readelf, "-d", protocol_exe], capture_output=True,
                            text=True, check=True)
    assert "libc++_shared.so" not in result.stdout
    assert "libcrypto.so" not in result.stdout
