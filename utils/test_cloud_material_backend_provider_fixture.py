import json
import os
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import base64
import shutil
from pathlib import Path


def require(condition, detail):
    if not condition:
        raise AssertionError(detail)


def free_port(excluded=()):
    while True:
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        if port not in excluded:
            return port


def request(port, payload):
    with socket.create_connection(("127.0.0.1", port), timeout=2) as connection:
        connection.sendall(payload)
        result = bytearray()
        while True:
            chunk = connection.recv(4096)
            if not chunk:
                return bytes(result)
            result.extend(chunk)


def http_request(port, method, path, token, body=b""):
    headers = [
        f"{method} {path} HTTP/1.1",
        "Host: localhost",
        f"Authorization: Bearer {token}",
        "Connection: close",
    ]
    if body:
        headers.extend(["Content-Type: application/json", f"Content-Length: {len(body)}"])
    else:
        headers.append("Content-Length: 0")
    return request(port, ("\r\n".join(headers) + "\r\n\r\n").encode() + body)


def status(response):
    return int(response.split(b" ", 2)[1])


def expect_status(response, expected, process):
    if status(response) == expected:
        return
    process.terminate()
    stdout, stderr = process.communicate(timeout=3)
    raise AssertionError((response, stdout, stderr))


def http_body(response):
    return response.split(b"\r\n\r\n", 1)[1]


def start_process(executable, environment, port):
    process = subprocess.Popen([str(executable)], env=environment,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    deadline = time.monotonic() + 3
    response = b""
    while time.monotonic() < deadline:
        try:
            response = request(port, b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n")
            if b"200" in response:
                break
        except OSError:
            time.sleep(0.02)
    require(b"200" in response and b'{"ready":true}' in response, response)
    return process


def admin_import_body(build_id, artifact_hash, region):
    manifest = json.dumps({"build_id": build_id, "software_id": "fixture.software"},
                          separators=(",", ":"), sort_keys=True).encode()
    registration = json.dumps({"build_id": build_id}, separators=(",", ":")).encode()
    sidecars = json.dumps({region: base64.b64encode(b"{}").decode()},
                          separators=(",", ":"), sort_keys=True).encode()
    return json.dumps({
        "final_artifact_hash": artifact_hash,
        "private_registration_b64": base64.b64encode(registration).decode(),
        "public_manifest_b64": base64.b64encode(manifest).decode(),
        "verifier_sidecars_b64": base64.b64encode(sidecars).decode(),
    }, separators=(",", ":"), sort_keys=True).encode()


def relay_body(build_id, artifact_hash, region):
    return relay_body_for({
        "build_id": build_id,
        "final_artifact_hash": artifact_hash,
    })


def relay_body_for(request_value):
    request_value = {
        "build_id": request_value["build_id"],
        "client_ephemeral_key": base64.b64encode(bytes.fromhex(
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")).decode(),
        "client_nonce": "44" * 32,
        "final_artifact_hash": request_value["final_artifact_hash"],
        "protocol_version": 2,
        "request_id": "33" * 32,
        "software_id": "fixture.software",
        "suite": "X25519-Ed25519-HKDF-SHA256-AES256GCM",
        "type": "session.open",
        **request_value,
    }
    canonical = json.dumps(request_value, separators=(",", ":"), sort_keys=True).encode()
    return json.dumps({
        "protocol": "xovm2_relay",
        "request_b64": base64.b64encode(canonical).decode(),
    }, separators=(",", ":")).encode()


def assert_window_material_provider_boundary(source_root):
    fixture = (Path(source_root) / "utils" /
               "CloudMaterialProviderFixture.cpp").read_text()
    require("result.build_window_material = buildWindowMaterial;" in fixture,
            "fixture must provide fixed-size window material")
    for forbidden in ("issueWindowGrant", "WindowIssueInput", "raw_api.algorithm"):
        require(forbidden not in fixture, forbidden)


def main():
    executable = Path(sys.argv[1])
    raw_client = Path(sys.argv[2]) if len(sys.argv) > 2 else None
    source_root = os.environ.get("XOLLVM_CLOUD_MATERIAL_SOURCE_ROOT")
    if source_root:
        assert_window_material_provider_boundary(source_root)
    migration = (Path(source_root) / "runtime" / "cloud_material_backend" / "migrations" /
                 "001_build_registry.sql") if source_root else executable.parent.parent.parent / "runtime" / "cloud_material_backend" / "migrations" / "001_build_registry.sql"
    with tempfile.TemporaryDirectory(prefix="xovm-backend-provider-") as temporary:
        root = Path(temporary)
        database = root / "registry.sqlite"
        state = root / "state"
        state.mkdir()
        with sqlite3.connect(database) as connection:
            connection.executescript(migration.read_text())
        port = free_port()
        raw_port = free_port({port})
        environment = os.environ.copy()
        environment.update({
            "XOVM_SQLITE_PATH": str(database),
            "XOVM_STATE_DIR": str(state),
            "XOVM_RELAY_TOKEN": "r" * 32,
            "XOVM_ADMIN_TOKEN": "a" * 32,
            "XOVM_TRUSTED_TIME_PROVIDER": "fixture",
            "XOVM_SIGNING_KEY_PROVIDER": "fixture",
            "XOVM_ANONYMOUS_POLICY_PROVIDER": "fixture",
            "XOVM_TRUST_ROOT_PROVIDER": "fixture",
            "PORT": str(port),
            "XOVM_RAW_PORT": str(raw_port),
        })
        build_id = "11" * 32
        artifact_hash = "22" * 32
        region = "22" * 32
        with socket.socket() as blocker:
            blocker.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            blocker.bind(("127.0.0.1", raw_port))
            blocker.listen(1)
            failed = subprocess.run([str(executable)], env=environment,
                                    capture_output=True, text=True, timeout=5)
            if failed.returncode != 1 or "bind_failed" not in failed.stderr:
                raise AssertionError((failed.returncode, failed.stdout, failed.stderr))
            with socket.socket() as probe:
                probe.settimeout(0.2)
                if probe.connect_ex(("127.0.0.1", port)) == 0:
                    raise AssertionError("HTTP listener opened before raw bind succeeded")
        process = start_process(executable, environment, port)
        try:
            with socket.create_connection(("127.0.0.1", raw_port), timeout=2):
                pass
            trust = request(port, b"GET /v2/trust/fixture.software HTTP/1.1\r\nHost: localhost\r\n\r\n")
            require(b"200" in trust and b"fixture-key" in trust, trust)
            imported = http_request(port, "POST", "/v2/admin/builds/import", "a" * 32,
                                    admin_import_body(build_id, artifact_hash, region))
            expect_status(imported, 200, process)
            enabled = http_request(port, "POST", f"/v2/admin/builds/{build_id}/enable",
                                   "a" * 32,
                                   json.dumps({"final_artifact_hash": artifact_hash},
                                              separators=(",", ":")).encode())
            expect_status(enabled, 200, process)
            if raw_client:
                blocked = subprocess.run(
                    [str(raw_client), str(raw_port), build_id, region],
                    capture_output=True, text=True, timeout=5)
                if blocked.returncode != 0:
                    raise AssertionError((blocked.stdout, blocked.stderr))
            opened = http_request(port, "POST", "/v2/relay", "r" * 32,
                                  relay_body(build_id, artifact_hash, region))
            expect_status(opened, 200, process)
            opened_http = json.loads(http_body(opened))
            opened_envelope = json.loads(base64.b64decode(opened_http["response_b64"]))
            opened_transcript = opened_envelope["transcript"]
            node = shutil.which("node")
            require(node, "node is required for cross-language material acceptance")
            opened_input = {
                "request": json.loads(relay_body(build_id, artifact_hash, region))["request_b64"],
                "response": opened_http["response_b64"],
                "trust_bundle": base64.b64encode(http_body(trust)).decode(),
                "client_private_key": "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
            }
            control_verified = subprocess.run(
                [node, str(Path(__file__).resolve().parents[1] / "cloud/material_v2/test/protocol.test.mjs"),
                 "--native-control-auth"], input=json.dumps(opened_input).encode(),
                capture_output=True, timeout=30)
            require(control_verified.returncode == 0, (control_verified.stdout,
                    control_verified.stderr.decode(errors="replace")))
            require(json.loads(control_verified.stdout)["ok"] is True,
                    control_verified.stdout)
            issue = relay_body_for({
                "build_id": build_id,
                "final_artifact_hash": artifact_hash,
                "session_id": opened_transcript["session_id"],
                "counter_epoch": opened_transcript["counter_epoch"],
                "region_id": region,
                "engine_abi_hash": "55" * 32,
                "mode": "lease",
                "previous_generation": "0",
                "request_id": "55" * 32,
                "client_nonce": "66" * 32,
                "client_ephemeral_key": base64.b64encode(bytes.fromhex(
                    "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")).decode(),
                "type": "material.issue",
            })
            issued = http_request(port, "POST", "/v2/relay", "r" * 32, issue)
            expect_status(issued, 200, process)
            issue_http = json.loads(http_body(issued))
            trust_bytes = http_body(trust)
            auth_input = {
                "request": json.loads(issue)["request_b64"],
                "response": issue_http["response_b64"],
                "trust_bundle": base64.b64encode(trust_bytes).decode(),
                "client_private_key": "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
                "expected": {
                    "software_id": "fixture.software",
                    "build_id": build_id,
                    "final_artifact_hash": artifact_hash,
                    "session_id": opened_transcript["session_id"],
                    "counter_epoch": opened_transcript["counter_epoch"],
                    "region_id": region,
                    "engine_abi_hash": "55" * 32,
                    "mode": "lease",
                },
            }
            verifier = Path(__file__).resolve().parents[1] / "cloud/material_v2/test/protocol.test.mjs"
            verified = subprocess.run(
                [node, str(verifier), "--native-auth"],
                input=json.dumps(auth_input).encode(), capture_output=True, timeout=30)
            require(verified.returncode == 0,
                    verified.stderr.decode(errors="replace"))
            package = json.loads(verified.stdout)
            require(package["ok"] is True, package)
            require(package["binding"]["build_id"] == build_id, package)
            require(package["binding"]["region_id"] == region, package)
            require(package["binding"]["mode"] == "lease", package)
            require(package["generation"] == "1", package)
            process.terminate()
            stdout, stderr = process.communicate(timeout=3)
            require(process.returncode == 0,
                    (process.returncode, stdout, stderr))
            process = start_process(executable, environment, port)
            replayed = http_request(port, "POST", "/v2/relay", "r" * 32,
                                     relay_body(build_id, artifact_hash, region))
            require(replayed == opened, (opened, replayed))
            replayed_issue = http_request(port, "POST", "/v2/relay", "r" * 32, issue)
            require(replayed_issue == issued, (issued, replayed_issue))
            revoked = http_request(port, "POST", f"/v2/admin/builds/{build_id}/revoke",
                                   "a" * 32, b"{}")
            expect_status(revoked, 200, process)
            revoked_issue = json.loads(issue)
            revoked_issue["request_b64"] = base64.b64encode(json.dumps({
                **json.loads(base64.b64decode(revoked_issue["request_b64"])),
                "request_id": "77" * 32,
                "client_nonce": "88" * 32,
                "client_ephemeral_key": base64.b64encode(bytes.fromhex(
                    "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")).decode(),
            }, separators=(",", ":"), sort_keys=True).encode()).decode()
            revoked_issue_body = json.dumps({"protocol": "xovm2_relay",
                                              "request_b64": revoked_issue["request_b64"]},
                                             separators=(",", ":")).encode()
            revoked_material = http_request(port, "POST", "/v2/relay", "r" * 32,
                                             revoked_issue_body)
            expect_status(revoked_material, 500, process)
            denied = http_request(port, "POST", "/v2/relay", "r" * 32,
                                  relay_body(build_id, artifact_hash, region))
            expect_status(denied, 500, process)
        finally:
            process.terminate()
            stdout, stderr = process.communicate(timeout=3)
            require(process.returncode == 0,
                    (process.returncode, stdout, stderr))


if __name__ == "__main__":
    main()
