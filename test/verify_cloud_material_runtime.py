#!/usr/bin/env python3
"""Check local cloud-material acceptance and fail-closed rejection paths."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("executable", type=Path)
    parser.add_argument("export_dir", type=Path)
    parser.add_argument("--bytecode-size", type=int, required=True)
    parser.add_argument("--results", type=Path, required=True)
    args = parser.parse_args()

    executable = args.executable.resolve()
    export_dir = args.export_dir.resolve()
    metadata = json.loads((export_dir / "metadata.json").read_text())
    assert len(metadata["materials"]) == 1, "test expects one material"
    material_id, material = next(iter(metadata["materials"].items()))
    assert material["window_count"] == 1, "test expects a single window"
    filename = f"{material_id}_w0_s0.bin"
    payload = (export_dir / "windows" / filename).read_bytes()
    assert len(payload) == material["total_size"] == 4096
    assert 0 < args.bytecode_size < len(payload)
    assert "sha256:" + hashlib.sha256(payload).hexdigest() == material["commitment"]

    first_byte = bytearray(payload)
    first_byte[0] ^= 1
    padding = bytearray(payload)
    padding[-1] ^= 1
    cases = [
        ("valid", payload, "SHA256 verification PASSED"),
        ("tampered-first-byte", first_byte, "SHA256 verification FAILED"),
        ("tampered-padding", padding, "SHA256 verification FAILED"),
        ("truncated", payload[:args.bytecode_size], "Expected 4096 bytes"),
        ("missing-window", None, "ERROR"),
        ("missing-directory", None, "Material not available"),
    ]
    results = []
    with tempfile.TemporaryDirectory(prefix="runtime-cases-", dir=executable.parent) as temporary:
        for name, data, expected_log in cases:
            case_dir = Path(temporary) / name
            if name != "missing-directory":
                windows = case_dir / "windows"
                windows.mkdir(parents=True)
                if data is not None:
                    (windows / filename).write_bytes(data)
            env = dict(os.environ, XOLLVM_CLOUD_EXPORT_DIR=str(case_dir))
            completed = subprocess.run(
                [str(executable)], env=env, capture_output=True, text=True, timeout=10
            )
            if name == "valid":
                passed = (
                    completed.returncode == 0
                    and completed.stdout.strip() == "Result: 208676"
                    and expected_log in completed.stderr
                )
            else:
                passed = (
                    completed.returncode != 0
                    and "Result:" not in completed.stdout
                    and "SHA256 verification PASSED" not in completed.stderr
                    and expected_log in completed.stderr
                )
            result = {
                "case": name,
                "passed": passed,
                "returncode": completed.returncode,
                "stdout": completed.stdout,
                "stderr": completed.stderr,
            }
            results.append(result)
            print(f"{name}: {'PASS' if passed else 'FAIL'} exit={completed.returncode}")
            if not passed:
                print(completed.stdout)
                print(completed.stderr)

    args.results.write_text(json.dumps(results, indent=2) + "\n")
    if not all(result["passed"] for result in results):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
