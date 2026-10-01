"""Unit tests for validating structured VM witness reports."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from cases._runner import _vm_witness_error


class VMWitnessValidationTests(unittest.TestCase):
    def test_capability_material_is_not_embedded_in_vm_witness(self) -> None:
        root = Path(__file__).resolve().parents[1]
        zone = (root / "zone_runtime/zone_wrapper.cpp").read_text()
        auth = (root / "ZoneAuth.cpp").read_text()
        self.assertIn("xollvm_zone_capability_seed", zone)
        self.assertIn("xollvm_zone_capability_seed", auth)
        self.assertNotIn("K_server", auth)
        self.assertNotIn("SIGNING_PRIVATE_KEY", auth)

    def test_capability_build_flags_are_opt_in_and_non_secret(self) -> None:
        options = (Path(__file__).resolve().parents[1] / "ObfuscationOptions.cpp").read_text()
        self.assertIn('"obf-zone-capability-operation"', options)
        self.assertIn('"obf-zone-capability-public-key"', options)
        self.assertIn('"obf-zone-capability-build-id"', options)
        self.assertNotIn('"obf-zone-capability-k-server"', options)
        self.assertNotIn('"obf-zone-capability-private-key"', options)

    def test_capability_key_id_is_compiler_configured(self) -> None:
        root = Path(__file__).resolve().parents[1]
        options = (root / "ObfuscationOptions.cpp").read_text()
        options_header = (root / "include/llvm/Transforms/Obfuscator/ObfuscationOptions.h").read_text()
        zone_auth = (root / "ZoneAuth.cpp").read_text()
        zone_header = (root / "zone_runtime/zone_wrapper.h").read_text()
        demo_mk = (Path("/data/user/0/com.termux/files/home/demo/jni/Android.mk")).read_text()
        self.assertIn('"obf-zone-capability-key-id"', options)
        self.assertIn("ObfZoneCapabilityKeyId", options_header)
        self.assertIn("ObfZoneCapabilityKeyId", zone_auth)
        self.assertIn("capability_key_id", zone_header)
        self.assertIn("XOLLVM_ZONE_CAPABILITY_KEY_ID", demo_mk)

    def test_rejects_missing_report(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            missing = Path(temp_dir) / "obf_report.json"
            self.assertIn("missing", _vm_witness_error(missing, "obf_target"))

    def test_rejects_function_without_structured_vm_witness(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            report = Path(temp_dir) / "obf_report.json"
            report.write_text(json.dumps({"functions": [
                {"name": "obf_target", "passes": []},
            ]}), encoding="utf-8")
            self.assertIn("structured VM witness", _vm_witness_error(report, "obf_target"))

    def test_accepts_function_with_structured_vm_witness(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            report = Path(temp_dir) / "obf_report.json"
            report.write_text(json.dumps({"functions": [
                {"name": "obf_target", "vm": {"real_handlers": ["binop"]}},
            ]}), encoding="utf-8")
            self.assertIsNone(_vm_witness_error(report, "obf_target"))


if __name__ == "__main__":
    unittest.main()
