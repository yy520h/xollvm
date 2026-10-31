"""Task 6 monotonic lease boundaries and original-request timing."""

import json
import subprocess
from pathlib import Path

import pytest

from cloud_material_support import build_material_harness, run_material_case

REPO = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="session")
def lease_harness(tmp_path_factory):
    return build_material_harness(
        tmp_path_factory.mktemp("cloud-material-lease"),
        defines=("XOVM_MATERIAL_STORE_TESTING=1",),
        sources=("material_protocol.cpp", "material_store.cpp", "material_runtime.cpp"))


def lease_fixture(case):
    return subprocess.run([
        "node", REPO / "cloud/material_v2/test/protocol.test.mjs",
        "--native-fixture", case,
    ], capture_output=True, check=True, timeout=30).stdout


def lease_pair_fixture(first_case="lease_120", second_case="lease_120_gen2"):
    first = json.loads(lease_fixture(first_case))
    second = json.loads(lease_fixture(second_case))
    return json.dumps({"first": first, "second": second},
                      separators=(",", ":")).encode()


def test_expiry_blocks_new_call_but_preserves_pinned_call(lease_harness):
    result = run_material_case(lease_harness,
                               "pin_at_119_expire_at_120",
                               input_bytes=lease_fixture("lease_120"))
    assert result["old_call_completed"] is True
    assert result["new_call_acquired"] is False
    assert result["old_bytes_live_until_release"] is True
    assert result["old_bytes_cleared_after_release"] is True


def test_late_retry_response_is_rejected_at_original_deadline(lease_harness):
    result = run_material_case(lease_harness, "late_response",
                               input_bytes=lease_fixture("late_response"))
    assert result["accepted"] is False
    assert result["code"] == "expired_response"


def test_retry_cannot_refresh_authenticated_request_timing(lease_harness):
    result = run_material_case(lease_harness, "timing_mismatch",
                               input_bytes=lease_fixture("lease_120"))
    assert result["accepted_after_deadline"] is False


def test_short_lease_renews_ten_seconds_before_expiry(lease_harness):
    result = run_material_case(lease_harness, "short_lease",
                               input_bytes=lease_fixture("short_lease"))
    assert result["deadline_ns"] == result["sent_ns"] + 45_000_000_000
    assert result["renew_at_ns"] == result["sent_ns"] + 35_000_000_000
    assert result["ten_second_lease_renews_immediately"] is False


def test_ten_second_lease_renews_at_original_send_time(lease_harness):
    result = run_material_case(lease_harness, "ten_second_lease",
                               input_bytes=lease_fixture("lease_10"))
    assert result["deadline_ns"] == result["sent_ns"] + 10_000_000_000
    assert result["renew_at_ns"] == result["sent_ns"]


def test_session_material_has_no_lease_deadline(lease_harness):
    result = run_material_case(lease_harness, "session_material",
                               input_bytes=lease_fixture("session_material"))
    assert result["acquired_after_lease_horizon"] is True
    assert result["has_deadline"] is False
