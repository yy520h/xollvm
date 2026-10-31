"""Task 6 immutable generations, shutdown and fork lifecycle."""

from test_cloud_material_lease import lease_fixture, lease_harness, lease_pair_fixture
from cloud_material_support import run_material_case


def test_publish_switches_new_calls_without_changing_pinned_call(lease_harness):
    result = run_material_case(lease_harness, "publish_while_pinned",
                               input_bytes=lease_pair_fixture())
    assert result["old_generation"] == "1"
    assert result["new_generation"] == "2"
    assert result["old_call_stayed_generation_one"] is True
    assert result["old_bytes_cleared_after_release"] is True


def test_publish_rejects_a_different_session_for_the_same_region(lease_harness):
    result = run_material_case(
        lease_harness, "publish_session_mismatch",
        input_bytes=lease_pair_fixture("lease_120", "lease_120_other_session"))
    assert result["replacement_accepted"] is False
    assert result["current_generation"] == "1"


def test_publish_rejects_a_generation_rollback(lease_harness):
    result = run_material_case(
        lease_harness, "publish_generation_rollback",
        input_bytes=lease_pair_fixture("lease_120_gen2", "lease_120"))
    assert result["replacement_accepted"] is False
    assert result["current_generation"] == "2"


def test_recursive_entry_cannot_inherit_expired_pin(lease_harness):
    result = run_material_case(lease_harness, "recursive_expired",
                               input_bytes=lease_fixture("lease_120"))
    assert result["outer_call_completed"] is True
    assert result["recursive_acquired"] is False


def test_idle_expiry_is_passive_and_shutdown_blocks_new_acquire(lease_harness):
    result = run_material_case(lease_harness, "shutdown",
                               input_bytes=lease_fixture("lease_120"))
    assert result["idle_expiry_faulted"] is False
    assert result["pinned_call_completed"] is True
    assert result["new_call_acquired"] is False
    assert result["bytes_cleared_after_release"] is True


def test_forked_child_rejects_inherited_store_without_touching_lock(lease_harness):
    result = run_material_case(lease_harness, "fork_rejected",
                               input_bytes=lease_fixture("lease_120"))
    assert result["child_rejected"] is True
    assert result["child_exit_status"] == 0
    assert result["parent_still_acquired"] is True
