import fcntl
import os
import pathlib
import subprocess
import sys
import tempfile


def run(binary: pathlib.Path, arguments: list[str], state: pathlib.Path | None):
    environment = os.environ.copy()
    for name in (
        "XOVM_SQLITE_PATH",
        "XOVM_RELAY_TOKEN",
        "XOVM_ADMIN_TOKEN",
        "XOVM_SIGNING_KEY_PROVIDER",
        "XOVM_ANONYMOUS_POLICY_PROVIDER",
        "XOVM_TRUST_ROOT_PROVIDER",
    ):
        environment.pop(name, None)
    if state is None:
        environment.pop("XOVM_STATE_DIR", None)
    else:
        environment["XOVM_STATE_DIR"] = str(state)
    environment["XOVM_TRUSTED_TIME_PROVIDER"] = "fixture"
    return subprocess.run(
        [str(binary), *arguments],
        env=environment,
        text=True,
        capture_output=True,
        timeout=10,
        check=False,
    )


def main() -> int:
    binary = pathlib.Path(sys.argv[1]).resolve()

    syntax = run(binary, [], None)
    assert syntax.returncode == 2
    assert syntax.stdout == ""

    with tempfile.TemporaryDirectory(prefix="xovm-maintenance-process-") as root:
        state = pathlib.Path(root) / "state"
        missing = run(binary, ["reclaim-expired"], state)
        assert missing.returncode == 1
        assert missing.stdout == ""
        assert missing.stderr == "state maintenance failed: lock_state_dir_missing\n"
        assert not state.exists()

        state.mkdir(mode=0o700)
        success = run(binary, ["reclaim-expired"], state)
        assert success.returncode == 0
        assert success.stdout == (
            "records_retired=0 response_bytes_reclaimed=0 "
            "replies_compacted=0 raw_registrations_compacted=0 "
            "sessions_compacted=0 claims_compacted=0 "
            "sequence=0 more_work=false\n"
        )
        assert success.stderr == ""
        assert (state / ".xovm.lock").stat().st_mode & 0o777 == 0o600
        assert not (state / "checkpoint.bin").exists()
        assert not (state / "state.wal").exists()

        with (state / ".xovm.lock").open("r+") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            busy = run(binary, ["reclaim-expired"], state)
            assert busy.returncode == 1
            assert busy.stdout == ""
            assert busy.stderr == "state maintenance failed: lock_busy\n"

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
