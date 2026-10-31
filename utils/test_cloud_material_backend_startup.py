import os
import socket
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def main():
    executable = Path(sys.argv[1])
    migration = executable.parent.parent.parent / "runtime" / "cloud_material_backend" / "migrations" / "001_build_registry.sql"
    with tempfile.TemporaryDirectory(prefix="xovm-backend-startup-") as temporary:
        root = Path(temporary)
        database = root / "registry.sqlite"
        state = root / "state"
        state.mkdir()
        with sqlite3.connect(database) as connection:
            connection.executescript(migration.read_text())
        port = free_port()
        environment = os.environ.copy()
        environment.update({
            "XOVM_SQLITE_PATH": str(database),
            "XOVM_STATE_DIR": str(state),
            "XOVM_RELAY_TOKEN": "r" * 32,
            "XOVM_ADMIN_TOKEN": "a" * 32,
            "XOVM_TRUSTED_TIME_PROVIDER": "missing.clock",
            "XOVM_SIGNING_KEY_PROVIDER": "missing.signer",
            "XOVM_ANONYMOUS_POLICY_PROVIDER": "missing.policy",
            "XOVM_TRUST_ROOT_PROVIDER": "missing.trust",
            "PORT": str(port),
        })
        result = subprocess.run(
            [str(executable)],
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
        )
        assert result.returncode == 1, (result.returncode, result.stderr)
        assert "provider_unavailable" in result.stderr, result.stderr
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.settimeout(0.2)
            assert probe.connect_ex(("127.0.0.1", port)) != 0


if __name__ == "__main__":
    main()
