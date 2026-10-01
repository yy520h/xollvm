import os
import subprocess


def test_external_mode_requires_each_declared_dependency(tmp_path):
    marked = tmp_path / "marked.o"
    marked.write_bytes(b"xollvm-zone-v1;mode=external;triple=aarch64-unknown-linux-gnu\0")
    result = subprocess.run(
        ["python", "zone_runtime/xollvm_zone_link.py", "--sdk-root", str(tmp_path),
         "--output", str(tmp_path / "zone.rsp"), "--target-triple",
         "aarch64-unknown-linux-gnu", "--link-arg=-lcurl", str(marked)],
        text=True, capture_output=True,
    )
    assert result.returncode == 2
    assert "curl" in result.stderr


def test_external_mode_requires_all_explicit_archive_paths(tmp_path):
    marked = tmp_path / "marked.o"
    marked.write_bytes(b"xollvm-zone-v1;mode=external;triple=x\0")
    archives = {}
    env = dict(os.environ)
    for name in ("CURL", "ZLIB", "SSL", "CRYPTO"):
        archive = tmp_path / f"lib{name.lower()}.a"
        archive.write_bytes(b"")
        archives[name] = archive
        env[f"XOLLVM_ZONE_EXTERNAL_{name}"] = str(archive)
    result = subprocess.run(
        ["python", "zone_runtime/xollvm_zone_link.py", "--sdk-root", str(tmp_path),
         "--output", str(tmp_path / "zone.rsp"), "--link-arg=-lcurl", str(marked)],
        env=env, text=True, capture_output=True,
    )
    assert result.returncode == 0, result.stderr
    assert {str(path) for path in archives.values()} == set(
        (tmp_path / "zone.rsp").read_text().splitlines())


def test_bundled_and_external_configuration_conflict(tmp_path):
    marked = tmp_path / "marked.o"
    marked.write_bytes(b"xollvm-zone-v1;mode=bundled;triple=x\0")
    result = subprocess.run(
        ["python", "zone_runtime/xollvm_zone_link.py", "--sdk-root", str(tmp_path),
         "--output", str(tmp_path / "zone.rsp"), "--link-arg=-lcurl", str(marked)],
        env={**os.environ, "XOLLVM_ZONE_EXTERNAL_CURL": str(tmp_path / "libcurl.a")},
        text=True, capture_output=True,
    )
    assert result.returncode == 2
    assert "bundled" in result.stderr or "external" in result.stderr
