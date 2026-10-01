import os
import subprocess


def run_helper(tmp_path, *args):
    output = tmp_path / "zone.rsp"
    helper = "zone_runtime/xollvm_zone_link.py"
    result = subprocess.run(
        ["python", helper, "--sdk-root", str(tmp_path), "--output", str(output), *args],
        text=True, capture_output=True,
    )
    return result, output


def test_no_marker_emits_empty_response_file(tmp_path):
    ordinary = tmp_path / "ordinary.o"
    ordinary.write_bytes(b"ordinary")
    result, output = run_helper(tmp_path, str(ordinary))
    assert result.returncode == 0, result.stderr
    assert output.read_text() == ""


def test_bundled_marker_selects_bundled_archive(tmp_path):
    marked = tmp_path / "marked.o"
    marked.write_bytes(b"xollvm-zone-v1;mode=bundled;triple=aarch64-unknown-linux-gnu\0")
    archive = tmp_path / "libzone.a"
    archive.write_bytes(b"")
    env = {**os.environ, "XOLLVM_ZONE_BUNDLED_ARCHIVE": str(archive)}
    result = subprocess.run(
        ["python", "zone_runtime/xollvm_zone_link.py", "--sdk-root", str(tmp_path),
         "--output", str(tmp_path / "zone.rsp"), "--target-triple",
         "aarch64-unknown-linux-gnu", str(marked)],
        env=env, text=True, capture_output=True,
    )
    output = tmp_path / "zone.rsp"
    assert result.returncode == 0, result.stderr
    assert str(archive) in output.read_text()


def test_bundled_marker_discovers_build_archive(tmp_path):
    marked = tmp_path / "marked.o"
    marked.write_bytes(b"xollvm-zone-v1;mode=bundled;triple=x\0")
    archive = tmp_path / "lib" / "libxollvm_zone_sdk.a"
    archive.parent.mkdir()
    archive.write_bytes(b"")
    result, output = run_helper(tmp_path, str(marked))
    assert result.returncode == 0, result.stderr
    assert str(archive) in output.read_text()


def test_conflicting_modes_fail(tmp_path):
    first = tmp_path / "first.o"
    second = tmp_path / "second.o"
    first.write_bytes(b"xollvm-zone-v1;mode=bundled;triple=x\0")
    second.write_bytes(b"xollvm-zone-v1;mode=external;triple=x\0")
    result, _ = run_helper(tmp_path, str(first), str(second))
    assert result.returncode == 2
    assert "conflicting" in result.stderr


def test_bundled_response_uses_private_archive_only(tmp_path):
    marked = tmp_path / "marked.o"
    marked.write_bytes(b"xollvm-zone-v1;mode=bundled;triple=x\0")
    archive = tmp_path / "zone_runtime" / "libxollvm_zone_sdk.a"
    archive.parent.mkdir()
    archive.write_bytes(b"")
    result, output = run_helper(tmp_path, str(marked))
    assert result.returncode == 0, result.stderr
    assert output.read_text().splitlines() == [str(archive)]


def test_no_marker_does_not_reference_zone_archives(tmp_path):
    ordinary = tmp_path / "ordinary.o"
    ordinary.write_bytes(b"ordinary")
    result, output = run_helper(tmp_path, str(ordinary))
    assert result.returncode == 0, result.stderr
    assert "xollvm_zone" not in output.read_text()
