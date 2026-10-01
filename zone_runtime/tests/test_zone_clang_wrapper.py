import os
import pathlib
import subprocess


WRAPPER = pathlib.Path(__file__).resolve().parents[1] / "xollvm-zone-clang"


def test_wrapper_does_not_add_zone_for_plain_compile(tmp_path):
    source = tmp_path / "main.c"
    output = tmp_path / "main.o"
    source.write_text("int main(void) { return 0; }\n")
    result = subprocess.run(
        ["/data/data/com.termux/files/usr/bin/bash", str(WRAPPER), "-c", str(source), "-o", str(output)],
        env={**os.environ, "XOLLVM_REAL_CLANG": "false"},
        text=True, capture_output=True,
    )
    assert result.returncode != 0
    assert "libxollvm_zone" not in result.stderr


def test_wrapper_links_bundled_archive_without_python(tmp_path):
    marker = tmp_path / "marked.o"
    archive = tmp_path / "libxollvm_zone_sdk_private.a"
    fake_clang = tmp_path / "fake-clang"
    marker.write_bytes(b"xollvm-zone-v1;mode=bundled;triple=aarch64-none-linux-android23\0")
    archive.write_bytes(b"archive")
    fake_clang.write_text(
        "#!/bin/sh\n"
        "printf '%s\\n' \"$@\" > \"$XOLLVM_TEST_ARGS\"\n"
        "for arg in \"$@\"; do case \"$arg\" in @*) cat \"${arg#@}\" >> \"$XOLLVM_TEST_ARGS\" ;; esac; done\n"
    )
    fake_clang.chmod(0o755)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "grep").symlink_to("/data/data/com.termux/files/usr/bin/grep")
    (bin_dir / "cat").symlink_to("/data/data/com.termux/files/usr/bin/cat")
    env = {
        **os.environ,
        "XOLLVM_REAL_CLANG": str(fake_clang),
        "XOLLVM_ZONE_SDK_ROOT": str(tmp_path),
        "XOLLVM_ZONE_BUNDLED_ARCHIVE": str(archive),
        "XOLLVM_TEST_ARGS": str(tmp_path / "args"),
        "PATH": str(bin_dir),
    }
    result = subprocess.run(
        ["/data/data/com.termux/files/usr/bin/bash", str(WRAPPER), str(marker), "-o", str(tmp_path / "out")],
        env=env, text=True, capture_output=True,
    )
    assert result.returncode == 0, result.stderr
    assert "python3" not in result.stderr
    assert str(archive) in (tmp_path / "args").read_text()
