import subprocess


def test_audit_cli_rejects_unprefixed_private_symbols(tmp_path):
    source = tmp_path / "bad.cpp"
    obj = tmp_path / "bad.o"
    archive = tmp_path / "libbad.a"
    source.write_text('extern "C" void SSL_CTX_new() {}\n')
    subprocess.run(["clang++", "-c", str(source), "-o", str(obj)], check=True)
    subprocess.run(["ar", "rcs", str(archive), str(obj)], check=True)
    result = subprocess.run(
        ["python", "zone_runtime/zone_archive_audit.py", "--prefix", "xollvm_zone_",
         str(archive)], text=True, capture_output=True,
    )
    assert result.returncode != 0
    assert "SSL_CTX_new" in result.stderr
