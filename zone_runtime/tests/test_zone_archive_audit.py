import subprocess

from zone_runtime.zone_archive_audit import audit_archive
from zone_runtime.zone_prefix_archive import prefix_archive


def make_archive(tmp_path, source):
    cpp = tmp_path / "fixture.cpp"
    obj = tmp_path / "fixture.o"
    archive = tmp_path / "libfixture.a"
    cpp.write_text(source)
    subprocess.run(["clang++", "-c", str(cpp), "-o", str(obj)], check=True)
    subprocess.run(["ar", "rcs", str(archive), str(obj)], check=True)
    return archive


def test_audit_rejects_unprefixed_dependency_symbols(tmp_path):
    archive = make_archive(tmp_path, "extern \"C\" void curl_easy_init() {}\n")
    report = audit_archive(archive, "xollvm_zone_curl_", "aarch64-unknown-linux-gnu")
    assert "curl_easy_init" in report.defined_public
    assert report.unprefixed_private


def test_audit_accepts_prefixed_dependency_and_system_reference(tmp_path):
    archive = make_archive(
        tmp_path,
        'extern "C" void xollvm_zone_curl_easy_init() {}\n'
        'extern "C" int puts(const char*);\n'
        'extern "C" int call_puts(const char* s) { return puts(s); }\n',
    )
    report = audit_archive(archive, "xollvm_zone_curl_", "aarch64-unknown-linux-gnu")
    assert not report.unprefixed_private
    assert "puts" in report.undefined_external


def test_prefix_archive_rewrites_public_definition(tmp_path):
    source = make_archive(tmp_path, 'extern "C" void curl_easy_init() {}\n')
    output = tmp_path / "libprivate.a"
    prefix_archive(source, output, "xollvm_zone_curl_")
    report = audit_archive(output, "xollvm_zone_curl_", "aarch64-unknown-linux-gnu")
    assert not report.unprefixed_private
    assert "xollvm_zone_curl_curl_easy_init" in report.defined_public
