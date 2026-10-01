import pathlib

from zone_runtime import xollvm_zone_link


def test_dependencies_are_defined_independently():
    assert tuple(xollvm_zone_link.DEPENDENCIES) == ("curl", "zlib", "ssl", "crypto")
    assert xollvm_zone_link.DEPENDENCIES["curl"].private_prefix == "xollvm_zone_curl_"
    assert xollvm_zone_link.DEPENDENCIES["zlib"].private_prefix == "xollvm_zone_zlib_"


def test_link_arguments_only_mark_libraries_that_are_present(tmp_path):
    decisions = xollvm_zone_link.resolve_dependencies(
        ["-L", str(tmp_path), "-lcurl", "-lz"],
        "aarch64-unknown-linux-gnu",
        "bundled",
        tmp_path,
    )
    assert decisions["curl"].status == "add-private"
    assert decisions["zlib"].status == "add-private"
    assert decisions["ssl"].status == "absent"
    assert decisions["crypto"].status == "absent"


def test_explicit_library_with_missing_required_symbol_is_incompatible(tmp_path, monkeypatch):
    archive = tmp_path / "libcurl.a"
    archive.write_bytes(b"fixture")
    monkeypatch.setattr(
        xollvm_zone_link,
        "inspect_library",
        lambda path, spec, target: xollvm_zone_link.LibraryInspection(
            path=path,
            compatible=False,
            reason="missing required symbol curl_easy_perform",
        ),
    )
    decisions = xollvm_zone_link.resolve_dependencies(
        [str(archive)], "aarch64-unknown-linux-gnu", "bundled", tmp_path
    )
    assert decisions["curl"].status == "add-private"
    assert "missing required symbol" in decisions["curl"].reason
