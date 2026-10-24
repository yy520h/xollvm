"""Task 3B public-manifest ELF finalization tests."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import struct
import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest

from vm_hardening_support import tools


REPO = Path(__file__).resolve().parents[1]
MATERIAL_NAME = ".rodata.xovm.material"
RECORD_SIZE = 120
DT_ANDROID_RELA = 0x60000011
DT_ANDROID_RELASZ = 0x60000012
REGIONS = [
    {
        "region_id": "11" * 32,
        "region_content_hash": "21" * 32,
        "region_name": "auth/session",
        "mode": "session",
        "engine_abi_hash": "31" * 32,
        "call_abi_hash": "41" * 32,
        "layout_hash": "51" * 32,
    },
    {
        "region_id": "12" * 32,
        "region_content_hash": "22" * 32,
        "region_name": "pay:lease",
        "mode": "lease",
        "engine_abi_hash": "32" * 32,
        "call_abi_hash": "42" * 32,
        "layout_hash": "52" * 32,
    },
]


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("ascii")


def framed_hash(label: str, payload: bytes) -> str:
    framed = label.encode("ascii") + b"\0" + struct.pack(">I", len(payload)) + payload
    return hashlib.sha256(framed).hexdigest()


def public_manifest(regions=None, **core_changes):
    core = {
        "format_version": 1,
        "protocol_version": 2,
        "vm_format_version": 1,
        "target_triple": "aarch64-linux-android26",
        "software_id": "fixture.software",
        "regions": list(REGIONS if regions is None else regions),
    }
    core.update(core_changes)
    build_id = framed_hash("XOVM2/build-id", canonical(core))
    return {**core, "build_id": build_id}


def _hex_initializer(value: str) -> str:
    return ",".join(f"0x{value[index:index + 2]}" for index in range(0, 64, 2))


def _record_initializer(region) -> str:
    mode = {"session": 1, "lease": 2, "operation": 3}[region["mode"]]
    return """{
      {'X','O','V','M','M','A','T',0}, 1, 16, 120,
      {1, %d, {0}, {%s}, {%s}}
    }""" % (mode, _hex_initializer(region["region_id"]),
              _hex_initializer(region["engine_abi_hash"]))


def _sections(data: bytes | bytearray):
    assert data[:6] == b"\x7fELF\x02\x01"
    shoff = struct.unpack_from("<Q", data, 40)[0]
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 58)
    assert shoff and shentsize == 64 and 0 < shstrndx < shnum
    headers = []
    for index in range(shnum):
        offset = shoff + index * shentsize
        values = struct.unpack_from("<IIQQQQIIQQ", data, offset)
        headers.append({
            "index": index, "header_offset": offset, "name_offset": values[0],
            "type": values[1], "flags": values[2], "address": values[3],
            "offset": values[4], "size": values[5],
        })
    strings_header = headers[shstrndx]
    strings = data[strings_header["offset"]:
                   strings_header["offset"] + strings_header["size"]]
    for header in headers:
        start = header["name_offset"]
        end = strings.find(b"\0", start)
        assert 0 <= start < len(strings) and end >= start
        header["name"] = strings[start:end].decode("ascii")
    return headers


def _program_headers(data: bytes | bytearray):
    phoff = struct.unpack_from("<Q", data, 32)[0]
    phentsize, phnum = struct.unpack_from("<HH", data, 54)
    assert phoff and phentsize == 56 and phnum
    headers = []
    for index in range(phnum):
        offset = phoff + index * phentsize
        values = struct.unpack_from("<IIQQQQQQ", data, offset)
        headers.append({
            "index": index, "header_offset": offset, "type": values[0],
            "flags": values[1], "offset": values[2], "address": values[3],
            "file_size": values[5], "memory_size": values[6],
        })
    return headers


def _material_section(data: bytes | bytearray):
    matches = [section for section in _sections(data)
               if section["name"] == MATERIAL_NAME]
    assert len(matches) == 1
    return matches[0]


def _named_section(data: bytes | bytearray, name: str):
    return next(section for section in _sections(data) if section["name"] == name)


def _dynamic_segment(data: bytes | bytearray):
    return next(header for header in _program_headers(data) if header["type"] == 2)


def _write_dynamic(data: bytearray, entries):
    dynamic = _dynamic_segment(data)
    assert (len(entries) + 1) * 16 <= dynamic["file_size"]
    start = dynamic["offset"]
    data[start:start + dynamic["file_size"]] = bytes(dynamic["file_size"])
    for index, (tag, value) in enumerate(entries):
        struct.pack_into("<QQ", data, start + index * 16, tag, value)


def _dynamic_tags(data: bytes | bytearray):
    dynamic = _dynamic_segment(data)
    result = {}
    for offset in range(dynamic["offset"],
                        dynamic["offset"] + dynamic["file_size"], 16):
        tag, value = struct.unpack_from("<QQ", data, offset)
        if tag == 0:
            break
        result[tag] = value
    return result


def _sleb(value: int) -> bytes:
    result = bytearray()
    while True:
        byte = value & 0x7f
        value >>= 7
        done = ((value == 0 and not byte & 0x40) or
                (value == -1 and byte & 0x40))
        result.append(byte if done else byte | 0x80)
        if done:
            return bytes(result)


def _install_android_rela(data: bytearray, target: int, *, truncate=False):
    storage = _named_section(data, ".eh_frame")
    packed = (b"APS2" + _sleb(1) + _sleb(0) + _sleb(1) + _sleb(8) +
              _sleb(target) + _sleb(0x403) + _sleb(0))
    if truncate:
        packed = packed[:-1] + b"\x80"
    assert len(packed) <= storage["size"]
    data[storage["offset"]:storage["offset"] + len(packed)] = packed
    _write_dynamic(data, [
        (DT_ANDROID_RELA, storage["address"]),
        (DT_ANDROID_RELASZ, len(packed)),
    ])


def _install_dynamic_relocation(data: bytearray, target: int, *, rela: bool):
    storage = _named_section(data, ".eh_frame")
    if rela:
        struct.pack_into("<QQq", data, storage["offset"], target, 0x403, 0)
        _write_dynamic(data, [(7, storage["address"]), (8, 24), (9, 24)])
    else:
        struct.pack_into("<QQ", data, storage["offset"], target, 0x403)
        _write_dynamic(data, [(17, storage["address"]), (18, 16), (19, 16)])


def read_descriptors(path: Path):
    data = path.read_bytes()
    section = _material_section(data)
    assert section["size"] % RECORD_SIZE == 0
    result = []
    for relative in range(0, section["size"], RECORD_SIZE):
        offset = section["offset"] + relative
        result.append({
            "magic": data[offset:offset + 8],
            "version": struct.unpack_from("<H", data, offset + 8)[0],
            "header_size": struct.unpack_from("<H", data, offset + 10)[0],
            "record_size": struct.unpack_from("<I", data, offset + 12)[0],
            "abi_version": struct.unpack_from("<I", data, offset + 16)[0],
            "mode": struct.unpack_from("<I", data, offset + 20)[0],
            "build_id": data[offset + 24:offset + 56].hex(),
            "region_id": data[offset + 56:offset + 88].hex(),
            "engine_abi_hash": data[offset + 88:offset + 120].hex(),
        })
    return result


@pytest.fixture(scope="module")
def compiled_material_elf(tmp_path_factory):
    work = tmp_path_factory.mktemp("material-elf")
    assert stat.S_IMODE(work.stat().st_mode) == 0o700
    source = work / "fixture.c"
    # Reverse record order deliberately: equality is by descriptor set, not ELF order.
    source.write_text("""
#include "runtime/cloud_material/material_abi.h"
__attribute__((used, visibility("default"), section(".xovm_material"), aligned(1)))
const XovmMaterialRecord material_records[] = {
%s,
%s
};
extern int fixture_external(int);
__attribute__((visibility("default")))
int (*fixture_pointer)(int) = fixture_external;
__attribute__((visibility("default"))) int fixture_entry(void) {
  return fixture_pointer(7) + fixture_external(1);
}
    """ % (_record_initializer(REGIONS[1]), _record_initializer(REGIONS[0])))
    linked = work / "linked.so"
    elf = work / "fixture.so"
    t = tools()
    command = [
        t.clang, "--target=aarch64-linux-android26", f"--sysroot={t.sysroot}",
        "-std=c11", "-fPIC", "-nostdlib", "-shared", "-Wl,--build-id=none",
        "-Wl,--rosegment", "-I", REPO, source, "-o", linked,
    ]
    built = subprocess.run([str(arg) for arg in command], capture_output=True,
                           text=True, timeout=120)
    assert built.returncode == 0, built.stdout + built.stderr
    objcopy = t.clang.parent / "llvm-objcopy"
    renamed = subprocess.run([
        str(objcopy), "--rename-section",
        f".xovm_material={MATERIAL_NAME},alloc,load,readonly,data,contents",
        str(linked), str(elf),
    ], capture_output=True, text=True, timeout=60)
    assert renamed.returncode == 0, renamed.stdout + renamed.stderr
    readelf = t.clang.parent / "llvm-readelf"
    inspected = subprocess.run([str(readelf), "-SW", str(elf)], capture_output=True,
                               text=True, timeout=60)
    assert inspected.returncode == 0, inspected.stdout + inspected.stderr
    assert MATERIAL_NAME in inspected.stdout
    data = elf.read_bytes()
    assert struct.unpack_from("<H", data, 16)[0] == 3
    assert struct.unpack_from("<H", data, 18)[0] == 183
    assert _material_section(data)["size"] == 2 * RECORD_SIZE
    tags = _dynamic_tags(data)
    assert DT_ANDROID_RELA in tags and DT_ANDROID_RELASZ in tags
    assert tags[23] and tags[2] and tags[20] == 7
    return data


@dataclass
class ManifestFixture:
    work: Path
    original: bytes
    counter: int = 0

    def __post_init__(self):
        self.input = self.work / "input.so"
        self.input.write_bytes(self.original)
        self.input.chmod(0o751)
        self.output = self.work / "output.so"
        self.correct = public_manifest()
        self.expected_build_id = self.correct["build_id"]
        wrong = [dict(region) for region in REGIONS]
        wrong[0]["region_id"] = "10" * 32
        self.wrong_region_manifest = canonical(public_manifest(wrong))
        self.correct_manifest = canonical(self.correct)

    def finalize(self, manifest, *, input_path=None, output_name="output.so",
                 env=None):
        self.counter += 1
        manifest_path = self.work / f"manifest-{self.counter}.json"
        manifest_path.write_bytes(manifest if isinstance(manifest, bytes)
                                  else canonical(manifest))
        self.output = self.work / output_name
        return subprocess.run([
            str(tools().hardener), "materials", "--input",
            str(input_path or self.input), "--manifest", str(manifest_path),
            "--output", str(self.output),
        ], capture_output=True, text=True, timeout=60,
            env={**os.environ, **(env or {})})

    def read_descriptor(self, index=0):
        return read_descriptors(self.output)[index]

    def mutated_input(self, mutate, name="mutated.so"):
        data = bytearray(self.original)
        mutate(data)
        path = self.work / name
        path.write_bytes(data)
        path.chmod(0o751)
        return path


@pytest.fixture
def manifest_fixture(tmp_path, compiled_material_elf):
    return ManifestFixture(tmp_path, compiled_material_elf)


def assert_rejected_without_output(fixture, manifest, diagnostic, *,
                                   input_path=None, output_name="output.so"):
    result = fixture.finalize(manifest, input_path=input_path,
                              output_name=output_name)
    assert result.returncode != 0, result.stdout + result.stderr
    assert not fixture.output.exists()
    assert len(result.stderr) < 1024
    assert f"materials: {diagnostic}" in result.stderr
    assert "materials: output_" not in result.stderr


def test_material_descriptor_requires_matching_public_region(manifest_fixture):
    fixture = manifest_fixture
    rejected = fixture.finalize(fixture.wrong_region_manifest)
    assert rejected.returncode != 0
    assert "materials: descriptor_set_mismatch" in rejected.stderr
    assert fixture.output.exists() is False
    accepted = fixture.finalize(fixture.correct_manifest)
    assert accepted.returncode == 0, accepted.stdout + accepted.stderr
    assert fixture.read_descriptor()["build_id"] == fixture.expected_build_id


def test_real_fixture_and_independent_parser_cover_exact_record_layout(manifest_fixture):
    records = read_descriptors(manifest_fixture.input)
    assert [record["region_id"] for record in records] == ["12" * 32, "11" * 32]
    assert all(record["magic"] == b"XOVMMAT\0" for record in records)
    assert all(record["version"] == 1 and record["header_size"] == 16
               and record["record_size"] == 120 and record["abi_version"] == 1
               and record["build_id"] == "00" * 32 for record in records)


def _invalid_manifest_cases():
    base = public_manifest()
    missing = dict(base)
    del missing["software_id"]
    unknown = {**base, "unexpected": 1}
    private = json.loads(json.dumps(base))
    private["regions"][0]["canonical_bc"] = "AA=="
    duplicate = canonical(base)
    duplicate = b'{"build_id":"' + base["build_id"].encode() + b'",' + duplicate[1:]
    noncanonical = json.dumps(base, sort_keys=True).encode("ascii")
    float_u32 = canonical(base).replace(b'"format_version":1',
                                        b'"format_version":1.0')
    unicode_name = json.loads(json.dumps(base))
    unicode_name["regions"][0]["region_name"] = "auth-\u4e2d"
    return [
        pytest.param(canonical(missing), id="missing-key"),
        pytest.param(canonical(unknown), id="unknown-key"),
        pytest.param(canonical(private), id="private-field"),
        pytest.param(duplicate, id="duplicate-key"),
        pytest.param(noncanonical, id="whitespace"),
        pytest.param(canonical(base) + b"\n", id="trailing-newline"),
        pytest.param(float_u32, id="non-u32"),
        pytest.param(canonical(unicode_name), id="non-ascii"),
    ]


@pytest.mark.parametrize("manifest", _invalid_manifest_cases())
def test_rejects_noncanonical_or_nonpublic_manifest(manifest_fixture, manifest):
    assert_rejected_without_output(manifest_fixture, manifest,
                                   "invalid_public_manifest")


def _descriptor_mismatch_cases():
    wrong_mode = [dict(region) for region in REGIONS]
    wrong_mode[0]["mode"] = "lease"
    wrong_engine = [dict(region) for region in REGIONS]
    wrong_engine[1]["engine_abi_hash"] = "39" * 32
    extra = [*REGIONS, {
        "region_id": "13" * 32, "region_content_hash": "23" * 32,
        "region_name": "extra", "mode": "session",
        "engine_abi_hash": "33" * 32, "call_abi_hash": "43" * 32,
        "layout_hash": "53" * 32,
    }]
    duplicate = [dict(REGIONS[0]), dict(REGIONS[0])]
    return [
        pytest.param(public_manifest(wrong_mode), "descriptor_set_mismatch", id="mode"),
        pytest.param(public_manifest(wrong_engine), "descriptor_set_mismatch", id="engine-abi"),
        pytest.param(public_manifest(REGIONS[:1]), "descriptor_set_mismatch", id="missing-region"),
        pytest.param(public_manifest(extra), "descriptor_set_mismatch", id="extra-region"),
        pytest.param(public_manifest(duplicate), "invalid_public_manifest", id="duplicate-region"),
        pytest.param(public_manifest(list(reversed(REGIONS))), "invalid_public_manifest", id="unsorted-region"),
    ]


@pytest.mark.parametrize("manifest,diagnostic", _descriptor_mismatch_cases())
def test_descriptor_set_must_exactly_equal_manifest(manifest_fixture, manifest,
                                                    diagnostic):
    assert_rejected_without_output(manifest_fixture, manifest, diagnostic)


def test_rejects_manifest_build_digest_tamper(manifest_fixture):
    manifest = public_manifest()
    manifest["build_id"] = "f0" + manifest["build_id"][2:]
    assert_rejected_without_output(manifest_fixture, manifest,
                                   "invalid_public_manifest")


@pytest.mark.parametrize("relative,value,diagnostic", [
    (0, b"BADMAGIC", "invalid_material_record_header"),
    (8, struct.pack("<H", 2), "invalid_material_record_header"),
    (10, struct.pack("<H", 15), "invalid_material_record_header"),
    (12, struct.pack("<I", 119), "invalid_material_record_header"),
    (16, struct.pack("<I", 2), "invalid_material_record_header"),
    (20, struct.pack("<I", 0), "invalid_material_record_mode"),
    (56, bytes.fromhex("19" * 32), "descriptor_set_mismatch"),
    (88, bytes.fromhex("39" * 32), "descriptor_set_mismatch"),
])
def test_rejects_malformed_or_mismatched_record(manifest_fixture, relative, value,
                                                diagnostic):
    section = _material_section(manifest_fixture.original)
    path = manifest_fixture.mutated_input(
        lambda data: data.__setitem__(slice(section["offset"] + relative,
                                            section["offset"] + relative + len(value)),
                                      value),
        f"record-{relative}.so")
    assert_rejected_without_output(manifest_fixture, manifest_fixture.correct_manifest,
                                   diagnostic, input_path=path)


def test_rejects_duplicate_record_region(manifest_fixture):
    section = _material_section(manifest_fixture.original)
    first_region = manifest_fixture.original[section["offset"] + 56:
                                             section["offset"] + 88]
    path = manifest_fixture.mutated_input(
        lambda data: data.__setitem__(
            slice(section["offset"] + RECORD_SIZE + 56,
                  section["offset"] + RECORD_SIZE + 88), first_region),
        "duplicate-record.so")
    assert_rejected_without_output(manifest_fixture, manifest_fixture.correct_manifest,
                                   "duplicate_material_record", input_path=path)


def _set_build_ids(data: bytearray, values):
    section = _material_section(data)
    for index, value in enumerate(values):
        start = section["offset"] + index * RECORD_SIZE + 24
        data[start:start + 32] = value


@pytest.mark.parametrize("values,diagnostic", [
    ([b"\x01" + bytes(31), bytes(32)], "invalid_material_build_id"),
    ([bytes.fromhex(public_manifest()["build_id"]), bytes(32)],
     "mixed_material_build_ids"),
    ([bytes.fromhex("aa" * 32), bytes.fromhex("aa" * 32)],
     "invalid_material_build_id"),
])
def test_rejects_partial_mixed_or_other_build_ids(manifest_fixture, values,
                                                  diagnostic):
    path = manifest_fixture.mutated_input(
        lambda data: _set_build_ids(data, values), "bad-build-state.so")
    assert_rejected_without_output(manifest_fixture, manifest_fixture.correct_manifest,
                                   diagnostic, input_path=path)


def test_same_build_id_is_idempotent_and_only_build_bytes_change(manifest_fixture):
    first = manifest_fixture.finalize(manifest_fixture.correct_manifest,
                                      output_name="first.so")
    assert first.returncode == 0, first.stdout + first.stderr
    first_path = manifest_fixture.output
    before = manifest_fixture.original
    after = first_path.read_bytes()
    section = _material_section(before)
    changed = set()
    for index, (old, new) in enumerate(zip(before, after)):
        if old != new:
            changed.add(index)
    allowed = set()
    for record in range(2):
        start = section["offset"] + record * RECORD_SIZE + 24
        allowed.update(range(start, start + 32))
    assert changed and changed <= allowed

    second = manifest_fixture.finalize(manifest_fixture.correct_manifest,
                                       input_path=first_path,
                                       output_name="second.so")
    assert second.returncode == 0, second.stderr
    assert manifest_fixture.output.read_bytes() == after


def test_output_is_no_replace_and_preserves_input_permissions(manifest_fixture):
    collision = manifest_fixture.work / "collision.so"
    collision.write_bytes(b"existing")
    result = manifest_fixture.finalize(manifest_fixture.correct_manifest,
                                       output_name=collision.name)
    assert result.returncode != 0
    assert "materials: output_exists" in result.stderr
    assert collision.read_bytes() == b"existing"

    accepted = manifest_fixture.finalize(manifest_fixture.correct_manifest,
                                         output_name="permission.so")
    assert accepted.returncode == 0, accepted.stdout + accepted.stderr
    assert stat.S_IMODE(manifest_fixture.output.stat().st_mode) == 0o751
    assert not list(manifest_fixture.work.glob(".xollvm-material-*.tmp"))


def test_output_strips_unsafe_write_and_special_permission_bits(manifest_fixture):
    manifest_fixture.input.chmod(0o7777)
    assert stat.S_IMODE(manifest_fixture.input.stat().st_mode) == 0o7777
    accepted = manifest_fixture.finalize(manifest_fixture.correct_manifest,
                                         output_name="safe-permissions.so",
                                         env={"XOVM_TEST_MATERIAL_PUBLISH_FAULT":
                                              "require_safe_stage_mode"})
    assert accepted.returncode == 0, accepted.stdout + accepted.stderr
    assert stat.S_IMODE(manifest_fixture.output.stat().st_mode) == 0o755


def test_same_inode_content_mutation_is_rejected_without_output(manifest_fixture):
    manifest_fixture.input.chmod(0o777)
    result = manifest_fixture.finalize(
        manifest_fixture.correct_manifest, output_name="content-race-safe.so",
        env={"XOVM_TEST_MATERIAL_PUBLISH_FAULT": "mutate_stage_content"})
    assert result.returncode != 0
    assert "materials: output_precommit_failed" in result.stderr
    assert not manifest_fixture.output.exists()
    assert not list(manifest_fixture.work.glob(".xollvm-material-*.tmp"))


def test_named_staging_substitution_is_rejected_without_output(manifest_fixture):
    result = manifest_fixture.finalize(
        manifest_fixture.correct_manifest, output_name="race-safe.so",
        env={"XOVM_TEST_MATERIAL_PUBLISH_FAULT": "substitute_stage"})
    assert result.returncode != 0
    assert "materials: output_precommit_failed" in result.stderr
    assert not manifest_fixture.output.exists()
    stages = list(manifest_fixture.work.glob(".xollvm-material-*.tmp"))
    assert len(stages) == 1 and stages[0].read_bytes() == b"substituted"


@pytest.mark.parametrize("mode", [0o720, 0o702], ids=["group", "other"])
def test_publication_rejects_group_or_other_writable_parent(manifest_fixture,
                                                            mode):
    manifest_fixture.work.chmod(mode)
    try:
        result = manifest_fixture.finalize(manifest_fixture.correct_manifest,
                                           output_name="writable-parent.so")
        assert result.returncode != 0
        assert "materials: output_parent_untrusted" in result.stderr
        assert not manifest_fixture.output.exists()
    finally:
        manifest_fixture.work.chmod(0o700)


def test_postcommit_parent_sync_uncertainty_is_distinct(manifest_fixture):
    result = manifest_fixture.finalize(
        manifest_fixture.correct_manifest, output_name="committed-uncertain.so",
        env={"XOVM_TEST_MATERIAL_PUBLISH_FAULT": "after_rename_sync"})
    assert result.returncode != 0
    assert "materials: output_committed_sync_failed" in result.stderr
    assert manifest_fixture.output.exists()
    assert manifest_fixture.read_descriptor()["build_id"] == \
        manifest_fixture.expected_build_id


def test_precommit_failure_leaves_no_output(manifest_fixture):
    result = manifest_fixture.finalize(
        manifest_fixture.correct_manifest, output_name="precommit-failure.so",
        env={"XOVM_TEST_MATERIAL_PUBLISH_FAULT": "before_rename"})
    assert result.returncode != 0
    assert "materials: output_precommit_failed" in result.stderr
    assert not manifest_fixture.output.exists()


def test_existing_input_cannot_be_used_as_output(manifest_fixture):
    before = manifest_fixture.input.read_bytes()
    result = manifest_fixture.finalize(manifest_fixture.correct_manifest,
                                       output_name=manifest_fixture.input.name)
    assert result.returncode != 0
    assert "materials: output_exists" in result.stderr
    assert manifest_fixture.input.read_bytes() == before


@pytest.mark.parametrize("offset,value", [
    (4, b"\x01"),
    (5, b"\x02"),
    (6, b"\x00"),
    (16, struct.pack("<H", 1)),
    (18, struct.pack("<H", 62)),
    (20, struct.pack("<I", 0)),
    (52, struct.pack("<H", 63)),
])
def test_rejects_wrong_elf_kind_without_output(manifest_fixture, offset, value):
    path = manifest_fixture.mutated_input(
        lambda data: data.__setitem__(slice(offset, offset + len(value)), value),
        f"elf-kind-{offset}.so")
    assert_rejected_without_output(manifest_fixture, manifest_fixture.correct_manifest,
                                   input_path=path, diagnostic="unsupported_elf")


def test_rejects_stripped_or_missing_material_section(manifest_fixture):
    def strip_sections(data):
        struct.pack_into("<Q", data, 40, 0)
        struct.pack_into("<H", data, 60, 0)
        struct.pack_into("<H", data, 62, 0)

    stripped = manifest_fixture.mutated_input(strip_sections, "stripped.so")
    assert_rejected_without_output(manifest_fixture, manifest_fixture.correct_manifest,
                                   "malformed_elf_tables", input_path=stripped)

    section = _material_section(manifest_fixture.original)
    missing = manifest_fixture.mutated_input(
        lambda data: struct.pack_into("<I", data, section["header_offset"], 0),
        "missing.so")
    assert_rejected_without_output(manifest_fixture, manifest_fixture.correct_manifest,
                                   "missing_material_section", input_path=missing,
                                   output_name="missing-output.so")


def test_rejects_multiple_material_sections(manifest_fixture):
    sections = _sections(manifest_fixture.original)
    material = _material_section(manifest_fixture.original)
    other = next(section for section in sections
                 if section["index"] and section["name"] not in
                 (MATERIAL_NAME, ".shstrtab"))
    duplicate = manifest_fixture.mutated_input(
        lambda data: struct.pack_into("<I", data, other["header_offset"],
                                      material["name_offset"]),
        "multiple.so")
    assert_rejected_without_output(manifest_fixture, manifest_fixture.correct_manifest,
                                   "multiple_material_sections", input_path=duplicate)


def test_rejects_material_section_out_of_bounds_or_overlap(manifest_fixture):
    material = _material_section(manifest_fixture.original)
    out_of_bounds = manifest_fixture.mutated_input(
        lambda data: struct.pack_into("<Q", data,
                                      material["header_offset"] + 24,
                                      len(data) - 8),
        "out-of-bounds.so")
    assert_rejected_without_output(manifest_fixture, manifest_fixture.correct_manifest,
                                   "malformed_elf_section", input_path=out_of_bounds)

    sections = _sections(manifest_fixture.original)
    other = next(section for section in sections
                 if section["index"] and section["type"] not in (0, 8)
                 and section["size"] and section["name"] != MATERIAL_NAME)

    def overlap(data):
        struct.pack_into("<Q", data, other["header_offset"] + 24,
                         material["offset"])
        struct.pack_into("<Q", data, other["header_offset"] + 32, 1)

    overlapping = manifest_fixture.mutated_input(overlap, "overlap.so")
    assert_rejected_without_output(manifest_fixture, manifest_fixture.correct_manifest,
                                   "overlapping_elf_sections", input_path=overlapping,
                                   output_name="overlap-output.so")


@pytest.mark.parametrize("size,diagnostic", [
    (0, "malformed_material_section"),
    (RECORD_SIZE - 1, "malformed_material_section"),
    (RECORD_SIZE * 4097, "malformed_elf_section"),
])
def test_rejects_invalid_material_section_size(manifest_fixture, size,
                                               diagnostic):
    material = _material_section(manifest_fixture.original)
    malformed = manifest_fixture.mutated_input(
        lambda data: struct.pack_into("<Q", data,
                                      material["header_offset"] + 32, size),
        f"bad-section-size-{size}.so")
    assert_rejected_without_output(manifest_fixture, manifest_fixture.correct_manifest,
                                   diagnostic, input_path=malformed)


def test_rejects_material_section_with_inconsistent_load_mapping(manifest_fixture):
    material = _material_section(manifest_fixture.original)
    inconsistent = manifest_fixture.mutated_input(
        lambda data: struct.pack_into("<Q", data,
                                      material["header_offset"] + 16,
                                      material["address"] + 1),
        "inconsistent-mapping.so")
    assert_rejected_without_output(manifest_fixture, manifest_fixture.correct_manifest,
                                   "material_section_not_file_backed",
                                   input_path=inconsistent)


@pytest.mark.parametrize("header_offset,count_offset,count,overflow_offset", [
    (32, 56, None, True),
    (40, 60, None, True),
    (32, 56, 0xfffe, False),
    (40, 60, 0xffff, False),
], ids=["program-offset", "section-offset", "program-product",
        "section-product"])
def test_rejects_overflowing_elf_table_offset_and_product(
        manifest_fixture, header_offset, count_offset, count, overflow_offset):
    def overflow_table(data):
        if overflow_offset:
            struct.pack_into("<Q", data, header_offset, 0xfffffffffffffff0)
        else:
            struct.pack_into("<H", data, count_offset, count)

    malformed = manifest_fixture.mutated_input(
        overflow_table,
        f"overflow-table-{header_offset}.so")
    assert_rejected_without_output(manifest_fixture,
                                   manifest_fixture.correct_manifest,
                                   input_path=malformed,
                                   diagnostic="malformed_elf_tables")


@pytest.mark.parametrize("flags", [6, 5], ids=["writable", "executable"])
def test_rejects_material_in_writable_or_executable_load(manifest_fixture, flags):
    material = _material_section(manifest_fixture.original)
    load = next(header for header in _program_headers(manifest_fixture.original)
                if header["type"] == 1
                and header["offset"] <= material["offset"]
                and material["offset"] + material["size"] <=
                header["offset"] + header["file_size"])
    malformed = manifest_fixture.mutated_input(
        lambda data: struct.pack_into("<I", data, load["header_offset"] + 4,
                                      flags),
        f"material-load-flags-{flags}.so")
    assert_rejected_without_output(manifest_fixture,
                                   manifest_fixture.correct_manifest,
                                   input_path=malformed,
                                   diagnostic="material_section_not_read_only")


def test_rejects_nonload_metadata_alias_of_material(manifest_fixture):
    material = _material_section(manifest_fixture.original)
    dynamic = _dynamic_segment(manifest_fixture.original)

    def alias(data):
        offset = dynamic["header_offset"]
        struct.pack_into("<I", data, offset + 4, 4)
        struct.pack_into("<QQQ", data, offset + 8, material["offset"],
                         material["address"], material["address"])
        struct.pack_into("<QQQ", data, offset + 32, 16, 16, 1)

    malformed = manifest_fixture.mutated_input(alias, "metadata-alias.so")
    assert_rejected_without_output(manifest_fixture,
                                   manifest_fixture.correct_manifest,
                                   input_path=malformed,
                                   diagnostic="material_aliases_loader_metadata")


@pytest.mark.parametrize("rela", [True, False], ids=["rela", "rel"])
@pytest.mark.parametrize("field_offset", [16, 20, 24, 56, 88],
                         ids=["abi", "mode", "build-id", "region-id",
                              "engine-abi"])
def test_rejects_dynamic_relocation_targeting_any_descriptor_field(
        manifest_fixture, rela, field_offset):
    material = _material_section(manifest_fixture.original)
    malformed = manifest_fixture.mutated_input(
        lambda data: _install_dynamic_relocation(
            data, material["address"] + field_offset, rela=rela),
        f"dynamic-{'rela' if rela else 'rel'}-{field_offset}.so")
    assert_rejected_without_output(manifest_fixture,
                                   manifest_fixture.correct_manifest,
                                   input_path=malformed,
                                   diagnostic="relocation_targets_material")


@pytest.mark.parametrize("rela", [True, False], ids=["rela", "rel"])
def test_rejects_section_relocation_targeting_material(manifest_fixture, rela):
    material = _material_section(manifest_fixture.original)
    relocation = _named_section(manifest_fixture.original, ".comment")
    dynsym = _named_section(manifest_fixture.original, ".dynsym")

    def install(data):
        header = relocation["header_offset"]
        size = 24 if rela else 16
        struct.pack_into("<I", data, header + 4, 4 if rela else 9)
        struct.pack_into("<Q", data, header + 8, 2)
        struct.pack_into("<Q", data, header + 32, size)
        struct.pack_into("<I", data, header + 40, dynsym["index"])
        struct.pack_into("<Q", data, header + 48, 8)
        struct.pack_into("<Q", data, header + 56, size)
        if rela:
            struct.pack_into("<QQq", data, relocation["offset"],
                             material["address"] + 24, 0x403, 0)
        else:
            struct.pack_into("<QQ", data, relocation["offset"],
                             material["address"] + 24, 0x403)

    malformed = manifest_fixture.mutated_input(
        install, f"section-{'rela' if rela else 'rel'}.so")
    assert_rejected_without_output(manifest_fixture,
                                   manifest_fixture.correct_manifest,
                                   input_path=malformed,
                                   diagnostic="relocation_targets_material")


@pytest.mark.parametrize("kind", ["relr", "android-rel", "android-relr",
                                   "auth-relr"])
def test_rejects_unsupported_dynamic_relocation_formats(manifest_fixture, kind):
    storage = _named_section(manifest_fixture.original, ".eh_frame")
    tags = {
        "relr": [(36, storage["address"]), (35, 8), (37, 8)],
        "android-rel": [(0x6000000f, storage["address"]),
                        (0x60000010, 8)],
        "android-relr": [(0x6fffe000, storage["address"]),
                         (0x6fffe001, 8), (0x6fffe003, 8)],
        "auth-relr": [(0x70000012, storage["address"]),
                      (0x70000011, 8), (0x70000013, 8)],
    }
    malformed = manifest_fixture.mutated_input(
        lambda data: _write_dynamic(data, tags[kind]),
        f"unsupported-{kind}.so")
    assert_rejected_without_output(manifest_fixture,
                                   manifest_fixture.correct_manifest,
                                   input_path=malformed,
                                   diagnostic="unsupported_relocation_format")


def test_rejects_truncated_android_packed_rela(manifest_fixture):
    storage = _named_section(manifest_fixture.original, ".text")
    malformed = manifest_fixture.mutated_input(
        lambda data: _install_android_rela(
            data, storage["address"], truncate=True),
        "truncated-android-rela.so")
    assert_rejected_without_output(
        manifest_fixture, manifest_fixture.correct_manifest,
        "malformed_android_packed_relocations", input_path=malformed)


def test_rejects_android_packed_rela_targeting_material(manifest_fixture):
    material = _material_section(manifest_fixture.original)
    malformed = manifest_fixture.mutated_input(
        lambda data: _install_android_rela(data, material["address"] + 24),
        "material-android-rela.so")
    assert_rejected_without_output(
        manifest_fixture, manifest_fixture.correct_manifest,
        "relocation_targets_material", input_path=malformed)


def test_accepts_nonallocated_retained_static_relocation_type(manifest_fixture):
    relocation = _named_section(manifest_fixture.original, ".comment")
    symtab = _named_section(manifest_fixture.original, ".symtab")
    text = _named_section(manifest_fixture.original, ".text")

    def install(data):
        header = relocation["header_offset"]
        struct.pack_into("<I", data, header + 4, 4)
        struct.pack_into("<Q", data, header + 8, 0)
        struct.pack_into("<Q", data, header + 32, 24)
        struct.pack_into("<I", data, header + 40, symtab["index"])
        struct.pack_into("<I", data, header + 44, text["index"])
        struct.pack_into("<Q", data, header + 48, 8)
        struct.pack_into("<Q", data, header + 56, 24)
        struct.pack_into("<QQq", data, relocation["offset"],
                         text["address"], 283, 0)

    retained = manifest_fixture.mutated_input(
        install, "retained-static-relocation.so")
    result = manifest_fixture.finalize(
        manifest_fixture.correct_manifest, input_path=retained,
        output_name="retained-static-output.so")
    assert result.returncode == 0, result.stdout + result.stderr
    assert manifest_fixture.read_descriptor()["build_id"] == \
        manifest_fixture.expected_build_id


@pytest.mark.parametrize("section_type", [19, 0x40000014, 0x70000004],
                         ids=["relr", "crel", "aarch64-auth-relr"])
def test_rejects_unsupported_section_relocation_format(manifest_fixture,
                                                       section_type):
    relocation = _named_section(manifest_fixture.original, ".comment")

    def install(data):
        header = relocation["header_offset"]
        struct.pack_into("<I", data, header + 4, section_type)
        struct.pack_into("<Q", data, header + 8, 2)
        struct.pack_into("<Q", data, header + 32, 8)
        struct.pack_into("<Q", data, header + 48, 8)
        struct.pack_into("<Q", data, header + 56, 8)

    malformed = manifest_fixture.mutated_input(
        install, f"unsupported-section-{section_type:x}.so")
    assert_rejected_without_output(manifest_fixture,
                                   manifest_fixture.correct_manifest,
                                   input_path=malformed,
                                   diagnostic="unsupported_relocation_format")


def test_rejects_unknown_dynamic_crel_format(manifest_fixture):
    storage = _named_section(manifest_fixture.original, ".eh_frame")
    malformed = manifest_fixture.mutated_input(
        lambda data: _write_dynamic(data, [(0x40000026, storage["address"])]),
        "unsupported-dynamic-crel.so")
    assert_rejected_without_output(manifest_fixture,
                                   manifest_fixture.correct_manifest,
                                   input_path=malformed,
                                   diagnostic="unsupported_relocation_format")


@pytest.mark.parametrize("kind", ["missing-size", "bad-entry-size",
                                   "bad-address"])
def test_rejects_malformed_dynamic_relocation_tags(manifest_fixture, kind):
    storage = _named_section(manifest_fixture.original, ".eh_frame")
    entries = {
        "missing-size": [(7, storage["address"]), (9, 24)],
        "bad-entry-size": [(7, storage["address"]), (8, 24), (9, 16)],
        "bad-address": [(7, 0xfffffffffffffff0), (8, 24), (9, 24)],
    }
    malformed = manifest_fixture.mutated_input(
        lambda data: _write_dynamic(data, entries[kind]),
        f"malformed-dynamic-{kind}.so")
    diagnostic = ("relocation_address_not_file_backed" if kind == "bad-address"
                  else "incomplete_dynamic_relocation_tags")
    assert_rejected_without_output(manifest_fixture,
                                   manifest_fixture.correct_manifest,
                                   input_path=malformed,
                                   diagnostic=diagnostic)


def test_rejects_dynamic_relocation_block_aliasing_material(manifest_fixture):
    material = _material_section(manifest_fixture.original)
    malformed = manifest_fixture.mutated_input(
        lambda data: _write_dynamic(data, [
            (7, material["address"]), (8, 24), (9, 24),
        ]), "relocation-block-alias.so")
    assert_rejected_without_output(manifest_fixture,
                                   manifest_fixture.correct_manifest,
                                   input_path=malformed,
                                   diagnostic="relocation_block_aliases_material")


@pytest.mark.parametrize("rela", [True, False], ids=["rela", "rel"])
def test_rejects_dynamic_relative_count_that_reinterprets_none_relocation(
        manifest_fixture, rela):
    material = _material_section(manifest_fixture.original)
    storage = _named_section(manifest_fixture.original, ".eh_frame")

    def install(data):
        target = material["address"] + 24
        if rela:
            struct.pack_into("<QQq", data, storage["offset"], target, 0, 0)
            _write_dynamic(data, [
                (7, storage["address"]), (8, 24), (9, 24),
                (0x6ffffff9, 1),
            ])
        else:
            struct.pack_into("<QQ", data, storage["offset"], target, 0)
            _write_dynamic(data, [
                (17, storage["address"]), (18, 16), (19, 16),
                (0x6ffffffa, 1),
            ])

    malformed = manifest_fixture.mutated_input(
        install, f"relative-count-{'rela' if rela else 'rel'}.so")
    assert_rejected_without_output(
        manifest_fixture, manifest_fixture.correct_manifest,
        input_path=malformed, diagnostic="malformed_dynamic_relocation_count")


def test_manifest_larger_than_four_mib_is_rejected(manifest_fixture):
    oversized = manifest_fixture.correct_manifest + b" " * (
        4 * 1024 * 1024 - len(manifest_fixture.correct_manifest) + 1)
    assert_rejected_without_output(manifest_fixture, oversized,
                                   "manifest_read_failed")
