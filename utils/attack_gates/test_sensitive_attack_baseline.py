import os
import re
import shutil
import struct
import subprocess
from pathlib import Path

import pytest

from elf_model import (
    ElfFormatError,
    LoadSegment,
    ZeroRun,
    find_zero_runs,
    parse_load_segments,
)


def make_elf64(*, elf_class=2, elf_data=1, phoff=64, phentsize=56, phnum=1,
               segment_offset=0x80, segment_size=4):
    data = bytearray(0x100)
    data[:16] = bytes([0x7F]) + b'ELF' + bytes([elf_class, elf_data, 1]) + bytes(9)
    struct.pack_into(
        '<HHIQQQIHHHHHH',
        data,
        16,
        2,
        183,
        1,
        0,
        phoff,
        0,
        0,
        64,
        phentsize,
        phnum,
        0,
        0,
        0,
    )
    if phnum and phoff + 56 <= len(data):
        struct.pack_into(
            '<IIQQQQQQ',
            data,
            phoff,
            1,
            5,
            segment_offset,
            0x400080,
            0x400080,
            segment_size,
            segment_size,
            0x1000,
        )
    return bytes(data)


def test_zero_run_threshold_is_inclusive():
    blob = b'A' + bytes(511) + b'B' + bytes(512) + b'C'
    assert find_zero_runs(blob, 512) == [ZeroRun(513, 512)]


def test_parse_load_segments_returns_read_only_program_header_view(tmp_path):
    binary = tmp_path / 'fixture.elf'
    original = make_elf64()
    binary.write_bytes(original)

    assert parse_load_segments(binary) == [LoadSegment(0x80, 4, 0x400080, 5)]
    assert binary.read_bytes() == original


@pytest.mark.parametrize(
    ('kwargs', 'message'),
    [
        ({'elf_class': 1}, 'ELF64'),
        ({'elf_data': 2}, 'little-endian'),
        ({'phoff': 0xF0}, 'program header table'),
        ({'segment_offset': 0xF0, 'segment_size': 0x20}, 'segment file range'),
    ],
)
def test_parse_load_segments_rejects_malformed_elf(tmp_path, kwargs, message):
    binary = tmp_path / 'malformed.elf'
    binary.write_bytes(make_elf64(**kwargs))

    with pytest.raises(ElfFormatError, match=message):
        parse_load_segments(binary)


FIXTURE = Path(__file__).parents[1] / 'fixtures' / 'sensitive_decision_fixture.cpp'


def direct_call_to(symbol, disassembly):
    return re.search(rf'\bbl\s+[^\n]*<{re.escape(symbol)}(?:@plt)?>', disassembly) is not None


def conditional_failure_edge_after(symbol, disassembly):
    call = re.search(rf'\bbl\s+[^\n]*<{re.escape(symbol)}(?:@plt)?>', disassembly)
    if not call:
        return False
    following = disassembly[call.end():].splitlines()[:4]
    return any(re.search(r'\b(?:cbz|cbnz|tbz|tbnz|b\.[a-z]+)\b', line) for line in following)


def xrefs_to(symbol, disassembly):
    return len(re.findall(rf'\bbl\s+[^\n]*<{re.escape(symbol)}(?:@plt)?>', disassembly))


def executable_zero_runs(binary):
    data = binary.read_bytes()
    runs = []
    for segment in parse_load_segments(binary):
        if segment.flags & 1:
            segment_data = data[segment.offset:segment.offset + segment.file_size]
            runs.extend(find_zero_runs(segment_data, 512))
    return runs


def _tool(clang, name):
    sibling = Path(clang).with_name(name)
    return str(sibling) if sibling.exists() else shutil.which(name) or name


@pytest.fixture(scope='module')
def fixture_artifacts(tmp_path_factory):
    clang = os.environ.get('XOLLVM_TEST_CLANG')
    if not clang:
        pytest.skip('XOLLVM_TEST_CLANG is required for the AArch64 baseline')
    output = tmp_path_factory.mktemp('sensitive-attack-baseline')
    object_file = output / 'sensitive_decision_fixture.o'
    binary = output / 'sensitive_decision_fixture.so'
    compile_command = [
        clang,
        '-target',
        'aarch64-linux-android',
        '-O0',
        '-fno-pie',
        '-fno-stack-protector',
        '-c',
        str(FIXTURE),
        '-o',
        str(object_file),
    ]
    subprocess.run(compile_command, check=True, capture_output=True, text=True)
    link_command = [
        clang,
        '-target',
        'aarch64-linux-android',
        '-fuse-ld=lld',
        '-nostdlib',
        '-shared',
        str(object_file),
        '-o',
        str(binary),
    ]
    subprocess.run(link_command, check=True, capture_output=True, text=True)
    objdump = _tool(clang, 'llvm-objdump')
    readelf = _tool(clang, 'llvm-readelf')
    disassembly = subprocess.run(
        [objdump, '-d', str(binary)], check=True, capture_output=True, text=True
    ).stdout
    symbols = subprocess.run(
        [readelf, '--dyn-syms', '--relocs', str(binary)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return binary, disassembly, symbols


def test_dynamic_verifier_observation_is_visible(fixture_artifacts):
    _, _, symbols = fixture_artifacts
    assert re.search(r'R_AARCH64_JUMP_SLOT\s+.*fixture_verify', symbols)


def test_direct_call_to_verifier_is_visible(fixture_artifacts):
    _, disassembly, _ = fixture_artifacts
    assert direct_call_to('fixture_verify', disassembly)


def test_conditional_failure_edge_after_compare_is_visible(fixture_artifacts):
    _, disassembly, _ = fixture_artifacts
    assert conditional_failure_edge_after('fixture_compare', disassembly)


def test_transport_xrefs_are_visible(fixture_artifacts):
    _, disassembly, _ = fixture_artifacts
    assert xrefs_to('fixture_transport', disassembly)


def test_executable_zero_runs_are_visible(fixture_artifacts):
    binary, _, _ = fixture_artifacts
    assert any(run.size >= 512 for run in executable_zero_runs(binary))
