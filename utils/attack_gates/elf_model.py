import struct
from dataclasses import dataclass
from pathlib import Path


class ElfFormatError(ValueError):
    pass


@dataclass(frozen=True)
class LoadSegment:
    offset: int
    file_size: int
    virtual_address: int
    flags: int


@dataclass(frozen=True)
class ZeroRun:
    offset: int
    size: int


def find_zero_runs(data: bytes, minimum: int) -> list[ZeroRun]:
    if minimum <= 0:
        raise ValueError('minimum must be positive')

    runs = []
    start = None
    for offset, value in enumerate(data):
        if value == 0 and start is None:
            start = offset
        elif value != 0 and start is not None:
            if offset - start >= minimum:
                runs.append(ZeroRun(start, offset - start))
            start = None

    if start is not None and len(data) - start >= minimum:
        runs.append(ZeroRun(start, len(data) - start))
    return runs


def parse_load_segments(path: Path) -> list[LoadSegment]:
    data = path.read_bytes()
    if len(data) < 64 or data[:4] != bytes([0x7F]) + b'ELF':
        raise ElfFormatError('not an ELF file')
    if data[4] != 2:
        raise ElfFormatError('expected ELF64 input')
    if data[5] != 1:
        raise ElfFormatError('expected little-endian input')

    try:
        header = struct.unpack_from('<HHIQQQIHHHHHH', data, 16)
    except struct.error as error:
        raise ElfFormatError('truncated ELF64 header') from error

    program_offset = header[4]
    program_entry_size = header[8]
    program_count = header[9]
    if program_entry_size < 56:
        raise ElfFormatError('invalid program header entry size')
    program_end = program_offset + program_entry_size * program_count
    if program_offset > len(data) or program_end > len(data):
        raise ElfFormatError('program header table exceeds file bounds')

    segments = []
    for index in range(program_count):
        offset = program_offset + index * program_entry_size
        try:
            fields = struct.unpack_from('<IIQQQQQQ', data, offset)
        except struct.error as error:
            raise ElfFormatError('truncated program header') from error
        segment_type, flags, file_offset, virtual_address, _, file_size, _, _ = fields
        if file_offset + file_size > len(data):
            raise ElfFormatError('segment file range exceeds file bounds')
        if segment_type == 1:
            segments.append(
                LoadSegment(file_offset, file_size, virtual_address, flags)
            )
    return segments
