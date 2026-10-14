"""只从最终 ELF 的公开 descriptor 逆解目标，独立于 compiler/hardener。"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess

MASK = (1 << 64) - 1


class ELF:
    def __init__(self, path):
        self.path = Path(path)
        self.data = self.path.read_bytes()
        d = self.data
        if len(d) < 64 or d[:6] != b'\x7fELF\x02\x01':
            raise ValueError('requires valid ELF64 little endian')
        if struct.unpack_from('<H', d, 18)[0] != 183:
            raise NotImplementedError('requires AArch64')
        off = struct.unpack_from('<Q', d, 32)[0]
        size, count = struct.unpack_from('<HH', d, 54)
        if size < 56 or off + count * size > len(d):
            raise ValueError('invalid program headers')
        self.loads = []
        for i in range(count):
            typ, flags, pos, va, _, filesz, memsz, align = struct.unpack_from('<IIQQQQQQ', d, off + i * size)
            if pos + filesz > len(d) or filesz > memsz:
                raise ValueError('segment outside file')
            if typ == 1:
                self.loads.append((flags, pos, va, filesz))

    def offset(self, va, size=1):
        for _, off, base, length in self.loads:
            if base <= va and va + size <= base + length:
                return off + va - base
        raise ValueError('VA outside file-backed load')

    def executable(self, va):
        return any(flags & 1 and base <= va < base + length for flags, _, base, length in self.loads)

    def targets(self):
        found, targets = 0, []
        d = self.data
        for flags, off, va, size in self.loads:
            if flags & 1:
                continue
            pos = off
            while True:
                pos = d.find(b'XOVMTGT1', pos, off + size)
                if pos < 0:
                    break
                if pos + 32 > off + size:
                    raise ValueError('truncated descriptor')
                ver, state, count, role, reserved = struct.unpack_from('<IIIIQ', d, pos + 8)
                if ver != 1 or state != 1 or role not in (1, 2) or reserved or not count:
                    raise ValueError('descriptor not processed/valid')
                if count > (off + size - pos - 32) // 32:
                    raise ValueError('truncated records')
                found += 1
                for i in range(count):
                    r = pos + 32 + i * 32
                    word, key, add, rot, kind = struct.unpack_from('<QQQII', d, r)
                    if not 0 < rot < 64 or kind not in (0, 1):
                        raise ValueError('invalid record')
                    if not kind:
                        continue
                    relative = ((((word >> rot) | (word << (64 - rot))) & MASK) - add) & MASK
                    target = ((va + r - off) + (relative ^ key)) & MASK
                    if not self.executable(target):
                        raise ValueError('decoded target outside PF_X')
                    targets.append((role, target))
                pos += 32 + count * 32
        return found, targets


def analyze(path):
    try:
        elf = ELF(path)
        descriptors, targets = elf.targets()
        if not targets:
            return {'status': 'NOT_RECOVERED_WITHIN_BUDGET', 'detail': 'no supported target descriptor found; not a security conclusion'}
        objdump = shutil.which('llvm-objdump')
        if not objdump:
            return {'status': 'UNSUPPORTED', 'detail': 'llvm-objdump unavailable; target inverse worked, instruction validation unavailable'}
        # 对全部目标用真实 AArch64 反汇编验证，而不是只检查 PF_X 范围。
        p = subprocess.run([objdump, '-d', '--no-show-raw-insn', str(path)], capture_output=True, text=True, timeout=30)
        if p.returncode:
            raise ValueError(f'objdump failed: {p.stderr[-1000:]}')
        instructions = {}
        for line in p.stdout.splitlines():
            m = re.match(r'\s*([0-9a-f]+):\s+(.+)', line)
            if m:
                instructions[int(m[1], 16)] = m[2]
        unique = {t for _, t in targets}
        valid = {t for t in unique if t in instructions and '<unknown>' not in instructions[t]}
        if valid != unique:
            raise ValueError('some decoded targets lack valid disassembled instructions')
        return {'status': 'RECOVERED', 'detail': 'public record parameters statically invert all handler/engine target slots; bytecode semantics not recovered',
                'extra': {'descriptors': descriptors, 'targets': len(targets), 'unique_targets': len(unique),
                          'disassembled_targets': len(valid), 'engine_targets': sum(role == 2 for role, _ in targets)}}
    except NotImplementedError as e:
        return {'status': 'UNSUPPORTED', 'detail': str(e)}
    except subprocess.TimeoutExpired:
        return {'status': 'TIMEOUT', 'detail': 'AArch64 disassembly exceeded 30s'}
    except (OSError, ValueError, struct.error) as e:
        return {'status': 'TOOL_ERROR', 'detail': str(e)}


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('elf', type=Path)
    print(json.dumps(analyze(ap.parse_args().elf)))
