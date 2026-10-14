"""AArch64 最终 ELF 的静态引用侦察；未实现动态白盒提取，不将其计为抗性。"""
import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess
from .aarch64_vm_targets import ELF


def analyze(path):
    try:
        elf = ELF(path)
        objdump = shutil.which('llvm-objdump')
        if not objdump:
            return {'status': 'UNSUPPORTED', 'detail': 'AArch64 disassembler unavailable'}
        p = subprocess.run([objdump, '-d', '--no-show-raw-insn', str(path)], capture_output=True, text=True, timeout=30)
        if p.returncode:
            return {'status': 'TOOL_ERROR', 'detail': p.stderr[-1000:]}
        # 追踪相邻 ADRP+ADD，识别指向非 executable PT_LOAD 的数据引用。
        pages, refs = {}, set()
        for line in p.stdout.splitlines():
            m = re.match(r'\s*([0-9a-f]+):\s+adrp\s+(x\d+),\s*(0x[0-9a-f]+)', line)
            if m:
                pages[m[2]] = (int(m[1], 16), int(m[3], 16))
                continue
            m = re.match(r'\s*([0-9a-f]+):\s+add\s+(x\d+),\s*(x\d+),\s*#(0x[0-9a-f]+|\d+)', line)
            if m and m[3] in pages:
                origin, page = pages[m[3]]
                if int(m[1], 16) - origin <= 16:
                    address = page + int(m[4], 0)
                    if any(not flags & 1 and base <= address < base + size for flags, _, base, size in elf.loads):
                        refs.add(address)
            # 避免跨函数/远距离引用错误地复用寄存器页地址。
            if re.search(r'\b(ret|br|blr)\b', line):
                pages.clear()
        return {'status': 'UNSUPPORTED',
                'detail': 'static ADRP+ADD data-reference reconnaissance ran; dynamic AArch64 whitebox bytecode extraction adapter is not implemented. No plaintext recovery or resilience claim.',
                'extra': {'data_reference_candidates': len(refs), 'plaintext_recovered': False,
                          'scope': 'static references only; candidates are not proven bytecode'}}
    except NotImplementedError as e:
        return {'status': 'UNSUPPORTED', 'detail': str(e)}
    except subprocess.TimeoutExpired:
        return {'status': 'TIMEOUT', 'detail': 'AArch64 reconnaissance exceeded 30s'}
    except (OSError, ValueError) as e:
        return {'status': 'TOOL_ERROR', 'detail': str(e)}


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('elf', type=Path)
    print(json.dumps(analyze(ap.parse_args().elf)))
