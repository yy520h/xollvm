"""Android 生产验收：显式运行 cloud / arm32 / all，真实卡密仅从环境读取。"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import struct
import subprocess
import tempfile
import time


FIXTURES = Path(__file__).resolve().parent / 'fixtures/production'
ARM_SPECS = {
    'plain': 'vm(hardened=0,encBytecode=0,lazyDecrypt=0,constInStream=0)',
    'encrypted': 'vm(encBytecode=1,lazyDecrypt=1,constInStream=1,hardened=1)',
    'diversified': 'vm(encBytecode=1,lazyDecrypt=1,hardened=1,randISA=1,operandLayout=1,extendedISA=1,threadedDispatch=1,handlerVariants=4,encDispatch=1)',
    'max-portable': 'vm(preset=max,encodedTargets=0,nestedVM=0)',
}
ARM_OUTPUT = '24 input pairs: i32/i64/ptr/fp equal\n'


class AcceptanceError(RuntimeError):
    pass


def require(condition, detail):
    if not condition:
        raise AcceptanceError(detail)


def require_vm(report, names, *, cloud=False):
    for name in names:
        matches = [f for f in report.get('functions', []) if f.get('name') == name]
        require(len(matches) == 1, f'missing/duplicate VM function: {name}')
        fn = matches[0]
        passes = [p for p in fn.get('passes', []) if p.get('id') == 'vm']
        require(bool(passes) and all(p.get('status') == 'ran' for p in passes),
                f'VM not run for {name}: {passes}')
        vm = fn.get('vm', {})
        require(vm.get('phase') == 'committed', f'VM not committed: {name}')
        if cloud:
            require(vm.get('effective', {}).get('cloudDispatch') is True,
                    f'cloudDispatch not effective: {name}')


def replay_dispatch(instructions, start, fault, registers, read, offset, *, fault_registers=None):
    """受限解释器重放真实返回点后的整数分发检查；未知指令一律拒绝。"""
    def execute(cloud):
        regs = list(registers)
        regs[0] = cloud
        pc, carry, zero, negative, overflow = start, False, False, False, False
        loads, visited, cmps = [], [], []

        def get(token):
            token = token.strip()
            if token.startswith('#'):
                return int(token[1:], 0)
            if token in ('wzr', 'xzr'):
                return 0
            if token == 'sp':
                return registers[31]
            require(re.fullmatch(r'[wx]\d+', token) is not None, f'unsupported register: {token}')
            return regs[int(token[1:])] & ((1 << (32 if token[0] == 'w' else 64)) - 1)

        def condition(name):
            conditions = {'eq': zero, 'ne': not zero, 'hs': carry, 'cs': carry,
                          'lo': not carry, 'cc': not carry, 'hi': carry and not zero,
                          'ls': not carry or zero, 'ge': negative == overflow,
                          'lt': negative != overflow, 'gt': not zero and negative == overflow,
                          'le': zero or negative != overflow}
            require(name in conditions, f'unsupported condition: {name}')
            return conditions[name]

        for _ in range(512):
            require(pc in instructions, 'dispatch replay left decoded code')
            text = instructions[pc].split('//')[0].strip()
            fields = text.split(None, 1)
            op, rest = fields[0], fields[1] if len(fields) == 2 else ''
            a = [v.strip() for v in rest.split(',')]
            visited.append(pc)
            next_pc = pc + 4
            if op == 'brk':
                return {'end': pc, 'loads': loads, 'cmps': cmps, 'visited': visited, 'registers': regs}
            if op in ('b', 'b.eq', 'b.ne', 'b.hs', 'b.lo', 'b.hi', 'b.ls'):
                if op == 'b' or condition(op[2:]):
                    next_pc = int(a[0].split()[0], 0)
            elif op in ('tbz', 'tbnz'):
                bit = bool(get(a[0]) & (1 << get(a[1])))
                if bit == (op == 'tbnz'):
                    next_pc = int(a[2].split()[0], 0)
            elif op in ('cbz', 'cbnz'):
                if (get(a[0]) != 0) == (op == 'cbnz'):
                    next_pc = int(a[1].split()[0], 0)
            elif op == 'ldr':
                match = re.fullmatch(r'([wx]\d+), \[(sp|x\d+)(?:, (#(?:0x[0-9a-f]+|\d+)))?\]', rest)
                require(match is not None, f'unsupported load: {text}')
                dest, base, displacement = match.groups()
                address = get(base) + (get(displacement) if displacement else 0)
                value = read(address, 4 if dest[0] == 'w' else 8)
                regs[int(dest[1:])] = value
                loads.append((address, value, dest))
            elif op == 'cset':
                regs[int(a[0][1:])] = int(condition(a[1]))
            elif op in ('ret', 'br', 'blr', 'bl', 'str', 'stp') or (op == 'lsl' and a[-1] == '#5'):
                return {'end': pc, 'loads': loads, 'cmps': cmps, 'visited': visited, 'registers': regs}
            else:
                compare = op == 'cmp'
                dest = a[0]
                bits = 32 if dest[0] == 'w' else 64
                mask = (1 << bits) - 1
                operands = a if compare else a[1:]
                lhs = get(operands[0])
                rhs = get(operands[1]) if len(operands) > 1 else 0
                if len(operands) > 2:
                    shift = re.fullmatch(r'(lsl|lsr) #(\d+)', operands[2])
                    require(shift is not None, f'unsupported shifted operand: {text}')
                    rhs = rhs << int(shift[2]) if shift[1] == 'lsl' else rhs >> int(shift[2])
                if op in ('add', 'adds'):
                    value = lhs + rhs
                elif op in ('sub', 'subs', 'cmp'):
                    value = lhs - rhs
                    cmps.append((lhs, rhs))
                elif op == 'eor': value = lhs ^ rhs
                elif op == 'eon': value = lhs ^ ~rhs
                elif op == 'and': value = lhs & rhs
                elif op == 'bic': value = lhs & ~rhs
                elif op == 'orr': value = lhs | rhs
                elif op == 'orn': value = lhs | ~rhs
                elif op == 'mov': value = lhs
                elif op == 'mvn': value = ~lhs
                elif op == 'lsl': value = lhs << rhs
                elif op == 'lsr': value = lhs >> rhs
                else: raise AcceptanceError(f'unsupported dispatch instruction: {text}')
                if op in ('subs', 'adds', 'cmp'):
                    zero, negative = (value & mask) == 0, bool(value & (1 << (bits - 1)))
                    carry = lhs >= rhs if op != 'adds' else value > mask
                    overflow = bool(((lhs ^ rhs) if op != 'adds' else ~(lhs ^ rhs)) &
                                    (lhs ^ value) & (1 << (bits - 1)))
                if not compare:
                    regs[int(dest[1:])] = value & mask
            pc = next_pc
        raise AcceptanceError('dispatch replay exceeded instruction limit')

    expired, fresh = execute(offset), execute(0)
    require(expired['end'] == fault and instructions[fault].startswith('brk'),
            'fault is not the replayed dispatch trap')
    require(fresh['end'] != fault, 'zero cloud offset still reaches the fault')
    require(re.fullmatch(r'lsl\s+x\d+, x\d+, #5', instructions[fresh['end']]) is not None,
            'zero offset did not reach handler record addressing')
    if fault_registers is not None:
        require(expired['registers'][:31] == list(fault_registers),
                'replayed registers disagree with kernel fault context')
    # 对真实 header 读取和索引比较联合取证，不接受仅位于 engine 范围内的任意 trap。
    for address, state, _ in expired['loads']:
        if state != 1:
            continue
        for count_address, count, _ in expired['loads']:
            if count_address != address + 4 or not 0 < count < 65536:
                continue
            for slot, limit in expired['cmps']:
                if limit != count or slot < count:
                    continue
                if (slot - offset, count) not in fresh['cmps'] or not 0 <= slot - offset < count:
                    continue
                return {'descriptor': address - 12, 'count': count,
                        'baseSlot': slot - offset, 'expiredSlot': slot,
                        'replayedInstructions': len(expired['visited'])}
    raise AcceptanceError('no cloud-caused descriptor bounds failure')


def check_cloud(mode, code, output, *, fault=None):
    calls = [tuple(map(int, row)) for row in re.findall(
        r'^call=(\d+) window=(\d+) value=(-?\d+)$', output, re.M)]
    require(calls and calls[0][0] == 0 and all(r[2] == 11299 for r in calls),
            f'{mode}: missing/wrong protected result')
    if mode == 'online':
        require(code == 0 and 'acceptance complete' in output, 'online did not finish')
        require([r[0] for r in calls] == list(range(126)), 'online needs exactly 126 calls')
        windows = [r[1] for r in calls]
        require(windows == sorted(windows) and len(set(windows)) >= 3 and
                windows[-1] >= windows[0] + 2, 'online did not cross two window boundaries')
        return {'calls': len(calls), 'windows': sorted(set(windows))}
    require(mode in ('offline-expiry', 'recovery'), 'unknown cloud mode')
    offline = re.search(r'^offline expired window=(\d+) offset=(\d+) refresh=(\d+) denied=(\d+)$',
                        output, re.M)
    if offline is None:
        raise AcceptanceError('missing offline evidence')
    window, offset, refresh, denied = map(int, offline.groups())
    require(window > calls[0][1] and offset > 0 and refresh == 0 and denied > 0,
            'offline did not expire/block real network refresh')
    if mode == 'offline-expiry':
        require('calling expired VM; abnormal termination expected' in output and len(calls) == 1,
                'expired VM was not reached or returned a value')
        require(code in (-signal.SIGTRAP, -signal.SIGILL, -signal.SIGSEGV, -signal.SIGABRT),
                f'expired VM did not fault as expected: {code}')
        require(fault is not None, 'missing verified fault evidence')
        require(fault.get('offset') == offset and fault.get('signal') == -code,
                'fault evidence disagrees with expired offset/signal')
    else:
        require(code == 0 and [r[0] for r in calls] == [0, 1] and calls[1][1] >= window and
                'network restored offset=0' in output and 'acceptance complete' in output,
                'recovery lacks fresh dispatch/protected result')
    return {'expiredWindow': window, 'offset': offset, 'denied': denied, 'exit': code,
            **({'fault': fault} if fault is not None else {})}


class Runner:
    def __init__(self, output, secrets=()):
        self.output = Path(output)
        self.secrets = tuple(s for s in secrets if s)
        self.steps = []

    def redact(self, text):
        for secret in self.secrets:
            text = text.replace(secret, '[REDACTED]')
        return text

    def run(self, name, args, *, timeout=180, env=None, cwd=None):
        start = time.monotonic()
        command = list(map(str, args))
        code, status, text = None, 'TOOL_ERROR', ''
        try:
            child = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                     env=env, cwd=cwd, start_new_session=True)
            try:
                raw, _ = child.communicate(timeout=timeout)
                status = 'OK' if child.returncode == 0 else 'NONZERO'
            except subprocess.TimeoutExpired:
                # 杀掉整个编译/运行进程组，避免超时后仍留下联网或链接子进程。
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                raw, _ = child.communicate()
                status = 'TIMEOUT'
            code = child.returncode
            text = raw.decode(errors='replace')
        except OSError as error:
            text = str(error)
        text = self.redact(text)
        log = self.output / f'{name}.log'
        log.write_text(text)
        row = {'name': name, 'command': [self.redact(a) for a in command],
               'status': status, 'exit': code, 'seconds': time.monotonic() - start,
               'log': str(log), 'output': text}
        self.steps.append(row)
        return row

    def checked(self, name, args, **kwargs):
        row = self.run(name, args, **kwargs)
        require(row['status'] == 'OK', f'{name}: {row["status"]} exit={row["exit"]}; see {row["log"]}')
        return row


def native_env():
    env = dict(os.environ)
    # 32 位子进程不能加载 Termux 的 64 位预加载库。
    env.pop('LD_PRELOAD', None)
    env.pop('LD_LIBRARY_PATH', None)
    env.pop('XOLLVM_ZONE_CARD', None)
    return env


def tool(path):
    require(path.is_file() and os.access(path, os.X_OK), f'missing executable: {path}')
    return path


def finalize(run, exe, hardener):
    for stage in ('targets', 'audit', 'seal', 'verify'):
        args = [hardener, stage, '--input', exe]
        if stage in ('targets', 'seal'):
            args += ['--output', exe]
        run.checked(f'cloud-{stage}', args)


def verify_cloud_fault(exe, path, run, tools):
    from deobf_bench.attacks.aarch64_vm_targets import ELF
    raw = path.read_bytes()
    require(len(raw) == 332 * 8, 'missing/truncated fault evidence')
    data = struct.unpack('<332Q', raw)
    magic, sig, si_code, tid, absolute_pc, address, base, captured, lr, sp = data[:10]
    require(magic == 0x584f4641554c5431 and sig == signal.SIGTRAP and si_code > 0,
            'fault evidence is not a synchronous kernel SIGTRAP')
    require(tid == data[297] and captured > 0, 'fault on wrong thread/no dispatch snapshot')
    pc, start = absolute_pc - base, lr - base
    elf = ELF(exe)
    _, targets = elf.targets()
    symbols = run.checked('cloud-fault-symbols', [tool(tools / 'llvm-readelf'), '-sW', exe])['output']
    engines = [(int(a, 16), int(size), name) for a, size, name in re.findall(
        r'\d+:\s+([0-9a-fA-F]+)\s+(\d+)\s+FUNC\s+LOCAL\s+\S+\s+\d+\s+(__vm_engine[\w.]*)', symbols)]
    engine = next(((a, size, name) for a, size, name in engines
                   if a <= start - 4 < pc < a + size and (2, a) in targets), None)
    require(engine is not None, 'fault/caller not in the same finalized VM engine')
    require(0 < pc - start <= 2048, 'fault is not adjacent to last cloud dispatch call')
    disassembly = run.checked('cloud-fault-disassembly', [tool(tools / 'llvm-objdump'), '-d',
        '--no-show-raw-insn', f'--start-address={start - 4}', f'--stop-address={pc + 4}', exe])['output']
    instructions = {int(a, 16): text.strip() for a, text in re.findall(
        r'^\s*([0-9a-f]+):\s+(.+)$', disassembly, re.M)}
    require('<__wrap___zone_get_dispatch_offset>' in instructions.get(start - 4, '') and
            instructions[start - 4].startswith('bl'), 'last caller is not the real offset wrapper')
    registers = list(data[10:41]) + [sp]
    offset = registers[0]
    require(0 < offset <= 0xfff, 'snapshot has no expired cloud offset')

    def read(address, size):
        if sp <= address and address + size <= sp + 2048:
            return int.from_bytes(raw[41 * 8 + address - sp:41 * 8 + address - sp + size], 'little')
        pos = elf.offset(address - base, size)
        return int.from_bytes(elf.data[pos:pos + size], 'little')

    result = replay_dispatch(instructions, start, pc, registers, read, offset,
                             fault_registers=data[300:331])
    descriptor = result['descriptor'] - base
    pos = elf.offset(descriptor, 32)
    require(elf.data[pos:pos + 8] == b'XOVMTGT1' and
            struct.unpack_from('<IIII', elf.data, pos + 8) == (1, 1, result['count'], 1),
            'replayed bounds check is not a finalized handler descriptor')
    require(address == absolute_pc and data[331] == sp, 'fault PC/address/stack mismatch')
    result.update(descriptor=descriptor, signal=sig, siCode=si_code, offset=offset,
                  pc=pc, returnPC=start, engine=engine[2], thread=tid,
                  snapshotCalls=captured, cause='cloud-offset-handler-index-out-of-bounds')
    return result


def cloud(args, run, card):
    from deobf_bench.attacks.aarch64_vm_targets import ELF
    root, tools, ndk = args.project, args.tools, args.ndk
    demo = root / 'demo'
    host = ndk / 'toolchains/llvm/prebuilt/linux-arm64'
    obj, ssl = demo / 'obj/local/arm64-v8a', demo / 'obj/openssl/arm64-v8a'
    clang, linker, hardener = (tool(p) for p in
                              (tools / 'clang', host / 'bin/clang++', tools / 'xollvm-elf-hardener'))
    env = native_env()
    env.update(XOLLVM_NDK_ROOT=str(ndk), XOLLVM_TOOLS_DIR=str(tools),
               XOLLVM_OBFUSCATOR_CLANG=str(clang), XOLLVM_REAL_CLANG=str(linker),
               XOLLVM_ELF_HARDENER=str(hardener))
    require((demo / 'jni/zone_config.local.h').is_file(), 'missing demo local Zone configuration')
    # 依赖使用当前源码增量构建，生产 main 强制重编，确保预算回归不会被旧对象掩盖。
    build_env = dict(os.environ)
    build_env.pop('XOLLVM_ZONE_CARD', None)
    build_env.update({key: value for key, value in env.items() if key.startswith('XOLLVM_')})
    bash = shutil.which('bash')
    require(bash is not None, 'bash required for NDK build scripts')
    run.checked('cloud-demo-build', [bash, tool(ndk / 'ndk-build'), '-j2', '-W', './jni/main.cpp', 'V=0'],
                env=build_env, cwd=demo, timeout=900)
    work = run.output
    report, object_file, exe = (work / n for n in ('cloud-vm.json', 'cloud.o', 'cloud.elf'))
    run.checked('cloud-compile', [clang, '--target=aarch64-linux-android26',
        f'--sysroot={host / "sysroot"}', '-std=c++20', '-O2', '-g0', '-fPIC',
        '-ffunction-sections', '-fdata-sections', f'-I{demo / "jni/zone_runtime"}',
        f'-I{demo / "jni"}', f'-DXOLLVM_DEMO_SOURCE="{demo / "jni/main.cpp"}"',
        '-mllvm', '-enable-obfuscation', '-mllvm', '-obf-seed=20260930',
        '-mllvm', '-obf-verify', '-mllvm', '-obf-max-function-insts=500',
        '-mllvm', '-obf-max-function-blocks=80', '-mllvm', '-obf-ir-budget-multiplier=12',
        '-mllvm', '-obf-ir-budget-max=12000', '-mllvm', '-obf-shield-auto',
        '-mllvm', f'-obf-report-json={report}', '-c', FIXTURES / 'cloud.cpp', '-o', object_file], env=env)
    require_vm(json.loads(report.read_text()), ['_Z24demo_protected_operationi'], cloud=True)
    run.checked('cloud-link', [linker, '--target=aarch64-linux-android26', '-static-libstdc++',
        '-Wl,--rosegment', '-Wl,--gc-sections', '-Wl,--wrap=connect',
        '-Wl,--wrap=__zone_get_dispatch_offset', object_file,
        obj / 'libzone_runtime_static.a', obj / 'libzone_capability_client.a', obj / 'libcurl_core.a',
        ssl / 'libssl.a', ssl / 'libcrypto.a',
        *[ssl / 'providers' / n for n in ('libcommon.a', 'libdefault.a', 'liblegacy.a')],
        obj / 'libzlib_core.a', '-latomic', '-ldl', '-lm', '-pthread', '-o', exe], env=env)
    finalize(run, exe, hardener)
    descriptors, targets = ELF(exe).targets()
    require(descriptors >= 2 and any(role == 2 for role, _ in targets), 'missing finalized VM descriptors')
    result = {'sha256': hashlib.sha256(exe.read_bytes()).hexdigest(),
              'descriptors': descriptors, 'modes': {}, 'faultRejections': []}
    for negative in ('unrelated-trap', 'offset-unrelated-trap', 'background-trap'):
        path = work / (negative + '.bin')
        row = run.run('cloud-' + negative, [exe, negative, path], env=env, timeout=15)
        require(row['status'] == 'NONZERO' and row['exit'] == -signal.SIGTRAP,
                f'{negative}: negative fixture did not trap')
        try:
            verify_cloud_fault(exe, path, run, tools)
        except AcceptanceError as error:
            result['faultRejections'].append({'case': negative, 'reason': str(error)})
            row['status'] = 'EXPECTED_REJECTION'
        else:
            raise AcceptanceError(f'{negative}: unrelated crash was accepted')
    # 单张卡的会话顺序运行，过期异常退出放最后，避免干扰后续登录。
    env['XOLLVM_ZONE_CARD'] = card
    for mode in ('online', 'recovery', 'offline-expiry'):
        fault_path = work / 'cloud-fault.bin'
        command = [exe, mode] + ([fault_path] if mode == 'offline-expiry' else [])
        row = run.run(f'cloud-{mode}', command, env=env, timeout=240)
        require(row['status'] in ('OK', 'NONZERO'), f'{mode}: {row["status"]}')
        fault = verify_cloud_fault(exe, fault_path, run, tools) if mode == 'offline-expiry' else None
        result['modes'][mode] = check_cloud(mode, row['exit'], row['output'], fault=fault)
        if mode == 'offline-expiry':
            row['status'] = 'EXPECTED_FAULT'
    return result


def arm32(args, run):
    host = args.ndk / 'toolchains/llvm/prebuilt/linux-arm64'
    clang, opt, linker = (tool(p) for p in
                          (args.tools / 'clang', args.tools / 'opt', host / 'bin/clang'))
    resources = [args.arm32_resource_dir] if args.arm32_resource_dir else sorted(
        (host / 'lib/clang').iterdir(), key=lambda p: int(p.name) if p.name.isdigit() else -1, reverse=True)
    resource = None
    for index, candidate in enumerate(resources):
        row = run.run(f'arm32-resource-{index}', [linker, '--target=armv7a-linux-androideabi26',
                      f'-resource-dir={candidate}', '-print-libgcc-file-name'])
        path = Path(row['output'].strip())
        if row['status'] == 'OK' and path.is_file() and 'arm' in path.name + str(path.parent):
            resource = candidate
            break
    require(resource is not None, 'missing ARM32 builtins; specify --arm32-resource-dir')
    base = ['--target=armv7a-linux-androideabi26', f'--sysroot={host / "sysroot"}',
            '-march=armv7-a', '-mfloat-abi=softfp', f'-resource-dir={resource}', '-ffp-contract=off']
    work, env = run.output, native_env()
    source = FIXTURES / 'arm32.c'
    baseline = work / 'arm32-baseline'
    run.checked('arm32-baseline-build', [linker, *base, '-O2', source, '-o', baseline], env=env)
    row = run.checked('arm32-baseline-run', [baseline], env=env, timeout=30)
    require(row['output'] == ARM_OUTPUT, 'ARM32 baseline output mismatch')
    result = {'resourceDir': str(resource), 'fpContract': 'off', 'variants': [], 'rejections': []}
    names = ['protected32', 'protected64', 'protected_fp']
    for name, spec in ARM_SPECS.items():
        ir, obf, report = (work / (name + suffix) for suffix in ('.ll', '-obf.ll', '-vm.json'))
        run.checked(f'arm32-{name}-ir', [clang, *base, '-O0', '-Xclang', '-disable-O0-optnone',
                    f'-DVM_SPEC="{spec}"', '-S', '-emit-llvm', source, '-o', ir], env=env)
        run.checked(f'arm32-{name}-vm', [opt, '-passes=obfuscation', '-obf-seed=42', '-obf-verify',
                    '-obf-no-skips', '-obf-ir-budget-multiplier=1000',
                    f'-obf-report-json={report}', '-S', ir, '-o', obf], env=env)
        require_vm(json.loads(report.read_text()), names)
        obf.write_text('\n'.join(line for line in obf.read_text().splitlines()
                                 if not line.startswith('@llvm.global.annotations')) + '\n')
        for backend in ('O0', 'O2'):
            label = f'arm32-{name}-{backend}'
            exe = work / label
            run.checked(label + '-build', [linker, *base, '-' + backend, obf,
                        '-ldl', '-pthread', '-lm', '-o', exe], env=env)
            row = run.checked(label + '-run', [exe], env=env, timeout=30)
            require(row['output'] == ARM_OUTPUT, f'{label}: output mismatch')
            result['variants'].append({'case': name, 'spec': spec, 'backend': backend, 'inputPairs': 24})
    from vm_hardening_support import annotation
    for index, spec in enumerate(('vm(encodedTargets=1)', 'vm(preset=max)')):
        src = work / f'arm32-unsupported-{index}.ll'
        src.write_text('target triple = "armv7-none-linux-android26"\n'
                       'define i32 @target(i32 %x) { ret i32 %x }\n' + annotation(['target'], spec))
        row = run.run(f'arm32-reject-{index}', [opt, '-passes=obfuscation', '-disable-output', src], env=env)
        require(row['status'] == 'NONZERO' and
                'encodedTargets requires AArch64 little-endian ELF' in row['output'],
                f'unsupported ARM32 configuration was not explicitly rejected: {spec}')
        row['status'] = 'EXPECTED_REJECTION'
        result['rejections'].append(spec)
    return result


def main(argv=None):
    repo = Path(__file__).resolve().parents[1]
    root = repo.parents[2] if repo.parent.name == '.worktrees' else repo.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('cloud', 'arm32', 'all'))
    parser.add_argument('--project', type=Path, default=root, help='包含 demo 的项目目录')
    parser.add_argument('--tools', type=Path, help='当前 XOLLVM bin 目录')
    parser.add_argument('--ndk', type=Path, default=Path(os.environ.get(
        'XOLLVM_NDK', Path.home() / 'android-ndk-r30-ollvm-r23-beta3')))
    parser.add_argument('--arm32-resource-dir', type=Path, help='覆盖自动探测的 ARM32 runtime 资源目录')
    parser.add_argument('--output', type=Path, help='新的空输出目录；默认在 TMPDIR 建立独立目录')
    args = parser.parse_args(argv)
    args.project = args.project.resolve()
    args.tools = (args.tools or args.project / 'build-sensitive/bin').resolve()
    args.ndk = args.ndk.resolve()
    if args.output:
        args.output = args.output.resolve()
        require(not args.output.exists() or not any(args.output.iterdir()), 'output must be a new/empty directory')
        args.output.mkdir(parents=True, exist_ok=True)
    else:
        args.output = Path(tempfile.mkdtemp(prefix='xollvm-acceptance-', dir=os.environ.get('TMPDIR')))
    card = os.environ.get('XOLLVM_ZONE_CARD', '')
    run = Runner(args.output, secrets=[card])
    report = {'mode': args.mode, 'status': 'FAIL', 'steps': run.steps, 'results': {},
              'project': str(args.project), 'tools': str(args.tools), 'ndk': str(args.ndk)}
    try:
        if args.mode in ('cloud', 'all'):
            require(bool(card), 'set XOLLVM_ZONE_CARD for real cloud acceptance')
        if args.mode in ('arm32', 'all'):
            report['results']['arm32'] = arm32(args, run)
        if args.mode in ('cloud', 'all'):
            report['results']['cloud'] = cloud(args, run, card)
        report['status'] = 'PASS'
    except (AcceptanceError, OSError, ValueError, KeyError) as error:
        report['error'] = run.redact(str(error))
    finally:
        # JSON 不重复嵌入冗长输出；日志保留完整脱敏证据。
        for row in run.steps:
            row.pop('output', None)
        (args.output / 'report.json').write_text(run.redact(json.dumps(report, indent=2, ensure_ascii=False)) + '\n')
    print(f'{report["status"]}: {args.output / "report.json"}')
    if 'error' in report:
        print(report['error'])
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
