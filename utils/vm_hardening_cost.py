"""相同 NDK 后端下测量 old/new max；每个子进程独立 wait4 峰值 RSS。"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import struct
import subprocess
import tempfile
import time

from vm_hardening_support import annotation, tools

FIXTURES = {
    'arithmetic': ('%s = add i64 %a,%b\n %r = xor i64 %s,7\n ret i64 %r', '(a+b)^7'),
    'branch': ('%c = icmp ult i64 %a,%b\n br i1 %c,label %yes,label %no\nyes:\n %s = add i64 %a,%b\n ret i64 %s\nno:\n %d = sub i64 %a,%b\n ret i64 %d', 'a<b?a+b:a-b'),
    'memory': ('%q = getelementptr i64,ptr %p,i64 1\n %s = add i64 %a,%b\n store i64 %s,ptr %q,align 1\n %v = load i64,ptr %q,align 1\n %r = xor i64 %v,%b\n ret i64 %r', '(a+b)^b'),
    'call': ('%r = call i64 @helper(i64 %a,i64 %b)\n ret i64 %r', '(a^b)+17'),
    'nested': ('%s = add i64 %a,%b\n %t = xor i64 %s,%b\n %u = mul i64 %t,3\n %r = sub i64 %u,%a\n ret i64 %r', '(((a+b)^b)*3)-a'),
}


def measure_process(argv, work, timeout):
    start = time.monotonic()
    work = Path(work)
    with tempfile.TemporaryFile(dir=work) as stdout, tempfile.TemporaryFile(dir=work) as stderr:
        try:
            p = subprocess.Popen([str(a) for a in argv], stdout=stdout, stderr=stderr, start_new_session=True)
        except OSError as e:
            return {'status': 'TOOL_ERROR', 'detail': str(e), 'returncode': None,
                    'wallTime': time.monotonic()-start, 'maxRSS': None, 'runtimeNs': None}
        expired = False
        peak = 0
        while True:
            try:
                # wait4 的 high-water 可能含 fork 时继承的父进程峰值；
                # /proc 的 exec 后 VmHWM 仅采样真正运行的工具镜像。
                if Path(f'/proc/{p.pid}/exe').resolve() != Path('/proc/self/exe').resolve():
                    for line in Path(f'/proc/{p.pid}/status').read_text().splitlines():
                        if line.startswith('VmHWM:'):
                            peak = max(peak, int(line.split()[1])*1024)
            except (OSError, ValueError):
                pass
            pid, state, usage = os.wait4(p.pid, os.WNOHANG)
            if pid:
                break
            if time.monotonic()-start >= timeout:
                expired = True
                try:
                    os.killpg(p.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                _, state, usage = os.wait4(p.pid, 0)
                break
            time.sleep(0.01)
        p.returncode = os.waitstatus_to_exitcode(state)
        stdout.seek(0); stderr.seek(0)
        return {'status': 'TIMEOUT' if expired else 'OK' if p.returncode == 0 else 'TOOL_ERROR',
                'returncode': p.returncode, 'wallTime': time.monotonic()-start,
                'maxRSS': peak or int(usage.ru_maxrss)*1024, 'wait4MaxRSS': int(usage.ru_maxrss)*1024, 'runtimeNs': None,
                'stdout': stdout.read().decode(errors='replace'),
                'detail': stderr.read().decode(errors='replace')[-4000:]}


def sha256(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for chunk in iter(lambda: f.read(1024*1024), b''):
            h.update(chunk)
    return h.hexdigest()


def elf_sizes(path):
    d = Path(path).read_bytes()
    off = struct.unpack_from('<Q', d, 40)[0]
    size, count, string_index = struct.unpack_from('<HHH', d, 58)
    if size < 64 or off + size*count > len(d) or string_index >= count:
        raise ValueError('invalid ELF section headers')
    sections = [struct.unpack_from('<IIQQQQIIQQ', d, off+i*size) for i in range(count)]
    strings = sections[string_index]
    names = d[strings[4]:strings[4]+strings[5]]
    result = {'textBytes': 0, 'rodataBytes': 0, 'relocBytes': 0, 'fileBytes': len(d)}
    for name, typ, flags, va, pos, length, *_ in sections:
        label = names[name:names.find(b'\0', name)].decode(errors='replace')
        if flags & 4 and typ != 8:
            result['textBytes'] += length
        if label.startswith('.rodata'):
            result['rodataBytes'] += length
        if typ in (4, 9, 19, 0x60000001, 0x60000002):
            result['relocBytes'] += length
    return result


def build_fixture(work, opt, hardener, seed, fixture, timeout, *, backend_opt='-O0'):
    """构建侧保留 IR；攻击侧仅得到返回的 final ELF，不读本目录。"""
    work = Path(work); work.mkdir(parents=True, exist_ok=True)
    body, expected = FIXTURES[fixture]
    source = ('target triple = "aarch64-unknown-linux-android26"\n'
              'declare i64 @helper(i64,i64)\n'
              'define i64 @target(i64 %a,i64 %b,ptr %p) {\n'+body+'\n}\n'+annotation(['target'], 'vm(preset=max)'))
    src, ir, lowered, harness, obj, exe = (work/n for n in ('input.ll','obf.ll','lowered.ll','harness.cpp','vm.o','final.elf'))
    src.write_text(source)
    harness.write_text('''#include <cstdint>
#include <cstdio>
#include <ctime>
extern "C" uint64_t target(uint64_t,uint64_t,uint64_t*);
extern "C" uint64_t helper(uint64_t a,uint64_t b) { return (a^b)+17; }
static uint64_t ns() { timespec t; clock_gettime(CLOCK_MONOTONIC,&t); return uint64_t(t.tv_sec)*1000000000+t.tv_nsec; }
int main() { uint64_t p[3]={},sum=0; const unsigned n=128;
uint64_t start=ns();
for(unsigned i=0;i<n;++i) { uint64_t a=i*17,b=(i*31)%127;
uint64_t want='''+expected+'''; uint64_t got=target(a,b,p);
if(got!=want) { fprintf(stderr,"semantic mismatch i=%u\\n",i); return 7; } sum+=got; }
printf("{\\"runtimeNs\\":%llu,\\"iterations\\":%u,\\"checksum\\":%llu}\\n",(unsigned long long)(ns()-start)/n,n,(unsigned long long)sum); }
''')
    t = tools()
    steps = {}
    def run(name, argv):
        r = measure_process(argv, work, timeout)
        steps[name] = {k:v for k,v in r.items() if k != 'stdout'}
        if r['status'] != 'OK':
            return r
        return None
    fail = run('opt', [opt,'-passes=obfuscation','-obf-verify',f'-obf-seed={seed}','-S',src,'-o',ir])
    if not fail:
        # 旧 max IR 很大，流式处理避免基准驱动自身占用数百 MB。
        with ir.open() as input_ir, lowered.open('w') as output_ir:
            for line in input_ir:
                if not line.startswith('@llvm.global.annotations'):
                    output_ir.write(line)
        fail = run('backend', [t.clang,'--target=aarch64-linux-android26',f'--sysroot={t.sysroot}',backend_opt,'-c',lowered,'-o',obj])
    if not fail:
        fail = run('link', [t.clangxx,'--target=aarch64-linux-android26',f'--sysroot={t.sysroot}',
            '-std=c++20','-static-libstdc++','-Wl,--rosegment','-Wl,--gc-sections',harness,obj,'-ldl','-pthread','-o',exe])
    if not fail:
        fail = run('strip', [t.clang.parent/'llvm-strip','--strip-all',exe])
    if not fail:
        stages = ['targets','audit']
        # 旧 max 没有 manifest/encoded targets，seal/verify 对它并不适用。
        # 保留正式 audit；不能把缺少 manifest 的策略拒绝当作语义失败。
        image = exe.read_bytes()
        if b'XOVMTGT1' in image or b'XOLINT01' in image:
            stages += ['seal','verify']
        else:
            steps['integrityNotRequired'] = {'status':'NOT_REQUIRED','wallTime':0,'maxRSS':0,'detail':'no VM targets or sensitive manifest'}
        del image
        for stage in stages:
            argv = [hardener,stage,'--input',exe]
            if stage in ('targets','seal'): argv += ['--output',exe]
            fail = run(stage, argv)
            if fail: break
    result = {'seed': seed, 'fixture': fixture, 'config': 'vm(preset=max)', 'backendOpt': backend_opt,
              'steps': steps, 'wallTime': sum(r['wallTime'] for r in steps.values()),
              'compileWallTime': sum(steps[n]['wallTime'] for n in ('opt','backend','link') if n in steps),
              'maxRSS': max((r['maxRSS'] or 0 for r in steps.values()), default=0),
              'runtimeNs': None, 'status': fail['status'] if fail else 'OK', 'artifact': str(exe)}
    if fail:
        result['detail'] = fail['detail']
        return result
    result.update(elf_sizes(exe)); result['artifactSHA256'] = sha256(exe)
    # 独立重复 native 计时，报告中保存全部样本，取中位数。
    runtimes = []
    for _ in range(3):
        native = measure_process([exe], work, timeout)
        if native['status'] != 'OK':
            result.update(status=native['status'], detail=native['detail'])
            return result
        data = json.loads(native['stdout'])
        runtimes.append(data['runtimeNs'])
    result['runtimeSamplesNs'] = runtimes
    result['runtimeNs'] = sorted(runtimes)[1]
    # 仅回收本次构建刚产生的中间文件，保留输入、最终 ELF 和测量数据。
    for generated in (ir, lowered, obj):
        generated.unlink()
    return result


def tool_identity(path):
    p = subprocess.run([str(path),'--version'], capture_output=True, text=True, timeout=10)
    return {'path': str(path), 'sha256': sha256(path), 'version': p.stdout.strip(), 'versionExit': p.returncode}


def resume_row(row, timeout):
    """仅复用已通过编译/link/audit 的旧样本，不重复昂贵编译。"""
    work = Path(row['artifact']).parent
    steps = row['steps']
    if row.get('detail') != 'error: no xollvm integrity manifest found\n' or steps.get('audit',{}).get('status') != 'OK':
        return row
    steps.pop('seal')
    steps['integrityNotRequired'] = {'status':'NOT_REQUIRED','wallTime':0,'maxRSS':0,'detail':'old max no manifest or target descriptor'}
    row.update(elf_sizes(row['artifact']))
    row['artifactSHA256'] = sha256(row['artifact'])
    values = []
    for _ in range(3):
        r = measure_process([row['artifact']],work,timeout)
        if r['status'] != 'OK':
            row.update(status=r['status'],detail=r['detail'])
            return row
        values.append(json.loads(r['stdout'])['runtimeNs'])
    row.update(status='OK', runtimeNs=sorted(values)[1],runtimeSamplesNs=values)
    row.pop('detail',None)
    row['wallTime'] = sum(r['wallTime'] for r in steps.values())
    row['memoryMeasurementNote'] = 'first run wait4 values may inherit driver peak; retained exact original measurements; compiler peaks exceed that floor'
    for name in ('obf.ll','lowered.ll','vm.o'):
        generated = work/name
        if generated.is_file(): generated.unlink()
    return row


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--baseline-opt', type=Path, required=True)
    ap.add_argument('--current-opt', type=Path, required=True)
    ap.add_argument('--seeds', default='1,42,20260930')
    ap.add_argument('--timeout', type=float, default=180)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--resume', action='store_true')
    ap.add_argument('--remeasure-inherited-rss', action='store_true', help='Remeasure current rows from the early wait4-only driver')
    args = ap.parse_args()
    if args.resume:
        data = json.loads(args.output.read_text())
        work = Path(data['work'])
        for label,opt in (('baseline',args.baseline_opt),('current',args.current_opt)):
            if sha256(opt) != data[label]['sha256']:
                raise ValueError(f'{label} tool differs from recorded measurement; start a new output')
        data['rows'] = [resume_row(row,args.timeout) for row in data['rows']]
        if args.remeasure_inherited_rss:
            for i,row in enumerate(data['rows']):
                if row['toolchain']=='current' and 'wait4MaxRSS' not in row['steps']['opt']:
                    corrected = build_fixture(Path(row['artifact']).parent,args.current_opt,tools().hardener,
                        row['seed'],row['fixture'],args.timeout)
                    corrected['toolchain'] = 'current'
                    corrected['previousMeasurement'] = {k:row[k] for k in ('compileWallTime','maxRSS','runtimeNs','artifactSHA256')}
                    data['rows'][i] = corrected
                    args.output.write_text(json.dumps(data,indent=2)+'\n')
        data['units']['maxRSS'] = 'bytes; /proc post-exec VmHWM sampled at10ms, wait4 fallback for short tools; initial baseline compiler peaks exceed inherited floor'
    else:
        work = Path(tempfile.mkdtemp(prefix='max-vm-cost-', dir=args.output.parent))
        data = {'units': {'wallTime':'seconds','maxRSS':'bytes; post-exec /proc VmHWM sampled at10ms, wait4 fallback for short tools','runtimeNs':'nanoseconds per call (128 iterations)'},
            'work': str(work), 'baseline':tool_identity(args.baseline_opt), 'current':tool_identity(args.current_opt),
            'baselineProvenance': {'sourceHEADRecorded': 'ae54339', 'historicalUncommittedPatchHash': None,
                'limitation': 'tools saved before Task1 per ledger; patch hash not captured then and cannot be reconstructed'},
            'backend':tool_identity(tools().clang), 'rows':[], 'ratios':[]}
    for fixture in FIXTURES:
        for seed in map(int,args.seeds.split(',')):
            pair = {}
            for label,opt in (('baseline',args.baseline_opt),('current',args.current_opt)):
                old = next((r for r in data['rows'] if r['fixture']==fixture and r['seed']==seed and r['toolchain']==label),None)
                if old:
                    pair[label] = old
                    continue
                row = build_fixture(work/f'{fixture}-{seed}-{label}',opt,tools().hardener,seed,fixture,args.timeout)
                row['toolchain'] = label
                data['rows'].append(row); pair[label] = row
                print(f'{fixture} seed={seed} {label}: {row["status"]} compile={row["compileWallTime"]:.3f}s runtime={row["runtimeNs"]}', flush=True)
            if all(r['status']=='OK' for r in pair.values()):
                data['ratios'] = [r for r in data['ratios'] if (r['fixture'],r['seed']) != (fixture,seed)]
                data['ratios'].append({'fixture':fixture,'seed':seed, **{k:pair['current'][k]/pair['baseline'][k]
                    if pair['baseline'][k] else None for k in ('compileWallTime','maxRSS','textBytes','rodataBytes','relocBytes','runtimeNs')}})
            args.output.write_text(json.dumps(data,indent=2)+'\n')
    return 0 if all(r['status']=='OK' for r in data['rows']) else 1


if __name__ == '__main__':
    raise SystemExit(main())
