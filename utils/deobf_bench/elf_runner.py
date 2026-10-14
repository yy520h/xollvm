"""构建与攻击分离：攻击子进程的唯一输入是 stripped/sealed ELF。"""
from dataclasses import asdict
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile

from .attacks import AttackResult, run_attack_process
from .scorer import group_by_case
from .report import print_table, write_json_report
from vm_hardening_cost import build_fixture

ATTACKS = {
    'aarch64-vm-targets': ('aarch64_vm_targets', 'ELF descriptor inverse + AArch64 disassembly'),
    'aarch64-vm-bytecode': ('aarch64_vm_bytecode', 'AArch64 data-reference reconnaissance; dynamic extraction unsupported'),
}


def run(args, wanted):
    if args.list:
        for attack in sorted(wanted):
            print(f'{attack}: final stripped AArch64 max ELF (arithmetic fixture)')
        return 0
    if not args.build_dir:
        print('error: --build-dir required')
        return 1
    parent = Path(args.work) if args.work else Path.cwd()/'deobf_bench_work'
    parent.mkdir(parents=True,exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix='run-',dir=parent))
    build = Path(args.build_dir).resolve()/'bin'
    results = []
    for seed in map(int,args.seeds.split(',')):
        fixture = work/f'build-{seed}'
        built = build_fixture(fixture,build/'opt',build/'xollvm-elf-hardener',seed,'arithmetic',args.case_timeout)
        for attack in sorted(wanted):
            module,technique = ATTACKS[attack]
            if built['status'] != 'OK':
                results.append(AttackResult('aarch64-max',attack,seed,built['status'],None,
                    'fixture build/native failed: '+built.get('detail',''),'toolchain',technique))
                continue
            # attack cwd 只有 ELF；argv 不传 seed、key、IR、原始 descriptor 或明文。
            attack_dir = Path(tempfile.mkdtemp(prefix='attack-',dir=work))
            elf = attack_dir/'input.elf'
            shutil.copyfile(built['artifact'],elf)
            result = run_attack_process('aarch64-max',attack,seed,
                [sys.executable,'-B','-m',f'deobf_bench.attacks.{module}',str(elf)],
                timeout=args.case_timeout,tool='python+llvm-objdump',technique=technique,
                cwd=attack_dir,env=dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1])))
            result.extra['artifactSHA256'] = built['artifactSHA256']
            results.append(result)
            print(f'{attack} seed={seed}: {result.status} — {result.detail}',flush=True)
    scores = group_by_case(results)
    print_table(scores)
    if args.json_report:
        path = Path(args.json_report)
        write_json_report(scores,path)
        data = json.loads(path.read_text())
        data.update(work=str(work),results=[asdict(r) for r in results],
            threatModel='attack processes receive final ELF only; tool implementations may know the public format; no dynamic whitebox extraction implemented')
        path.write_text(json.dumps(data,indent=2)+'\n')
    return 1 if any(r.status in ('TIMEOUT','TOOL_ERROR') for r in results) else 0
