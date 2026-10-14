"""真实子进程分类：故障与超时不能被计为抗分析成功。"""
import json
import subprocess
import sys
from pathlib import Path
import pytest
from deobf_bench import attacks
from deobf_bench.scorer import score_case


@pytest.mark.parametrize('code,status', [
    ('raise SystemExit(7)', 'TOOL_ERROR'),
    ('import os,signal; os.kill(os.getpid(), signal.SIGKILL)', 'TOOL_ERROR'),
    ('import time; time.sleep(5)', 'TIMEOUT'),
    ('print(\'{"status":"UNSUPPORTED","detail":"missing dynamic tool"}\')', 'UNSUPPORTED'),
    ('print(\'{"status":"RECOVERED","detail":"recovered"}\')', 'RECOVERED'),
    ('print("invalid json")', 'TOOL_ERROR')])
def test_real_attack_process_outcomes(tmp_path, code, status):
    result = attacks.run_attack_process('fixture', 'fixture', 1,
        [sys.executable, '-c', code], timeout=0.2, tool='python', technique='real subprocess')
    assert result.status == status
    score = score_case('fixture', 'fixture', [result])
    if status in ('TOOL_ERROR', 'TIMEOUT', 'UNSUPPORTED'):
        assert result.resilience is None and score.resilience is None
    elif status == 'RECOVERED':
        assert score.resilience == 0.0


def test_module_cli_preserves_existing_work(tmp_path):
    work = tmp_path / 'work'; work.mkdir()
    sentinel = work / 'user-data'; sentinel.write_text('keep')
    p = subprocess.run([sys.executable, '-m', 'utils.deobf_bench', '--list',
        '--attacks', 'aarch64-vm-targets', '--work', str(work)],
        capture_output=True, text=True, timeout=10)
    assert p.returncode == 0, p.stderr
    assert 'aarch64' in p.stdout
    assert sentinel.read_text() == 'keep'


def test_stripped_final_elf_targets_recovered_without_ir(tmp_path):
    from vm_hardening_support import annotation, transform, build_native, checked, tools
    from deobf_bench.attacks.aarch64_vm_targets import analyze
    ir = transform(tmp_path, 'define i64 @target(i64 %x) { %r = add i64 %x,7\n ret i64 %r }\n' +
        annotation(['target'], 'vm(encodedTargets=1,hardened=0)'))
    exe = build_native(tmp_path, ir, 'extern "C" unsigned long target(unsigned long); int main() { return target(2)!=9; }', finalize_targets=True)
    checked([tools().clang.parent / 'llvm-strip', '--strip-all', exe])
    checked([tools().hardener, 'seal', '--input', exe, '--output', exe])
    checked([tools().hardener, 'verify', '--input', exe])
    # 攻击接口只接收一个 final ELF 路径。
    outcome = analyze(exe)
    assert outcome['status'] == 'RECOVERED'
    assert outcome['extra']['targets'] > 0
    assert outcome['extra']['disassembled_targets'] > 0


def test_invalid_elf_is_tool_error(tmp_path):
    from deobf_bench.attacks.aarch64_vm_targets import analyze
    elf = tmp_path / 'bad'; elf.write_bytes(b'not an elf')
    assert analyze(elf)['status'] == 'TOOL_ERROR'


def test_measured_process_reports_real_exit_and_memory(tmp_path):
    from vm_hardening_cost import measure_process
    result = measure_process([sys.executable, '-c', 'a=bytearray(8*1024*1024); raise SystemExit(9)'], tmp_path, 10)
    assert result['status'] == 'TOOL_ERROR'
    assert result['returncode'] == 9
    assert result['wallTime'] > 0 and result['maxRSS'] > 0


def test_measured_process_timeout_reaps_child(tmp_path):
    from vm_hardening_cost import measure_process
    result = measure_process([sys.executable, '-c', 'import time; time.sleep(5)'], tmp_path, 0.1)
    assert result['status'] == 'TIMEOUT'
    assert result['runtimeNs'] is None


def test_missing_attack_executable_is_not_resilience(tmp_path):
    result = attacks.run_attack_process('fixture','fixture',1,[str(tmp_path/'missing')],
        timeout=1,tool='missing',technique='missing executable')
    assert result.status == 'TOOL_ERROR'
    assert score_case('fixture','fixture',[result]).resilience is None


def test_timeout_terminates_attack_descendants(tmp_path):
    import os
    import time
    pidfile = tmp_path/'child.pid'
    code = ('import subprocess,sys,time; from pathlib import Path; '
            'p=subprocess.Popen([sys.executable,"-c","import time; time.sleep(30)"]); '
            f'Path({str(pidfile)!r}).write_text(str(p.pid)); time.sleep(30)')
    result = attacks.run_attack_process('fixture','fixture',1,[sys.executable,'-c',code],
        timeout=0.5,tool='python',technique='child cleanup')
    assert result.status == 'TIMEOUT'
    pid = int(pidfile.read_text())
    # 已结束的 orphan zombie 不再耗 CPU/执行攻击，不视为存活工具。
    for _ in range(50):
        status = Path(f'/proc/{pid}/status')
        if not status.exists() or 'State:\tZ' in status.read_text():
            return
        time.sleep(0.02)
    os.kill(pid,9)
    pytest.fail('attack descendant survived timeout')
