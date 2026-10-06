from gates import run_gate

import subprocess
import os
import shutil
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
BUILD = Path(os.environ.get("XOLLVM_BUILD_DIR", ROOT.parent / "build")) / "bin"


def compile_android_antidebug(tmp_path, options, extra="", target="aarch64-linux-android24", report=False):
    if not (BUILD / "opt").exists() or not (BUILD / "clang").exists():
        pytest.skip("set XOLLVM_BUILD_DIR to a built xollvm LLVM tree")
    source = tmp_path / "probe.c"
    original = tmp_path / "original.ll"
    transformed = tmp_path / "transformed.ll"
    source.write_text(
        f'__attribute__((annotate("obf: antidebug({options})")))\n'
        'int probe(int x) { return x + 9; }\n' + extra
    )
    subprocess.run([
        str(BUILD / "clang"), f"--target={target}", "-O0",
        "-Xclang", "-disable-O0-optnone", "-S", "-emit-llvm",
        str(source), "-o", str(original),
    ], check=True, capture_output=True, text=True)
    result = subprocess.run([
        str(BUILD / "opt"), "-passes=obfuscation", "-S", str(original),
        *([f"-obf-report-json={tmp_path / 'report.json'}"] if report else []),
        "-o", str(transformed),
    ], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    return transformed.read_text()


@pytest.mark.parametrize("option,expected", [
    ("debuggerProcess=1,rootRequired=1", "/proc/%d/comm"),
    ("injection=1", "frida-agent"),
    ("debugPorts=1", "@connect"),
    ("vpn=1", "/proc/net/dev"),
    ("proxy=1", "http_proxy"),
    ("iptables=1,rootRequired=1", "iptables -t nat -L -n"),
    ("selinux=1", "/sys/fs/selinux/enforce"),
])
def test_android_independent_detector_emitted(tmp_path, option, expected):
    assert expected in compile_android_antidebug(tmp_path, option)


def test_root_only_detector_is_skipped_without_root_required(tmp_path):
    ir = compile_android_antidebug(tmp_path, "iptables=1,debuggerProcess=1")
    assert "iptables -t nat -L -n" not in ir
    assert "/proc/%d/comm" not in ir


def test_root_required_checks_euid(tmp_path):
    ir = compile_android_antidebug(tmp_path, "iptables=1,rootRequired=1")
    assert "@geteuid" in ir


def test_default_does_not_emit_optional_probes(tmp_path):
    ir = compile_android_antidebug(tmp_path, "enabled=1")
    for marker in ("/proc/net/dev", "http_proxy", "iptables -t nat -L -n",
                   "/sys/fs/selinux/enforce", "frida-agent", "@geteuid"):
        assert marker not in ir


def test_tracer_pid_parses_a_non_one_pid(tmp_path):
    ir = compile_android_antidebug(tmp_path, "tracerPid=1")
    assert "@strtol" in ir
    assert "TracerPid:" in ir
    assert "TracerPid: 1" not in ir


def run_android_probe(tmp_path, options, stubs, main="return probe(7);", wraps=(), extra=""):
    if not (os.environ.get("PREFIX", "").endswith("com.termux/files/usr")):
        pytest.skip("native Android runtime tests need Termux")
    compile_android_antidebug(tmp_path, options, extra=extra)
    harness = tmp_path / "harness.c"
    harness.write_text('int probe(int);\n' + stubs + '\nint main(void) {' + main + '}\n')
    obj = tmp_path / "probe.o"
    exe = tmp_path / "probe"
    result = subprocess.run([str(BUILD / "clang"), "-O2", "-fPIC", "-c",
                             str(tmp_path / "transformed.ll"), "-o", str(obj)],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    host_clang = shutil.which("clang")
    assert host_clang is not None
    result = subprocess.run([host_clang, str(obj), str(harness),
                             *["-Wl,--wrap=" + w for w in wraps], "-o", str(exe)],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    return subprocess.run([str(exe)], capture_output=True, timeout=10).returncode


def file_fixture(body, *, uid=0):
    import json
    # Only the detector's fopen is replaced; the generated parser and real stdio run.
    payload = 'return 0;' if body is None else (
        f'FILE *f = tmpfile(); fputs({json.dumps(body)}, f); rewind(f); return f;')
    return '#include <stdio.h>\n#include <unistd.h>\n' + (
        f'unsigned int __wrap_geteuid(void) {{ return {uid}; }}\n'
        f'FILE *__wrap_fopen(const char *p, const char *m) {{ {payload} }}\n')


@pytest.mark.parametrize("text,strict,expected", [
    ("Name:\tprobe\nTracerPid:\t0\n", 0, 16),
    ("Name:\tprobe\nTracerPid:\t4827\n", 0, 0),
    ("TracerPid: 87\n", 0, 0),
    ("Name:\tprobe\n", 1, 0),
    ("TracerPid:\tgarbage\n", 1, 0),
    ("TracerPid:\t0junk\n", 1, 0),
    ("TracerPid:\t-1\n", 1, 0),
    (None, 0, 16),
    (None, 1, 0),
])
def test_tracer_runtime(tmp_path, text, strict, expected):
    assert run_android_probe(tmp_path, f"tracerPid=1,rootRequired={strict}",
                             file_fixture(text), wraps=("fopen", "geteuid")) == expected


@pytest.mark.parametrize("text,strict,expected", [
    ("1\n", 0, 16), ("0\n", 0, 0), ("invalid\n", 1, 0),
    ("1garbage\n", 1, 0), ("1\n0\n", 1, 0), ("", 1, 0),
    (None, 0, 16), (None, 1, 0),
])
def test_selinux_runtime(tmp_path, text, strict, expected):
    assert run_android_probe(tmp_path, f"selinux=1,rootRequired={strict}",
                             file_fixture(text), wraps=("fopen", "geteuid")) == expected


@pytest.mark.parametrize("uid,strict,expected", [(2000, 1, 0), (0, 1, 16), (2000, 0, 16)])
def test_root_permission_runtime(tmp_path, uid, strict, expected):
    assert run_android_probe(tmp_path, f"selinux=1,rootRequired={strict}",
                             file_fixture("1\n", uid=uid), wraps=("fopen", "geteuid")) == expected


def test_root_failure_does_not_execute_privileged_probe(tmp_path):
    stubs = '''#include <stdio.h>
#include <stdlib.h>
unsigned int __wrap_geteuid(void) { return 2000; }
FILE *__wrap_popen(const char *c, const char *m) { _Exit(91); }
'''
    assert run_android_probe(tmp_path, "iptables=1,rootRequired=1", stubs,
                             wraps=("geteuid", "popen")) == 0


@pytest.mark.parametrize("text,expected", [
    ("Chain OUTPUT (policy ACCEPT)\ntarget prot opt source destination\n", 16),
    ("Chain OUTPUT (policy ACCEPT)\nREDIRECT tcp -- anywhere anywhere redir ports 8080\n", 0),
    ("Chain OUTPUT (policy ACCEPT)\nDNAT tcp -- anywhere anywhere to:127.0.0.1:8080\n", 0),
    ("", 0),
])
def test_iptables_runtime(tmp_path, text, expected):
    import json
    stubs = f'''#include <stdio.h>
unsigned int __wrap_geteuid(void) {{ return 0; }}
FILE *__wrap_popen(const char *c, const char *m) {{
    FILE *f = tmpfile(); fputs({json.dumps(text)}, f); rewind(f); return f;
}}
int __wrap_pclose(FILE *f) {{ return fclose(f); }}
'''
    assert run_android_probe(tmp_path, "iptables=1,rootRequired=1", stubs,
                             wraps=("geteuid", "popen", "pclose")) == expected


def test_new_checks_not_emitted_for_linux(tmp_path):
    ir = compile_android_antidebug(tmp_path,
        "selinux=1,iptables=1,debuggerProcess=1,injection=1,proxy=1,vpn=1,debugPorts=1,rootRequired=1,dynamic=1",
        target="aarch64-linux-gnu")
    for symbol in ("__obf_ad_", "@geteuid", "@pthread_create", "@fopen", "@popen"):
        assert symbol not in ir


def test_dynamic_keeps_distinct_detector_configurations(tmp_path):
    ir = compile_android_antidebug(tmp_path, "proxy=1,dynamic=1,interval=50", extra='''
__attribute__((annotate("obf: antidebug(selinux=1,dynamic=1,interval=100)")))
int other(int x) { return x + 10; }
''')
    import re
    monitors = re.findall(r"define internal ptr @__obf_antidebug_monitor[^ (]*\([^}]+}", ir)
    assert len(monitors) == 2


def test_root_required_alone_does_not_enable_detectors(tmp_path):
    ir = compile_android_antidebug(tmp_path, "rootRequired=1")
    assert "@geteuid" not in ir
    assert "__obf_ad_" not in ir


@pytest.mark.parametrize("option,text,strict,expected", [
    ("maps", "1000-2000 r-xp 00000000 00:00 0 /data/libok.so\n", 0, 16),
    ("maps", "1000-2000 r-xp 00000000 00:00 0 /data/gdbserver\n", 0, 0),
    ("injection", "1000-2000 r-xp 00000000 00:00 0 /data/frida-agent.so\n", 0, 0),
    ("injection", "1000-2000 r-xp 00000000 00:00 0 /data/libok.so\n", 0, 16),
    ("injection", "broken maps\n", 1, 0),
    ("injection", "1000-2000 rrrr 0 00:00 0 /data/libok.so\n", 1, 0),
    ("injection", "1000-2000 r-xp 0 nonsense 0 /data/libok.so\n", 1, 0),
    ("injection", None, 1, 0),
    ("injection", None, 0, 16),
    ("injection", "1000-2000 r-xp 00000000 00:00 0 /data/" + "a" * 5000 + "/frida-agent.so\n", 0, 0),
    ("injection", "1000-2000 r-xp 00000000 00:00 0 /data/libok.so\n" * 120 +
     "3000-4000 r-xp 00000000 00:00 0 /data/frida-agent.so\n", 0, 0),
    ("vpn", "Inter-| Receive | Transmit\n face |bytes packets\n lo: " + "0 " * 16 + "\n", 0, 16),
    ("vpn", " tun42: " + "0 " * 16 + "\n", 0, 0),
    ("vpn", " atun42: " + "0 " * 16 + "\n", 0, 16),
    ("vpn", " wlan0: invalid\n", 1, 0),
    ("vpn", " wlan0: -1 " + "0 " * 15 + "\n", 1, 0),
    ("vpn", " wlan0: " + "0 " * 16 + "garbage\n", 1, 0),
    ("vpn", " wlan0: 18446744073709551616 " + "0 " * 15 + "\n", 1, 0),
    ("vpn", None, 0, 16),
    ("vpn", None, 1, 0),
])
def test_file_detectors_runtime(tmp_path, option, text, strict, expected):
    assert run_android_probe(tmp_path, f"{option}=1,rootRequired={strict}",
                             file_fixture(text), wraps=("fopen", "geteuid")) == expected


@pytest.mark.parametrize("name,value,expected", [
    ("http_proxy", "http://127.0.0.1:8080", 0),
    ("ALL_PROXY", "socks5://127.0.0.1:1080", 0),
    ("https_proxy", "", 16),
    ("no_proxy", "localhost", 16),
])
def test_proxy_runtime(tmp_path, name, value, expected):
    import json
    stubs = '#include <string.h>\n' + (
        f'char *__wrap_getenv(const char *name) {{ return strcmp(name, {json.dumps(name)}) == 0 '
        f'? {json.dumps(value)} : 0; }}\n')
    assert run_android_probe(tmp_path, "proxy=1", stubs, wraps=("getenv",)) == expected


@pytest.mark.parametrize("mode,strict,expected", [
    (0, 0, 0), (1, 0, 16), (2, 1, 0), (2, 0, 16),
    (3, 1, 0), (3, 0, 16), (4, 1, 16), (5, 1, 0),
    (6, 1, 0), (6, 0, 16),
])
def test_port_runtime(tmp_path, mode, strict, expected):
    stubs = f'''#include <sys/socket.h>
#include <netinet/in.h>
#include <poll.h>
#include <errno.h>
#include <stdlib.h>
unsigned int __wrap_geteuid(void) {{ return 0; }}
int __wrap_socket(int domain, int type, int protocol) {{
    if ({mode} == 2) {{ errno = EACCES; return -1; }}
    return 91;
}}
int __wrap_connect(int fd, const struct sockaddr *addr, socklen_t len) {{
    const struct sockaddr_in *a = (const struct sockaddr_in*)addr;
    if (len != sizeof(*a) || a->sin_family != AF_INET || a->sin_addr.s_addr != htonl(0x7f000001)) _Exit(93);
    unsigned port = ntohs(a->sin_port);
    if (port != 23946 && port != 23947 && port != 27042) _Exit(94);
    if ({mode} == 0) return 0;
    errno = {mode} == 1 ? ECONNREFUSED : EINPROGRESS;
    return -1;
}}
int __wrap_poll(struct pollfd *p, nfds_t count, int timeout) {{
    return {mode} == 3 ? 0 : 1;
}}
int __wrap_getsockopt(int fd, int level, int option, void *value, socklen_t *len) {{
    *(int*)value = {mode} == 4 || {mode} == 6 ? ECONNREFUSED : 0;
    *len = {mode} == 6 ? 0 : sizeof(int); return 0;
}}
int __wrap_close(int fd) {{ if (fd != 91) _Exit(95); return 0; }}
'''
    assert run_android_probe(tmp_path, f"debugPorts=1,rootRequired={strict}", stubs,
        wraps=("geteuid", "socket", "connect", "poll", "getsockopt", "close")) == expected


@pytest.mark.parametrize("comm,mode,expected", [
    ("normal_app\n", 0, 16), ("gdbserver\n", 0, 0),
    ("mygdbserver_app\n", 0, 16), ("frida-server\n", 0, 0),
    (None, 1, 0), (None, 2, 16), (None, 3, 0),
])
def test_process_runtime(tmp_path, comm, mode, expected):
    stubs = file_fixture(comm) + f'''
#include <dirent.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
DIR *__wrap_opendir(const char *name) {{ return (DIR*)1; }}
struct dirent *__wrap_readdir(DIR *dir) {{
    static struct dirent ent;
    static int count;
    if (count++) {{ errno = {mode} == 3 ? EACCES : 0; return 0; }}
    strcpy(ent.d_name, "321");
    return &ent;
}}
int __wrap_closedir(DIR *dir) {{ return 0; }}
'''
    if comm is None:
        stubs = stubs.replace('return 0; }\n\n#include <dirent.h>',
            f'errno = {2 if mode == 2 else 13}; return 0; }}\n\n#include <dirent.h>')
        stubs = '#include <errno.h>\n' + stubs
    assert run_android_probe(tmp_path, "debuggerProcess=1,rootRequired=1", stubs,
        wraps=("geteuid", "fopen", "opendir", "readdir", "closedir")) == expected


def test_dynamic_detection_survives_later_clean_entry(tmp_path):
    stubs = '''#include <pthread.h>
#include <string.h>
#include <stdatomic.h>
#include <unistd.h>
static atomic_int detected;
static atomic_int clean;
static pthread_t main_thread;
static void *(*saved_start)(void*);
static void *saved_arg;
int __real_pthread_create(pthread_t*, const pthread_attr_t*, void *(*)(void*), void*);
static void *run(void *arg) {
    void *result = saved_start(saved_arg); return result;
}
int __wrap_pthread_create(pthread_t *t, const pthread_attr_t *a, void *(*fn)(void*), void *arg) {
    main_thread = pthread_self(); saved_start = fn; saved_arg = arg;
    return __real_pthread_create(t, a, run, 0);
}
char *__wrap_getenv(const char *name) {
    if (!pthread_equal(pthread_self(), main_thread) && strcmp(name, "http_proxy") == 0) {
        if (!atomic_load(&clean)) { atomic_store(&detected, 1); return "proxy"; }
    }
    return 0;
}
'''
    main = '''for (int i = 0; i < 200 && !atomic_load(&detected); ++i) usleep(1000);
    if (!atomic_load(&detected)) return 90;
    usleep(100000); atomic_store(&clean, 1); usleep(100000);
    return probe(7);'''
    assert run_android_probe(tmp_path, "proxy=1,dynamic=1,interval=50", stubs,
                             main=main, wraps=("pthread_create", "getenv")) == 0


def test_ptrace_probe_is_stable_across_repeated_entries(tmp_path):
    stubs = '''#include <stdint.h>
#include <errno.h>
static int calls;
long __wrap_ptrace(int request, int pid, void *addr, void *data) {
    if (calls++ == 0) return 0;
    errno = 1;
    return -1;
}
'''
    main = '''if (probe(7) != 16) return 90;
    if (probe(7) != 16) return 91;
    return 0;'''
    assert run_android_probe(tmp_path, "ptrace=1", stubs, main=main,
                             wraps=("ptrace",)) == 0


def test_sync_does_not_share_dynamic_latch(tmp_path):
    ir = compile_android_antidebug(tmp_path, "proxy=1,dynamic=1", extra='''
__attribute__((annotate("obf: antidebug(proxy=1)")))
int other(int x) { return x + 10; }
''')
    import re
    states = re.findall(r"^@__obf_antidebug_response[^ ]* =", ir, re.M)
    assert len(states) == 2


def test_default_gate_rejects_new_artifacts():
    assert run_gate("antidebug_default_off", obf_ir="define i32 @f() { ret i32 0 }") is None
    assert run_gate("antidebug_default_off", obf_ir="define i1 @__obf_ad_check() { ret i1 false }")


def test_tracer_gate_requires_only_tracer_dependencies(tmp_path):
    ir = compile_android_antidebug(tmp_path, "tracerPid=1")
    assert run_gate("antidebug_tracer_symbols", obf_ir=ir) is None
    assert run_gate("antidebug_tracer_symbols", obf_ir=ir.replace("@getline", "@missing"))


def test_dynamic_gate_requires_single_thread_creation(tmp_path):
    ir = compile_android_antidebug(tmp_path, "tracerPid=1,dynamic=1", extra='''
__attribute__((annotate("obf: antidebug(tracerPid=1,dynamic=1)")))
int other(int x) { return x + 10; }
''')
    assert run_gate("antidebug_dynamic_singleton", obf_ir=ir) is None
    assert run_gate("antidebug_dynamic_singleton", obf_ir=ir.replace("@pthread_join", "@missing"))


def test_report_includes_android_detectors_and_root_policy(tmp_path):
    import json
    compile_android_antidebug(tmp_path,
        "debuggerProcess=1,injection=1,debugPorts=1,vpn=1,proxy=1,iptables=1,selinux=1,rootRequired=1",
        report=True)
    report = json.loads((tmp_path / "report.json").read_text())
    record = next(f for f in report["functions"] if f["name"] == "probe")["anti_debug"]
    assert record["enabled"] is True
    assert record["root_required"] is True
    assert set(record["detectors"]) == {
        "debuggerProcess", "injection", "debugPorts", "vpn", "proxy", "iptables", "selinux"}


def test_dynamic_thread_is_joined_on_exit(tmp_path):
    stubs = '''#include <pthread.h>
#include <stdlib.h>
static int joined;
int __real_pthread_join(pthread_t, void**);
int __wrap_pthread_join(pthread_t t, void **result) {
    int rc = __real_pthread_join(t, result); if (rc == 0) joined++; return rc;
}
char *__wrap_getenv(const char *name) { return 0; }
__attribute__((destructor(101))) static void verify_join(void) {
    if (joined != 1) _Exit(92);
}
'''
    assert run_android_probe(tmp_path, "proxy=1,dynamic=1,interval=60000", stubs,
                             wraps=("pthread_join", "getenv")) == 16


@pytest.mark.parametrize("strict,expected", [(0, 16), (1, 0)])
def test_dynamic_thread_creation_failure(tmp_path, strict, expected):
    stubs = '''#include <pthread.h>
#include <stdlib.h>
unsigned int __wrap_geteuid(void) { return 0; }
int __wrap_pthread_create(pthread_t *t, const pthread_attr_t *a, void *(*fn)(void*), void *arg) { return 11; }
int __wrap_pthread_join(pthread_t t, void **result) { _Exit(93); }
char *__wrap_getenv(const char *name) { return 0; }
'''
    assert run_android_probe(tmp_path, f"proxy=1,dynamic=1,rootRequired={strict}", stubs,
                             wraps=("pthread_create", "pthread_join", "getenv", "geteuid")) == expected


def test_integrity_with_vm_keeps_hash_constructor(tmp_path):
    ir = compile_android_antidebug(tmp_path, "integrity=1", extra='''
__attribute__((annotate("obf: vm(minBlocks=1), antidebug(integrity=1)")))
int vm_probe(int x) { return x * 3 + 7; }
''')
    assert "vm_probe.vm.hash.ctor" in ir
    assert "vm.hash.fail" in ir
