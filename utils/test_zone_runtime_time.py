"""真实 runtime 时间回归：推进时钟，不等待窗口或响应实际过期。"""

import hashlib
import hmac
import struct
import subprocess
from pathlib import Path

import pytest


@pytest.fixture(scope="module")
def runtime_time_binary(tmp_path_factory):
    repo = Path(__file__).resolve().parents[1]
    root = repo.parents[2] if repo.parent.name == ".worktrees" else repo.parent
    runtime = root / "demo/jni/zone_runtime"
    ndk = root.parent / "android-ndk-r30-ollvm-r23-beta3/toolchains/llvm/prebuilt/linux-arm64"
    clang = ndk / "bin/clang++"
    openssl = root / "demo/obj/openssl/arm64-v8a"
    if not clang.exists() or not (openssl / "libcrypto.a").exists() or not runtime.exists():
        pytest.skip("native runtime/compiler unavailable")
    work = tmp_path_factory.mktemp("runtime-time")
    # Python 标准 HMAC 独立生成只在窗口 100 下有效的固定云值。
    for nonce in range(100000):
        value = nonce.to_bytes(32, "little")
        digest = hmac.new(value, struct.pack("<Q", 100), hashlib.sha256).digest()
        advanced = hmac.new(value, struct.pack("<Q", 200), hashlib.sha256).digest()
        expected = int.from_bytes(advanced[:8], "little") & 4095
        if int.from_bytes(digest[:8], "little") & 4095 == 0 and expected != 0:
            break
    else:
        raise AssertionError("cannot find cloud fixture")
    src = work / "time.cpp"
    src.write_text(r'''
#include "capability_client.h"
#include "cloud_value_manager.h"
#include <ctime>
#include <cstring>
#include <iostream>
#include <cerrno>
#include <pthread.h>
static time_t fake_time = 1000;
extern "C" time_t __wrap_time(time_t* out) {
    if (out) *out = fake_time;
    return fake_time;
}
extern "C" int __wrap_clock_gettime(clockid_t, timespec* out) {
    out->tv_sec = fake_time; out->tv_nsec = 0; return 0;
}
extern "C" int __wrap_pthread_create(pthread_t*, const pthread_attr_t*,
                                     void* (*)(void*), void*) { return EAGAIN; }
int main(int argc, char** argv) {
    if (argc != 2) return 2;
    if (std::strcmp(argv[1], "cloud") == 0) {
        fake_time = 6000;
        auto& mgr = xollvm::CloudValueManager::getInstance();
        const unsigned char value[32] = {VALUE_BYTES};
        mgr.updateV(value, sizeof(value));
        auto initial = mgr.computeDispatchOffset();
        fake_time = 12000;
        auto advanced = mgr.computeDispatchOffset();
        std::cout << "initial=" << initial << " advanced=" << advanced << '\n';
        return initial != 0 || advanced != EXPECTED_OFFSET;
    }
    xollvm::CapabilityClientConfig config;
    config.operation = "auth";
    config.server_time = 1000;
    xollvm::CapabilityClient client(config);
    bool fresh = std::strstr(argv[1], "fresh") != nullptr;
    xollvm::CapabilityResponse r;
    r.protocol = 1; r.ok = true; r.operation = "auth";
    r.request_hash = std::string(64, 'a'); r.device_id_hash = std::string(64, 'b');
    r.next_state = "next-state"; r.vm_value = "value";
    r.server_time = fresh ? 5000 : 1000;
    r.issued_at = fresh ? 4990 : 990;
    r.expires_at = fresh ? 5050 : 1040;
    r.policy_version = 1; r.key_id = "key-1";
    if (!client.signTestResponse(&r)) return 3;
    fake_time = 5000;
    bool dispatch = std::strstr(argv[1], "dispatch") != nullptr;
    bool accepted = dispatch ? client.verifyDispatchResponse(r, r.request_hash, r.device_id_hash)
                             : client.acceptResponse(r, r.request_hash, r.device_id_hash);
    std::cout << "accepted=" << accepted << " expected=" << fresh << '\n';
    return accepted != fresh;
}
'''.replace("VALUE_BYTES", ",".join(str(b) for b in value))
       .replace("EXPECTED_OFFSET", str(expected)))
    exe = work / "time-test"
    result = subprocess.run(
        [str(clang), "--target=aarch64-linux-android26", f"--sysroot={ndk / 'sysroot'}",
         "-std=c++20", "-static-libstdc++", "-Wno-deprecated-declarations",
         f"-I{runtime}", f"-I{openssl / 'include'}", f"-I{runtime / 'openssl_core/src/include'}",
         str(src), str(runtime / "cloud_value_manager.cpp"),
         str(runtime / "capability_client.cpp"), str(runtime / "capability_protocol.cpp"),
         "-Wl,--wrap=time", "-Wl,--wrap=clock_gettime", "-Wl,--wrap=pthread_create",
         "-Wl,--start-group", str(openssl / "libcrypto.a"),
         *[str(openssl / "providers" / lib) for lib in
           ("libcommon.a", "libdefault.a", "liblegacy.a")],
         "-Wl,--end-group", "-ldl", "-pthread", "-o", str(exe)],
        capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stderr
    return exe


@pytest.mark.parametrize("case", ["cloud", "expired", "fresh", "dispatch-expired", "dispatch-fresh"])
def test_clock_progression(runtime_time_binary, case):
    run = subprocess.run([str(runtime_time_binary), case], capture_output=True, text=True, timeout=15)
    assert run.returncode == 0, run.stdout + run.stderr
