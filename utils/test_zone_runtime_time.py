"""真实 runtime 时间回归：推进时钟，不等待窗口或响应实际过期。"""

import hashlib
import hmac
import struct
import subprocess
from pathlib import Path

import pytest


@pytest.fixture(scope="module", params=["plain", "vm"])
def runtime_time_binary(tmp_path_factory, request):
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
    bool rejected = false;
    if (std::strcmp(argv[1], "fresh-policy") == 0) { r.policy_version = 2; rejected = true; }
    if (std::strcmp(argv[1], "fresh-key") == 0) { r.key_id = "other-key"; rejected = true; }
    if (std::strcmp(argv[1], "fresh-operation") == 0) { r.operation = "other"; rejected = true; }
    if (!client.signTestResponse(&r)) return 3;
    std::string request_hash = r.request_hash;
    std::string device_hash = r.device_id_hash;
    if (std::strcmp(argv[1], "fresh-request") == 0) { request_hash = std::string(64, 'c'); rejected = true; }
    if (std::strcmp(argv[1], "fresh-device") == 0) { device_hash = std::string(64, 'c'); rejected = true; }
    if (std::strcmp(argv[1], "fresh-signature") == 0) { r.next_state = "tampered"; rejected = true; }
    bool expected_accept = fresh && !rejected;
    fake_time = 5000;
    bool dispatch = std::strstr(argv[1], "dispatch") != nullptr;
    bool accepted = dispatch ? client.verifyDispatchResponse(r, r.request_hash, r.device_id_hash)
                              : client.acceptResponse(r, request_hash, device_hash);
    std::cout << "accepted=" << accepted << " expected=" << expected_accept << '\n';
    return accepted != expected_accept || (!dispatch && client.hasState() != expected_accept);
}
'''.replace("VALUE_BYTES", ",".join(str(b) for b in value))
       .replace("EXPECTED_OFFSET", str(expected)))
    exe = work / "time-test"
    client = runtime / "capability_client.cpp"
    hardener = root / "build-sensitive/bin/xollvm-elf-hardener"
    if request.param == "vm":
        opt = root / "build-sensitive/bin/opt"
        if not opt.exists() or not hardener.exists():
            pytest.skip("sensitive toolchain unavailable")
        ir = work / "capability.ll"
        obf = work / "capability.obf.ll"
        client = work / "capability.o"
        compile_ir = subprocess.run(
            [str(clang), "--target=aarch64-linux-android26", f"--sysroot={ndk / 'sysroot'}",
             "-std=c++17", "-O0", "-g0", "-DXOLLVM_ZONE_OBFUSCATE=1",
             f"-I{runtime}", f"-I{openssl / 'include'}", f"-I{runtime / 'openssl_core/src/include'}",
             "-S", "-emit-llvm", str(runtime / "capability_client.cpp"), "-o", str(ir)],
            capture_output=True, text=True, timeout=120)
        assert compile_ir.returncode == 0, compile_ir.stderr
        transform = subprocess.run(
            [str(opt), "-passes=obfuscation", "-obf-seed=20260930", "-obf-verify",
             "-S", str(ir), "-o", str(obf)], capture_output=True, text=True, timeout=120)
        assert transform.returncode == 0, transform.stderr
        obf.write_text("\n".join(line for line in obf.read_text().splitlines()
                                 if not line.startswith("@llvm.global.annotations")) + "\n")
        lower = subprocess.run([str(clang), "--target=aarch64-linux-android26", "-O0",
                                "-c", str(obf), "-o", str(client)],
                               capture_output=True, text=True, timeout=120)
        assert lower.returncode == 0, lower.stderr
    result = subprocess.run(
        [str(clang), "--target=aarch64-linux-android26", f"--sysroot={ndk / 'sysroot'}",
         "-std=c++20", "-static-libstdc++", "-Wno-deprecated-declarations",
         f"-I{runtime}", f"-I{openssl / 'include'}", f"-I{runtime / 'openssl_core/src/include'}",
         str(src), str(runtime / "cloud_value_manager.cpp"),
          str(client), str(runtime / "capability_protocol.cpp"),
         "-Wl,--wrap=time", "-Wl,--wrap=clock_gettime", "-Wl,--wrap=pthread_create",
         "-Wl,--start-group", str(openssl / "libcrypto.a"),
         *[str(openssl / "providers" / lib) for lib in
           ("libcommon.a", "libdefault.a", "liblegacy.a")],
          "-Wl,--end-group", "-Wl,--rosegment", "-ldl", "-pthread", "-o", str(exe)],
        capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stderr
    if request.param == "vm":
        for command in (["audit", "--input", str(exe)],
                        ["seal", "--input", str(exe), "--output", str(exe)]):
            checked = subprocess.run([str(hardener), *command], capture_output=True,
                                     text=True, timeout=30)
            assert checked.returncode == 0, checked.stdout + checked.stderr
    return exe


@pytest.mark.parametrize("case", ["cloud", "expired", "fresh", "dispatch-expired", "dispatch-fresh",
                                  "fresh-policy", "fresh-key", "fresh-operation", "fresh-request",
                                  "fresh-device", "fresh-signature"])
def test_clock_progression(runtime_time_binary, case):
    run = subprocess.run([str(runtime_time_binary), case], capture_output=True, text=True, timeout=15)
    assert run.returncode == 0, run.stdout + run.stderr
