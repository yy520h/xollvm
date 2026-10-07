"""阻塞网络边界，验证真实 wrapper 与清理/重新初始化的串行关系。"""

import subprocess
from pathlib import Path

import pytest


@pytest.fixture(scope="module")
def concurrency_binary(tmp_path_factory):
    repo = Path(__file__).resolve().parents[1]
    root = repo.parents[2] if repo.parent.name == ".worktrees" else repo.parent
    runtime = root / "demo/jni/zone_runtime"
    ndk = root.parent / "android-ndk-r30-ollvm-r23-beta3/toolchains/llvm/prebuilt/linux-arm64"
    openssl = root / "demo/obj/openssl/arm64-v8a"
    if not (ndk / "bin/clang++").exists() or not (openssl / "libcrypto.a").exists():
        pytest.skip("native NDK/OpenSSL unavailable")
    work = tmp_path_factory.mktemp("runtime-concurrency")
    src = work / "concurrency.cpp"
    src.write_text(r'''
#include "zone_wrapper.cpp"
#include <future>
static std::mutex network_mutex;
static std::condition_variable network_wake;
static bool entered = false, released = false;
static std::atomic<bool> destroyed_during_request{false};
ZoneHelper::ZoneHelper(const std::string&, const std::string&, const std::string&,
    const std::string&, const eum_EncryptType&, const eum_LoginType&,
    const eum_AgreementType&, eum_NetworkRegion) {}
ZoneHelper::~ZoneHelper() {
    std::lock_guard<std::mutex> lock(network_mutex);
    if (entered && !released) destroyed_during_request = true;
}
int ZoneHelper::LoginC(ApiResponse&, const std::string&, std::string, std::string) { return 0; }
int ZoneHelper::HeartBeat(ApiResponse&) { return 0; }
int ZoneHelper::Logout(ApiResponse&) { return 0; }
int ZoneHelper::GetAntiAlgorithmValue(ApiResponse&, const std::string&, std::string) {
    std::unique_lock<std::mutex> lock(network_mutex);
    entered = true;
    network_wake.notify_all();
    network_wake.wait(lock, [] { return released; });
    return 0;
}
static void initialize() {
    if (!xollvm_zone_initialize("fixture", "1", "key", "iv", "capability_v1", "key-1", 120, 180))
        std::abort();
    xollvm_zone_set_shutdown_mode(0);
    std::lock_guard<std::mutex> lock(state().mutex);
    state().loggedIn = true;
    state().leaseValid = true;
}
int main(int argc, char** argv) {
    if (argc != 3) return 2;
    initialize();
    auto request = std::async(std::launch::async, [&] {
        return std::string(argv[1]) == "dispatch" ? xollvm_zone_vm_dispatch_refresh()
            : xollvm_zone_capability_begin("demo_sensitive_action", "");
    });
    {
        std::unique_lock<std::mutex> lock(network_mutex);
        if (!network_wake.wait_for(lock, std::chrono::seconds(3), [] { return entered; }))
            std::_Exit(3);
    }
    std::promise<void> attempted;
    auto cleanup = std::async(std::launch::async, [&] {
        attempted.set_value();
        if (std::string(argv[2]) == "clear") xollvm_zone_capability_clear();
        else if (std::string(argv[2]) == "initialize") initialize();
        else xollvm_zone_shutdown();
    });
    attempted.get_future().wait();
    bool overtook = cleanup.wait_for(std::chrono::milliseconds(200)) == std::future_status::ready;
    {
        std::lock_guard<std::mutex> lock(network_mutex);
        released = true;
    }
    network_wake.notify_all();
    int result = request.get();
    cleanup.get();
    std::cout << "cleanup_overtook=" << overtook << " destroyed_during_request="
              << destroyed_during_request << " request_result=" << result << '\n';
    xollvm_zone_shutdown();
    return overtook || destroyed_during_request || result != 0;
}
''')
    exe = work / "concurrency-test"
    command = [str(ndk / "bin/clang++"), "--target=aarch64-linux-android26",
               f"--sysroot={ndk / 'sysroot'}", "-std=c++20", "-static-libstdc++",
               "-Wno-deprecated-declarations", f"-I{runtime}", f"-I{openssl / 'include'}",
               f"-I{runtime / 'openssl_core/src/include'}", str(src),
               *[str(runtime / f) for f in ("capability_client.cpp", "capability_protocol.cpp",
                                          "vm_dispatch_value.cpp", "Core/base64.cpp")],
               "-Wl,--start-group", str(openssl / "libcrypto.a"),
               *[str(openssl / "providers" / f) for f in
                 ("libcommon.a", "libdefault.a", "liblegacy.a")],
               "-Wl,--end-group", "-ldl", "-pthread", "-o", str(exe)]
    build = subprocess.run(command, capture_output=True, text=True, timeout=120)
    assert build.returncode == 0, build.stderr
    return exe


@pytest.mark.parametrize("operation", ["capability", "dispatch"])
@pytest.mark.parametrize("cleanup", ["clear", "initialize", "shutdown"])
def test_cleanup_waits_for_inflight_request(concurrency_binary, operation, cleanup):
    run = subprocess.run([str(concurrency_binary), operation, cleanup],
                         capture_output=True, text=True, timeout=10)
    assert run.returncode == 0, run.stdout + run.stderr
