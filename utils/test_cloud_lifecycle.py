"""实际云值线程：shutdown 等待请求、唤醒预取等待并允许重新启动。"""
import subprocess
from pathlib import Path
import pytest


@pytest.fixture(scope='module')
def cloud_binary(tmp_path_factory):
    repo = Path(__file__).resolve().parents[1]
    root = repo.parents[2] if repo.parent.name == '.worktrees' else repo.parent
    rt = root / 'demo/jni/zone_runtime'
    ndk = root.parent / 'android-ndk-r30-ollvm-r23-beta3/toolchains/llvm/prebuilt/linux-arm64'
    ssl = root / 'demo/obj/openssl/arm64-v8a'
    work = tmp_path_factory.mktemp('cloud-life')
    src = work / 'test.cpp'
    src.write_text(r'''
#include "cloud_value_manager.h"
#include <future>
#include <condition_variable>
#include <iostream>
static std::mutex m;
static std::condition_variable cv;
static bool entered = false, release_request = false;
extern "C" int xollvm_zone_vm_dispatch_refresh() {
    std::unique_lock<std::mutex> lock(m);
    entered = true; cv.notify_all();
    cv.wait(lock, [] { return release_request; });
    return 0;
}
extern "C" int xollvm_zone_vm_dispatch_copy_v(uint8_t*) { return 0; }
int main(int argc, char**) {
    auto& mgr = xollvm::CloudValueManager::getInstance();
    mgr.initialize();
    {
        std::unique_lock<std::mutex> lock(m);
        if (!cv.wait_for(lock, std::chrono::seconds(2), [] { return entered; })) return 3;
    }
    auto stop = std::async(std::launch::async, [&] { mgr.shutdown(); });
    bool returned_early = stop.wait_for(std::chrono::milliseconds(100)) == std::future_status::ready;
    { std::lock_guard<std::mutex> lock(m); release_request = true; }
    cv.notify_all();
    if (stop.wait_for(std::chrono::seconds(1)) != std::future_status::ready) std::_Exit(4);
    stop.get();
    if (returned_early) { std::cout << "shutdown overtook request\n"; std::_Exit(5); }
    { std::lock_guard<std::mutex> lock(m); entered = false; }
    mgr.initialize();
    {
        std::unique_lock<std::mutex> lock(m);
        if (!cv.wait_for(lock, std::chrono::seconds(1), [] { return entered; })) std::_Exit(6);
    }
    auto again = std::async(std::launch::async, [&] { mgr.shutdown(); });
    if (again.wait_for(std::chrono::seconds(1)) != std::future_status::ready) std::_Exit(7);
    again.get();
    return 0;
}
''')
    exe = work / 'test'
    cmd = [str(ndk / 'bin/clang++'), '--target=aarch64-linux-android26',
           f'--sysroot={ndk / "sysroot"}', '-std=c++20', '-static-libstdc++',
           '-Wno-deprecated-declarations', f'-I{rt}', f'-I{ssl / "include"}',
           f'-I{rt / "openssl_core/src/include"}',
           str(src), str(rt / 'cloud_value_manager.cpp'),
           '-Wl,--start-group', str(ssl / 'libcrypto.a'),
           *[str(ssl / 'providers' / f) for f in ('libcommon.a', 'libdefault.a', 'liblegacy.a')],
           '-Wl,--end-group', '-ldl', '-pthread', '-o', str(exe)]
    build = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    assert build.returncode == 0, build.stderr
    return exe


def test_shutdown_joins_and_restarts(cloud_binary):
    run = subprocess.run([str(cloud_binary)], capture_output=True, text=True, timeout=5)
    assert run.returncode == 0, run.stdout + run.stderr
