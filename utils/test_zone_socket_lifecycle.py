"""本机 TCP 服务验证 SDK socket 析构等待收包和保活线程结束。"""
import subprocess
from pathlib import Path


def test_socket_destruction_joins_workers(tmp_path):
    repo = Path(__file__).resolve().parents[1]
    root = repo.parents[2] if repo.parent.name == '.worktrees' else repo.parent
    rt = root / 'demo/jni/zone_runtime'
    ndk = root.parent / 'android-ndk-r30-ollvm-r23-beta3/toolchains/llvm/prebuilt/linux-arm64'
    source = tmp_path / 'socket.cpp'
    source.write_text(r'''
#include "Core/SocketClientCore.h"
#include <atomic>
#include <future>
#include <pthread.h>
static std::atomic<int> joins;
extern "C" int __real_pthread_join(pthread_t, void**);
extern "C" int __wrap_pthread_join(pthread_t t, void** r) {
    int rc = __real_pthread_join(t, r);
    if (!rc) ++joins;
    return rc;
}
int main() {
    int server = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET; addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(server, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) || listen(server, 1)) return 2;
    socklen_t len = sizeof(addr);
    if (getsockname(server, reinterpret_cast<sockaddr*>(&addr), &len)) return 3;
    SocketReadMsgContainer messages;
    auto* client = new SocketClientCore("127.0.0.1", ntohs(addr.sin_port), messages);
    int peer = accept(server, nullptr, nullptr);
    if (peer < 0 || !client->con_status) return 4;
    send(peer, "ok<~end~>", 9, MSG_NOSIGNAL);
    bool received = false;
    for (int i = 0; i < 100 && !received; ++i) {
        { std::lock_guard<std::mutex> lock(messages.lockObject);
          received = messages.read_msg.size() == 1 && messages.read_msg[0] == "ok"; }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    if (!received) std::_Exit(7);
    auto stop = std::async(std::launch::async, [&] { delete client; });
    if (stop.wait_for(std::chrono::seconds(1)) != std::future_status::ready) std::_Exit(5);
    stop.get();
    if (joins.load() != 2) std::_Exit(6);
    close(peer); close(server);
    return 0;
}
''')
    exe = tmp_path / 'socket'
    build = subprocess.run([str(ndk / 'bin/clang++'), '--target=aarch64-linux-android26',
                            f'--sysroot={ndk / "sysroot"}', '-std=c++20', '-static-libstdc++',
                            f'-I{rt}', str(source), str(rt / 'Core/SocketClientCore.cpp'),
                            '-Wl,--wrap=pthread_join', '-pthread', '-o', str(exe)],
                           capture_output=True, text=True, timeout=120)
    assert build.returncode == 0, build.stderr
    run = subprocess.run([str(exe)], capture_output=True, text=True, timeout=5)
    assert run.returncode == 0, f'{run.returncode}: {run.stdout}{run.stderr}'
