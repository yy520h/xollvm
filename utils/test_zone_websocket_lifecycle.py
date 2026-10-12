"""静默本机 WebSocket 服务：析构停止并回收保活及收包线程。"""
import socket
import subprocess
import threading
import pytest
from pathlib import Path


@pytest.mark.parametrize('reconnect', [False, True])
def test_websocket_destruction_joins_workers(tmp_path, reconnect):
    repo = Path(__file__).resolve().parents[1]
    root = repo.parents[2] if repo.parent.name == '.worktrees' else repo.parent
    rt = root / 'demo/jni/zone_runtime'
    ndk = root.parent / 'android-ndk-r30-ollvm-r23-beta3/toolchains/llvm/prebuilt/linux-arm64'
    source = tmp_path / 'ws.cpp'
    source.write_text(r'''
#include <iostream>
#include "Core/WebSocketClient.hpp"
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
int main(int argc, char** argv) {
    auto* client = new ZoneWebSocketClient(std::string("ws://127.0.0.1:") + argv[1]);
    if (!client->con_status) return 2;
    client->StartKeepAlive();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    if (argc > 2) {
        bool received = false;
        for (int i = 0; i < 100 && !received; ++i) {
            received = !client->GetMessages().empty();
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        if (!received) std::_Exit(7);
    }
    auto stop = std::async(std::launch::async, [&] { delete client; });
    if (stop.wait_for(std::chrono::seconds(1)) != std::future_status::ready) std::_Exit(5);
    stop.get();
    if (joins.load() != 2) std::_Exit(6);
    return 0;
}
''')
    exe = tmp_path / 'ws'
    build = subprocess.run([str(ndk / 'bin/clang++'), '--target=aarch64-linux-android26',
                            f'--sysroot={ndk / "sysroot"}', '-std=c++20', '-static-libstdc++',
                            f'-I{rt}', str(source), str(rt / 'Core/cyanray/WebSocketClient.cpp'),
                            '-Wl,--wrap=pthread_join', '-pthread', '-o', str(exe)],
                           capture_output=True, text=True, timeout=120)
    assert build.returncode == 0, build.stderr
    with socket.socket() as server:
        server.bind(('127.0.0.1', 0))
        server.listen(1)
        server.settimeout(5)
        def serve():
            if reconnect:
                with server.accept()[0] as peer:
                    peer.recv(4096)
                    peer.sendall(b'HTTP/1.1 101 Switching Protocols\r\n\r\n')
                    # 握手之后主动断开，驱动真实的丢线回调重连。
                    threading.Event().wait(0.05)
            with server.accept()[0] as peer:
                peer.settimeout(5)
                peer.recv(4096)
                peer.sendall(b'HTTP/1.1 101 Switching Protocols\r\n\r\n')
                if reconnect:
                    threading.Event().wait(0.05)
                    peer.sendall(b'\x81\x02ok')
                try:
                    while peer.recv(4096):
                        pass
                except (TimeoutError, ConnectionResetError):
                    pass
        thread = threading.Thread(target=serve)
        thread.start()
        try:
            run = subprocess.run([str(exe), str(server.getsockname()[1]), *(['reconnect'] if reconnect else [])],
                                 capture_output=True, text=True, timeout=5)
        finally:
            thread.join(timeout=6)
    assert run.returncode == 0, f'{run.returncode}: {run.stdout}{run.stderr}'
