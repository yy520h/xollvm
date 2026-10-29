"""Authenticated Guardian/Worker lifecycle and immutable lease-pin tests."""

from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]


def _compile(tmp_path, name, source, *, testing=True):
    source_path = tmp_path / f"{name}.cpp"
    source_path.write_text(source, encoding="ascii")
    executable = tmp_path / name
    command = [
        "c++", "-std=c++20", "-Wall", "-Wextra", "-Werror", "-pthread",
        "-I", str(ROOT),
    ]
    if testing:
        command.append("-DXOVM_GUARDIAN_TESTING")
    command += [
        str(source_path),
        str(ROOT / "runtime/cloud_material/guardian_channel.cpp"),
        str(ROOT / "runtime/cloud_material/launcher.cpp"),
        str(ROOT / "runtime/cloud_material/dynamic_vm_schema.cpp"),
        str(ROOT / "runtime/cloud_material/dynamic_vm_window_provider.cpp"),
        "-lcrypto", "-o", str(executable),
    ]
    result = subprocess.run(command, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    return executable


def test_authenticated_guardian_worker_lifecycle(tmp_path):
    executable = _compile(tmp_path, "guardian_lifecycle", r'''
#include "runtime/cloud_material/launcher.h"
#include "runtime/cloud_material/dynamic_vm_window_provider.h"

#include <openssl/crypto.h>
#include <cassert>

using namespace xovm::material;

int main() {
    GuardianChannel direct;
    assert(!direct.established());
    assert(direct.poisoned());

    Launcher::StartOptions options;
    options.hello.session_id[0] = 8;
    options.hello.generation = 1;
    options.hello.challenge_counter = 7;
    options.hello.previous_state_digest[0] = 9;
    options.current_window_id = 11;
    options.worker = [](GuardianChannel &channel) {
        assert(channel.established());
        assert(channel.role() == GuardianChannel::Role::Worker);
        assert(channel.peerPid() > 0);
        assert(channel.serveChallenge());
        assert(channel.serveChallenge());
        auto installed = channel.receiveGeneration();
        assert(installed);
        assert(installed->request_id[0] == 12);
        assert(installed->artifact_hash[0] == 3);
        assert(installed->grant.generation == 2);
        assert(installed->grant.window_id == 1);
        assert(installed->grant_key[0] == 6);
        OPENSSL_cleanse(installed->grant_key.data(), installed->grant_key.size());
        assert(channel.receiveShutdown());
        return 0;
    };

    auto child = Launcher::start(options);
    assert(child);
    assert(child->pid() > 0);
    assert(child->channel().established());
    assert(child->channel().role() == GuardianChannel::Role::Guardian);
    assert(child->challenge(8, 1));
    assert(!child->challenge(8, 1));
    assert(child->challenge(9, 1));
    assert(!child->challenge(10, 2));

    GuardianGeneration next;
    next.request_id[0] = 12;
    next.sent_at_ns = 100000000ULL;
    next.artifact_hash[0] = 3;
    next.grant.build_id[0] = 1;
    next.grant.region_id[0] = 2;
    next.grant.session_id = options.hello.session_id;
    next.grant.generation = 2;
    next.grant.window_id = 1;
    next.grant.previous_state_hash = options.hello.previous_state_digest;
    next.grant.next_state_hash[0] = 4;
    next.grant.issued_at_ms = 100;
    next.grant.expires_at_ms = 220;
    next.grant.key_version = 1;
    WindowIssueInput issue;
    issue.build_id = next.grant.build_id;
    issue.region_id = next.grant.region_id;
    issue.session_id = next.grant.session_id;
    issue.generation = next.grant.generation;
    issue.window_id = next.grant.window_id;
    issue.previous_state_hash = next.grant.previous_state_hash;
    issue.next_state_hash = next.grant.next_state_hash;
    issue.now_ms = next.grant.issued_at_ms;
    issue.expires_at_ms = next.grant.expires_at_ms;
    issue.key_version = next.grant.key_version;
    issue.session_secret[0] = 6;
    issue.material.assign(kWindowMaterialSize, 5);
    auto issued = issueWindowGrant(issue);
    assert(issued);
    next.grant = std::move(*issued);
    next.grant_key = issue.session_secret;
    GuardianGeneration skipped;
    skipped.request_id = next.request_id;
    skipped.sent_at_ns = next.sent_at_ns;
    skipped.artifact_hash = next.artifact_hash;
    skipped.grant = next.grant;
    skipped.grant.generation = 3;
    skipped.grant_key[0] = 6;
    assert(!child->channel().installGeneration(std::move(skipped)));
    assert(child->channel().installGeneration(std::move(next)));
    assert((next.grant_key == std::array<uint8_t, 32>{}));
    assert(child->channel().shutdown());
    assert(child->wait() == 0);
    return 0;
}
''')
    result = subprocess.run([str(executable)], capture_output=True, text=True,
                            timeout=10)
    assert result.returncode == 0, result.stderr


def test_generation_install_rejects_wrong_grant_key(tmp_path):
    executable = _compile(tmp_path, "guardian_wrong_key", r'''
#include "runtime/cloud_material/launcher.h"
#include "runtime/cloud_material/dynamic_vm_window_provider.h"

#include <cassert>

using namespace xovm::material;

int main() {
    Launcher::StartOptions options;
    options.hello.session_id[0] = 8;
    options.hello.generation = 1;
    options.hello.challenge_counter = 7;
    options.hello.previous_state_digest[0] = 9;
    options.current_window_id = 11;
    options.worker = [](GuardianChannel &channel) {
        assert(channel.established());
        assert(!channel.receiveGeneration());
        assert(channel.poisoned());
        return 0;
    };

    auto child = Launcher::start(options);
    assert(child);
    GuardianGeneration next;
    next.request_id[0] = 12;
    next.sent_at_ns = 100000000ULL;
    next.artifact_hash[0] = 3;

    WindowIssueInput issue;
    issue.build_id[0] = 1;
    issue.region_id[0] = 2;
    issue.session_id = options.hello.session_id;
    issue.session_secret[0] = 6;
    issue.generation = 2;
    issue.window_id = 1;
    issue.previous_state_hash = options.hello.previous_state_digest;
    issue.next_state_hash[0] = 4;
    issue.now_ms = 100;
    issue.expires_at_ms = 220;
    issue.key_version = 1;
    issue.material.assign(kWindowMaterialSize, 5);
    auto issued = issueWindowGrant(issue);
    assert(issued);
    next.grant = std::move(*issued);
    next.grant_key = issue.session_secret;
    next.grant_key[0] ^= 1;

    assert(!child->channel().installGeneration(std::move(next)));
    assert(child->channel().poisoned());
    assert(child->wait() == 0);
    return 0;
}
''')
    result = subprocess.run([str(executable)], capture_output=True, text=True,
                            timeout=10)
    assert result.returncode == 0, result.stderr


def test_launcher_rejects_multithreaded_fork(tmp_path):
    executable = _compile(tmp_path, "guardian_multithreaded", r'''
#include "runtime/cloud_material/launcher.h"

#include <atomic>
#include <cassert>
#include <thread>

using namespace xovm::material;

int main() {
    std::atomic<bool> stop{false};
    std::atomic<bool> ready{false};
    std::thread peer([&] {
        ready.store(true, std::memory_order_release);
        while (!stop.load(std::memory_order_acquire)) std::this_thread::yield();
    });
    while (!ready.load(std::memory_order_acquire)) std::this_thread::yield();

    Launcher::StartOptions options;
    options.hello.session_id[0] = 1;
    options.hello.generation = 1;
    options.hello.challenge_counter = 1;
    options.hello.previous_state_digest[0] = 2;
    options.current_window_id = 1;
    options.worker = [](GuardianChannel &) { return 0; };
    assert(!Launcher::start(options));

    stop.store(true, std::memory_order_release);
    peer.join();
    return 0;
}
''')
    result = subprocess.run([str(executable)], capture_output=True, text=True,
                            timeout=10)
    assert result.returncode == 0, result.stderr


def test_worker_closes_inherited_descriptors(tmp_path):
    executable = _compile(tmp_path, "guardian_fd_isolation", r'''
#include "runtime/cloud_material/launcher.h"

#include <cassert>
#include <cerrno>

#include <fcntl.h>
#include <unistd.h>

using namespace xovm::material;

int main() {
    const int inherited = open("/dev/null", O_RDONLY | O_CLOEXEC);
    assert(inherited > STDERR_FILENO);

    Launcher::StartOptions options;
    options.hello.session_id[0] = 1;
    options.hello.generation = 1;
    options.hello.challenge_counter = 1;
    options.hello.previous_state_digest[0] = 2;
    options.current_window_id = 1;
    options.worker = [inherited](GuardianChannel &channel) {
        errno = 0;
        assert(fcntl(inherited, F_GETFD) == -1);
        assert(errno == EBADF);
        return channel.receiveShutdown() ? 0 : 1;
    };
    auto child = Launcher::start(options);
    assert(child);
    assert(child->channel().shutdown());
    assert(child->wait() == 0);
    assert(fcntl(inherited, F_GETFD) >= 0);
    close(inherited);
    return 0;
}
''')
    result = subprocess.run([str(executable)], capture_output=True, text=True,
                            timeout=10)
    assert result.returncode == 0, result.stderr


def test_guardian_death_poison_and_sealed_executor(tmp_path):
    executable = _compile(tmp_path, "guardian_death", r'''
#include "runtime/cloud_material/launcher.h"

#include <cassert>

using namespace xovm::material;

int main() {
    Launcher::StartOptions options;
    options.hello.session_id[0] = 1;
    options.hello.generation = 1;
    options.hello.challenge_counter = 1;
    options.hello.previous_state_digest[0] = 2;
    options.current_window_id = 1;
    options.worker = [](GuardianChannel &channel) {
        assert(channel.established());
        return channel.receiveShutdown() ? 17 : 18;
    };
    auto child = Launcher::start(options);
    assert(child);
    LeaseState bound(120000000000ULL, child->channel());
    auto first = bound.acquire(100000000000ULL, 1, 100000000000ULL, 220000000000ULL);
    assert(first);
    assert(child->channel().shutdown());
    assert(child->wait() == 17);
    assert(!bound.pin(110000000000ULL));
    assert(!child->channel().established());
    return 0;
}
''')
    result = subprocess.run([str(executable)], capture_output=True, text=True,
                            timeout=10)
    assert result.returncode == 0, result.stderr

    production_probe = tmp_path / "production_probe.cpp"
    production_probe.write_text(r'''
#include "runtime/cloud_material/launcher.h"
#include <type_traits>
using namespace xovm::material;
template <typename T> concept HasWorker = requires(T value) { value.worker; };
static_assert(!HasWorker<Launcher::StartOptions>);
static_assert(!std::is_constructible_v<GuardianChannel,
                                      std::array<unsigned char, 32>, uint64_t>);
int main() { return 0; }
''', encoding="ascii")
    result = subprocess.run([
        "c++", "-std=c++20", "-Wall", "-Wextra", "-Werror", "-I", str(ROOT),
        str(production_probe), "-c", "-o", str(tmp_path / "production_probe.o"),
    ], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


def test_immutable_concurrent_lease_pins(tmp_path):
    executable = _compile(tmp_path, "lease_pins", r'''
#include "runtime/cloud_material/guardian_channel.h"

#include <atomic>
#include <cassert>
#include <thread>
#include <vector>

#include <sys/wait.h>
#include <unistd.h>

using namespace xovm::material;

int main() {
    constexpr uint64_t second = 1000000000ULL;
    LeaseState capped(120 * second);
    auto short_grant = capped.acquire(
        100 * second, 1, 101 * second, 145 * second);
    assert(short_grant && short_grant->deadlineNs() == 145 * second);
    assert(!capped.pin(145 * second));
    LeaseState late(120 * second);
    assert(!late.acquire(
        100 * second, 1, 220 * second, 220 * second));

    LeaseState lease(120 * second);
    auto original = lease.acquire(
        100 * second, 1, 100 * second, 220 * second);
    assert(original);
    assert(original->generation() == 1);
    assert(original->deadlineNs() == 220 * second);
    assert(!lease.renewIfDue(209 * second));
    assert(lease.renewIfDue(210 * second));
    assert(lease.needsRenewal());
    assert(lease.pin(219 * second));
    assert(!lease.pin(220 * second));
    assert(!lease.acquire(
        220 * second, 3, 220 * second, 340 * second));
    assert(!lease.acquire(
        209 * second, 2, 209 * second, 329 * second));

    auto replacement = lease.acquire(
        220 * second, 2, 220 * second, 340 * second);
    assert(replacement);
    assert(replacement->generation() == 2);
    assert(original->generation() == 1);
    assert(original->deadlineNs() == 220 * second);

    std::atomic<unsigned> pins{0};
    std::vector<std::thread> threads;
    for (unsigned i = 0; i < 16; ++i) {
        threads.emplace_back([&] {
            auto pin = lease.pin(221 * second);
            if (pin && pin->generation() == 2) ++pins;
        });
    }
    for (auto &thread : threads) thread.join();
    assert(pins == 16);

    auto draining = lease.pin(222 * second);
    assert(draining);
    lease.markRenewalFailed();
    assert(lease.pin(223 * second));
    assert(!lease.pin(340 * second));
    assert(draining->generation() == 2);

    const pid_t inherited = fork();
    assert(inherited >= 0);
    if (inherited == 0) {
        if (*draining || draining->generation() != 0 || lease.pin(224 * second))
            _exit(1);
        _exit(0);
    }
    int inherited_status = 0;
    assert(waitpid(inherited, &inherited_status, 0) == inherited);
    assert(WIFEXITED(inherited_status));
    assert(WEXITSTATUS(inherited_status) == 0);

    auto recovered = lease.acquire(
        330 * second, 3, 330 * second, 450 * second);
    assert(recovered);
    assert(lease.pin(331 * second));
    return 0;
}
''')
    result = subprocess.run([str(executable)], capture_output=True, text=True,
                            timeout=10)
    assert result.returncode == 0, result.stderr
