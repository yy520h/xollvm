"""Guardian/Worker channel and 110/120-second lease tests."""

from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]


def test_guardian_channel_and_lease_state_machine(tmp_path):
    source = tmp_path / "guardian_probe.cpp"
    source.write_text(
        '#include "runtime/cloud_material/guardian_channel.h"\n'
        '#include "runtime/cloud_material/launcher.h"\n'
        '#include <cassert>\n'
        'int main() {\n'
        '  using namespace xovm::material;\n'
        '  std::array<unsigned char, 32> boot{}; boot[0] = 9;\n'
        '  GuardianChannel channel(boot, 42);\n'
        '  GuardianChannelHello hello{}; hello.boot_nonce = boot; hello.generation = 1;\n'
        '  hello.challenge_counter = 1; hello.session_id[0] = 8; hello.previous_state_digest[0] = 7; assert(channel.handshake(hello));\n'
        '  assert(channel.challenge(1, 1)); assert(!channel.challenge(1, 1));\n'
        '  LeaseState lease(100000000000ULL);\n'
        '  assert(lease.acquire(100000000000ULL, 1));\n'
        '  assert(!lease.renewIfDue(189000000000ULL));\n'
        '  assert(lease.renewIfDue(190000000000ULL));\n'
        '  assert(lease.pin(199000000000ULL));\n'
         '  assert(!lease.acquire(200000000000ULL, 1));\n'
         '  assert(lease.acquire(200000000000ULL, 2));\n'
         '  lease.release();\n'
         '  assert(!Launcher::validateWorkerEntry(channel));\n'
          '  GuardianChannelHello second{}; second.boot_nonce = boot; second.generation = 2; second.challenge_counter = 1; second.session_id[0] = 8; second.previous_state_digest[0] = 7;\n'
         '  auto worker = Launcher::createWorkerChannel(boot, 42, second); assert(worker);\n'
         '  assert(Launcher::validateWorkerEntry(*worker));\n'
          '  Launcher::StartOptions options; options.worker = [](int fd) { return fd >= 0 ? 0 : 1; };\n'
          '  std::array<unsigned char, 32> empty_boot{}; assert(!Launcher::start(empty_boot, 42, options));\n'
          '  assert(!Launcher::start(boot, 0, options));\n'
          '  auto started = Launcher::start(boot, 42, options); assert(started);\n'
         '  assert(started->wait() == 0);\n'
         '  auto failed = Launcher::start(boot, 42, Launcher::StartOptions{[](int) { return 7; }}); assert(failed);\n'
         '  assert(failed->wait() == 7);\n'
         '  LeaseState monotonic(100000000000ULL); assert(monotonic.acquire(1, 2)); monotonic.release();\n'
         '  assert(!monotonic.acquire(2, 1)); assert(monotonic.acquire(3, 3));\n'
         '  return 0;\n'
        '}\n', encoding="ascii")
    exe = tmp_path / "probe"
    result = subprocess.run(
        ["c++", "-std=c++20", "-Wall", "-Wextra", "-Werror", "-I", str(ROOT),
         str(source), str(ROOT / "runtime/cloud_material/guardian_channel.cpp"),
         str(ROOT / "runtime/cloud_material/launcher.cpp"),
         str(ROOT / "runtime/cloud_material/dynamic_vm_schema.cpp"), "-lcrypto", "-o", str(exe)],
        capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert subprocess.run([str(exe)], capture_output=True, text=True).returncode == 0
