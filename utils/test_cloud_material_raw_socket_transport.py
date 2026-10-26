"""Raw transport short-I/O and frame-boundary coverage."""

from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]


def test_raw_transport_handles_partial_io_without_libc_network_symbols(tmp_path):
    source = tmp_path / "raw_socket_probe.cpp"
    source.write_text(
        '#include "runtime/cloud_material/raw_socket_transport.h"\n'
        '#include <cassert>\n'
        '#include <cstring>\n'
        '#include <vector>\n'
        'using namespace xovm::material;\n'
        'static std::vector<unsigned char> wire; static size_t read_pos = 0;\n'
        'static long fake_socket(int, int, int) { return 7; }\n'
        'static long fake_connect(int, const void *, unsigned) { return 0; }\n'
        'static long fake_send(int, const void *data, size_t size, int) {\n'
        '  const size_t count = size > 3 ? 3 : size;\n'
        '  const auto *bytes = static_cast<const unsigned char *>(data);\n'
        '  wire.insert(wire.end(), bytes, bytes + count); return static_cast<long>(count);\n'
        '}\n'
        'static long fake_recv(int, void *data, size_t size, int) {\n'
        '  if (read_pos == wire.size()) return 0;\n'
        '  const size_t count = size > 2 ? 2 : size;\n'
        '  const size_t available = wire.size() - read_pos;\n'
        '  const size_t actual = count < available ? count : available;\n'
        '  std::memcpy(data, wire.data() + read_pos, actual); read_pos += actual;\n'
        '  return static_cast<long>(actual);\n'
        '}\n'
        'static long fake_close(int) { return 0; }\n'
        'int main() {\n'
        '  const RawSyscallTable table{fake_socket, fake_connect, fake_send, fake_recv, fake_close};\n'
        '  RawSocketResult connect_result{}; auto socket = RawSocketFd::connectIpv4(0, 0, table, &connect_result);\n'
        '  assert(socket.get() == 7 && static_cast<bool>(connect_result));\n'
        '  RawFrameTransport transport(std::move(socket));\n'
        '  RawFrameHeader header{}; header.type = RawFrameType::RemoteVariables; header.payload_length = 5;\n'
        '  const unsigned char payload[] = {1, 2, 3, 4, 5};\n'
        '  assert(transport.sendFrame(header, payload));\n'
        '  RawFrameHeader received{}; auto body = transport.receiveFrame(received);\n'
        '  assert(std::holds_alternative<std::vector<uint8_t>>(body));\n'
        '  assert(received.type == RawFrameType::RemoteVariables);\n'
        '  assert(std::get<std::vector<uint8_t>>(body) == std::vector<uint8_t>(payload, payload + 5));\n'
        '  return 0;\n'
        '}\n',
        encoding="ascii",
    )
    exe = tmp_path / "probe"
    result = subprocess.run(
        ["c++", "-std=c++20", "-Wall", "-Wextra", "-Werror", "-I", str(ROOT),
         str(source), str(ROOT / "runtime/cloud_material/raw_protocol.cpp"),
         str(ROOT / "runtime/cloud_material/raw_frame.cpp"),
         str(ROOT / "runtime/cloud_material/raw_socket_syscall_aarch64.cpp"),
         str(ROOT / "runtime/cloud_material/raw_socket_transport.cpp"), "-lcrypto", "-o", str(exe)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    undefined = subprocess.run(["nm", "-u", str(exe)], capture_output=True, text=True,
                               check=True).stdout
    assert " socket" not in undefined
    assert subprocess.run([str(exe)], capture_output=True, text=True).returncode == 0
