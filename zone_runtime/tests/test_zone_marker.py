import pathlib
import subprocess


def test_zone_marker_is_emitted_for_zone_enabled_ir(tmp_path):
    source = tmp_path / "zone.c"
    source.write_text(
        '__attribute__((annotate("obf: zoneauth(capability=main, policy=fail_closed)")))\n'
        'int main(void) { return 0; }\n'
    )
    input_ir = tmp_path / "zone.ll"
    output = tmp_path / "zone.out.ll"
    opt = pathlib.Path(__file__).resolve().parents[3] / "build" / "bin" / "opt"
    clang = opt.parent / "clang"
    compile_result = subprocess.run(
        [str(clang), "-O0", "-Xclang", "-disable-O0-optnone", "-S",
         "-emit-llvm", str(source), "-o", str(input_ir)],
        text=True, capture_output=True,
    )
    assert compile_result.returncode == 0, compile_result.stderr
    result = subprocess.run(
        [str(opt), "-passes=obfuscation", "-obf-zone-enable",
         "-obf-zone-software-id=id", "-obf-zone-version=1.0.0",
         "-obf-zone-encrypt-key=key", "-obf-zone-encrypt-iv=iv",
         "-obf-zone-algorithm=attest", "-S", str(input_ir), "-o", str(output)],
        text=True, capture_output=True,
    )
    assert result.returncode == 0, result.stderr
    transformed = output.read_text()
    assert ".xollvm.zone.link" in transformed
    assert "@llvm.compiler.used" in transformed
    assert "call i32 @xollvm_zone_initialize" in transformed
    assert "call void @xollvm_zone_set_shutdown_mode(i32 1)" in transformed
    assert "@llvm.global_ctors" not in transformed
    assert "__xollvm_zone_start" not in transformed


def test_zone_marker_is_absent_without_zone_enable(tmp_path):
    source = tmp_path / "plain.c"
    source.write_text("int main(void) { return 0; }\n")
    input_ir = tmp_path / "plain.ll"
    output = tmp_path / "plain.out.ll"
    opt = pathlib.Path(__file__).resolve().parents[3] / "build" / "bin" / "opt"
    clang = opt.parent / "clang"
    compile_result = subprocess.run(
        [str(clang), "-O0", "-Xclang", "-disable-O0-optnone", "-S",
         "-emit-llvm", str(source), "-o", str(input_ir)],
        text=True, capture_output=True,
    )
    assert compile_result.returncode == 0, compile_result.stderr
    result = subprocess.run(
        [str(opt), "-passes=obfuscation", "-S", str(input_ir), "-o", str(output)],
        text=True, capture_output=True,
    )
    assert result.returncode == 0, result.stderr
    assert ".xollvm.zone.link" not in output.read_text()


def test_zone_shutdown_mode_is_injected(tmp_path):
    source = tmp_path / "zone.c"
    source.write_text(
        '__attribute__((annotate("obf: zoneauth(capability=main, policy=fail_closed)")))\n'
        'int main(void) { return 0; }\n'
    )
    input_ir = tmp_path / "zone.ll"
    output = tmp_path / "zone.out.ll"
    opt = pathlib.Path(__file__).resolve().parents[3] / "build" / "bin" / "opt"
    clang = opt.parent / "clang"
    compile_result = subprocess.run(
        [str(clang), "-O0", "-Xclang", "-disable-O0-optnone", "-S",
         "-emit-llvm", str(source), "-o", str(input_ir)],
        text=True, capture_output=True,
    )
    assert compile_result.returncode == 0, compile_result.stderr
    result = subprocess.run(
        [str(opt), "-passes=obfuscation", "-obf-zone-enable",
         "-obf-zone-shutdown-mode=manual", "-obf-zone-software-id=id",
         "-obf-zone-version=1.0.0", "-obf-zone-encrypt-key=key",
         "-obf-zone-encrypt-iv=iv", "-obf-zone-algorithm=attest", "-S",
         str(input_ir), "-o", str(output)], text=True, capture_output=True,
    )
    assert result.returncode == 0, result.stderr
    transformed = output.read_text()
    assert "call void @xollvm_zone_set_shutdown_mode" in transformed
    assert "i32 0" in transformed
