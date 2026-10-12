"""保留真实 SDK facade，用本地 core 替身隔离构造时的外部网络。"""
import subprocess
from pathlib import Path


def test_instances_own_and_release_their_core(tmp_path):
    repo = Path(__file__).resolve().parents[1]
    root = repo.parents[2] if repo.parent.name == '.worktrees' else repo.parent
    rt = root / 'demo/jni/zone_runtime'
    ndk = root.parent / 'android-ndk-r30-ollvm-r23-beta3/toolchains/llvm/prebuilt/linux-arm64'
    ssl = root / 'demo/obj/openssl/arm64-v8a'
    src = tmp_path / 'ownership.cpp'
    src.write_text(r'''
#include "Core/ZoneHelper.cpp"
static int live = 0;
EncryptCore::EncryptCore() {}
ZoneHelperCore::ZoneHelperCore(const std::string& id, const std::string&,
    const std::string&, const std::string&, eum_EncryptType, eum_LoginType,
    eum_AgreementType, eum_NetworkRegion) : SoftwareId(id) { ++live; }
ZoneHelperCore::~ZoneHelperCore() { --live; }
bool ZoneHelperCore::QueryCard(const std::string&, ApiResponse& r) {
    r.Code = SoftwareId; return true;
}
int main() {
    {
        ZoneHelper a("first", "1", "", "", eum_EncryptType::AES,
            eum_LoginType::Card, eum_AgreementType::HTTP, eum_NetworkRegion::Global);
        {
            ZoneHelper b("second", "1", "", "", eum_EncryptType::AES,
                eum_LoginType::Card, eum_AgreementType::HTTP, eum_NetworkRegion::Global);
            ApiResponse r;
            if (a.QueryCard(r, "") != 1 || r.Code != "first") return 3;
            if (b.QueryCard(r, "") != 1 || r.Code != "second") return 4;
        }
        if (live != 1) return 5;
        ApiResponse r;
        if (a.QueryCard(r, "") != 1 || r.Code != "first") return 6;
    }
    return live != 0;
}
''')
    exe = tmp_path / 'ownership'
    build = subprocess.run([str(ndk / 'bin/clang++'), '--target=aarch64-linux-android26',
        f'--sysroot={ndk / "sysroot"}', '-std=c++20', '-static-libstdc++',
        '-ffunction-sections', '-fdata-sections', '-Wl,--gc-sections',
        f'-I{rt}', f'-I{ssl / "include"}', f'-I{rt / "openssl_core/src/include"}',
        str(src), '-o', str(exe)], capture_output=True, text=True, timeout=120)
    assert build.returncode == 0, build.stderr
    run = subprocess.run([str(exe)], capture_output=True, text=True, timeout=10)
    assert run.returncode == 0, f'instance isolation/release failed: {run.returncode}'
