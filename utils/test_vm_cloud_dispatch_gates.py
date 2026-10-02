"""VM 云值驱动 dispatch 的结构 gate。

锁定 cloudDispatch 特性：配置项、解析、dispatch 注入点、引擎 key 参与，
以及默认关闭（保证未启用时 byte-identical）。
"""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _read(rel):
    return (ROOT / rel).read_text()


def test_cloud_dispatch_flag_registered_and_defaults_off():
    cfg = _read("include/llvm/Transforms/Obfuscator/ObfuscationConfig.h")
    lines = [l for l in cfg.splitlines() if "cloudDispatch" in l]
    assert lines, "cloudDispatch 未在 VMPassConfig 中注册"
    assert any("false" in l for l in lines), "cloudDispatch 默认值必须为 false"


def test_pass_parses_cloud_dispatch():
    src = _read("VMPass.cpp")
    assert 'getBool("cloudDispatch", Cfg.cloudDispatch)' in src


def test_dispatch_path_calls_runtime_offset():
    src = _read("VMPass_Dispatch.cpp")
    assert "__zone_get_dispatch_offset" in src
    # 两个 dispatch 路径（central + threaded）都要注入
    assert src.count("__zone_get_dispatch_offset") >= 2


def test_cloud_dispatch_enters_engine_key():
    src = _read("VMPass_Requirements.cpp")
    assert "cloudDispatch" in src


def test_runtime_offset_zero_means_valid():
    """运行时语义：合法 V 返回 0；窗口推进使旧 V 非 0。"""
    src = _read("zone_runtime/cloud_value_manager.cpp")
    assert "VM_DISPATCH_OFFSET_MASK" in src
    assert "getWindowId" in src
    assert "HMAC" not in src or "SHA256" in src  # 手写 HMAC，避免前缀漏改


def test_dispatch_offset_injection_is_gated_for_non_cloud_parity():
    """Task 6：两处 dispatch 注入都必须包在 `if (CloudDispatch)` 里。

    cloudDispatch 关闭时（默认）不产生任何新 IR / 不引用运行时符号，
    保证非云 VM 输出与非云基线一致。
    """
    src = _read("VMPass_Dispatch.cpp")
    # 每个注入点前面必须紧跟 CloudDispatch 守卫
    idx = 0
    while True:
        idx = src.find("__zone_get_dispatch_offset", idx)
        if idx == -1:
            break
        window = src[max(0, idx - 400):idx]
        assert "if (CloudDispatch)" in window, "dispatch 注入未受 CloudDispatch 守卫"
        idx += 1

