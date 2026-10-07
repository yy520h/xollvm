"""Demo 端到端集成：受保护函数消费云值 dispatch。

锁定：
- demo 的 VM 注解启用 cloudDispatch（云值缺省/过期时 dispatch 越界自然崩溃）。
- demo 源码里没有任何本地授权布尔分支（零校验）。
"""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROJECT = ROOT.parents[2] if ROOT.parent.name == ".worktrees" else ROOT.parent
DEMO = PROJECT / "demo/jni/main.cpp"


def _demo_src():
    return DEMO.read_text()


def test_demo_vm_function_requests_cloud_dispatch():
    src = _demo_src()
    assert "cloudDispatch=1" in src, "demo 的 VM 注解未启用 cloudDispatch=1"


def test_demo_has_no_local_auth_branch():
    src = _demo_src()
    for token in ["verifySignature", "windowExpired", "dispatchValid"]:
        assert token not in src, f"demo 出现本地校验分支: {token}"
