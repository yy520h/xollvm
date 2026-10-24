"""显式项目根目录支持 worktree，缺失工具仍须失败。"""
import pytest

import vm_hardening_support as support


@pytest.fixture
def tool_layout(tmp_path, monkeypatch):
    root = tmp_path / 'xollvm-android'
    expected = {
        'opt': root / 'build-sensitive/bin/opt',
        'clang': tmp_path / 'android-ndk-r30-ollvm-r23-beta3/toolchains/llvm/prebuilt/linux-arm64/bin/clang',
        'clangxx': tmp_path / 'android-ndk-r30-ollvm-r23-beta3/toolchains/llvm/prebuilt/linux-arm64/bin/clang++',
        'sysroot': tmp_path / 'android-ndk-r30-ollvm-r23-beta3/toolchains/llvm/prebuilt/linux-arm64/sysroot',
        'hardener': root / 'build-sensitive/bin/xollvm-elf-hardener',
    }
    for name, path in expected.items():
        if name == 'sysroot':
            path.mkdir(parents=True)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.touch()
    monkeypatch.setattr(support, '__file__', str(
        root / 'xollvm/.worktrees/cloud-material-v2/utils/vm_hardening_support.py'))
    monkeypatch.delenv('XOLLVM_PROJECT_ROOT', raising=False)
    monkeypatch.delenv('XOLLVM_OPT', raising=False)
    return root, expected


def test_explicit_root_resolves_worktree_tools(tool_layout, monkeypatch):
    root, expected = tool_layout
    monkeypatch.setenv('XOLLVM_PROJECT_ROOT', str(root))

    assert support.tools() == support.VMTools(**expected)


def test_original_checkout_default(tool_layout, monkeypatch):
    root, expected = tool_layout
    monkeypatch.setattr(support, '__file__', str(root / 'xollvm/utils/vm_hardening_support.py'))

    assert support.tools() == support.VMTools(**expected)


def test_explicit_opt_overrides_root_default(tool_layout, monkeypatch, tmp_path):
    root, expected = tool_layout
    override = tmp_path / 'custom-opt'
    override.touch()
    expected['opt'].unlink()
    expected['opt'] = override
    monkeypatch.setenv('XOLLVM_PROJECT_ROOT', str(root))
    monkeypatch.setenv('XOLLVM_OPT', str(override))

    assert support.tools() == support.VMTools(**expected)


@pytest.mark.parametrize('name', ['opt', 'clang', 'clangxx', 'hardener'])
def test_explicit_root_rejects_missing_tool(tool_layout, monkeypatch, name):
    root, expected = tool_layout
    missing = expected[name]
    missing.unlink()
    monkeypatch.setenv('XOLLVM_PROJECT_ROOT', str(root))

    with pytest.raises(RuntimeError) as error:
        support.tools()
    assert str(error.value) == f'required tool missing: {missing}'


def test_missing_explicit_opt_does_not_fall_back(tool_layout, monkeypatch, tmp_path):
    root, _ = tool_layout
    missing = tmp_path / 'missing-opt'
    monkeypatch.setenv('XOLLVM_PROJECT_ROOT', str(root))
    monkeypatch.setenv('XOLLVM_OPT', str(missing))

    with pytest.raises(RuntimeError) as error:
        support.tools()
    assert str(error.value) == f'required tool missing: {missing}'
