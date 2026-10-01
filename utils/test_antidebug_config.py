from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_antidebug_pass_is_registered():
    text = (ROOT / "include/llvm/Transforms/Obfuscator/PassIds.h").read_text()
    assert '"antidebug"' in text


def test_defaults_are_explicitly_disabled():
    text = (ROOT / "include/llvm/Transforms/Obfuscator/ObfuscationConfig.h").read_text()
    assert "bool enabled = false" in text
    assert "bool tracerPid = false" in text
    assert "bool dynamic = false" in text


def test_dynamic_requires_sync_detector():
    text = (ROOT / "ObfuscationConfig.cpp").read_text()
    assert "dynamic monitor requires at least one detector" in text
