from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

def test_unwrap_body_key_is_pure_and_present():
    src = (ROOT / "zone_runtime/vm_dispatch_value.cpp").read_text()
    assert "unwrapBodyKey" in src
    assert "functionId" in src

def test_body_key_entry_exists_and_is_not_a_bool():
    src = (ROOT / "zone_runtime/zone_wrapper.cpp").read_text()
    assert "xollvm_zone_vm_body_key" in src

def test_body_key_binds_tick_and_device():
    hdr = (ROOT / "zone_runtime/vm_dispatch_value.h").read_text()
    assert "unwrapBodyKey" in hdr
    assert "clientTick" in hdr
    assert "deviceId" in hdr
