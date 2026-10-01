from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

def test_dispatch_value_entry_exists_and_does_not_return_auth_bool():
    src = (ROOT / "zone_runtime/zone_wrapper.cpp").read_text()
    assert "xollvm_zone_vm_dispatch_value" in src
    assert "xollvm_zone_vm_dispatch_refresh" in src
    body = src[src.index("xollvm_zone_vm_dispatch_value"):]
    assert "authorized" not in body[:800]
    assert "ok ?" not in body[:800]

def test_prefetch_interval_and_window_are_fifty_and_sixty():
    src = (ROOT / "zone_runtime/zone_wrapper.cpp").read_text()
    assert "dispatchPrefetchSeconds" in src
    assert "dispatchWindowSeconds" in src
    assert "50" in src and "60" in src

def test_dispatch_state_caches_key_and_tick():
    src = (ROOT / "zone_runtime/zone_wrapper.cpp").read_text()
    assert "dispatchKey" in src
    assert "dispatchFetchedAt" in src
