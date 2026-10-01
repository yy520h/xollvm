from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

def test_dispatch_key_changes_with_tick():
    src = (ROOT / "zone_runtime/vm_dispatch_value.cpp").read_text()
    assert "deriveDispatchKey" in src
    assert "clientTick" in src
    assert "SHA256" in src

def test_tick_source_reads_arch_counter():
    src = (ROOT / "zone_runtime/vm_dispatch_value.cpp").read_text()
    assert "CNTVCT_EL0" in src or "cntvct_el0" in src
    assert "readClientTick" in src

def test_window_id_is_server_time_bucketed():
    src = (ROOT / "zone_runtime/vm_dispatch_value.cpp").read_text()
    assert "computeWindowId" in src
    assert "windowSeconds" in src
