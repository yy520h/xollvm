from pathlib import Path


def test_zone_sdk_transport_pointers_are_null_initialized():
    root = Path(__file__).resolve().parents[2]
    header = (root / "third_party/zone_sdk/Core/ZoneHelperCore.h").read_text()
    assert "SocketClientCore* usr_SocketClientCore = nullptr;" in header
    assert "ZoneWebSocketClient* usr_webSocketClient = nullptr;" in header


def test_device_identity_does_not_use_boot_id_and_has_persistent_fallback():
    root = Path(__file__).resolve().parents[2]
    source = (root / "third_party/zone_sdk/Core/hw_info.cpp").read_text()
    assert "random/boot_id" not in source
    assert "XOLLVM_ZONE_DEVICE_ID_PATH" in source
    assert "persist" in source.lower()
    assert "flock" in source
    assert "return persisted ? value : \"\";" in source


def test_zone_shutdown_has_normal_and_signal_cleanup():
    root = Path(__file__).resolve().parents[2]
    source = (root / "zone_runtime/zone_wrapper.cpp").read_text()
    assert "std::atexit" in source
    assert "SIGINT" in source
    assert "SIGTERM" in source
    assert "SIGHUP" in source
    assert "Zone logout response" in source
    assert source.index("stopHeartbeat") < source.index("Logout")
