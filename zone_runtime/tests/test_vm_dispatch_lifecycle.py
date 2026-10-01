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
    assert "dispatchPrefetchSeconds = 50" in src
    assert "dispatchWindowSeconds = 60" in src


def test_dispatch_state_caches_key_and_tick():
    src = (ROOT / "zone_runtime/zone_wrapper.cpp").read_text()
    assert "dispatchKey" in src
    assert "dispatchFetchedAt" in src


def test_vm_dispatch_value_cpp_is_in_cmake_source_list():
    cmake = (ROOT / "zone_runtime/CMakeLists.txt").read_text()
    library_block = cmake[cmake.index("add_library(xollvm_zone_sdk STATIC"):]
    library_block = library_block[: library_block.index(")")]
    assert "vm_dispatch_value.cpp" in library_block, \
        "vm_dispatch_value.cpp must be in the xollvm_zone_sdk STATIC sources"


def test_unwrap_helper_is_single_shared_function():
    src = (ROOT / "zone_runtime/zone_wrapper.cpp").read_text()
    assert "bool unwrapResponseJson(" in src, "shared unwrap helper must exist"
    # 解包逻辑只允许出现一次：共享函数内。pre-fix 代码在 capability_begin
    # 与 extractJsonString 各有一份内联的 4 层 Result.RetMsg 循环。
    assert src.count('json.contains("Result")') == 1, \
        "Result.RetMsg unwrap must live in exactly one shared helper"
    assert src.count("unwrapResponseJson(") >= 3, \
        "helper must be defined once and used by both begin and dispatch paths"
    assert "unwrapResponseJson(response.Data.value" in src, \
        "capability_begin must call the shared helper"
    assert "extractJsonString" in src, \
        "dispatch path must reuse the helper via extractJsonString"


def test_refresh_has_generation_recheck():
    src = (ROOT / "zone_runtime/zone_wrapper.cpp").read_text()
    refresh_body = src[src.index("xollvm_zone_vm_dispatch_refresh"):]
    refresh_body = refresh_body[: refresh_body.index("\n}\n")]
    assert "s.capabilityClient.get() != client" in refresh_body, \
        "refresh must re-check the CapabilityClient generation before storing"
    assert "!s.loggedIn" in refresh_body
    assert "!s.leaseValid" in refresh_body


def test_refresh_snapshots_state_before_unlock():
    src = (ROOT / "zone_runtime/zone_wrapper.cpp").read_text()
    refresh_body = src[src.index("xollvm_zone_vm_dispatch_refresh"):]
    refresh_body = refresh_body[: refresh_body.index("\n}\n")]
    unlock = refresh_body.index("lock.unlock()")
    snapshot = refresh_body.index("DispatchSnapshot snapshot;")
    assert snapshot < unlock, "state must be snapshotted before unlocking for the network call"
    for field in ("snapshot.softwareId", "snapshot.clientState", "snapshot.buildId", "snapshot.deviceId"):
        assert field in refresh_body[:unlock], f"{field} must be read under the lock"
    network_call = refresh_body.index("GetAntiAlgorithmValue")
    assert "s.softwareId" not in refresh_body[unlock:network_call]
    assert "s.capabilityClient" not in refresh_body[unlock:network_call]
