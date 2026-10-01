from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_capability_mode_is_explicit_and_stage1_remains_default():
    source = (ROOT / "zone_runtime/zone_wrapper.cpp").read_text()
    header = (ROOT / "zone_runtime/zone_wrapper.h").read_text()
    assert "XOLLVM_ZONE_CAPABILITY_OPERATION" in source
    assert "capability_v1" in source
    assert "xollvm_zone_capability_begin" in header
    assert "GetAntiAlgorithmValue" in source
    assert "XOLLVM_ZONE_CAPABILITY_PUBLIC_KEY" in source


def test_require_is_local_and_capability_disabled_does_not_write_state():
    source = (ROOT / "zone_runtime/zone_wrapper.cpp").read_text()
    require_body = source[source.index("extern \"C\" int xollvm_zone_require"):source.index("extern \"C\" int xollvm_zone_capability_begin")]
    assert "GetAntiAlgorithmValue" not in require_body
    assert "capabilityClient" in require_body
    assert "XOLLVM_ZONE_LIVE" not in require_body


def test_capability_algorithm_does_not_use_legacy_empty_algorithm_request():
    source = (ROOT / "zone_runtime/zone_wrapper.cpp").read_text()
    first_heartbeat = source[
        source.index('extern "C" int xollvm_zone_first_heartbeat'):
        source.index('extern "C" int xollvm_zone_refresh_lease')
    ]
    assert 's.algorithm != "capability_v1"' in first_heartbeat
    assert "xollvm_zone_capability_begin" not in first_heartbeat


def test_capability_response_parse_and_shape_errors_are_distinguished():
    source = (ROOT / "zone_runtime/zone_wrapper.cpp").read_text()
    assert "Zone capability rejected: malformed response JSON" in source
    assert "Zone capability rejected: response root is not an object" in source
    assert "Zone capability rejected: invalid field=" not in source
    assert '"request_hash", nlohmann::json::value_t::string' in source
    assert "Zone capability raw Data.value:" not in source
    assert "Zone capability rejected: response validation failed" in source
    assert 'json.contains("Result")' in source
    assert 'json["Result"].contains("RetMsg")' in source
    assert "for (unsigned int unwrapDepth = 0; unwrapDepth < 4" in source
    assert "if (!json.contains(\"protocol\") || !json[\"protocol\"].is_number())" in source


def test_zone_startup_exits_before_main_when_card_login_or_heartbeat_fails():
    source = (ROOT / "ZoneAuth.cpp").read_text()
    startup = source[source.index("static void injectStartup"):source.index("PreservedAnalyses ZoneAuthModulePass::run")]
    assert "LoginResult" in startup
    assert "HeartbeatResult" in startup
    assert '"mov x8, #94\\nmov x0, #1\\nsvc #0"' in startup
    assert "InlineAsm::get" in startup


def test_zone_capability_request_is_deferred_until_protected_call():
    source = (ROOT / "zone_runtime/zone_wrapper.cpp").read_text()
    heartbeat = source[
        source.index('extern "C" int xollvm_zone_first_heartbeat'):
        source.index('extern "C" int xollvm_zone_refresh_lease')
    ]
    assert "xollvm_zone_capability_begin" not in heartbeat
    assert 'extern "C" int xollvm_zone_capability_begin' in source
    assert 'xollvm_zone_capability_begin(s.capabilityOperation.c_str(), "demo")' not in source


def test_zoneauth_gate_passes_runtime_function_argument_as_payload():
    source = (ROOT / "ZoneAuth.cpp").read_text()
    gate = source[source.index("static bool injectGate"):source.index("static void injectStartup")]
    assert '"xollvm_zone_capability_begin"' in gate
    assert 'Builder.CreateCall(Begin' in gate
    assert '"zoneauth.payload"' in gate
    assert gate.index("Builder.CreateCall(Begin") < gate.index("Builder.CreateCall(Require")


def test_release_capability_errors_do_not_disclose_binding_details():
    source = (ROOT / "zone_runtime/zone_wrapper.cpp").read_text()
    assert "key_id=" not in source
    assert "operation=" not in source
    assert "protocol=" not in source
    assert "policy=" not in source
