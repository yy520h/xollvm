"""Selective authenticated-window runtime tests."""

from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]
RUNTIME_SOURCES = [
    ROOT / "runtime/cloud_material/dynamic_vm_runtime.cpp",
    ROOT / "runtime/cloud_material/dynamic_vm_artifact.cpp",
    ROOT / "runtime/cloud_material/dynamic_vm_schema.cpp",
    ROOT / "runtime/cloud_material/dynamic_vm_window_provider.cpp",
    ROOT / "runtime/cloud_material/dynamic_vm_shard.cpp",
    ROOT / "runtime/cloud_material/continuation_executor.cpp",
    ROOT / "runtime/cloud_material/jit_handler_buffer.cpp",
    ROOT / "runtime/cloud_material/integrity_state.cpp",
]


def _compile(source: Path, output: Path, *, testing: bool = True,
             extra_flags: tuple[str, ...] = ()) -> None:
    flags = ["-DXOVM_DYNAMIC_VM_TESTING=1"] if testing else []
    result = subprocess.run(
        [
            "c++", "-std=c++20", "-Wall", "-Wextra", "-Werror",
            *flags, *extra_flags, "-I", str(ROOT), str(source),
            *(str(path) for path in RUNTIME_SOURCES), "-lcrypto", "-o",
            str(output),
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


def test_each_authenticated_window_executes_exactly_one_selected_node(tmp_path):
    source = tmp_path / "selective_runtime_probe.cpp"
    source.write_text(
        r'''#include "runtime/cloud_material/dynamic_vm_runtime.h"
#include "runtime/cloud_material/dynamic_vm_shard.h"
#include <cassert>
#include <cstring>
#include <openssl/evp.h>
#include <vector>

using namespace xovm::material;

static const std::vector<uint8_t> kLoad = {
    0x01,0x04,0x40,0xf9, 0x02,0xcf,0x8a,0x52,
    0x82,0x46,0xa2,0x72, 0x22,0x04,0x00,0xb9,
    0xc3,0x00,0x80,0x52, 0x03,0x20,0x00,0xb9,
    0x00,0x00,0x80,0x52, 0xc0,0x03,0x5f,0xd6,
};
static const std::vector<uint8_t> kReturn = {
    0x01,0x04,0x40,0xf9, 0x02,0x0c,0x40,0xf9,
    0x23,0x04,0x40,0xb9, 0x43,0x00,0x00,0xb9,
    0x03,0x01,0x80,0x52, 0x03,0x20,0x00,0xb9,
    0x20,0x00,0x80,0x52, 0xc0,0x03,0x5f,0xd6,
};

static DynamicHash rawHash(std::span<const uint8_t> bytes) {
    DynamicHash result{};
    unsigned int size = 0;
    assert(EVP_Digest(bytes.data(), bytes.size(), result.data(), &size,
                      EVP_sha256(), nullptr) == 1);
    assert(size == result.size());
    return result;
}

struct Fixture {
    ArtifactSourceV3 source;
    DynamicVmExecutionAbiV2 abi;
    ContinuationGraphV2 graph;
    BuiltDynamicVmArtifactV3 built;
};

static Fixture makeFixture() {
    ArtifactSourceV3 source{};
    source.build_id[0] = 1;
    source.region_id[0] = 2;
    source.node_capabilities = {{10, {}}, {11, {}}};
    source.node_capabilities[0].capability.fill(0x31);
    source.node_capabilities[1].capability.fill(0x42);

    DynamicVmExecutionAbiV2 abi{};
    abi.abi_id = 0x01020304;
    abi.i32_register_count = 7;
    abi.loadi32_opcode = 0xa1;
    abi.return_i32_opcode = 0xb2;
    abi.decode_salt = 0x5a;
    source.bytecode = {
        abi.loadi32_opcode, static_cast<uint8_t>(1 ^ abi.decode_salt),
        0x78,0x56,0x34,0x12,
        abi.return_i32_opcode, static_cast<uint8_t>(1 ^ abi.decode_salt),
    };
    std::vector<uint8_t> raw_handlers = kLoad;
    raw_handlers.insert(raw_handlers.end(), kReturn.begin(), kReturn.end());

    ContinuationGraphV2 graph{};
    graph.descriptor.abi_id = abi.abi_id;
    graph.descriptor.abi_hash = *hashDynamicVmExecutionAbiV2(abi);
    graph.descriptor.bytecode_hash = rawHash(source.bytecode);
    graph.descriptor.bytecode_size = source.bytecode.size();
    graph.descriptor.handler_shards_size = raw_handlers.size();
    graph.descriptor.entry_node_id = 10;
    graph.descriptor.node_count = 2;
    ContinuationNodeV2 load{};
    load.node_id = 10;
    load.shard_id = 20;
    load.bytecode_size = 6;
    load.shard_size = kLoad.size();
    load.next_node_id = 11;
    load.register_index = 1;
    load.semantic = ContinuationNodeSemanticV2::LoadI32;
    load.status = ContinuationNodeStatusV2::Continue;
    load.variant_id = 30;
    load.bytecode_block_commitment = hashDynamicVmBytecodeBlockV2(
        std::span<const uint8_t>(source.bytecode).first(6));
    load.handler_shard_commitment = hashDynamicVmHandlerShardV2(kLoad);
    load.transition_tail_commitment = *hashDynamicVmTransitionTailV2(load);
    ContinuationNodeV2 ret{};
    ret.node_id = 11;
    ret.shard_id = 21;
    ret.bytecode_offset = 6;
    ret.bytecode_size = 2;
    ret.shard_offset = kLoad.size();
    ret.shard_size = kReturn.size();
    ret.register_index = 1;
    ret.semantic = ContinuationNodeSemanticV2::ReturnI32;
    ret.status = ContinuationNodeStatusV2::Return;
    ret.variant_id = 31;
    ret.bytecode_block_commitment = hashDynamicVmBytecodeBlockV2(
        std::span<const uint8_t>(source.bytecode).last(2));
    ret.handler_shard_commitment = hashDynamicVmHandlerShardV2(kReturn);
    ret.transition_tail_commitment = *hashDynamicVmTransitionTailV2(ret);
    graph.nodes = {load, ret};
    graph.descriptor.graph_commitment = *hashDynamicVmContinuationGraphV2(graph);
    source.continuation_descriptors = encodeDynamicVmExecutionAbiV2(abi);
    const auto graph_bytes = encodeContinuationGraphV2(graph);
    source.continuation_descriptors.insert(source.continuation_descriptors.end(),
                                           graph_bytes.begin(), graph_bytes.end());
    HandlerShardDescriptor handler_descriptor{};
    handler_descriptor.shard_id = graph.nodes.front().shard_id;
    handler_descriptor.code_size = raw_handlers.size();
    handler_descriptor.commitment = hashAarch64ShardCode(raw_handlers);
    source.handler_shards = encodeHandlerShardPayload(
        handler_descriptor, raw_handlers);
    assert(!source.handler_shards.empty());
    auto built = buildSelectiveEncryptedVmArtifactV3(source);
    assert(built);
    return Fixture{std::move(source), abi, graph, std::move(*built)};
}

static WindowGrant grantFor(const Fixture &fixture,
                            const DynamicVmWindowSelectorV3 &selector,
                            std::span<const uint8_t, 32> capability,
                            const std::array<uint8_t, 16> &session,
                            std::span<const uint8_t, 32> session_secret,
                            uint64_t window_id, const DynamicHash &previous,
                            uint8_t next_value) {
    WindowMaterial material{};
    std::copy(capability.begin(), capability.end(), material.window.begin());
    material.decode[0] = fixture.abi.decode_salt;
    material.integrity[0] = static_cast<uint8_t>(0x50 + window_id);
    std::vector<uint8_t> bytes(sizeof(material));
    std::memcpy(bytes.data(), &material, sizeof(material));
    WindowIssueInput input{};
    input.build_id = fixture.source.build_id;
    input.region_id = fixture.source.region_id;
    input.artifact_hash = fixture.built.artifact.artifact_hash;
    input.selector = selector;
    input.session_id = session;
    std::copy(session_secret.begin(), session_secret.end(),
              input.session_secret.begin());
    input.generation = 5;
    input.window_id = window_id;
    input.previous_state_hash = previous;
    input.next_state_hash[0] = next_value;
    input.now_ms = 100;
    input.expires_at_ms = 200;
    input.key_version = 1;
    input.material = std::move(bytes);
    auto grant = issueWindowGrant(input);
    assert(grant);
    return std::move(*grant);
}

int main() {
    auto fixture = makeFixture();
    assert(fixture.built.registration.capabilities().size() == 2);
    const auto selector1 = fixture.built.registration.capabilities()[0].selector;
    const auto selector2 = fixture.built.registration.capabilities()[1].selector;
    const auto capability1 = fixture.built.registration.capabilities()[0].capability;
    const auto capability2 = fixture.built.registration.capabilities()[1].capability;
    assert(selector1.node_id == 10 && selector2.node_id == 11);
    assert(capability1 != capability2);

    std::array<uint8_t, 16> session{};
    session.fill(4);
    std::array<uint8_t, 32> session_secret{};
    session_secret.fill(9);
    DynamicHash initial{};
    initial[0] = 10;
    auto consumer = DynamicVmWindowConsumer::create(
        fixture.built.artifact, fixture.source.build_id, fixture.source.region_id,
        fixture.built.artifact.artifact_hash, session, initial, 5);
    assert(consumer && consumer->expectedSelector() == selector1);

    auto first_grant = grantFor(fixture, selector1, capability1, session,
                                session_secret, 1, initial, 20);
    auto wrong_selector = first_grant;
    wrong_selector.selector = selector2;
    assert(!consumer->consume(wrong_selector, session_secret, 150));
    assert(!consumer->pending() && consumer->windowId() == 0);

    auto scope_consumer = DynamicVmWindowConsumer::create(
        fixture.built.artifact, fixture.source.build_id, fixture.source.region_id,
        fixture.built.artifact.artifact_hash, session, initial, 5);
    assert(scope_consumer);
    {
        auto abandoned = scope_consumer->consume(
            first_grant, session_secret, 150, 10);
        assert(abandoned && scope_consumer->pending());
    }
    assert(!scope_consumer->pending());
    assert(!scope_consumer->consume(first_grant, session_secret, 150, 10));
    assert(scope_consumer->windowId() == 0 && scope_consumer->stateHash() == initial);

    auto overwrite_consumer_a = DynamicVmWindowConsumer::create(
        fixture.built.artifact, fixture.source.build_id, fixture.source.region_id,
        fixture.built.artifact.artifact_hash, session, initial, 5);
    auto overwrite_consumer_b = DynamicVmWindowConsumer::create(
        fixture.built.artifact, fixture.source.build_id, fixture.source.region_id,
        fixture.built.artifact.artifact_hash, session, initial, 5);
    assert(overwrite_consumer_a && overwrite_consumer_b);
    auto overwritten = overwrite_consumer_a->consume(
        first_grant, session_secret, 150, 10);
    auto replacement_authority = overwrite_consumer_b->consume(
        first_grant, session_secret, 150, 10);
    assert(overwritten && replacement_authority);
    *overwritten = std::move(*replacement_authority);
    assert(!overwrite_consumer_a->pending());
    assert(overwrite_consumer_b->pending());
    overwritten.reset();
    assert(!overwrite_consumer_b->pending());
    assert(!overwrite_consumer_a->consume(
        first_grant, session_secret, 150, 10));
    assert(!overwrite_consumer_b->consume(
        first_grant, session_secret, 150, 10));

    auto first_window = consumer->consume(first_grant, session_secret, 150, 10);
    assert(first_window && first_window->live() && consumer->pending());
    assert(consumer->windowId() == 0 && consumer->stateHash() == initial);
    assert(!consumer->consume(first_grant, session_secret, 150));
    DynamicVmExecutionStateForTesting execution;
#if !defined(__aarch64__) || defined(XOVM_DYNAMIC_VM_TEST_NON_AARCH64)
    assert(!executeDynamicVmWindowForTesting(
        fixture.built.artifact, *consumer, std::move(*first_window), execution, 150));
    assert(!first_window->live());
    assert(!consumer->pending());
    assert(!consumer->consume(first_grant, session_secret, 150));
#else
    auto first_result = executeDynamicVmWindowForTesting(
        fixture.built.artifact, *consumer, std::move(*first_window), execution, 150);
    assert(first_result && !first_result->complete);
    assert(first_result->status == XOVM_SHARD_CONTINUE && first_result->ip == 6);
    assert(consumer->windowId() == 1 && consumer->expectedSelector() == selector2);
    assert(!first_window->live());

    DynamicHash second_previous{};
    second_previous[0] = 20;
    auto second_grant = grantFor(fixture, selector2, capability2, session,
                                 session_secret, 2, second_previous, 30);
    auto second_window = consumer->consume(second_grant, session_secret, 150, 11);
    assert(second_window && consumer->pending());
    auto second_result = executeDynamicVmWindowForTesting(
        fixture.built.artifact, *consumer, std::move(*second_window), execution, 150);
    assert(second_result && second_result->complete);
    assert(second_result->status == XOVM_SHARD_RETURN && second_result->ip == 8);
    assert(second_result->return_value == 0x12345678);
    assert(execution.complete() && execution.returnValue() == 0x12345678);
    assert(consumer->windowId() == 2 && !consumer->pending());
    assert(!consumer->consume(second_grant, session_secret, 150));
#endif

    auto poisoned = DynamicVmWindowConsumer::create(
        fixture.built.artifact, fixture.source.build_id, fixture.source.region_id,
        fixture.built.artifact.artifact_hash, session, initial, 5);
    assert(poisoned);
    auto bad_capability = capability1;
    bad_capability[0] ^= 1;
    auto bad_grant = grantFor(fixture, selector1, bad_capability, session,
                              session_secret, 1, initial, 40);
    auto bad_window = poisoned->consume(bad_grant, session_secret, 150);
    assert(bad_window);
    DynamicVmExecutionStateForTesting bad_execution;
    assert(!executeDynamicVmWindowForTesting(
        fixture.built.artifact, *poisoned, std::move(*bad_window),
        bad_execution, 150));
    assert(poisoned->stateHash() == initial && poisoned->windowId() == 0);
    assert(!poisoned->consume(first_grant, session_secret, 150));
    return 0;
}
''',
        encoding="ascii",
    )
    executable = tmp_path / "selective_runtime_probe"
    _compile(source, executable)
    run = subprocess.run([str(executable)], capture_output=True, text=True, timeout=5)
    assert run.returncode == 0, run.stderr

    non_aarch64 = tmp_path / "selective_runtime_probe_non_aarch64"
    _compile(source, non_aarch64,
             extra_flags=("-DXOVM_DYNAMIC_VM_TEST_NON_AARCH64=1",))
    run = subprocess.run([str(non_aarch64)], capture_output=True, text=True, timeout=5)
    assert run.returncode == 0, run.stderr


def test_production_build_hides_every_dynamic_vm_executor(tmp_path):
    source = tmp_path / "production_probe.cpp"
    source.write_text(
        '#include "runtime/cloud_material/dynamic_vm_runtime.h"\n'
        '#include <type_traits>\n'
        'using namespace xovm::material;\n'
        'static_assert(!std::is_copy_constructible_v<ConsumedDynamicVmWindow>);\n'
        'int main() { return 0; }\n',
        encoding="ascii",
    )
    executable = tmp_path / "production_probe"
    _compile(source, executable, testing=False)
    symbols = subprocess.run(
        ["nm", "-C", str(executable)], capture_output=True, text=True, check=True
    ).stdout
    assert "executeDynamicVmWindow" not in symbols
    assert "executeDynamicVmArtifact" not in symbols

    forbidden = tmp_path / "forbidden_executor_probe.cpp"
    forbidden.write_text(
        '#include "runtime/cloud_material/dynamic_vm_runtime.h"\n'
        'auto *executor = &xovm::material::executeDynamicVmWindowForTesting;\n',
        encoding="ascii",
    )
    result = subprocess.run(
        ["c++", "-std=c++20", "-Wall", "-Wextra", "-Werror", "-I",
         str(ROOT), "-c", str(forbidden), "-o", str(tmp_path / "forbidden.o")],
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
