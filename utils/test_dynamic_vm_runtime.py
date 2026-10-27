"""Authenticated window authority and native dynamic VM runtime tests."""

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


def _compile(
    source: Path,
    output: Path,
    *,
    testing: bool = True,
    extra_flags: tuple[str, ...] = (),
) -> None:
    flags = ["-DXOVM_DYNAMIC_VM_TESTING=1"] if testing else []
    flags.extend(extra_flags)
    result = subprocess.run(
        [
            "c++",
            "-std=c++20",
            "-Wall",
            "-Wextra",
            "-Werror",
            *flags,
            "-I",
            str(ROOT),
            str(source),
            *(str(path) for path in RUNTIME_SOURCES),
            "-lcrypto",
            "-o",
            str(output),
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


def test_dynamic_runtime_consumes_only_contiguous_authenticated_windows(tmp_path):
    source = tmp_path / "dynamic_runtime_probe.cpp"
    source.write_text(
        r'''#include "runtime/cloud_material/dynamic_vm_runtime.h"
#include "runtime/cloud_material/dynamic_vm_artifact.h"
#include "runtime/cloud_material/dynamic_vm_shard.h"
#include "runtime/cloud_material/dynamic_vm_window_provider.h"

#include <array>
#include <cassert>
#include <cstring>
#include <openssl/evp.h>
#include <utility>
#include <vector>

using namespace xovm::material;

static EncryptedVmArtifact makeArtifact(ArtifactSource &source) {
    const std::vector<uint8_t> ret = {
        0x01, 0x04, 0x40, 0xf9, 0x02, 0x0c, 0x40, 0xf9,
        0x23, 0x04, 0x40, 0xb9, 0x43, 0x00, 0x00, 0xb9,
        0x43, 0x00, 0x80, 0x52, 0x03, 0x20, 0x00, 0xb9,
        0x20, 0x00, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6,
    };
    DynamicVmExecutionAbiV2 abi{};
    abi.abi_id = 7;
    abi.i32_register_count = 4;
    abi.loadi32_opcode = 0xa1;
    abi.return_i32_opcode = 0xb2;
    abi.decode_salt = 0x5a;
    source.bytecode = {abi.return_i32_opcode,
                       static_cast<uint8_t>(1 ^ abi.decode_salt)};

    ContinuationGraphV2 graph{};
    graph.descriptor.abi_id = abi.abi_id;
    graph.descriptor.abi_hash = *hashDynamicVmExecutionAbiV2(abi);
    unsigned int digest_size = 0;
    assert(EVP_Digest(source.bytecode.data(), source.bytecode.size(),
                      graph.descriptor.bytecode_hash.data(), &digest_size,
                      EVP_sha256(), nullptr) == 1);
    graph.descriptor.bytecode_size = source.bytecode.size();
    graph.descriptor.handler_shards_size = ret.size();
    graph.descriptor.entry_node_id = 10;
    graph.descriptor.node_count = 1;
    ContinuationNodeV2 node{};
    node.node_id = 10;
    node.shard_id = 20;
    node.bytecode_size = source.bytecode.size();
    node.shard_size = ret.size();
    node.register_index = 1;
    node.semantic = ContinuationNodeSemanticV2::ReturnI32;
    node.status = ContinuationNodeStatusV2::Return;
    node.variant_id = 30;
    node.bytecode_block_commitment = hashDynamicVmBytecodeBlockV2(source.bytecode);
    node.handler_shard_commitment = hashDynamicVmHandlerShardV2(ret);
    node.transition_tail_commitment = *hashDynamicVmTransitionTailV2(node);
    graph.nodes = {node};
    graph.descriptor.graph_commitment = *hashDynamicVmContinuationGraphV2(graph);
    source.continuation_descriptors = encodeDynamicVmExecutionAbiV2(abi);
    const auto graph_bytes = encodeContinuationGraphV2(graph);
    source.continuation_descriptors.insert(source.continuation_descriptors.end(),
                                           graph_bytes.begin(), graph_bytes.end());
    HandlerShardDescriptor descriptor{};
    descriptor.shard_id = node.shard_id;
    descriptor.code_size = ret.size();
    descriptor.commitment = hashAarch64ShardCode(ret);
    source.handler_shards = encodeHandlerShardPayload(descriptor, ret);
    auto artifact = buildEncryptedVmArtifact(source);
    assert(artifact);
    return *artifact;
}

int main() {
    ArtifactSource source{};
    source.build_id[0] = 1;
    source.region_id[0] = 2;
    source.artifact_key.fill(3);
    const auto artifact = makeArtifact(source);
    std::array<uint8_t, 16> session{};
    session.fill(4);
    DynamicHash initial{};
    initial[0] = 10;
    auto consumer = DynamicVmWindowConsumer::create(
        artifact, source.build_id, source.region_id, artifact.artifact_hash,
        session, initial, 9);
    assert(consumer && consumer->generation() == 9);
    auto wrong_hash = artifact.artifact_hash;
    wrong_hash[0] ^= 1;
    assert(!DynamicVmWindowConsumer::create(
        artifact, source.build_id, source.region_id, wrong_hash, session,
        initial, 9));

    WindowMaterial material{};
    material.window = source.artifact_key;
    material.decode[0] = 0x5a;
    material.jit[0] = 12;
    material.integrity[0] = 13;
    std::vector<uint8_t> bytes(sizeof(material));
    std::memcpy(bytes.data(), &material, sizeof(material));
    WindowRequest request{};
    request.build_id = source.build_id;
    request.region_id = source.region_id;
    request.session_id = session;
    request.session_secret.fill(9);
    request.generation = 9;
    request.window_id = 1;
    request.previous_state_hash = initial;
    request.next_state_hash[0] = 20;
    request.now_ms = 100;
    request.expires_at_ms = 200;
    request.key_version = 1;
    request.material = bytes;
    auto grant = issueWindowGrant(request);
    assert(grant);
    auto moved_consumer = std::move(*consumer);
    assert(!consumer->consume(*grant, request.session_secret, 150, 7));
    auto consumed = moved_consumer.consume(*grant, request.session_secret, 150, 7);
    assert(consumed && consumed->live());
    assert(consumed->buildId() == source.build_id);
    assert(consumed->regionId() == source.region_id);
    assert(consumed->artifactHash() == artifact.artifact_hash);
    assert(consumed->generation() == 9 && consumed->windowId() == 1);
    assert(consumed->matchesDecodeSalt(0x5a));
    assert(moved_consumer.integrityCommitment() != DynamicHash{});
    assert(!moved_consumer.consume(*grant, request.session_secret, 150));

    request.window_id = 2;
    request.previous_state_hash = request.next_state_hash;
    request.next_state_hash = {};
    request.next_state_hash[0] = 30;
    auto next = issueWindowGrant(request);
    assert(next);
    auto next_consumed = moved_consumer.consume(*next, request.session_secret, 150);
    assert(next_consumed && next_consumed->generation() == 9);
    assert(next_consumed->windowId() == 2);

    WindowGrant wrong_generation = *next;
    wrong_generation.generation = 10;
    wrong_generation.window_id = 3;
    wrong_generation.previous_state_hash = request.next_state_hash;
    wrong_generation.next_state_hash[0] = 40;
    assert(!moved_consumer.consume(wrong_generation, request.session_secret, 150));
    WindowGrant skipped = wrong_generation;
    skipped.generation = 9;
    skipped.window_id = 4;
    assert(!moved_consumer.consume(skipped, request.session_secret, 150));
    auto expired = *next;
    expired.window_id = 3;
    expired.previous_state_hash = request.next_state_hash;
    expired.next_state_hash[0] = 40;
    assert(!moved_consumer.consume(expired, request.session_secret, 200));
    return 0;
}
''',
        encoding="ascii",
    )
    executable = tmp_path / "window_probe"
    _compile(source, executable)
    run = subprocess.run([str(executable)], capture_output=True, text=True, timeout=5)
    assert run.returncode == 0, run.stderr


def test_dynamic_runtime_preflights_whole_package_and_executes_exact_native_graph(tmp_path):
    source = tmp_path / "dynamic_execution_probe.cpp"
    source.write_text(
        r'''#include "runtime/cloud_material/dynamic_vm_runtime.h"
#include "runtime/cloud_material/dynamic_vm_artifact.h"
#include "runtime/cloud_material/dynamic_vm_shard.h"
#include "runtime/cloud_material/dynamic_vm_window_provider.h"

#include <array>
#include <cassert>
#include <cstring>
#include <openssl/evp.h>
#include <utility>
#include <vector>

using namespace xovm::material;

struct Fixture {
    ArtifactSource source;
    EncryptedVmArtifact artifact;
    uint8_t decode_salt = 0;
};

enum class FixtureKind { TwoNode, OneNode };

static const std::vector<uint8_t> kLoad = {
    0x01, 0x04, 0x40, 0xf9, 0x02, 0xcf, 0x8a, 0x52,
    0x82, 0x46, 0xa2, 0x72, 0x22, 0x04, 0x00, 0xb9,
    0xc3, 0x00, 0x80, 0x52, 0x03, 0x20, 0x00, 0xb9,
    0x00, 0x00, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6,
};
static const std::vector<uint8_t> kReturnAtEight = {
    0x01, 0x04, 0x40, 0xf9, 0x02, 0x0c, 0x40, 0xf9,
    0x23, 0x04, 0x40, 0xb9, 0x43, 0x00, 0x00, 0xb9,
    0x03, 0x01, 0x80, 0x52, 0x03, 0x20, 0x00, 0xb9,
    0x20, 0x00, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6,
};
static const std::vector<uint8_t> kReturnAtTwo = {
    0x01, 0x04, 0x40, 0xf9, 0x02, 0x0c, 0x40, 0xf9,
    0x23, 0x04, 0x40, 0xb9, 0x43, 0x00, 0x00, 0xb9,
    0x43, 0x00, 0x80, 0x52, 0x03, 0x20, 0x00, 0xb9,
    0x20, 0x00, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6,
};

static DynamicHash rawHash(const std::vector<uint8_t> &bytes) {
    DynamicHash result{};
    unsigned int size = 0;
    assert(EVP_Digest(bytes.data(), bytes.size(), result.data(), &size,
                      EVP_sha256(), nullptr) == 1);
    assert(size == result.size());
    return result;
}

static Fixture makeFixture(FixtureKind kind, uint8_t identity) {
    Fixture fixture{};
    fixture.source.build_id[0] = identity;
    fixture.source.region_id[0] = static_cast<uint8_t>(identity + 1);
    fixture.source.artifact_key.fill(static_cast<uint8_t>(identity + 2));
    fixture.decode_salt = 0x5a;
    DynamicVmExecutionAbiV2 abi{};
    abi.abi_id = 0x01020304;
    abi.i32_register_count = 7;
    abi.loadi32_opcode = 0xa1;
    abi.return_i32_opcode = 0xb2;
    abi.decode_salt = fixture.decode_salt;

    std::vector<uint8_t> handlers;
    ContinuationGraphV2 graph{};
    graph.descriptor.abi_id = abi.abi_id;
    graph.descriptor.abi_hash = *hashDynamicVmExecutionAbiV2(abi);
    graph.descriptor.entry_node_id = 10;
    if (kind == FixtureKind::TwoNode) {
        fixture.source.bytecode = {
            abi.loadi32_opcode, static_cast<uint8_t>(1 ^ abi.decode_salt),
            0x78, 0x56, 0x34, 0x12,
            abi.return_i32_opcode, static_cast<uint8_t>(1 ^ abi.decode_salt),
        };
        handlers = kLoad;
        handlers.insert(handlers.end(), kReturnAtEight.begin(), kReturnAtEight.end());
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
            std::span<const uint8_t>(fixture.source.bytecode).first(6));
        load.handler_shard_commitment = hashDynamicVmHandlerShardV2(kLoad);
        load.transition_tail_commitment = *hashDynamicVmTransitionTailV2(load);
        ContinuationNodeV2 ret{};
        ret.node_id = 11;
        ret.shard_id = 21;
        ret.bytecode_offset = 6;
        ret.bytecode_size = 2;
        ret.shard_offset = kLoad.size();
        ret.shard_size = kReturnAtEight.size();
        ret.register_index = 1;
        ret.semantic = ContinuationNodeSemanticV2::ReturnI32;
        ret.status = ContinuationNodeStatusV2::Return;
        ret.variant_id = 31;
        ret.bytecode_block_commitment = hashDynamicVmBytecodeBlockV2(
            std::span<const uint8_t>(fixture.source.bytecode).last(2));
        ret.handler_shard_commitment = hashDynamicVmHandlerShardV2(kReturnAtEight);
        ret.transition_tail_commitment = *hashDynamicVmTransitionTailV2(ret);
        graph.nodes = {load, ret};
    } else {
        fixture.source.bytecode = {
            abi.return_i32_opcode, static_cast<uint8_t>(1 ^ abi.decode_salt),
        };
        handlers = kReturnAtTwo;
        ContinuationNodeV2 ret{};
        ret.node_id = 10;
        ret.shard_id = 20;
        ret.bytecode_size = 2;
        ret.shard_size = handlers.size();
        ret.register_index = 1;
        ret.semantic = ContinuationNodeSemanticV2::ReturnI32;
        ret.status = ContinuationNodeStatusV2::Return;
        ret.variant_id = 30;
        ret.bytecode_block_commitment = hashDynamicVmBytecodeBlockV2(
            fixture.source.bytecode);
        ret.handler_shard_commitment = hashDynamicVmHandlerShardV2(handlers);
        ret.transition_tail_commitment = *hashDynamicVmTransitionTailV2(ret);
        graph.nodes = {ret};
    }
    graph.descriptor.bytecode_hash = rawHash(fixture.source.bytecode);
    graph.descriptor.bytecode_size = fixture.source.bytecode.size();
    graph.descriptor.handler_shards_size = handlers.size();
    graph.descriptor.node_count = graph.nodes.size();
    graph.descriptor.graph_commitment = *hashDynamicVmContinuationGraphV2(graph);
    fixture.source.continuation_descriptors = encodeDynamicVmExecutionAbiV2(abi);
    const auto graph_bytes = encodeContinuationGraphV2(graph);
    fixture.source.continuation_descriptors.insert(
        fixture.source.continuation_descriptors.end(), graph_bytes.begin(),
        graph_bytes.end());
    HandlerShardDescriptor descriptor{};
    descriptor.shard_id = graph.nodes.front().shard_id;
    descriptor.code_size = handlers.size();
    descriptor.commitment = hashAarch64ShardCode(handlers);
    fixture.source.handler_shards = encodeHandlerShardPayload(descriptor, handlers);
    auto artifact = buildEncryptedVmArtifact(fixture.source);
    assert(artifact);
    fixture.artifact = std::move(*artifact);
    return fixture;
}

static std::optional<ConsumedDynamicVmWindow> makeWindow(
    const Fixture &fixture, std::array<uint8_t, 32> key, uint8_t decode_salt) {
    std::array<uint8_t, 16> session{};
    session.fill(4);
    DynamicHash initial{};
    initial[0] = 9;
    auto consumer = DynamicVmWindowConsumer::create(
        fixture.artifact, fixture.source.build_id, fixture.source.region_id,
        fixture.artifact.artifact_hash, session, initial, 5);
    assert(consumer);
    WindowMaterial material{};
    material.window = key;
    material.decode[0] = decode_salt;
    material.integrity[0] = 1;
    std::vector<uint8_t> bytes(sizeof(material));
    std::memcpy(bytes.data(), &material, sizeof(material));
    WindowRequest request{};
    request.build_id = fixture.source.build_id;
    request.region_id = fixture.source.region_id;
    request.session_id = session;
    request.session_secret.fill(8);
    request.generation = 5;
    request.window_id = 1;
    request.previous_state_hash = initial;
    request.next_state_hash[0] = 10;
    request.now_ms = 100;
    request.expires_at_ms = 200;
    request.key_version = 1;
    request.material = bytes;
    auto grant = issueWindowGrant(request);
    assert(grant);
    return consumer->consume(*grant, request.session_secret, 150);
}

int main() {
    const auto two = makeFixture(FixtureKind::TwoNode, 1);
    const auto one = makeFixture(FixtureKind::OneNode, 4);
    auto bad_salt = makeWindow(
        two, two.source.artifact_key,
        static_cast<uint8_t>(two.decode_salt ^ 1));
    assert(bad_salt && bad_salt->live());
    assert(!executeDynamicVmArtifactForTesting(
        two.artifact, std::move(*bad_salt), 150));
    assert(!bad_salt->live());
    assert(!executeDynamicVmArtifactForTesting(
        two.artifact, std::move(*bad_salt), 150));

    auto bad_key = two.source.artifact_key;
    bad_key[0] ^= 1;
    auto wrong_key = makeWindow(two, bad_key, two.decode_salt);
    assert(wrong_key);
    assert(!executeDynamicVmArtifactForTesting(
        two.artifact, std::move(*wrong_key), 150));

    auto wrong_identity = makeWindow(two, two.source.artifact_key, two.decode_salt);
    assert(wrong_identity);
    assert(!executeDynamicVmArtifactForTesting(
        one.artifact, std::move(*wrong_identity), 150));

    auto expired = makeWindow(two, two.source.artifact_key, two.decode_salt);
    assert(expired && expired->expiresAtMs() == 200);
    assert(!executeDynamicVmArtifactForTesting(
        two.artifact, std::move(*expired), 200));
    assert(!expired->live());

    auto wrong_ip = makeWindow(two, two.source.artifact_key, two.decode_salt);
    assert(wrong_ip);
    assert(!executeDynamicVmArtifactForTesting(
        two.artifact, std::move(*wrong_ip), 150, 6));

#if !defined(__aarch64__) || defined(XOVM_DYNAMIC_VM_TEST_NON_AARCH64)
    auto unsupported_host = makeWindow(
        two, two.source.artifact_key, two.decode_salt);
    assert(unsupported_host);
    assert(!executeDynamicVmArtifactForTesting(
        two.artifact, std::move(*unsupported_host), 150));
    assert(!unsupported_host->live());
#else
    auto two_window = makeWindow(two, two.source.artifact_key, two.decode_salt);
    assert(two_window);
    auto two_result = executeDynamicVmArtifactForTesting(
        two.artifact, std::move(*two_window), 150);
    assert(two_result && two_result->status == XOVM_SHARD_RETURN);
    assert(two_result->ip == 8 && two_result->return_value == 0x12345678);
    assert(!two_window->live());

    auto one_window = makeWindow(one, one.source.artifact_key, one.decode_salt);
    assert(one_window);
    auto one_result = executeDynamicVmArtifactForTesting(
        one.artifact, std::move(*one_window), 150);
    assert(one_result && one_result->status == XOVM_SHARD_RETURN);
    assert(one_result->ip == 2 && one_result->return_value == 0);
    assert(!one_window->live());
#endif
    return 0;
}
''',
        encoding="ascii",
    )
    executable = tmp_path / "execution_probe"
    _compile(source, executable)
    run = subprocess.run([str(executable)], capture_output=True, text=True, timeout=5)
    assert run.returncode == 0, run.stderr

    non_aarch64 = tmp_path / "execution_probe_non_aarch64"
    _compile(
        source,
        non_aarch64,
        extra_flags=("-DXOVM_DYNAMIC_VM_TEST_NON_AARCH64=1",),
    )
    run = subprocess.run(
        [str(non_aarch64)], capture_output=True, text=True, timeout=5
    )
    assert run.returncode == 0, run.stderr


def test_production_build_hides_every_dynamic_vm_executor(tmp_path):
    source = tmp_path / "production_probe.cpp"
    source.write_text(
        r'''#include "runtime/cloud_material/dynamic_vm_runtime.h"
#include <type_traits>
using namespace xovm::material;
static_assert(!std::is_copy_constructible_v<ConsumedDynamicVmWindow>);
static_assert(!std::is_copy_assignable_v<ConsumedDynamicVmWindow>);
int main() { return 0; }
''',
        encoding="ascii",
    )
    executable = tmp_path / "production_probe"
    _compile(source, executable, testing=False)
    symbols = subprocess.run(
        ["nm", "-C", str(executable)], capture_output=True, text=True, check=True
    ).stdout
    assert "executeDynamicVmArtifact" not in symbols

    forbidden = tmp_path / "forbidden_executor_probe.cpp"
    forbidden.write_text(
        '#include "runtime/cloud_material/dynamic_vm_runtime.h"\n'
        'auto *executor = &xovm::material::executeDynamicVmArtifactForTesting;\n',
        encoding="ascii",
    )
    result = subprocess.run(
        [
            "c++",
            "-std=c++20",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-I",
            str(ROOT),
            "-c",
            str(forbidden),
            "-o",
            str(tmp_path / "forbidden.o"),
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
''
