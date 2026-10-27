"""Continuation traversal must be descriptor-driven and validated before use."""

from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]


def test_continuation_cursor_validates_then_advances_declared_chain(tmp_path):
    source = tmp_path / "continuation_probe.cpp"
    source.write_text(
        r'''#include "runtime/cloud_material/continuation_executor.h"
#include <cassert>

using namespace xovm::material;

static DynamicVmExecutionAbiV2 makeAbi() {
  DynamicVmExecutionAbiV2 abi{};
  abi.abi_id = 7;
  abi.i32_register_count = 2;
  abi.loadi32_opcode = 0xa1;
  abi.return_i32_opcode = 0xb2;
  abi.decode_salt = 1;
  return abi;
}

static ContinuationNodeV2 makeNode(uint32_t node_id, uint32_t shard_id,
                                   uint32_t bytecode_offset,
                                   uint32_t bytecode_size,
                                   uint32_t shard_offset, uint32_t shard_size,
                                   uint32_t next_node_id,
                                   ContinuationNodeSemanticV2 semantic,
                                   ContinuationNodeStatusV2 status) {
  ContinuationNodeV2 node{};
  node.node_id = node_id;
  node.shard_id = shard_id;
  node.bytecode_offset = bytecode_offset;
  node.bytecode_size = bytecode_size;
  node.shard_offset = shard_offset;
  node.shard_size = shard_size;
  node.next_node_id = next_node_id;
  node.register_index = 1;
  node.semantic = semantic;
  node.status = status;
  node.variant_id = node_id;
  node.bytecode_block_commitment[0] = 1;
  node.handler_shard_commitment[0] = 2;
  node.transition_tail_commitment[0] = 3;
  return node;
}

static ContinuationGraphV2 makeGraph(const DynamicVmExecutionAbiV2 &abi) {
  ContinuationGraphV2 graph{};
  graph.descriptor.abi_id = abi.abi_id;
  graph.descriptor.abi_hash = *hashDynamicVmExecutionAbiV2(abi);
  graph.descriptor.bytecode_hash[0] = 1;
  graph.descriptor.bytecode_size = 8;
  graph.descriptor.handler_shards_size = 5;
  graph.descriptor.entry_node_id = 10;
  graph.descriptor.node_count = 2;
  graph.descriptor.graph_commitment[0] = 1;
  graph.nodes = {
      makeNode(10, 20, 0, 6, 0, 2, 11,
               ContinuationNodeSemanticV2::LoadI32,
               ContinuationNodeStatusV2::Continue),
      makeNode(11, 21, 6, 2, 2, 3, 0,
               ContinuationNodeSemanticV2::ReturnI32,
               ContinuationNodeStatusV2::Return),
  };
  for (auto &node : graph.nodes)
    node.transition_tail_commitment = *hashDynamicVmTransitionTailV2(node);
  graph.descriptor.graph_commitment =
      *hashDynamicVmContinuationGraphV2(graph);
  return graph;
}

int main() {
  const auto abi = makeAbi();
  auto graph = makeGraph(abi);

  auto cursor = ContinuationCursorV2::create(abi, graph);
  assert(cursor);
  assert(!cursor->complete());
  assert(cursor->current() && cursor->current()->node_id == 10);
  assert(cursor->current()->semantic == ContinuationNodeSemanticV2::LoadI32);

  // A completion cannot redirect traversal, lie about status, or name a
  // different node. Failed advances leave the authenticated cursor in place.
  assert(!cursor->advance({99, ContinuationNodeStatusV2::Continue, 11,
                           cursor->current()->transition_tail_commitment}));
  assert(!cursor->advance({10, ContinuationNodeStatusV2::Return, 11,
                           cursor->current()->transition_tail_commitment}));
  assert(!cursor->advance({10, ContinuationNodeStatusV2::Continue, 0,
                           cursor->current()->transition_tail_commitment}));
  assert(cursor->current() && cursor->current()->node_id == 10);

  assert(cursor->advance({10, ContinuationNodeStatusV2::Continue, 11,
                          cursor->current()->transition_tail_commitment}));
  assert(cursor->current() && cursor->current()->node_id == 11);
  assert(cursor->current()->semantic == ContinuationNodeSemanticV2::ReturnI32);

  // Only the authenticated terminal status and null tail can complete it.
  assert(!cursor->advance({11, ContinuationNodeStatusV2::Continue, 0,
                           cursor->current()->transition_tail_commitment}));
  assert(!cursor->advance({11, ContinuationNodeStatusV2::Return, 10,
                           cursor->current()->transition_tail_commitment}));
  assert(cursor->current() && cursor->current()->node_id == 11);
  auto wrong_tail = cursor->current()->transition_tail_commitment;
  wrong_tail[0] ^= 1;
  assert(!cursor->advance(
      {11, ContinuationNodeStatusV2::Return, 0, wrong_tail}));
  assert(cursor->advance({11, ContinuationNodeStatusV2::Return, 0,
                          cursor->current()->transition_tail_commitment}));
  assert(cursor->complete());
  assert(cursor->current() == nullptr);
  assert(!cursor->advance(
      {11, ContinuationNodeStatusV2::Return, 0, DynamicHash{}}));

  // The cursor owns the graph that passed validation. Later mutation of the
  // caller's descriptors cannot remove or redirect nodes during execution.
  auto isolated = ContinuationCursorV2::create(abi, graph);
  assert(isolated);
  graph.nodes.clear();
  graph.descriptor.node_count = 0;
  assert(isolated->current() && isolated->current()->node_id == 10);
  assert(isolated->advance({10, ContinuationNodeStatusV2::Continue, 11,
                            isolated->current()->transition_tail_commitment}));
  assert(isolated->current() && isolated->current()->node_id == 11);

  // No node is exposed unless the complete topology has already validated.
  auto invalid = makeGraph(abi);
  invalid.nodes.pop_back();
  assert(!ContinuationCursorV2::create(abi, invalid));
  invalid = makeGraph(abi);
  invalid.nodes[0].next_node_id = 12;
  assert(!ContinuationCursorV2::create(abi, invalid));
  invalid = makeGraph(abi);
  invalid.nodes[1].status = ContinuationNodeStatusV2::Continue;
  assert(!ContinuationCursorV2::create(abi, invalid));

  auto wrong_abi = abi;
  wrong_abi.abi_id = 8;
  assert(!ContinuationCursorV2::create(wrong_abi, makeGraph(abi)));
  return 0;
}
''',
        encoding="ascii",
    )
    exe = tmp_path / "probe"
    result = subprocess.run(
        [
            "c++",
            "-std=c++20",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-I",
            str(ROOT),
            str(source),
            str(ROOT / "runtime/cloud_material/continuation_executor.cpp"),
            str(ROOT / "runtime/cloud_material/dynamic_vm_schema.cpp"),
            "-lcrypto",
            "-o",
            str(exe),
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    run = subprocess.run([str(exe)], capture_output=True, text=True)
    assert run.returncode == 0, run.stderr
