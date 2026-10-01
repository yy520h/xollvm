import os
import json
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
OPT = Path(os.environ.get("XOLLVM_OPT", ROOT / "../build/bin/opt"))


def test_graph_report_contract_is_declared():
    options = (ROOT / "ObfuscationOptions.cpp").read_text(encoding="utf-8")
    options_header = (
        ROOT / "include/llvm/Transforms/Obfuscator/ObfuscationOptions.h"
    ).read_text(encoding="utf-8")
    report_header = (ROOT / "include/llvm/Transforms/Obfuscator/ObfReport.h").read_text(
        encoding="utf-8"
    )
    report_source = (ROOT / "ObfReport.cpp").read_text(encoding="utf-8")

    assert '"obf-graph-dir"' in options
    assert '"obf-graph-mode"' in options
    assert "ObfGraphDir" in options_header
    assert "ObfGraphMode" in options_header
    assert "GraphModel" in report_header
    assert "writeGraphReport" in report_header
    assert "program_callgraph.svg" in report_source


def test_graph_report_emits_callgraph_and_function_svgs(tmp_path):
    if not OPT.is_file():
        pytest.skip(f"opt not found: {OPT}")

    ir = tmp_path / "graph.ll"
    ir.write_text(
        """; graph-report fixture
define i32 @main() {
entry:
  %v = call i32 @worker()
  ret i32 %v
}
define i32 @worker() {
entry:
  ret i32 7
}
""",
        encoding="utf-8",
    )
    out = tmp_path / "graphs"
    result = subprocess.run(
        [
            str(OPT),
            "-passes=obfuscation",
            f"-obf-graph-dir={out}",
            str(ir),
            "-S",
            "-o",
            str(tmp_path / "out.ll"),
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert result.returncode == 0, result.stderr
    assert (out / "obfuscated_callgraph.svg").is_file()
    assert (out / "obfuscated_callgraph.json").is_file()
    assert (out / "functions" / "main.svg").is_file()
    assert (out / "functions" / "worker.svg").is_file()

    callgraph = (out / "obfuscated_callgraph.svg").read_text(encoding="utf-8")
    assert "main" in callgraph
    assert "worker" in callgraph


def test_graph_report_direct_mode_keeps_legacy_svg_name(tmp_path):
    if not OPT.is_file():
        pytest.skip(f"opt not found: {OPT}")
    ir = tmp_path / "direct.ll"
    ir.write_text(
        """define void @main() {
entry:
  ret void
}
""",
        encoding="utf-8",
    )
    out = tmp_path / "graphs"
    result = subprocess.run(
        [
            str(OPT),
            "-passes=obfuscation",
            "-obf-graph-mode=direct",
            f"-obf-graph-dir={out}",
            str(ir),
            "-S",
            "-o",
            str(tmp_path / "out.ll"),
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert result.returncode == 0, result.stderr
    assert (out / "program_callgraph.svg").is_file()
    graph = json.loads((out / "obfuscated_callgraph.json").read_text(encoding="utf-8"))
    assert {edge["type"] for edge in graph["edges"]} <= {"direct_call"}


def test_graph_report_classifies_indirect_and_vm_table_edges(tmp_path):
    if not OPT.is_file():
        pytest.skip(f"opt not found: {OPT}")
    ir = tmp_path / "vm.ll"
    ir.write_text(
        """@vm_table.vm.ophandlers = private constant [1 x ptr] [ptr blockaddress(@__vm_engine_0, %handler)]

define void @__vm_engine_0(ptr %target) {
entry:
  indirectbr ptr %target, [label %handler]
handler:
  ret void
}
""",
        encoding="utf-8",
    )
    out = tmp_path / "graphs"
    result = subprocess.run(
        [
            str(OPT),
            "-passes=obfuscation",
            f"-obf-graph-dir={out}",
            str(ir),
            "-S",
            "-o",
            str(tmp_path / "out.ll"),
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert result.returncode == 0, result.stderr
    graph = json.loads((out / "obfuscated_callgraph.json").read_text(encoding="utf-8"))
    types = {edge["type"] for edge in graph["edges"]}
    node_types = {node["type"] for node in graph["nodes"]}
    assert "indirect_branch" in types
    assert "handler_table" in types
    assert "vm_dispatch" in types
    assert "vm_engine" in node_types
    assert "vm_handler" in node_types


def test_graph_report_exports_vm_engine_witness_metadata(tmp_path):
    if not OPT.is_file():
        pytest.skip(f"opt not found: {OPT}")
    ir = tmp_path / "witness.ll"
    ir.write_text(
        """define void @__vm_engine(ptr %target) !obf.vm.engine !0 {
entry:
  ret void
}
!0 = !{i32 3, i32 4, i32 2, i32 211, i1 true}
""",
        encoding="utf-8",
    )
    out = tmp_path / "graphs"
    result = subprocess.run(
        [
            str(OPT),
            "-passes=obfuscation",
            f"-obf-graph-dir={out}",
            str(ir),
            "-S",
            "-o",
            str(tmp_path / "out.ll"),
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert result.returncode == 0, result.stderr
    graph = json.loads((out / "obfuscated_callgraph.json").read_text(encoding="utf-8"))
    assert graph["vm_engines"] == [
        {
            "function_id": "function:__vm_engine",
            "engine_id": 3,
            "handler_variants": 4,
            "decoys": 2,
            "handler_table_entries": 211,
            "encrypted_dispatch": True,
        }
    ]
    assert {node["type"] for node in graph["nodes"]} >= {
        "vm_engine",
        "vm_dispatcher",
        "vm_handler_variant",
        "vm_handler",
    }
    assert {edge["type"] for edge in graph["edges"]} >= {
        "vm_dispatch",
        "handler_variant",
        "handler_table",
    }


def test_graph_report_supports_obfuscated_mode_json(tmp_path):
    if not OPT.is_file():
        pytest.skip(f"opt not found: {OPT}")

    ir = tmp_path / "mode.ll"
    ir.write_text(
        """define void @main() {
entry:
  ret void
}
""",
        encoding="utf-8",
    )
    out = tmp_path / "graphs"
    result = subprocess.run(
        [
            str(OPT),
            "-passes=obfuscation",
            "-obf-graph-mode=obfuscated",
            f"-obf-graph-dir={out}",
            str(ir),
            "-S",
            "-o",
            str(tmp_path / "out.ll"),
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert result.returncode == 0, result.stderr
    report = out / "obfuscated_callgraph.json"
    assert report.is_file()
    assert '"graph_mode": "obfuscated"' in report.read_text(encoding="utf-8")
