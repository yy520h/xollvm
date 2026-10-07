"""执行 release job 的条件表达式，覆盖可选依赖与失败/取消组合。"""

import itertools
import re
from pathlib import Path

import pytest


REPO = Path(__file__).resolve().parents[1]
WORKFLOWS = [REPO / ".github/workflows/release.yml"]


def release_enabled(workflow, inputs, results, cancelled=False):
    text = workflow.read_text()
    job_match = re.search(r"^  release:\n(.*?)(?=^  \S|\Z)", text, re.M | re.S)
    assert job_match, "release job missing"
    job = job_match.group(1)
    match = re.search(r"^    if: (.*?)(?=^    [\w-]+:|\Z)", job, re.M | re.S)
    if not match:
        return not cancelled and all(value == "success" for value in results.values())
    expr = match.group(1).strip()
    if expr.startswith((">", "|")):
        expr = expr.split("\n", 1)[1].strip()
    expr = expr.removeprefix("${{").removesuffix("}}").strip()
    # Actions 无显式状态函数时隐含 success()，skipped needs 会阻止 job。
    status_fn = re.search(r"\b(?:always|cancelled|success|failure)\s*\(", expr)
    if not status_fn and (cancelled or any(r != "success" for r in results.values())):
        return False
    expr = re.sub(r"inputs\.(\w+)", lambda m: repr(inputs[m[1]]), expr)
    expr = re.sub(r"needs\['([^']+)'\]\.result", lambda m: repr(results[m[1]]), expr)
    expr = re.sub(r"needs\.([\w-]+)\.result", lambda m: repr(results[m[1]]), expr)
    functions = {"always": True, "cancelled": cancelled,
                 "success": all(r == "success" for r in results.values()),
                 "failure": any(r == "failure" for r in results.values())}
    expr = re.sub(r"(always|cancelled|success|failure)\(\)", lambda m: repr(functions[m[1]]), expr)
    expr = expr.replace("&&", " and ").replace("||", " or ")
    expr = re.sub(r"!(?!=)", " not ", expr)
    # 仅执行上述条件语法，拒绝表达式中的未知名字/访问。
    remainder = re.sub(r"'[^']*'|\b(?:True|False|and|or|not)\b|[()=\s]", "", expr)
    assert not remainder, f"unsupported release expression: {expr}"
    return bool(eval("(" + expr.strip() + ")", {"__builtins__": {}}, {}))


@pytest.mark.parametrize("workflow", WORKFLOWS)
def test_selected_builds_release_despite_optional_skips(workflow):
    for llvm22, llvm23, android in itertools.product((False, True), repeat=3):
        inputs = dict(build_llvm22=llvm22, build_llvm23=llvm23, build_android=android)
        selected = {"build22": llvm22, "build23": llvm23,
                    "build-android22": llvm22 and android, "build-android23": llvm23 and android}
        results = {job: "success" if enabled else "skipped" for job, enabled in selected.items()}
        assert release_enabled(workflow, inputs, results) == (llvm22 or llvm23), (inputs, results)


@pytest.mark.parametrize("workflow", WORKFLOWS)
def test_selected_build_failure_cancel_or_skip_blocks_release(workflow):
    for llvm22, llvm23, android in itertools.product((False, True), repeat=3):
        inputs = dict(build_llvm22=llvm22, build_llvm23=llvm23, build_android=android)
        selected = {"build22": llvm22, "build23": llvm23,
                    "build-android22": llvm22 and android, "build-android23": llvm23 and android}
        results = {job: "success" if enabled else "skipped" for job, enabled in selected.items()}
        for job, enabled in selected.items():
            if not enabled:
                continue
            for result in ("failure", "cancelled", "skipped"):
                broken = dict(results, **{job: result})
                assert not release_enabled(workflow, inputs, broken), (inputs, broken)
        assert not release_enabled(workflow, inputs, results, cancelled=True)
