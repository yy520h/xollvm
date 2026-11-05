"""Minimal C++ cloud API contract tests."""

from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]


def test_cloud_api_exposes_only_bounded_six_operation_provider_contract(tmp_path):
    source = tmp_path / "cloud_api_probe.cpp"
    source.write_text(
        '#include "runtime/cloud_material_backend/cloud_api.h"\n'
        '#include <cassert>\n'
        '#include <type_traits>\n'
        'int main() {\n'
        '  using namespace xovm::cloud_material;\n'
        '  using AlgorithmMethod = std::variant<xovm::material::WindowGrant, CloudApiError> (CloudApi::*)(const AuthenticatedRawContext &, const xovm::material::WindowAcquireRequest &) const;\n'
        '  static_assert(std::is_same_v<decltype(&CloudApi::algorithm), AlgorithmMethod>);\n'
        '  CloudApi api({});\n'
        '  auto a = api.announcement(); assert(std::holds_alternative<CloudApiError>(a));\n'
        '  auto u = api.update(""); assert(std::holds_alternative<CloudApiError>(u));\n'
        '  auto v = api.variables(""); assert(std::holds_alternative<CloudApiError>(v));\n'
        '  std::array<unsigned char, 1> proof{1};\n'
        '  auto l = api.accountLogin("user", proof); assert(std::holds_alternative<CloudApiError>(l));\n'
        '  auto c = api.cardLogin(proof, proof); assert(std::holds_alternative<CloudApiError>(c));\n'
        '  return 0;\n'
        '}\n', encoding="ascii")
    exe = tmp_path / "probe"
    result = subprocess.run(
        ["c++", "-std=c++20", "-Wall", "-Wextra", "-Werror", "-I", str(ROOT),
         str(source), str(ROOT / "runtime/cloud_material_backend/cloud_api.cpp"),
         str(ROOT / "runtime/cloud_material/dynamic_vm_schema.cpp"), "-lcrypto", "-o", str(exe)],
        capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert subprocess.run([str(exe)], capture_output=True, text=True).returncode == 0
