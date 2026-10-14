"""两个不同函数/动态 operand offset 的实际 byte 解码语义。"""
import pytest
from vm_hardening_support import annotation, transform, build_native, run_case


@pytest.mark.parametrize('strong', [0, 1])
@pytest.mark.parametrize('lazy', [0, 1])
def test_decode_context_native(tmp_path, strong, lazy):
    source = '''
define i32 @first(i32 %a) { %r = xor i32 %a, 305419896
 ret i32 %r }
define i32 @second(i32 %a) { %r = add i32 %a, 16909060
 ret i32 %r }
'''
    source += annotation(['first', 'second'],
        f'vm(encBytecode=1,strongBytecode={strong},lazyDecrypt={lazy},hardened=1)')
    exe = build_native(tmp_path, transform(tmp_path, source), '''
#include <cstdint>
#include <cstdio>
extern "C" uint32_t first(uint32_t), second(uint32_t);
int main() {
    uint32_t a = 0;
    for (unsigned i = 0; i != 64; ++i) {
        a = a * 1664525u + 1013904223u;
        if (first(a) != (a ^ 305419896u) || second(a) != a + 16909060u) return 1;
    }
    puts("equal");
}
''')
    run_case(exe)
