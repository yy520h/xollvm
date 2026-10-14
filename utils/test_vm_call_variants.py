"""CALL 必须使用真实 ABI，所有 K 变体都有独立可达目标。"""
import re
import os
import subprocess
import pytest
from vm_hardening_support import annotation, transform, build_native, run_case, tools, checked


@pytest.mark.parametrize('threaded', [0, 1])
def test_all_call_variants_and_typed_abi(tmp_path, threaded):
    source = '''
declare i32 @add2(i32, i32)
declare i64 @mix3(i64, i64, i64)
declare void @store1(ptr, i32)
declare ptr @identity(ptr)
declare double @sumfp(float, double)
define i32 @ci(i32 %a) { %r = call i32 @add2(i32 %a, i32 -4)
 ret i32 %r }
define i64 @cl(i64 %a) { %r = call i64 @mix3(i64 %a, i64 4, i64 3)
 ret i64 %r }
define void @cv(ptr %p, i32 %a) { call void @store1(ptr %p, i32 %a)
 ret void }
define ptr @cp(ptr %p) { %r = call ptr @identity(ptr %p)
 ret ptr %r }
define double @cf(float %a, double %b) { %r = call double @sumfp(float %a, double %b)
 ret double %r }
'''
    source += annotation(['ci', 'cl', 'cv', 'cp', 'cf'],
        f'vm(handlerVariants=4,strongBytecode=1,encBytecode=1,lazyDecrypt=1,hardened=1,threadedDispatch={threaded})')
    ir = transform(tmp_path, source)
    # 实际 dispatch table 对 CALL 各类保留四个不同 handler 入口。
    for kind in ['void', 'int', 'int64', 'ptr', 'f']:
        targets = set(re.findall(r'blockaddress\([^\n]*?%([\w.]*call_' + kind + r'\.v\d+)',
                                 ir.read_text()))
        assert len(targets) >= 4, f'{kind} CALL targets collapsed to {targets}'
    exe = build_native(tmp_path, ir, '''
#include <cstdint>
#include <cstdio>
extern "C" int add2(int a, int b) { return a + b; }
extern "C" uint64_t mix3(uint64_t a,uint64_t b,uint64_t c) { return (a^b)+c; }
extern "C" void store1(int* p,int a) { *p=a; }
extern "C" int* identity(int* p) { return p; }
extern "C" double sumfp(float a,double b) { return double(a)+b; }
extern "C" int ci(int); extern "C" uint64_t cl(uint64_t);
extern "C" void cv(int*,int); extern "C" int* cp(int*);
extern "C" double cf(float,double);
int main() {
    for (int a=0;a<64;++a) {
        int out=0; cv(&out,a);
        if(ci(a)!=a-4 || cl(a)!=((uint64_t(a)^4)+3) || out!=a || cp(&out)!=&out
           || cf(1.5f,2.25)!=3.75) return 1;
    }
    puts("equal");
}
''')
    run_case(exe)


@pytest.mark.parametrize('abi', ['fastcc', 'byval', 'bundle'])
def test_unsupported_call_abi_is_rejected(tmp_path, abi):
    calls = {
        'fastcc': ('declare fastcc i32 @callee(i32)', '%r = call fastcc i32 @callee(i32 %x)'),
        'byval': ('declare i32 @callee(ptr byval(i32))',
                  '%p = alloca i32\n %r = call i32 @callee(ptr byval(i32) %p)'),
        'bundle': ('declare i32 @callee(i32)', '%r = call i32 @callee(i32 %x) [ "deopt"(i32 %x) ]'),
    }
    decl, call = calls[abi]
    source = tmp_path / 'unsupported.ll'
    source.write_text(f'{decl}\ndefine i32 @target(i32 %x) {{ {call}\n ret i32 %r }}\n' +
                      annotation(['target'], 'vm(hardened=0)'))
    p = subprocess.run([str(tools().opt), '-passes=obfuscation', '-obf-no-skips',
                        '-S', str(source), '-o', str(tmp_path / 'out.ll')],
                       capture_output=True, text=True, timeout=60)
    assert p.returncode != 0, 'unsupported CALL ABI silently virtualized'
    assert 'CALL ABI' in p.stderr, p.stderr


def test_sixteen_args_narrow_extensions_and_varargs(tmp_path):
    types = ', '.join(['i64'] * 16)
    args = ', '.join(f'i64 {i}' for i in range(16))
    source = f'''
declare i64 @many({types})
declare i32 @narrow(i8 signext, i16 zeroext)
declare i64 @variadic(i32, ...)
define i64 @sixteen() {{ %r = call i64 @many({args})
 ret i64 %r }}
define i32 @small(i8 %a, i16 %b) {{ %r = call i32 @narrow(i8 signext %a, i16 zeroext %b)
 ret i32 %r }}
define i64 @va() {{ %r = call i64 (i32, ...) @variadic(i32 3, i64 9, double 2.5, ptr null)
 ret i64 %r }}
'''
    source += annotation(['sixteen', 'small', 'va'],
        'vm(handlerVariants=4,strongBytecode=1,encBytecode=1,lazyDecrypt=1,regEncrypt=1,rollingRegKey=1,hardened=1)')
    ir = transform(tmp_path, source)
    assert re.search(r'call i32 %[^\n]*\(i8 signext [^,]+, i16 zeroext ', ir.read_text()), \
        'narrow integer ABI extension attributes were lost'
    params = ','.join(f'uint64_t a{i}' for i in range(16))
    # 各参数权重不同，捕获尾部漏读、错序和错寄存器文件。
    result = '+'.join(f'a{i}*{i+1}' for i in range(16))
    harness = f'''
#include <cstdint>
#include <cstdio>
#include <cstdarg>
extern "C" uint64_t many({params}) {{ return {result}; }}
extern "C" int narrow(int8_t a,uint16_t b) {{ return int(a)+int(b); }}
extern "C" uint64_t variadic(int n,...) {{
    va_list ap; va_start(ap,n);
    uint64_t a=va_arg(ap,uint64_t); double b=va_arg(ap,double); void* p=va_arg(ap,void*);
    va_end(ap); return a+uint64_t(b)+uint64_t(p!=nullptr)+n;
}}
extern "C" uint64_t sixteen(); extern "C" int small(int8_t,uint16_t); extern "C" uint64_t va();
int main() {{
    if(sixteen()!=1360 || small(-123,65000)!=64877 || va()!=14) return 1;
    puts("equal");
}}
'''
    run_case(build_native(tmp_path, ir, harness))


def test_incremental_call_types_in_both_registration_orders(tmp_path):
    unit = tools().opt.parents[1] / 'tools/Obfuscator/VMRequirementsTests'
    checked([unit, '--gtest_filter=VMCallVariants.IncrementalTypesReachEveryVariant', '--gtest_brief=1'])
    env = dict(os.environ, OBF_VM_CALL_IR_DIR=str(tmp_path))
    p = subprocess.run([str(unit), '--gtest_filter=VMCallVariants.IncrementalTypesReachEveryVariant',
                        '--gtest_brief=1'], env=env, capture_output=True, text=True, timeout=120)
    assert p.returncode == 0, p.stdout + p.stderr
    harness = '''
#include <cstdint>
#include <cstdio>
extern "C" int one(int a) { return a-7; }
extern "C" int three(int a,uint64_t b,double c) { return a+int(b)+int(c); }
extern "C" int first(int); extern "C" int later(int,uint64_t,double);
int main() {
    for(int i=0;i<64;++i) if(first(i)!=i-7 || later(i,9,2.5)!=i+11) return 1;
    puts("equal");
}
'''
    for order in (0, 1):
        work = tmp_path / f'order-{order}'
        work.mkdir()
        ir = tmp_path / f'incremental-{order}.ll'
        assert ir.is_file(), 'incremental C++ witness did not execute'
        run_case(build_native(work, ir, harness))
