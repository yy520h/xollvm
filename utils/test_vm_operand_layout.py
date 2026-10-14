"""字段排列必须改变实际 bytecode，同时保持原生语义与边界检查。"""
import re
import pytest
from vm_hardening_support import annotation, transform, build_native, run_case


@pytest.mark.parametrize('seed', [1, 42, 20260930])
@pytest.mark.parametrize('threaded', [0, 1])
def test_random_operand_layout_executes(seed, threaded, tmp_path):
    source = '''
declare i32 @callee(i32)
define i64 @compute(i32 %x, i64 %y, ptr %p, double %f) {
entry:
 %n = sext i32 %x to i64
 %a = add i64 %n, %y
 %b = xor i64 %a, 53
 %g = getelementptr i64, ptr %p, i64 1
 store i64 %b, ptr %g, align 1
 %v = load i64, ptr %g, align 1
 %lo = trunc i64 %v to i32
 %c = icmp sgt i32 %lo, 0
 %s = select i1 %c, i64 %v, i64 %y
 %df = sitofp i32 %x to double
 %fs = select i1 %c, double %df, double %f
 %fr = fptosi double %fs to i64
 %q = call i32 @callee(i32 %x)
 %q64 = sext i32 %q to i64
 %r = add i64 %s, %fr
 %r2 = add i64 %r, %q64
 br i1 %c, label %yes, label %no
yes:
 ret i64 %r2
no:
 %neg = sub i64 0, %r2
 ret i64 %neg
}
'''
    source += annotation(['compute'],
        f'vm(operandLayout=1,randISA=1,strongBytecode=1,encBytecode=1,lazyDecrypt=1,'
        f'constInStream=1,handlerVariants=2,hardened=0,threadedDispatch={threaded})')
    ir = transform(tmp_path, source, seed)
    assert '!obf.vm.layout' in ir.read_text(), 'operandLayout request had no effective layout witness'
    run_case(build_native(tmp_path, ir, '''
#include <cstdint>
#include <cstdio>
extern "C" int callee(int x) { return x-3; }
extern "C" int64_t compute(int,int64_t,int64_t*,double);
int main() {
 for(int x=-50;x<50;++x) {
    int64_t p[2]={0,0}, y=uint64_t(x)*17;
    int64_t v=(uint64_t(int64_t(x))+uint64_t(y))^53;
    bool c=int32_t(v)>0;
    int64_t r=(c?v:y)+(c?x:7)+(x-3);
    if(compute(x,y,p,7.5)!=(c?r:-r) || p[1]!=v) return 1;
 }
 puts("equal");
}
'''))


def test_layout_changes_field_order_in_handler(tmp_path):
    source = 'define i32 @target(i32 %a,i32 %b) { %r = sub i32 %a,%b\n ret i32 %r }\n'
    offsets = []
    for seed in (1, 42, 20260930):
        work = tmp_path / str(seed)
        work.mkdir()
        ir = transform(work, source + annotation(['target'],
            'vm(operandLayout=1,obfRegIdx=0,encBytecode=0,hardened=0,handlerVariants=1)'), seed)
        text = ir.read_text()
        assert '!obf.vm.layout' in text
        match = re.search(r'vm.opc.binop.v0:.*?(?=\n[-\w.]+:)', text, re.S)
        assert match, 'actual BINOP handler missing'
        handler = match.group()
        offsets.append(re.findall(r'vm\.bo\.[dab]\.rb\.i32 = add i32 [^,]+, (\d+)', handler))
    assert len({tuple(x) for x in offsets}) > 1, 'seeds kept identical operand offsets'


@pytest.mark.parametrize('seed', [1, 42, 20260930])
def test_layout_cast_select_families_and_variable_tails(seed, tmp_path):
    source = '''
define i64 @casts(i8 %a, i16 %b, i64 %n) {
 %x = sext i8 %a to i64
 %y = zext i16 %b to i64
 %t = trunc i64 %n to i16
 %z = zext i16 %t to i64
 %s = add i64 %x, %y
 %r = add i64 %s, %z
 ret i64 %r
}
define float @floating(double %x,i64 %i) {
 %t = fptrunc double %x to float
 %e = fpext float %t to double
 %f = sitofp i64 %i to float
 %r = fadd float %t,%f
 ret float %r
}
define ptr @choose(i1 %c, ptr %a, ptr %b) { %r = select i1 %c, ptr %a, ptr %b
 ret ptr %r }
define i32 @switcher(i32 %a) {
 switch i32 %a, label %def [ i32 -2, label %neg i32 7, label %pos ]
neg: ret i32 17
pos: ret i32 23
def: ret i32 31
}
'''
    source += annotation(['casts', 'floating', 'choose', 'switcher'],
        'vm(operandLayout=1,randISA=1,encBytecode=1,lazyDecrypt=1,constInStream=1,keyedDispatch=1,hardened=1,handlerVariants=2)')
    ir = transform(tmp_path, source, seed)
    run_case(build_native(tmp_path, ir, '''
#include <cstdint>
#include <cstdio>
extern "C" int64_t casts(int8_t,uint16_t,uint64_t);
extern "C" float floating(double,int64_t);
extern "C" void* choose(bool,void*,void*); extern "C" int switcher(int);
int main() {
 int a,b;
 for(int i=-50;i<50;++i) {
    if(casts(int8_t(i),65000,0x1122334455667788ULL)!=i+65000+0x7788) return 1;
    float want=float(1.23456789)+float(int64_t(i));
    if(floating(1.23456789,i)!=want) return 2;
    if(choose(i>0,&a,&b)!=(i>0?&a:&b)) return 3;
    if(switcher(i)!=(i==-2?17:i==7?23:31)) return 4;
 }
 puts("equal");
}
'''))
