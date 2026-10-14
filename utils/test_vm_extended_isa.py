"""每个扩展 opcode 必须有实际发射证据和独立原生结果。"""
import pytest
from vm_hardening_support import annotation, transform, build_native, run_case

OPS = ('add', 'sub', 'mul', 'and', 'or', 'xor', 'shl', 'lshr', 'ashr')
FUSIONS = [('muladd64', 64, 'mul', 'add'), ('shladd64', 64, 'shl', 'add')]
FUSIONS += [(name + str(w), w, p, c) for w in (32, 64) for name, p, c in (
    ('xoradd', 'xor', 'add'), ('andadd', 'and', 'add'), ('oradd', 'or', 'add'),
    ('addxor', 'add', 'xor'), ('subxor', 'sub', 'xor'), ('mulxor', 'mul', 'xor'))]


@pytest.mark.parametrize('width,op', [(w, op) for w in (32, 64) for op in OPS])
def test_immediate_semantics(width, op, tmp_path):
    literals = [0, 1, 3, width - 1] if op in ('shl', 'lshr', 'ashr') else [0, 1, 3, (1 << width) - 1, 1 << (width - 1)]
    source, names = '', []
    for i, literal in enumerate(literals):
        name = f'f{i}'
        names.append(name)
        source += f'define i{width} @{name}(i{width} %a) {{ %r = {op} i{width} %a,{literal}\n ret i{width} %r }}\n'
    source += annotation(names, 'vm(extendedISA=1,operandLayout=1,randISA=1,encBytecode=1,lazyDecrypt=1,hardened=1,handlerVariants=2)')
    report = tmp_path / 'report.json'
    ir = transform(tmp_path, source, extra=(f'-obf-report-json={report}',))
    assert f'vm.opc.{op}i{width}.v0:' in ir.read_text(), f'{op}i{width} emitted no real handler'
    ty = f'uint{width}_t'
    signed = f'int{width}_t'
    expression = {'add': 'a + L', 'sub': 'a - L', 'mul': 'a * L', 'and': 'a & L',
                  'or': 'a | L', 'xor': 'a ^ L', 'shl': 'a << L', 'lshr': 'a >> L',
                  'ashr': f'{signed}(a) >> L'}[op]
    declarations = '\n'.join(f'extern "C" {ty} {n}({ty});' for n in names)
    checks = '\n'.join(f'{{ {ty} L={literal}ULL; if({n}(a)!={ty}({expression})) return {i+1}; }}'
                       for i, (n, literal) in enumerate(zip(names, literals)))
    harness = f'''
#include <cstdint>
#include <cstdio>
{declarations}
int main() {{
 uint64_t state=0x123456789abcdefULL;
 for(unsigned i=0;i<128;++i) {{
    state=state*6364136223846793005ULL+1442695040888963407ULL;
    {ty} a={ty}(i<4 ? (i==0?0:i==1?1:i==2?~0ULL:(1ULL<<{width-1})) : state);
    {checks}
 }}
 puts("equal");
}}
'''
    run_case(build_native(tmp_path, ir, harness))


@pytest.mark.parametrize('op', ['sub', 'shl', 'lshr', 'ashr'])
def test_left_immediate_noncommutative_falls_back(op, tmp_path):
    source = f'define i32 @target(i32 %a) {{ %r = {op} i32 37,%a\n ret i32 %r }}\n'
    source += annotation(['target'], 'vm(extendedISA=1,encBytecode=0,hardened=0)')
    ir = transform(tmp_path, source)
    expression = {'sub': '37u-a', 'shl': '37u<<a', 'lshr': '37u>>a', 'ashr': 'int32_t(37)>>a'}[op]
    run_case(build_native(tmp_path, ir, f'''
#include <cstdint>
#include <cstdio>
extern "C" uint32_t target(uint32_t);
int main() {{ for(unsigned a=0;a<32;++a) if(target(a)!=uint32_t({expression})) return 1; puts("equal"); }}
'''))


@pytest.mark.parametrize('name,width,producer,consumer', FUSIONS)
def test_computational_fusion(name, width, producer, consumer, tmp_path):
    source = f'''define i{width} @target(i{width} %a,i{width} %b,i{width} %c) {{
 %p = {producer} i{width} %a,%b
 %r = {consumer} i{width} %p,%c
 ret i{width} %r }}\n'''
    source += annotation(['target'], 'vm(extendedISA=1,superOps=1,operandLayout=1,randISA=1,threaded=1,encBytecode=1,lazyDecrypt=1,hardened=1,handlerVariants=2)')
    ir = transform(tmp_path, source)
    assert f'vm.opc.{name}.v0:' in ir.read_text(), f'{name} not emitted'
    ty = f'uint{width}_t'
    operators = {'mul': '*', 'shl': '<<', 'add': '+', 'sub': '-', 'xor': '^', 'and': '&', 'or': '|'}
    expression = f'({ty}(a {operators[producer]} b)) {operators[consumer]} c'
    run_case(build_native(tmp_path, ir, f'''
#include <cstdint>
#include <cstdio>
extern "C" {ty} target({ty},{ty},{ty});
int main() {{
 uint64_t s=17;
 for(unsigned i=0;i<128;++i) {{
   s=s*6364136223846793005ULL+1; {ty} a=s;
   s=s*6364136223846793005ULL+1; {ty} b={'s%'+str(width) if producer=='shl' else 's'};
   s=s*6364136223846793005ULL+1; {ty} c=s;
   if(target(a,b,c)!={ty}({expression})) return 1;
 }}
 puts("equal");
}}
'''))


@pytest.mark.parametrize('kind,predicate', [('cmpsel64', p) for p in ('eq', 'ne', 'ugt', 'uge', 'ult', 'ule', 'sgt', 'sge', 'slt', 'sle')]
                         + [('andcmpz64', p) for p in ('eq', 'ne')])
def test_comparison_fusion(kind, predicate, tmp_path):
    body = (f'%p = icmp {predicate} i64 %a,%b\n %r = select i1 %p,i64 %c,i64 %d\n ret i64 %r'
            if kind == 'cmpsel64' else
            f'%p = and i64 %a,%b\n %r = icmp {predicate} i64 %p,0\n %z = zext i1 %r to i32\n ret i32 %z')
    rt = 'i64' if kind == 'cmpsel64' else 'i32'
    source = f'define {rt} @target(i64 %a,i64 %b,i64 %c,i64 %d) {{ {body} }}\n'
    source += annotation(['target'], 'vm(extendedISA=1,superOps=1,operandLayout=1,randISA=1,encBytecode=1,lazyDecrypt=1,hardened=1)')
    ir = transform(tmp_path, source)
    assert f'vm.opc.{kind}.v0:' in ir.read_text()
    ty = 'uint64_t' if kind == 'cmpsel64' else 'uint32_t'
    operators = {'eq': '==', 'ne': '!=', 'gt': '>', 'ge': '>=', 'lt': '<', 'le': '<='}
    op = operators[predicate if predicate in ('eq', 'ne') else predicate[1:]]
    cast = 'int64_t' if predicate.startswith('s') else 'uint64_t'
    expr = f'({cast}(a){op}{cast}(b)?c:d)' if kind == 'cmpsel64' else f'uint32_t((a&b){op}0)'
    run_case(build_native(tmp_path, ir, f'''
#include <cstdint>
#include <cstdio>
extern "C" {ty} target(uint64_t,uint64_t,uint64_t,uint64_t);
int main() {{
 uint64_t s=19;
 for(unsigned i=0;i<128;++i) {{
   s=s*6364136223846793005ULL+1; uint64_t a=s;
   s=s*6364136223846793005ULL+1; uint64_t b=i%4==0?0:i%4==1?a:i%4==2?~a:s,c=s^0x1234,d=s+99;
   if(target(a,b,c,d)!={expr}) return 1;
 }}
 puts("equal");
}}
'''))


@pytest.mark.parametrize('width,producer,consumer,name', [(32, 'mul', 'add', 'muladd'),
    (32, 'shl', 'add', 'shladd'), (64, 'xor', 'add', 'xoradd64')])
@pytest.mark.parametrize('reason', ['different-block', 'call-between', 'nsw', 'off'])
def test_fusion_structural_guards(width, producer, consumer, name, reason, tmp_path):
    gap = 'br label %next\nnext:' if reason == 'different-block' else 'call void @effect()' if reason == 'call-between' else ''
    flag = ' nsw' if reason == 'nsw' else ''
    source = f'''declare void @effect()
define i{width} @target(i{width} %a,i{width} %b,i{width} %c) {{
 %p = {producer} i{width} %a,%b
 {gap}
 %r = {consumer}{flag} i{width} %p,%c
 ret i{width} %r }}\n'''
    source += annotation(['target'], f'vm(extendedISA=1,superOps={0 if reason=="off" else 1},operandLayout=1,hardened=0)')
    ir = transform(tmp_path, source)
    # 旧四个 handler 会随 superOps 无条件构造；C++ 用真实字节码需求判定其回退。
    if width == 64:
        assert f'vm.opc.{name}.v0:' not in ir.read_text()
    ty = f'uint{width}_t'
    p = {'mul': '*', 'shl': '<<', 'xor': '^'}[producer]
    run_case(build_native(tmp_path, ir, f'''
#include <cstdint>
#include <cstdio>
extern "C" void effect() {{}}
extern "C" {ty} target({ty},{ty},{ty});
int main() {{ for({ty} a=0;a<32;++a) {{ {ty} b=2,c=7;
 if(target(a,b,c)!={ty}((a {p} b)+c)) return 1; }} puts("equal"); }}
'''))


@pytest.mark.parametrize('reason', ['different-block', 'two-uses', 'call-between', 'chain'])
def test_fusion_fallback_and_conflicts(reason, tmp_path):
    bodies = {
        'different-block': '%p = xor i64 %a,%b\n br label %next\nnext: %r = add i64 %p,%c\n ret i64 %r',
        'two-uses': '%p = xor i64 %a,%b\n %r = add i64 %p,%c\n %v = add i64 %r,%p\n ret i64 %v',
        'call-between': '%p = xor i64 %a,%b\n call void @effect()\n %r = add i64 %p,%c\n ret i64 %r',
        'chain': '%p = xor i64 %a,%b\n %r = add i64 %p,%c\n %v = xor i64 %r,%a\n ret i64 %v',
    }
    source = f'declare void @effect()\ndefine i64 @target(i64 %a,i64 %b,i64 %c) {{ {bodies[reason]} }}\n'
    source += annotation(['target'], 'vm(extendedISA=1,superOps=1,operandLayout=1,encBytecode=1,lazyDecrypt=1,hardened=0)')
    ir = transform(tmp_path, source)
    if reason != 'chain':
        assert 'vm.opc.xoradd64.v0:' not in ir.read_text(), 'unsafe fusion crossed structural boundary'
    expr = {'different-block': '(a^b)+c', 'call-between': '(a^b)+c',
            'two-uses': '((a^b)+c)+(a^b)', 'chain': '((a^b)+c)^a'}[reason]
    run_case(build_native(tmp_path, ir, f'''
#include <cstdint>
#include <cstdio>
extern "C" void effect() {{}}
extern "C" uint64_t target(uint64_t,uint64_t,uint64_t);
int main() {{ for(uint64_t a=0;a<128;++a) {{ uint64_t b=a*17,c=a+5;
 uint64_t expected=({expr}), actual=target(a,b,c);
 if(actual!=expected) {{ printf("a=%llu actual=%llu expected=%llu\\n", (unsigned long long)a,
 (unsigned long long)actual, (unsigned long long)expected); return 1; }} }} puts("equal"); }}
'''))


@pytest.mark.parametrize('width,store', [(8, False), (16, False), (32, False), (64, False), (32, True), (64, True)])
@pytest.mark.parametrize('index_width', [32, 64])
def test_gep_memory_fusion(width, store, index_width, tmp_path):
    name = f'gep_{"store" if store else "load"}{width}'
    body = f'store i{width} %v,ptr %p,align 1\n ret void' if store else f'%r = load i{width},ptr %p,align 1\n ret i{width} %r'
    source = f'''define {"void" if store else f"i{width}"} @target(ptr %base,i{index_width} %idx,i{width} %v) {{
 %p = getelementptr i{width},ptr %base,i{index_width} %idx
 {body} }}\n'''
    source += annotation(['target'], 'vm(extendedISA=1,superOps=1,operandLayout=1,randISA=1,threaded=1,encBytecode=1,lazyDecrypt=1,hardened=1)')
    ir = transform(tmp_path, source)
    assert f'vm.opc.{name}.v0:' in ir.read_text(), f'{name} not emitted'
    ty, ix = f'uint{width}_t', f'int{index_width}_t'
    check = (f'target(base,idx,v); {ty} actual; memcpy(&actual,base+idx*{width//8},sizeof(actual)); if(actual!=v) return 1;'
             if store else f'{ty} expected; memcpy(&expected,base+idx*{width//8},sizeof(expected)); if(target(base,idx,v)!=expected) return 1;')
    run_case(build_native(tmp_path, ir, f'''
#include <cstdint>
#include <cstdio>
#include <cstring>
extern "C" {"void" if store else ty} target(void*,{ix},{ty});
int main() {{ uint8_t data[256]; for(unsigned i=0;i<256;++i) data[i]=i*13;
 uint8_t* base=data+97;
 for({ix} idx=-8;idx<=8;++idx) {{ {ty} v={ty}(uint64_t(idx)*123456789);
 {check} }} puts("equal"); }}
'''))


@pytest.mark.parametrize('reason', ['volatile', 'atomic', 'multi-use', 'different-block', 'call-between', 'multi-index', 'disabled'])
def test_gep_memory_fallback(reason, tmp_path):
    gep = 'getelementptr [4 x [4 x i32]],ptr %base,i64 0,i64 %idx,i64 1' if reason == 'multi-index' else 'getelementptr i32,ptr %base,i64 %idx'
    gap = {'different-block': 'br label %next\nnext:', 'call-between': 'call void @effect()',
           'multi-use': 'store i32 7,ptr %p,align 4'}.get(reason, '')
    load = 'load atomic i32,ptr %p monotonic,align 4' if reason == 'atomic' else f'load {"volatile " if reason=="volatile" else ""}i32,ptr %p,align 4'
    source = f'declare void @effect()\ndefine i32 @target(ptr %base,i64 %idx) {{ %p = {gep}\n {gap}\n %r = {load}\n ret i32 %r }}\n'
    source += annotation(['target'], f'vm(extendedISA={0 if reason=="disabled" else 1},superOps=1,hardened=0)')
    ir = transform(tmp_path, source)
    assert 'vm.opc.gep_load32.v0:' not in ir.read_text()


def test_gep_store_then_load_alias_order(tmp_path):
    source = '''define i64 @target(ptr %base,i64 %idx,i64 %v) {
 %p = getelementptr i64,ptr %base,i64 %idx
 store i64 %v,ptr %p,align 1
 %q = getelementptr i64,ptr %base,i64 %idx
 %r = load i64,ptr %q,align 1
 ret i64 %r }\n'''
    source += annotation(['target'], 'vm(extendedISA=1,superOps=1,operandLayout=1,encBytecode=1,lazyDecrypt=1,hardened=1)')
    ir = transform(tmp_path, source)
    assert 'vm.opc.gep_store64.v0:' in ir.read_text() and 'vm.opc.gep_load64.v0:' in ir.read_text()
    run_case(build_native(tmp_path, ir, '''
#include <cstdint>
#include <cstdio>
extern "C" uint64_t target(void*,int64_t,uint64_t);
int main() { uint8_t data[256]={}; for(int64_t i=-8;i<=8;++i)
 if(target(data+97,i,uint64_t(i)*999)!=uint64_t(i)*999) return 1; puts("equal"); }
'''))
