"""max 最终 AArch64 ELF 与显式组合语义差分。"""
import pytest
from vm_hardening_support import annotation, transform, build_native, run_case, checked, tools


@pytest.mark.parametrize('seed,knobs', [
    (1, ''), (42, 'threadedDispatch=0'), (20260930, 'perFnEngine=0'),
    (42, 'nestedVM=0'), (1, 'whiteboxAES=0'), (20260930, 'lazyDecrypt=0')])
def test_max_final_elf_semantics(tmp_path, seed, knobs):
    body = '''declare i64 @helper(i64,i64)
define i64 @target(i64 %a,i64 %b,ptr %p) {
 %sum = add i64 %a,%b
 %q = getelementptr i64,ptr %p,i64 1
 store i64 %sum,ptr %q,align 1
 %v = load i64,ptr %q,align 1
 %r = call i64 @helper(i64 %v,i64 %b)
 %c = icmp ult i64 %a,%b
 %s = select i1 %c,i64 %r,i64 %a
 ret i64 %s }
'''
    body += annotation(['target'], 'vm(preset=max'+(','+knobs if knobs else '')+')')
    ir = transform(tmp_path, body, seed=seed)
    exe = build_native(tmp_path, ir, '''
#include <cstdint>
#include <cstdio>
extern "C" uint64_t target(uint64_t,uint64_t,uint64_t*);
extern "C" uint64_t helper(uint64_t a,uint64_t b) { return (a^b)+17; }
int main() { uint64_t p[3]; for(uint64_t a=0;a<32;++a) for(uint64_t b=0;b<32;++b) {
 uint64_t want=a<b?((a+b)^b)+17:a;
 if(target(a,b,p)!=want || p[1]!=a+b) return 1; } puts("equal"); }
''', finalize_targets=True)
    for cmd in ('audit','seal','verify'):
        args = [tools().hardener, cmd, '--input', exe]
        if cmd == 'seal': args += ['--output', exe]
        checked(args)
    run_case(exe)


@pytest.mark.parametrize('cast,src,dst,arg,want', [
    ('fptosi', 'double', 'i64', '5.5', '5'),
    ('fptosi', 'double', 'i32', '-5.5', '-5'),
    ('sitofp', 'i64', 'double', '-7', '-7.0'),
    ('sitofp', 'i32', 'double', '-7', '-7.0')])
def test_cast_only_builds_float_handler(tmp_path, cast, src, dst, arg, want):
    body = f'define {dst} @target({src} %x) {{ %r = {cast} {src} %x to {dst}\n ret {dst} %r }}\n'
    ir = transform(tmp_path, body + annotation(['target'], 'vm(hardened=0,encBytecode=0)'))
    ctypes = {'i32': 'int', 'i64': 'long long', 'double': 'double'}
    exe = build_native(tmp_path, ir, f'''
#include <cstdio>
extern "C" {ctypes[dst]} target({ctypes[src]});
int main() {{ if(target({arg})!={want}) return 1; puts("equal"); }}
''')
    run_case(exe)


@pytest.mark.parametrize('backend_opt', ['-O0', '-O2'])
def test_max_five_call_categories(tmp_path, backend_opt):
    body = '''declare void @cv(ptr)
declare i32 @ci(i32)
declare i64 @cl(i64)
declare ptr @cp(ptr)
declare double @cf(double)
define i64 @target(ptr %p,i32 %x,i64 %y,double %f) {
 call void @cv(ptr %p)
 %i = call i32 @ci(i32 %x)
 %l = call i64 @cl(i64 %y)
 %q = call ptr @cp(ptr %p)
 %d = call double @cf(double %f)
 %v = load i64,ptr %q,align 1
 %z = sext i32 %i to i64
 %n = fptosi double %d to i64
 %a = add i64 %z,%l
 %b = add i64 %a,%v
 %r = add i64 %b,%n
 ret i64 %r }
'''
    ir = transform(tmp_path, body + annotation(['target'], 'vm(preset=max)'), seed=42)
    exe = build_native(tmp_path, ir, '''
#include <cstdint>
#include <cstdio>
extern "C" void cv(uint64_t* p) { *p=11; }
extern "C" int ci(int x) { return x-7; }
extern "C" uint64_t cl(uint64_t x) { return x^15; }
extern "C" uint64_t* cp(uint64_t* p) { return p; }
extern "C" double cf(double d) { return d+2.0; }
extern "C" uint64_t target(uint64_t*,int,uint64_t,double);
int main() { for(int x=-16;x<32;++x) { uint64_t p=0;
 if(target(&p,x,25,3.5)!=uint64_t(x-7)+(25^15)+11+5 || p!=11) return 1;
 } puts("equal"); }
''', finalize_targets=True, backend_opt=backend_opt)
    checked([tools().hardener, 'seal', '--input', exe, '--output', exe])
    checked([tools().hardener, 'verify', '--input', exe])
    run_case(exe)
