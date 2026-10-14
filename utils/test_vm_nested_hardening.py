"""真实嵌套 owner、内层加固、响应绑定；错误共享会导致语义差分失败。"""
import re
import subprocess
import pytest
from vm_hardening_support import annotation, transform, build_native, run_case


@pytest.mark.parametrize('threaded', [0, 1])
def test_distinct_nested_owners_with_real_inner_hardening(tmp_path, threaded):
    body = '''define i64 @first(i64 %a,i64 %b) { %r = add i64 %a,%b
 %s = xor i64 %r,%a
 ret i64 %s }
define i64 @second(i64 %a,i64 %b) { %r = sub i64 %a,%b
 %s = mul i64 %r,%b
 ret i64 %s }
'''
    common = f'nestedVM=1,nestedVMHardened=1,hardened=1,handlerVariants=2,threadedDispatch={threaded}'
    body += annotation(['first'], f'vm({common},whiteboxAES=1,lazyDecrypt=1,strongBytecode=1,operandLayout=1,randISA=1)')
    # 两种 annotation 的 global 名称需独立，保持真实两个配置。
    body += annotation(['second'], f'vm({common},whiteboxAES=0,lazyDecrypt=0,strongBytecode=0,operandLayout=0,randISA=0)').replace('@ann', '@ann2').replace('@llvm.global.annotations', '@second.annotations')
    # LLVM 只有一个 annotations 数组。
    body = body.replace('@llvm.global.annotations = appending global [1 x', '@llvm.global.annotations = appending global [2 x')
    second = re.search(r'@second.annotations = appending global \[1 x.*?\[([^\n]+)\]\n', body)
    assert second
    first_start = body.index('@llvm.global.annotations')
    end = body.index('\n', first_start)
    body = body[:end-1] + ', ' + second.group(1) + ']' + body[end:]
    body = re.sub(r'@second.annotations[^\n]+\n', '', body)
    ir = transform(tmp_path, body)
    text = ir.read_text()
    helpers = re.findall(r'define internal i64 @(__vm_h_binop64[^ (]*)\([^\n]*\).*?\n}', text, re.S)
    assert len(helpers) == 2, 'nested helper owner/config were shared'
    for name in helpers:
        fn = re.search(r'define internal [^\n]+@'+re.escape(name)+r'\([^\n]*\).*?\n}', text, re.S).group()
        assert 'vm.w.flat.disp' in fn, 'nestedVMHardened did not harden helper wrapper'
        assert not re.search(r'\bcall\b[^@\n]*@__vm_h_[\w.]+\(', fn), 'inner calls nested helper again'
    # helper 的 indirect engine 入口也必须是 layer-0，检查其实际函数体。
    engines = re.findall(r'define internal void @(__vm_engine[^ (]*)\([^\n]*\).*?\n}', text, re.S)
    inner_names = [n for n in engines if '.nest' not in n]
    assert len(inner_names) == 2
    for name in inner_names:
        fn = re.search(r'define internal void @'+re.escape(name)+r'\([^\n]*\).*?\n}', text, re.S).group()
        assert not re.search(r'\bcall\b[^@\n]*@__vm_h_[\w.]+\(', fn), 'inner engine recurses through nested helper'
    run_case(build_native(tmp_path, ir, '''
#include <cstdint>
#include <cstdio>
#include <thread>
#include <atomic>
extern "C" uint64_t first(uint64_t,uint64_t),second(uint64_t,uint64_t);
int main() { std::atomic<bool> ok=true; std::thread ts[8];
 for(auto& t:ts) t=std::thread([&] { for(uint64_t a=0;a<64;++a) { uint64_t b=a*13+5;
 if(first(a,b)!=((a+b)^a) || second(a,b)!=(a-b)*b) ok=false; } });
 for(auto& t:ts) t.join(); if(!ok) return 1; puts("equal"); }
'''))


def test_whitebox_effective_antidebug_binding(tmp_path):
    source = 'define i32 @target(i32 %x) { %r = add i32 %x,7\n ret i32 %r }\n'
    source += annotation(['target'], 'vm(whiteboxAES=1,lazyDecrypt=1,hardened=1,bindAntiDebug=1,nestedVM=1,nestedVMHardened=1), antidebug(tracerPid=1)')
    ir = transform(tmp_path, source)
    text = ir.read_text()
    assert 'vm.ad.bind' in text, 'merged antidebug binding was silently disabled'
    responses = re.findall(r'^@(__obf_antidebug_response[^ ]*) =', text, re.M)
    assert len(responses) == 1
    # 仅 fixture 暴露已有原子锁存状态，不开启真实检测/新增线程。
    state = responses[0]
    ir.write_text(text + f'\ndefine void @latch() {{ store atomic i32 1, ptr @{state} monotonic, align 4\n ret void }}\n')
    exe = build_native(tmp_path, ir, '''
#include <cstdio>
extern "C" int target(int); extern "C" void latch();
int main(int argc,char**) { if(argc>1) latch(); int r=target(5);
 if(argc==1 && r!=12) return 1; if(argc>1 && r==12) return 2; puts("equal"); }
''')
    run_case(exe)
    p = subprocess.run([str(exe), 'detected'], capture_output=True, text=True, timeout=30)
    assert p.returncode != 2, 'latched response left decode unchanged'
    assert p.returncode != 0 or p.stdout == 'equal\n'
