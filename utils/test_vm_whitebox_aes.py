"""白盒标准答案、实际 VM 后端和并发，不使用真实凭据。"""
import os
import subprocess
import re
from pathlib import Path
import pytest
from vm_hardening_support import annotation, transform, build_native, run_case, checked, tools


def test_native_fips_known_answer(tmp_path):
    ir = tmp_path / 'kat.ll'
    unit = Path(__file__).resolve().parents[2] / 'build-sensitive/tools/Obfuscator/VMRequirementsTests'
    env = dict(os.environ, XOLLVM_WHITEBOX_KAT_IR=str(ir))
    p = subprocess.run([str(unit), '--gtest_filter=VMWhiteBoxAES.*'], env=env, capture_output=True, text=True, timeout=120)
    assert p.returncode == 0, p.stdout+p.stderr
    run_case(build_native(tmp_path, ir, '''
#include <cstdint>
#include <cstdio>
#include <cstring>
extern "C" void kat(const uint8_t*,uint8_t*);
extern "C" { unsigned count=0; }
int main() { uint8_t in[16]={0,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff},out[16];
 const uint8_t expected[16]={0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a};
 kat(in,out); if(memcmp(out,expected,16)) return 1; puts("equal"); }
 '''))


def test_final_known_key_scan_and_unused_table_gc(tmp_path, fetch_ir):
    # FIPS-197 Appendix A.1 全部 round keys；期望值独立于生产 keyExpand。
    expanded = bytes.fromhex('''
000102030405060708090a0b0c0d0e0f
d6aa74fdd2af72fadaa678f1d6ab76fe
b692cf0b643dbdf1be9bc5006830b3fe
b6ff744ed2c2c9bf6c590cbf0469bf41
47f7f7bc95353e03f96c32bcfd058dfd
3caaa3e8a99f9deb50f3af57adf622aa
5e390f7df7a69296a7553dc10aa31f6b
14f9701ae35fe28c440adf4d4ea9c026
47438735a41c65b9e016baf4aebf7ad2
549932d1f08557681093ed9cbe2c974e
13111d7fe3944a17f307a78b4d2b30c5
''')
    assert len(expanded) == 176
    text = fetch_ir.read_text()
    live = re.search(r'@__vm_whitebox\.[\w]+ = private unnamed_addr constant \[372736 x i8\] c"([^"]+)"', text)
    assert live
    # LLVM 字符串可能保留 printable 字符，用完整解析避免漏字节。
    raw = live[1]; parsed = bytearray(); i = 0
    while i < len(raw):
        if raw[i] == '\\':
            if raw[i+1] == '\\':
                parsed.append(92); i += 2
            else:
                parsed.append(int(raw[i+1:i+3],16)); i += 3
        else:
            parsed.append(ord(raw[i])); i += 1
    table = bytes(parsed)
    assert len(table) == 372736 and expanded not in table
    marker = b'UNREFERENCED-WHITEBOX-TABLE-012345'
    encoded = ''.join(f'\\{b:02X}' for b in marker)
    fetch_ir.write_text(text+f'\n@__vm_whitebox.unused = private constant [{len(marker)} x i8] c"{encoded}"\n')
    exe = build_native(tmp_path, fetch_ir, '''
#include <cstdint>
extern "C" { unsigned count=0; }
extern "C" void kat(const uint8_t*,uint8_t*);
int main() { uint8_t in[16]={},out[16]; kat(in,out); return 0; }
''', backend_opt='-O2')
    image = exe.read_bytes()
    assert expanded not in image
    assert table in image
    assert marker not in image


@pytest.fixture
def fetch_ir(tmp_path):
    ir = tmp_path / 'fetch.ll'
    unit = Path(__file__).resolve().parents[2] / 'build-sensitive/tools/Obfuscator/VMRequirementsTests'
    p = subprocess.run([str(unit), '--gtest_filter=VMWhiteBoxAES.*'],
        env=dict(os.environ, XOLLVM_WHITEBOX_KAT_IR=str(ir)), capture_output=True, text=True, timeout=120)
    assert p.returncode == 0, p.stdout+p.stderr
    return ir


@pytest.mark.parametrize('indices,calls', [([0,1,15],1), ([15,16,17],2), ([31,0,31],3)])
def test_lazy_cache(indices, calls, tmp_path, fetch_ir):
    values = ','.join(map(str, indices))
    run_case(build_native(tmp_path, fetch_ir, f'''
#include <cstdint>
#include <cstdio>
#include <atomic>
extern "C" {{ std::atomic<unsigned> count=0; }}
extern "C" void init(void*);
extern "C" uint8_t fetch(void*,unsigned);
int main() {{ alignas(8) uint8_t ctx[40]; init(ctx);
 unsigned indices[]={{{values}}}; for(unsigned i:indices) if(fetch(ctx,i)!=uint8_t(i*7)) return 1;
 if(count!={calls}) return 2; printf("correct calls=%u\\n", count.load()); }}
'''), expected=f'correct calls={calls}\n')


def test_cache_recursive_concurrent_isolation(tmp_path, fetch_ir):
    run_case(build_native(tmp_path, fetch_ir, '''
#include <cstdint>
#include <cstdio>
#include <atomic>
#include <thread>
extern "C" { std::atomic<unsigned> count=0; }
extern "C" void init(void*);
extern "C" uint8_t fetch(void*,unsigned);
bool recurse(unsigned depth) { alignas(8) uint8_t ctx[40]; init(ctx);
 for(unsigned i=0;i<64;++i) { if(fetch(ctx,63-i)!=uint8_t((63-i)*7)) return false;
 if(i==31 && depth && !recurse(depth-1)) return false; } return true; }
int main() { std::atomic<bool> ok=true;
 std::thread ts[8]; for(auto& t:ts) t=std::thread([&]{ if(!recurse(3)) ok=false; });
 for(auto& t:ts) t.join(); if(!ok) return 1; puts("equal"); }
'''))


@pytest.mark.parametrize('length', [0, 1, 15, 16, 17, 64])
def test_ctr_boundary_and_reverse_seek(tmp_path, fetch_ir, length):
    # fetch 的密文由标准 AES 生成；零长度不调用后端，尾块不越界写输出。
    run_case(build_native(tmp_path, fetch_ir, f'''
#include <cstdint>
#include <cstdio>
#include <atomic>
extern "C" {{ std::atomic<unsigned> count=0; }}
extern "C" void init(void*);
extern "C" uint8_t fetch(void*,unsigned);
int main() {{ alignas(8) uint8_t ctx[40]; init(ctx);
 uint8_t out[{length + 1}]; out[{length}]=0xa5;
 for(unsigned j={length};j>0;--j) out[j-1]=fetch(ctx,j-1);
 for(unsigned j=0;j<{length};++j) if(out[j]!=uint8_t(j*7)) return 1;
 if(out[{length}]!=0xa5 || count!=({length}+15)/16) return 2; puts("equal"); }}
'''))


def test_whitebox_separate_translation_units_and_gc(tmp_path):
    objects = []
    for name in ('left', 'right'):
        work = tmp_path / name
        work.mkdir()
        ir = transform(work, f'define i64 @{name}(i64 %a) {{ %r = add i64 %a,7\n ret i64 %r }}\n' +
            annotation([name], 'vm(whiteboxAES=1,lazyDecrypt=1,hardened=1)'))
        obj = work / 'vm.o'
        lowered = work / 'lowered.ll'
        lowered.write_text('\n'.join(line for line in ir.read_text().splitlines()
            if not line.startswith('@llvm.global.annotations')) + '\n')
        checked([tools().clang, '--target=aarch64-linux-android26', '-ffunction-sections',
            '-fdata-sections', '-c', lowered, '-o', obj])
        objects.append(obj)
    harness = tmp_path / 'harness.cpp'
    harness.write_text('''#include <cstdint>
#include <cstdio>
extern "C" uint64_t left(uint64_t),right(uint64_t);
int main() { for(uint64_t i=0;i<100;++i) if(left(i)!=i+7 || right(i)!=i+7) return 1; puts("equal"); }
''')
    exe = tmp_path / 'native'
    t = tools()
    checked([t.clangxx, '--target=aarch64-linux-android26', f'--sysroot={t.sysroot}',
        '-static-libstdc++', '-Wl,--gc-sections', harness, *objects, '-ldl', '-pthread', '-o', exe])
    run_case(exe)


@pytest.mark.parametrize('lazy', [0, 1])
@pytest.mark.parametrize('threaded', [0, 1])
def test_vm_whitebox_multiple_keys_and_calls(tmp_path, lazy, threaded):
    source = '''declare i64 @helper(i64,i64)
define i64 @first(i64 %a,i64 %b) { %r = call i64 @helper(i64 %a,i64 %b)
 %s = add i64 %r,3
 ret i64 %s }
define i64 @second(i64 %a,i64 %b) { %r = xor i64 %a,%b
 ret i64 %r }\n'''
    source += annotation(['first', 'second'], f'vm(whiteboxAES=1,lazyDecrypt={lazy},threadedDispatch={threaded},extendedISA=1,operandLayout=1,randISA=1,handlerVariants=2,hardened=1)')
    ir = transform(tmp_path, source)
    text = ir.read_text()
    assert '__vm_whitebox_block' in text, 'whitebox backend missing'
    assert '.vm.aes.rk' not in text and '.vm.aes.rkmask' not in text
    assert '[176 x i8]' not in text
    assert text.count(' = private unnamed_addr constant [372736 x i8]') == 2
    run_case(build_native(tmp_path, ir, '''
#include <cstdint>
#include <cstdio>
#include <thread>
#include <atomic>
extern "C" uint64_t helper(uint64_t a,uint64_t b) { return a*b; }
extern "C" uint64_t first(uint64_t,uint64_t),second(uint64_t,uint64_t);
int main() { std::atomic<bool> ok=true;
 auto run=[&] { for(uint64_t a=0;a<128;++a) { uint64_t b=a*17;
 if(first(a,b)!=a*b+3 || second(a,b)!=(a^b)) ok=false; } };
 std::thread threads[8]; for(auto& t:threads) t=std::thread(run); for(auto& t:threads) t.join();
 if(!ok) return 1; puts("equal"); }
'''))
