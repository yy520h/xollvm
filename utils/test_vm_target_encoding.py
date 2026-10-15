"""检查真实 AArch64 PIE 的待封装目标，不使用业务凭据。"""
import struct
import subprocess
import pytest
from vm_hardening_support import annotation, transform, build_native, tools, checked, run_case


def elf_segments(data):
    phoff = struct.unpack_from('<Q', data, 32)[0]
    size, count = struct.unpack_from('<HH', data, 54)
    return [struct.unpack_from('<IIQQQQQQ', data, phoff+i*size) for i in range(count)]


def descriptors(data):
    result = []
    for typ, flags, off, va, _, size, _, _ in elf_segments(data):
        if typ != 1 or flags & 1:
            continue
        pos = off
        while True:
            pos = data.find(b'XOVMTGT1', pos, off+size)
            if pos < 0:
                break
            version, state, count, role = struct.unpack_from('<IIII', data, pos+8)
            assert version == 1 and state in (0, 1) and role in (1, 2)
            assert pos+32+count*32 <= off+size
            result.append((pos, va+pos-off, count, role))
            pos += 32+count*32
    return result


def relative_relocations(data):
    segments = elf_segments(data)
    def offset(va):
        return next(off+va-base for typ, _, off, base, _, size, _, _ in segments if typ==1 and base<=va<base+size)
    dynamic = next(p for p in segments if p[0] == 2)
    tags = dict(struct.unpack_from('<qQ', data, p) for p in range(dynamic[2], dynamic[2]+dynamic[5], 16))
    result = {}
    if 7 in tags:
        for p in range(offset(tags[7]), offset(tags[7])+tags[8], 24):
            slot, info, target = struct.unpack_from('<QQq', data, p)
            if info == 1027:
                result[slot] = target
    if 0x60000011 in tags:
        p = offset(tags[0x60000011])
        assert data[p:p+4] == b'APS2'
        p += 4
        def sleb():
            nonlocal p
            v, shift = 0, 0
            while True:
                b = data[p]; p += 1; v |= (b & 127) << shift; shift += 7
                if b < 128:
                    return v - (1 << shift) if b & 64 else v
        count, slot, add = sleb(), sleb(), 0
        while count:
            n, flags = sleb(), sleb()
            delta = sleb() if flags & 2 else None
            info = sleb() if flags & 1 else None
            if flags & 8 and flags & 4:
                add += sleb()
            for _ in range(n):
                slot += delta if flags & 2 else sleb()
                ri = info if flags & 1 else sleb()
                if flags & 8 and not flags & 4:
                    add += sleb()
                if not flags & 8:
                    add = 0
                if ri == 1027:
                    result[slot] = add
            count -= n
    # Android RELR 和标准 RELR。
    tag = 36 if 36 in tags else 0x6fffe000 if 0x6fffe000 in tags else None
    if tag is not None:
        sz = tags[35 if tag==36 else 0x6fffe001]
        where = 0
        for p in range(offset(tags[tag]), offset(tags[tag])+sz, 8):
            entry = struct.unpack_from('<Q', data, p)[0]
            slots = [entry] if not entry & 1 else [where+i*8 for i in range(63) if entry & (1 << (i+1))]
            for slot in slots:
                result[slot] = struct.unpack_from('<Q', data, offset(slot))[0]
            where = entry+8 if not entry & 1 else where+63*8
    return result


SOURCE = '''define i64 @target(i64 %a,i64 %b) { %r = xor i64 %a,%b
 ret i64 %r }\n'''
HARNESS = '''#include <cstdint>
#include <cstdio>
extern "C" uint64_t target(uint64_t,uint64_t);
int main() { if(target(9,4)!=13) return 1; puts("equal"); }
'''


@pytest.mark.parametrize('threaded', [0, 1])
def test_unprocessed_targets_fail_closed(tmp_path, threaded):
    ir = transform(tmp_path, SOURCE + annotation(['target'],
        f'vm(encodedTargets=1,threaded={threaded},encDispatch=1,handlerVariants=2,hardened=0)'))
    assert '.obf.vm.targets' in ir.read_text(), 'encoded targets descriptor missing'
    exe = build_native(tmp_path, ir, HARNESS)
    data = exe.read_bytes()
    start = data.find(b'XOVMTGT1')
    assert start >= 0
    version, state, count, role = struct.unpack_from('<IIII', data, start+8)
    assert version == 1 and state == 0 and count > 0 and role in (1, 2)
    ds = descriptors(data)
    assert len(ds) == 2 and sorted(d[3] for d in ds) == [1, 2]
    # 链接器确实生成 AArch64 RELATIVE relocation；raw blockaddress 解析为 PF_X 地址。
    loads = [(va, va+size) for typ, flags, _, va, _, size, _, _ in elf_segments(data) if typ == 1 and flags & 1]
    targets = relative_relocations(data)
    for off, va, count, role in ds:
        for i in range(count):
            record = off+32+i*32
            _, _, _, rotation, kind = struct.unpack_from('<QQQII', data, record)
            assert 0 < rotation < 64 and kind in (0, 1)
            if kind:
                raw = targets[va+32+i*32]
                assert any(a<=raw<b for a,b in loads)
    p = subprocess.run([str(exe)], capture_output=True, text=True, timeout=30)
    assert p.returncode != 0, 'pending encodedTargets executed successfully'


def test_unknown_platform_rejects_encoded_targets(tmp_path):
    from vm_hardening_support import tools
    src = tmp_path / 'unsupported.ll'
    src.write_text('target triple = "x86_64-unknown-linux-gnu"\n' + SOURCE +
                   annotation(['target'], 'vm(encodedTargets=1)'))
    p = subprocess.run([str(tools().opt), '-passes=obfuscation', '-S', str(src), '-o', str(tmp_path / 'out.ll')],
                       capture_output=True, text=True, timeout=30)
    assert p.returncode != 0 and 'encodedTargets' in p.stderr


def relink(work, packing):
    t = tools(); exe = work / 'native'
    checked([t.clangxx, '--target=aarch64-linux-android26', f'--sysroot={t.sysroot}',
             '-std=c++20', '-static-libstdc++', '-Wl,--rosegment', '-Wl,--gc-sections',
             f'-Wl,--pack-dyn-relocs={packing}', work / 'harness.cpp', work / 'vm.o',
             '-ldl', '-pthread', '-o', exe])
    return exe


@pytest.mark.parametrize('packing', ['none', 'android', 'relr', 'android+relr'])
@pytest.mark.parametrize('threaded', [0, 1])
def test_finalized_targets_relocations_removed_and_execute(tmp_path, packing, threaded):
    ir = transform(tmp_path, SOURCE + annotation(['target'],
        f'vm(encodedTargets=1,threadedDispatch={threaded},handlerVariants=4,encDispatch=1,hardened=1)'))
    build_native(tmp_path, ir, HARNESS)
    exe = relink(tmp_path, packing)
    before = exe.read_bytes()
    ds = descriptors(before)
    originals = relative_relocations(before)
    pending = subprocess.run([str(tools().hardener), 'verify', '--input', str(exe)], capture_output=True, text=True)
    assert pending.returncode != 0
    checked([tools().hardener, 'targets', '--input', exe, '--output', exe])
    after = exe.read_bytes()
    remaining = relative_relocations(after)
    mask = (1 << 64) - 1
    for off, va, count, _ in ds:
        assert struct.unpack_from('<I', after, off+12)[0] == 1
        for i in range(count):
            pos, slot = off+32+i*32, va+32+i*32
            e, key, add, rot, kind = struct.unpack_from('<QQQII', after, pos)
            if kind:
                decoded = (((((e>>rot) | (e<<(64-rot))) & mask) - add) & mask) ^ key
                assert (slot+decoded) & mask == originals[slot]
                assert slot not in remaining
    for _ in range(3):
        run_case(exe)
    checked([tools().hardener, 'verify', '--input', exe])
    checked([tools().hardener, 'targets', '--input', exe, '--output', exe])
    assert exe.read_bytes() == after, 'targets is not idempotent'
    strip = tools().clang.parent / 'llvm-strip'
    checked([strip, '--strip-all', exe])
    checked([tools().hardener, 'verify', '--input', exe])
    run_case(exe)


@pytest.mark.parametrize('field,value', [(8, 999), (12, 2), (16, 0xffffffff), (20, 7), (24, 1),
                                        (32+24, 0), (32+24, 64), (32+28, 7)])
def test_bad_descriptor_does_not_modify_input(tmp_path, field, value):
    ir = transform(tmp_path, SOURCE + annotation(['target'], 'vm(encodedTargets=1,hardened=0)'))
    exe = build_native(tmp_path, ir, HARNESS)
    damaged = bytearray(exe.read_bytes()); off = descriptors(damaged)[0][0]
    struct.pack_into('<I', damaged, off+field, value)
    exe.write_bytes(damaged)
    p = subprocess.run([str(tools().hardener), 'targets', '--input', str(exe), '--output', str(exe)],
                       capture_output=True, text=True)
    assert p.returncode != 0 and exe.read_bytes() == damaged


def test_targets_without_section_headers(tmp_path):
    ir = transform(tmp_path, SOURCE + annotation(['target'], 'vm(encodedTargets=1,hardened=0)'))
    exe = build_native(tmp_path, ir, HARNESS)
    data = bytearray(exe.read_bytes())
    struct.pack_into('<Q', data, 40, 0)
    struct.pack_into('<HHH', data, 58, 0, 0, 0)
    exe.write_bytes(data)
    checked([tools().hardener, 'targets', '--input', exe, '--output', exe])
    checked([tools().hardener, 'verify', '--input', exe])
    run_case(exe)


@pytest.mark.parametrize('spec', ['vm(encodedTargets=1,encBytecode=0,hardened=0)', 'vm(preset=max)'])
def test_targets_seal_with_sensitive_manifest(tmp_path, spec):
    source = '''declare i32 @fixture_verify(i32)
define i32 @target(i32 %a) {
 %r = call i32 @fixture_verify(i32 %a)
 %c = icmp eq i32 %r,1
 br i1 %c,label %yes,label %no
yes:
 ret i32 1
no:
 ret i32 0 }\n'''
    harness = '''#include <cstdio>
extern "C" int fixture_verify(int a) { return a==13; }
extern "C" int target(int);
int main() { if(target(13)!=1 || target(12)!=0) return 1; puts("equal"); }
'''
    ir = transform(tmp_path, source + annotation(['target'], 'sensitive(region=fixture,strict=1), ' + spec))
    exe = build_native(tmp_path, ir, harness)
    checked([tools().hardener, 'seal', '--input', exe, '--output', exe])
    checked([tools().hardener, 'verify', '--input', exe])
    run_case(exe)
    data = exe.read_bytes()
    checked([tools().hardener, 'seal', '--input', exe, '--output', exe])
    assert exe.read_bytes() == data


@pytest.mark.parametrize('damage', ['partial-slot-relocation', 'unsupported-rel', 'load-alias'])
def test_ambiguous_elf_targets_fail_closed(tmp_path, damage):
    ir = transform(tmp_path, SOURCE + annotation(['target'], 'vm(encodedTargets=1,hardened=0)'))
    build_native(tmp_path, ir, HARNESS)
    exe = relink(tmp_path, 'none')
    data = bytearray(exe.read_bytes()); off, va, _, _ = descriptors(data)[0]
    dynamic = next(p for p in elf_segments(data) if p[0] == 2)
    entries = [p for p in range(dynamic[2], dynamic[2]+dynamic[5], 16) if struct.unpack_from('<q',data,p)[0]]
    tags = {struct.unpack_from('<q',data,p)[0]:p for p in entries}
    rel = struct.unpack_from('<Q',data,tags[7]+8)[0]
    roff = next(o+rel-base for typ, _, o, base, _, size, _, _ in elf_segments(data) if typ==1 and base<=rel<base+size)
    if damage == 'partial-slot-relocation':
        pos = next(p for p in range(roff, roff+struct.unpack_from('<Q',data,tags[8]+8)[0],24)
                   if struct.unpack_from('<Q',data,p)[0]==va+32)
        # 指向前一 descriptor header 尾部：8-byte relocation 会跨入第一个 slot。
        struct.pack_into('<Q',data,pos,va+28)
    elif damage == 'unsupported-rel':
        # 保留 RELA，同时添加 DT_REL；不能忽略未知格式中的目标槽。
        p = next(p for p in entries if struct.unpack_from('<q',data,p)[0] not in (7,8,9,23,2,20))
        struct.pack_into('<qQ',data,p,17,rel)
    else:
        phoff = struct.unpack_from('<Q',data,32)[0]; stride,num = struct.unpack_from('<HH',data,54)
        dest = next(phoff+i*stride for i in range(num) if struct.unpack_from('<I',data,phoff+i*stride)[0] not in (1,2,6))
        load = next(phoff+i*stride for i in range(num)
                    if struct.unpack_from('<I',data,phoff+i*stride)[0]==1 and struct.unpack_from('<Q',data,phoff+i*stride+8)[0]<=off<struct.unpack_from('<Q',data,phoff+i*stride+8)[0]+struct.unpack_from('<Q',data,phoff+i*stride+32)[0])
        data[dest:dest+56] = data[load:load+56]
        struct.pack_into('<Q',data,dest+16,struct.unpack_from('<Q',data,load+16)[0]+0x10000000)
    exe.write_bytes(data)
    p = subprocess.run([str(tools().hardener),'targets','--input',str(exe),'--output',str(exe)],capture_output=True,text=True,timeout=30)
    assert p.returncode != 0, f'{damage} accepted'
    assert exe.read_bytes() == data


@pytest.mark.parametrize('damage', ['relocation-block-in-descriptor', 'pending-no-targets'])
def test_targets_never_clobber_own_descriptor(tmp_path, damage):
    ir = transform(tmp_path, SOURCE + annotation(['target'], 'vm(encodedTargets=1,hardened=0)'))
    build_native(tmp_path, ir, HARNESS)
    exe = relink(tmp_path, 'none')
    if damage == 'pending-no-targets':
        checked([tools().hardener,'targets','--input',exe,'--output',exe])
        data = bytearray(exe.read_bytes())
        for off,va,count,role in descriptors(data):
            struct.pack_into('<I',data,off+12,0)
            for i in range(count): struct.pack_into('<I',data,off+32+i*32+28,0)
    else:
        data = bytearray(exe.read_bytes()); ds = descriptors(data)
        off,va,_,_ = ds[0]
        original = relative_relocations(data)[va+32]
        for other,_,_,_ in ds[1:]: data[other:other+8]=b'\0'*8
        struct.pack_into('<II',data,off+16,1,2)
        # RELA 覆盖 descriptor 的 word/key/add；如果被序列化清零，runtime 逆解会坏。
        struct.pack_into('<QQQII',data,off+32,va+32,1027,original,7,1)
        dynamic = next(p for p in elf_segments(data) if p[0]==2)
        for pos in range(dynamic[2],dynamic[2]+dynamic[5],16):
            tag = struct.unpack_from('<q',data,pos)[0]
            if tag==7: struct.pack_into('<Q',data,pos+8,va+32)
            if tag==8: struct.pack_into('<Q',data,pos+8,24)
            if tag==0x6ffffff9: struct.pack_into('<Q',data,pos+8,1)
    exe.write_bytes(data)
    p = subprocess.run([str(tools().hardener),'targets','--input',str(exe),'--output',str(exe)],capture_output=True,text=True,timeout=30)
    assert p.returncode != 0, f'{damage} accepted'
    assert exe.read_bytes() == data


def test_multiple_archive_objects_keep_distinct_descriptors(tmp_path):
    t = tools()
    sources = [('first', 3), ('second', 17)]
    objects = []
    for name, literal in sources:
        work = tmp_path / name; work.mkdir()
        ir = transform(work, f'define i64 @{name}(i64 %a) {{ %r = add i64 %a,{literal}\n ret i64 %r }}\n' +
                       annotation([name], 'vm(encodedTargets=1,hardened=0)'), seed=literal)
        build_native(work, ir, f'extern "C" unsigned long {name}(unsigned long); int main() {{ return {name}(1)!= {literal+1}; }}')
        objects.append(work / 'vm.o')
    archive = tmp_path / 'vm.a'
    checked([t.clang.parent / 'llvm-ar', 'rcs', archive, *objects])
    harness = tmp_path / 'driver.cpp'
    harness.write_text('#include <cstdio>\nextern "C" unsigned long first(unsigned long),second(unsigned long);\n'
                       'int main() { if(first(5)!=8 || second(5)!=22) return 1; puts("equal"); }\n')
    exe = tmp_path / 'native'
    checked([t.clangxx, '--target=aarch64-linux-android26', f'--sysroot={t.sysroot}', '-static-libstdc++',
             '-Wl,--rosegment', '-Wl,--gc-sections', harness, archive, '-ldl', '-pthread', '-o', exe])
    assert len(descriptors(exe.read_bytes())) == 4
    checked([t.hardener, 'targets', '--input', exe, '--output', exe])
    checked([t.hardener, 'audit', '--input', exe])
    checked([t.hardener, 'verify', '--input', exe])
    run_case(exe)


def test_android_packed_irregular_relocations_survive_target_filter(tmp_path):
    """不等间隔数据重定位不能因 VM 槽过滤后低效重编码而溢出原 APS2 空间。"""
    ir = transform(tmp_path, SOURCE + annotation(['target'], 'vm(encodedTargets=1,hardened=0)'))
    rows = [('nullptr' if i % 7 in (1, 2, 4) else f'&cells[{i % 11}]') for i in range(768)]
    harness = '''#include <cstdio>
static int cells[] = {0,1,2,3,4,5,6,7,8,9,10};
static int* volatile refs[] = {''' + ','.join(rows) + '''};
extern "C" unsigned long target(unsigned long,unsigned long);
int main() {
    for (unsigned i = 0; i < 768; ++i) {
        if (i % 7 == 1 || i % 7 == 2 || i % 7 == 4) {
            if (refs[i] != nullptr) return 1;
        } else if (!refs[i] || *refs[i] != int(i % 11)) return 2;
    }
    if (target(9,4) != 13) return 3;
    puts("equal");
}
'''
    build_native(tmp_path, ir, harness)
    exe = relink(tmp_path, 'android')
    before = exe.read_bytes()
    originals = relative_relocations(before)
    removed = {va + 32 + i * 32 for off, va, count, _ in descriptors(before)
               for i in range(count) if struct.unpack_from('<I', before, off+32+i*32+28)[0]}
    checked([tools().hardener, 'targets', '--input', exe, '--output', exe])
    assert relative_relocations(exe.read_bytes()) == {
        slot: addend for slot, addend in originals.items() if slot not in removed}
    checked([tools().hardener, 'verify', '--input', exe])
    run_case(exe)


def test_android_grouped_addends_preserve_each_relocation(tmp_path):
    # 独立 ELF fixture：16 个保留 addend 每次递增 4，不能按单个共享 addend 编码。
    def sleb(value):
        result = bytearray()
        while True:
            byte = value & 127
            value >>= 7
            done = (value == 0 and not byte & 64) or (value == -1 and byte & 64)
            result.append(byte if done else byte | 128)
            if done:
                return result
    rows = [(0x10320, 0x20000)] + [(0x11000+i*8, (i+1)*4) for i in range(16)]
    packed = bytearray(b'APS2') + sleb(len(rows)) + sleb(0)
    slot = addend = 0
    # 合法但有充足空间的未分组 APS2，避免测试依赖链接器压缩启发式。
    for address, value in rows:
        packed += sleb(1) + sleb(8) + sleb(address-slot) + sleb(1027) + sleb(value-addend)
        slot, addend = address, value
    data = bytearray(0x3004)
    ident = b'\x7fELF' + bytes([2,1,1]) + bytes(9)
    struct.pack_into('<16sHHIQQQIHHHHHH', data, 0, ident, 3, 183, 1, 0, 64, 0, 0, 64, 56, 3, 0, 0, 0)
    for index, header in enumerate([(1,6,0,0x10000,0x10000,0x3000,0x3000,0x1000),
                                     (1,5,0x3000,0x20000,0x20000,4,4,0x1000),
                                     (2,6,0x200,0x10200,0x10200,64,64,8)]):
        struct.pack_into('<IIQQQQQQ', data, 64+index*56, *header)
    for index, (tag, value) in enumerate([(0x60000011,0x10400), (0x60000012,len(packed)), (9,24), (0,0)]):
        struct.pack_into('<qQ', data, 0x200+index*16, tag, value)
    struct.pack_into('<8sIIIIQ', data, 0x300, b'XOVMTGT1', 1, 0, 1, 2, 0)
    struct.pack_into('<QQQII', data, 0x320, 0, 17, 23, 7, 1)
    data[0x400:0x400+len(packed)] = packed
    exe = tmp_path/'grouped-addends.elf'
    exe.write_bytes(data)
    checked([tools().hardener, 'targets', '--input', exe, '--output', exe])
    assert relative_relocations(exe.read_bytes()) == dict(rows[1:])
    checked([tools().hardener, 'verify', '--input', exe])


@pytest.mark.parametrize('damage', ['empty-target-set', 'slot-symbol', 'metadata-relocation', 'truncated'])
def test_structural_damage_rejects_without_output_change(tmp_path, damage):
    ir = transform(tmp_path, SOURCE + annotation(['target'], 'vm(encodedTargets=1,hardened=0)'))
    build_native(tmp_path, ir, HARNESS)
    exe = relink(tmp_path, 'none')
    data = bytearray(exe.read_bytes()); off, va, count, _ = descriptors(data)[0]
    if damage == 'empty-target-set':
        for i in range(count):
            struct.pack_into('<I', data, off+32+i*32+28, 0)
    elif damage == 'truncated':
        data = data[:len(data)//2]
    else:
        dynamic = next(p for p in elf_segments(data) if p[0] == 2)
        tags = dict(struct.unpack_from('<qQ', data, p) for p in range(dynamic[2], dynamic[2]+dynamic[5], 16))
        rel = tags[7]
        roff = next(o+rel-base for typ, _, o, base, _, size, _, _ in elf_segments(data) if typ==1 and base<=rel<base+size)
        pos = next(p for p in range(roff, roff+tags[8], 24) if struct.unpack_from('<Q', data, p)[0] == va+32)
        if damage == 'slot-symbol':
            struct.pack_into('<Q', data, pos+8, 1025 | (1 << 32))
        else:
            struct.pack_into('<Q', data, pos, va+40)
    exe.write_bytes(data)
    p = subprocess.run([str(tools().hardener), 'targets', '--input', str(exe), '--output', str(exe)],
                       capture_output=True, text=True, timeout=30)
    assert p.returncode != 0, f'{damage} accepted'
    assert exe.read_bytes() == data
