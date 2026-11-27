"""
从已知版本的 packet/napi2native 偏移推导新版本偏移。

用法:
  python scripts/derive-packet-offset.py <pe|elf> <x64|arm64> <参照 wrapper.node> <新 wrapper.node> <参照偏移 hex> [最小字节数]

原理: 取参照偏移所在指令的字节序列（屏蔽相对跳转/RIP 相对位移），在新文件中搜索唯一匹配。
输出的 new_hook 即新版本偏移。只有 ref_self=1 且 new_matches=1 的结果才可直接采用。
"""
import sys
import re
import struct
import capstone


class Image:
    def __init__(self, kind, path):
        self.data = open(path, 'rb').read()
        self.segs = []  # (vaddr, offset, filesz)
        if kind == 'pe':
            import pefile
            pe = pefile.PE(path, fast_load=True)
            for s in pe.sections:
                self.segs.append((s.VirtualAddress, s.PointerToRawData, s.SizeOfRawData))
        else:
            phoff, = struct.unpack_from('<Q', self.data, 0x20)
            phentsize, phnum = struct.unpack_from('<HH', self.data, 0x36)
            for i in range(phnum):
                p_type, p_flags, p_offset, p_vaddr, _, p_filesz = struct.unpack_from(
                    '<IIQQQQ', self.data, phoff + i * phentsize)
                if p_type == 1:
                    self.segs.append((p_vaddr, p_offset, p_filesz))

    def off(self, va):
        for v, o, sz in self.segs:
            if v <= va < v + sz:
                return va - v + o
        raise ValueError(f'va {va:#x} not mapped')

    def va_of_off(self, fo):
        for v, o, sz in self.segs:
            if o <= fo < o + sz:
                return fo - o + v
        return None


def make_disasm(arch):
    if arch == 'x64':
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    else:
        md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    md.detail = True
    return md


def mask_of(ins, arch):
    mask = [False] * ins.size
    if arch == 'x64':
        if 'rip' in ins.op_str and ins.disp_size > 0:
            for i in range(ins.disp_offset, ins.disp_offset + ins.disp_size):
                mask[i] = True
        if (ins.group(capstone.CS_GRP_JUMP) or ins.group(capstone.CS_GRP_CALL)) and ins.imm_size > 0:
            for i in range(ins.imm_offset, ins.imm_offset + ins.imm_size):
                mask[i] = True
    else:
        pc_rel = ins.mnemonic in ('adrp', 'adr') or ins.group(capstone.CS_GRP_JUMP) or ins.group(capstone.CS_GRP_CALL) \
            or (ins.mnemonic.startswith('ldr') and '#0x' in ins.op_str and '[' not in ins.op_str) \
            or (ins.mnemonic.startswith('ldr') and 'pc' in ins.op_str)
        if pc_rel:
            mask = [True] * ins.size
    return mask


def find_anchor(img, md, arch, hook):
    if arch == 'arm64':
        return hook, 0
    start = hook - 0x200
    code = img.data[img.off(start):img.off(hook) + 0x20]
    for ins in md.disasm(code, start):
        if ins.address <= hook < ins.address + ins.size:
            return ins.address, hook - ins.address
    return hook, 0


def build_regex(img, md, arch, anchor, min_len):
    code = img.data[img.off(anchor):img.off(anchor) + 0x600]
    out = []
    total = 0
    for ins in md.disasm(code, anchor):
        mask = mask_of(ins, arch)
        for b, m in zip(ins.bytes, mask):
            out.append('.' if m else '\\x%02x' % b)
        total += ins.size
        if total >= min_len:
            break
    return re.compile(''.join(out).encode('latin1'), re.DOTALL), total


def main():
    fmt, arch, ref_path, new_path, hook_hex, min_len = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], int(sys.argv[6])
    ref = Image(fmt, ref_path)
    new = Image(fmt, new_path)
    md = make_disasm(arch)
    hook = int(hook_hex, 16)
    anchor, k = find_anchor(ref, md, arch, hook)
    pat, total = build_regex(ref, md, arch, anchor, min_len)
    ref_self = len(list(pat.finditer(ref.data)))
    hits = []
    for m in pat.finditer(new.data):
        va = new.va_of_off(m.start())
        if va is not None:
            hits.append(va)
    print(f'ref_hook={hook:#x} anchor={anchor:#x} k={k} bytes={total} ref_self={ref_self} new_matches={len(hits)}')
    for va in hits[:40]:
        print(f'  new_anchor={va:#x} new_hook={va + k:#x}')


main()
