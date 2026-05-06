#!/usr/bin/env python3
"""
patch_patreon_drm.py — Bypass Patreon DRM gates in YTLite.dylib

Derived from analysis of a cracked v5.2.1 binary.  The cracked build uses
a fundamentally different strategy than the naive "NOP all dispatch_once gates"
approach:

  1. dispatch_once gates are LEFT INTACT — the CSINC instruction is kept so
     that on first call (token=0) the runtime takes table[1] (the XOR-decode
     init path).  This ensures all obfuscated strings are decoded correctly on
     first launch, fixing garbled settings text.

  2. Auth state is forced at the source with targeted patches to ~10 specific
     regions (see DIRECT_OFFSET_PATCHES below).  These cover:
       • The byte-load that reads the auth token   → forced to 1 (logged-in)
       • Stores that would reset the token to 0    → NOP'd
       • Auth-check helper functions               → replaced with MOVZ/RET stubs
       • Subscription-status query functions       → replaced with MOVZ/RET stubs

  3. showAlertWithMessage:showSettingsButton: → RET (belt-and-suspenders; the
     auth bypass means the alert should never trigger, but keeping it silenced
     prevents any edge-case popup).

  4. patreonSection: / patreonButtonCellWithType:model: → MOV X0,#0 / RET
     Returns nil so the Patreon UI section is hidden in settings entirely.

  5. addSection:[patreonSection:] BL → NOP (0x1385c4)
     patreonSection: returns nil; NOP the addSection: call to avoid a crash.

Usage:
  python3 patch_patreon_drm.py YTLite.dylib               # patch in-place
  python3 patch_patreon_drm.py YTLite.dylib patched.dylib  # write to new file
  python3 patch_patreon_drm.py --dry-run YTLite.dylib      # show without applying
"""

import struct
import sys
import argparse
import json
from pathlib import Path

# ── ARM64 instruction constants ───────────────────────────────────────────────
NOP      = 0xD503201F
MOV_X0_0 = 0xD2800000  # MOV X0, #0  (nil / false return)
RET      = 0xD65F03C0

def movz_w(reg, imm):
    """MOVZ Wreg, #imm  (imm must fit in 16 bits, hw=0)"""
    return 0x52800000 | ((imm & 0xFFFF) << 5) | (reg & 0x1F)

# ── Binary helpers ────────────────────────────────────────────────────────────
def r32(d, o):    return struct.unpack_from("<I", d, o)[0]
def r32s(d, o):   return struct.unpack_from("<i", d, o)[0]
def r64(d, o):    return struct.unpack_from("<Q", d, o)[0]
def w32(d, o, v): struct.pack_into("<I", d, o, v)


# ── Mach-O parser ─────────────────────────────────────────────────────────────
class MachO:
    def __init__(self, data):
        self.data = data
        self.segs = {}
        self.sects = {}
        self._parse()

    def _parse(self):
        if r32(self.data, 0) != 0xFEEDFACF:
            raise ValueError("Not a 64-bit Mach-O")
        ncmds = r32(self.data, 16)
        off = 32
        for _ in range(ncmds):
            cmd     = r32(self.data, off)
            cmdsize = r32(self.data, off + 4)
            if cmd == 0x19:  # LC_SEGMENT_64
                name    = self.data[off+8:off+24].rstrip(b'\x00').decode()
                vmaddr  = r64(self.data, off + 24)
                vmsize  = r64(self.data, off + 32)
                fileoff = r64(self.data, off + 40)
                filesz  = r64(self.data, off + 48)
                nsects  = r32(self.data, off + 64)
                self.segs[name] = dict(vmaddr=vmaddr, vmsize=vmsize,
                                       fileoff=fileoff, filesz=filesz)
                s = off + 72
                for _ in range(nsects):
                    sname   = self.data[s:s+16].rstrip(b'\x00').decode()
                    svmaddr = r64(self.data, s + 32)
                    svmsize = r64(self.data, s + 40)
                    sfoff   = r32(self.data, s + 48)
                    key = f"{name},{sname}"
                    self.sects[key] = dict(vmaddr=svmaddr, vmsize=svmsize, fileoff=sfoff)
                    s += 80
            off += cmdsize

    def va2f(self, va):
        for seg in self.segs.values():
            if seg['vmaddr'] <= va < seg['vmaddr'] + seg['vmsize']:
                return int(va - seg['vmaddr'] + seg['fileoff'])
        return None

    def sect(self, name):
        return self.sects.get(name)


# ── ObjC metadata helpers ─────────────────────────────────────────────────────

def build_selref_map(data, macho):
    sr = macho.sect('__DATA,__objc_selrefs')
    mn = macho.sect('__TEXT,__objc_methname')
    if not sr or not mn:
        return {}
    selmap = {}
    for i in range(sr['vmsize'] // 8):
        entry_foff = sr['fileoff'] + i * 8
        raw  = r64(data, entry_foff)
        sfoff = raw & 0xFFFFFFFF
        if mn['fileoff'] <= sfoff < mn['fileoff'] + mn['vmsize']:
            try:
                end  = data.index(b'\x00', sfoff)
                name = data[sfoff:end].decode('utf-8', 'replace')
                selmap[sr['vmaddr'] + i * 8] = name
            except (ValueError, UnicodeDecodeError):
                pass
    return selmap


def build_method_map(data, macho, selref_map):
    ml = macho.sect('__TEXT,__objc_methlist')
    mn = macho.sect('__TEXT,__objc_methname')
    if not ml:
        return {}
    mn_foff = mn['fileoff'] if mn else 0
    mn_size = mn['vmsize']  if mn else 0
    method_map = {}
    pos = ml['fileoff']
    end = pos + ml['vmsize']
    while pos < end - 8:
        flags_size = r32(data, pos)
        count      = r32(data, pos + 4)
        ensize     = flags_size & 0xFFFC
        is_small   = bool(flags_size & 0x80000000)
        if ensize == 12 and is_small and 1 <= count <= 500:
            chunk_bytes = 8 + count * 12
            if pos + chunk_bytes > end:
                pos += 4
                continue
            chunk_va = ml['vmaddr'] + (pos - ml['fileoff'])
            for mi in range(count):
                mfoff = pos + 8 + mi * 12
                mva   = chunk_va + 8 + mi * 12
                sel_r = r32s(data, mfoff)
                imp_r = r32s(data, mfoff + 8)
                sel_ref_va = mva + sel_r
                imp_va     = (mva + 8) + imp_r
                imp_va    &= ~1
                sel_name = selref_map.get(sel_ref_va)
                if sel_name is None:
                    sfoff = macho.va2f(sel_ref_va)
                    if sfoff and mn_foff <= sfoff < mn_foff + mn_size:
                        try:
                            e = data.index(b'\x00', sfoff)
                            sel_name = data[sfoff:e].decode('utf-8', 'replace')
                        except (ValueError, UnicodeDecodeError):
                            sel_name = f"<selref={sel_ref_va:#x}>"
                    else:
                        sel_name = f"<selref={sel_ref_va:#x}>"
                imp_foff = macho.va2f(imp_va)
                method_map.setdefault(sel_name, []).append((imp_va, imp_foff))
            pos += chunk_bytes
        else:
            pos += 4
    return method_map


# ── Patch plan ────────────────────────────────────────────────────────────────

class PatchPlan:
    def __init__(self):
        self._patches = []
        self._seen    = set()

    def add(self, foff, value, desc):
        if foff not in self._seen:
            self._patches.append(dict(offset=foff, value=value, desc=desc))
            self._seen.add(foff)

    def apply(self, data, verbose=True):
        applied = []
        for p in self._patches:
            old = r32(data, p['offset'])
            if old == p['value']:
                if verbose:
                    print(f"  {p['offset']:#010x}: already {p['value']:#010x}  [{p['desc']} – skip]")
                continue
            w32(data, p['offset'], p['value'])
            applied.append(dict(offset=p['offset'], old=old, new=p['value'], desc=p['desc']))
            if verbose:
                print(f"  {p['offset']:#010x}: {old:#010x} → {p['value']:#010x}  [{p['desc']}]")
        return applied

    def dump(self):
        for p in self._patches:
            print(f"  {p['offset']:#010x}  {p['value']:#010x}  {p['desc']}")


# ── Patch tables (v5.2.1 file offsets) ───────────────────────────────────────

# Selectors whose IMP is replaced with MOV X0,#0 / RET  (return nil / false)
NIL_RETURN_SELECTORS = [
    'patreonSection:',
    'patreonButtonCellWithType:model:',
]

# Selectors whose IMP is replaced with RET  (void no-op)
VOID_NOP_SELECTORS = [
    'showAlertWithMessage:showSettingsButton:',
    'showAlertWithTitle:imageName:',
]

# Hard-coded call-site NOPs (file offsets)
CALLER_SITE_NOPS = [
    # rootTable calls addSection:[self patreonSection:entry].
    # patreonSection: returns nil (see above); NOP the BL so addSection:nil
    # is silently discarded instead of crashing.
    (0x1385c4, "rootTable: addSection:[patreonSection:nil] → NOP"),
]

# ── Direct auth-bypass patches (derived from cracked v5.2.1 binary) ──────────
#
# The cracked build keeps dispatch_once gates INTACT (CSINC not NOP'd) so that
# XOR-encoded strings are decoded on first launch.  Auth is bypassed via these
# targeted patches instead.
#
# Groups:
#   A) Force auth-token byte load to return 1 (logged-in) and NOP the AND that
#      isolates bit-0, so the auth flag stays 1.
#   B) NOP STRB WZR stores that would reset the auth flag to 0.
#   C) Replace auth-check helper functions with MOVZ W0,#0/RET or MOVZ W0,#1/RET
#      stubs depending on what the caller expects (false = "not restricted",
#      true = "access granted").
DIRECT_OFFSET_PATCHES = [
    # ── A. Force auth token = 1 ──────────────────────────────────────────────
    (0x1E98C, movz_w(8, 1), "auth token load → MOVZ W8,#1"),
    (0x1E990, movz_w(9, 1), "auth flag copy  → MOVZ W9,#1"),
    (0x1E994, NOP,           "auth AND gate   → NOP"),

    # ── B. Prevent auth flag reset ───────────────────────────────────────────
    (0x21770, NOP, "STRB WZR auth reset #1 → NOP"),
    (0x27054, NOP, "STRB WZR auth reset #2 → NOP"),

    # ── C. Auth-check function stubs ─────────────────────────────────────────
    # Function at 0x1EB4C: caller expects false (0) when restriction applies
    (0x1EB4C, movz_w(0, 0), "auth stub-false MOVZ W0,#0"),
    (0x1EB50, RET,           "auth stub-false RET"),
    (0x1EB54, NOP,           "auth stub-false pad"),
    (0x1EB58, NOP,           "auth stub-false pad"),
    (0x1EB5C, NOP,           "auth stub-false pad"),
    # Function at 0x1EB60: caller expects true (1) when access is granted
    (0x1EB60, movz_w(0, 1), "auth stub-true  MOVZ W0,#1"),
    (0x1EB64, RET,           "auth stub-true  RET"),
    (0x1EB68, NOP,           "auth stub-true  pad"),
    (0x1EB6C, NOP,           "auth stub-true  pad"),
    (0x1EB70, NOP,           "auth stub-true  pad"),

    # Auth check bypass #1
    (0x1EE0C, movz_w(8, 0), "auth check1 W8=0"),
    (0x1EE10, movz_w(9, 0), "auth check1 W9=0"),
    (0x1EE14, NOP,           "auth check1 NOP"),
    (0x1EE18, NOP,           "auth check1 NOP"),
    # Function at 0x1EEA8: access-granted stub
    (0x1EEA8, movz_w(0, 1), "auth granted    MOVZ W0,#1"),
    (0x1EEAC, RET,           "auth granted    RET"),
    (0x1EEB0, NOP,           "auth granted    pad"),
    (0x1EEB4, NOP,           "auth granted    pad"),
    (0x1EEB8, NOP,           "auth granted    pad"),

    # Auth check bypass #2
    (0x1EFC0, movz_w(8, 0), "auth check2 W8=0"),
    (0x1EFC4, movz_w(9, 0), "auth check2 W9=0"),
    (0x1EFC8, NOP,           "auth check2 NOP"),
    (0x1EFCC, NOP,           "auth check2 NOP"),

    # Auth check bypass #3
    (0x260B0, movz_w(8, 0), "auth check3 W8=0"),
    (0x260B4, movz_w(9, 0), "auth check3 W9=0"),
    (0x260B8, NOP,           "auth check3 NOP"),

    # Auth check bypass #4
    (0x260F0, movz_w(8, 0), "auth check4 W8=0"),
    (0x260F4, movz_w(9, 0), "auth check4 W9=0"),
    (0x260F8, NOP,           "auth check4 NOP"),
]



# ── Main patcher ──────────────────────────────────────────────────────────────

def run(dylib_path, output_path=None, dry_run=False):
    print(f"Loading {dylib_path} …")
    data  = bytearray(Path(dylib_path).read_bytes())
    macho = MachO(data)
    plan  = PatchPlan()
    report = {}

    selref_map = build_selref_map(data, macho)
    method_map = build_method_map(data, macho, selref_map)
    print(f"ObjC metadata: {len(selref_map)} selrefs, {len(method_map)} selectors")

    # ── 1. Nil-return patches ────────────────────────────────────────────────
    print("\n[1] Nil-return patches")
    for sel in NIL_RETURN_SELECTORS:
        imps = method_map.get(sel, [])
        if not imps:
            print(f"  {sel}: not found")
            continue
        for (imp_va, imp_foff) in imps:
            if imp_foff is None:
                continue
            plan.add(imp_foff,     MOV_X0_0, f"{sel} → mov x0,#0")
            plan.add(imp_foff + 4, RET,      f"{sel} → ret")
            print(f"  {sel} @ {imp_foff:#010x}")
    report['nil_return'] = NIL_RETURN_SELECTORS

    # ── 2. Void-nop patches ──────────────────────────────────────────────────
    print("\n[2] Void-nop patches")
    for sel in VOID_NOP_SELECTORS:
        imps = method_map.get(sel, [])
        if not imps:
            print(f"  {sel}: not found")
            continue
        for (imp_va, imp_foff) in imps:
            if imp_foff is None:
                continue
            plan.add(imp_foff, RET, f"{sel} → ret")
            print(f"  {sel} @ {imp_foff:#010x}")
    report['void_nop'] = VOID_NOP_SELECTORS

    # ── 3. Caller-site NOPs ──────────────────────────────────────────────────
    print("\n[3] Caller-site NOPs")
    for foff, desc in CALLER_SITE_NOPS:
        plan.add(foff, NOP, desc)
        print(f"  {foff:#010x}  [{desc}]")
    report['caller_site_nops'] = [hex(foff) for foff, _ in CALLER_SITE_NOPS]

    # ── 4. Direct auth-bypass patches ────────────────────────────────────────
    print("\n[4] Direct auth-bypass patches")
    for foff, value, desc in DIRECT_OFFSET_PATCHES:
        plan.add(foff, value, desc)
    print(f"  {len(DIRECT_OFFSET_PATCHES)} patch(es) queued")
    report['auth_bypass'] = len(DIRECT_OFFSET_PATCHES)

    # ── Apply / report ────────────────────────────────────────────────────────
    print(f"\n{'─'*60}")
    total = len(plan._patches)
    print(f"Patch plan: {total} instruction(s) to write")

    if dry_run:
        print("DRY RUN — no file changes")
        plan.dump()
        return report

    print("\nApplying:")
    applied = plan.apply(data, verbose=True)
    out = output_path or dylib_path
    Path(out).write_bytes(data)
    print(f"\n✓ {len(applied)} change(s) written → {out}")
    report['applied'] = len(applied)
    return report


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == '__main__':
    ap = argparse.ArgumentParser(
        description='Patch Patreon DRM out of YTLite.dylib',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)
    ap.add_argument('input',  help='Input dylib path')
    ap.add_argument('output', nargs='?', help='Output path (default: overwrite input)')
    ap.add_argument('--dry-run', action='store_true', help='Show patches without writing')
    ap.add_argument('--json',    metavar='FILE', help='Write JSON report to FILE')
    args = ap.parse_args()

    report = run(args.input, args.output, dry_run=args.dry_run)

    if args.json:
        Path(args.json).write_text(json.dumps(report, indent=2))
        print(f"Report → {args.json}")
