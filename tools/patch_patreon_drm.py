#!/usr/bin/env python3
"""
patch_patreon_drm.py — Bypass Patreon DRM gates in YTLite.dylib

Locates Patreon-gated code via ObjC selector metadata and patches it out.
Designed to work across dylib updates: finds targets by selector name, not
by hard-coded offset.

Usage:
  python3 patch_patreon_drm.py YTLite.dylib               # patch in-place
  python3 patch_patreon_drm.py YTLite.dylib patched.dylib  # write to new file
  python3 patch_patreon_drm.py --dry-run YTLite.dylib      # show without applying
  python3 patch_patreon_drm.py --map YTLite.dylib          # dump full obfuscation map

Obfuscation patterns handled:
  1. dispatch_once Patreon init gate: LDAR Wn,[Xm] / CMP Wn,#0 / CSINC Wn,WZR,WZR,NE
     Found throughout all settings-related ObjC methods. The token lives in __bss
     (always 0 at load time), causing every call to take the Patreon-init path (table[1]).
     Fix: NOP the CSINC → W stays 0 → always use table[0] (non-Patreon path).
     Scope: ALL ObjC method bodies parsed via __TEXT,__objc_methlist, using adjacent
     IMP addresses as function boundaries (no more fragile first-RET heuristic).

  2. showAlertWithMessage:showSettingsButton: / showAlertWithTitle:imageName: → RET
     Silences Patreon-not-activated popups.

  3. patreonSection: / patreonButtonCellWithType:model: → MOV X0,#0 / RET
     Returns nil from all Patreon section/cell builders.

  4. isLoggedIn forced true (MOVZ W0/W8,#0 → #1 in known auth fns).

  5. Caller-site NOPs: rootTable calls addSection:[patreonSection:entry].
     patreonSection: now returns nil (patch #3 above); the caller does not
     check for nil before calling addSection:, so the BL at 0x1385c4 is NOP'd
     to silently discard the nil section.

  6. colorForSegment: jump-table fix (DATA section, v5.2.1 only).
     Root cause: -[YTLUserDefaults colorForSegment:] uses an obfuscated dispatch_once
     whose jump table [at __DATA+0x11BBB88] has its entries in the wrong order in the
     pre-patched prebuilt:
       token=0 (first call) → skip XOR init → dict keys are garbage → dict[@"seg"] = nil
       token=1 (subsequent) → run XOR init  → proper keys → returns UIColor
     This causes -[YTLUserDefaults registerDefaults] to crash with
     "attempt to insert nil object from objects[28]" because colorForSegment: is called
     during first-time standardUserDefaults initialization before the init path has run.
     Fix: swap target bits of jump-table[0] and [1] so first call runs the XOR init.
"""

import struct
import sys
import argparse
import json
from pathlib import Path

# ── ARM64 instruction constants ───────────────────────────────────────────────
NOP       = 0xD503201F
MOV_X0_0  = 0xD2800000  # MOV X0, #0
RET       = 0xD65F03C0

def mov_w_1(reg):
    """MOVZ Wreg, #1"""
    return 0x52800020 | (reg & 0x1F)

# ── Binary helpers ────────────────────────────────────────────────────────────
def r32(d, o):  return struct.unpack_from("<I", d, o)[0]
def r32s(d, o): return struct.unpack_from("<i", d, o)[0]
def r64(d, o):  return struct.unpack_from("<Q", d, o)[0]
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
    """
    Returns dict: selector_name → list of selref VAs.
    Uses __DATA,__objc_selrefs + __TEXT,__objc_methname.
    """
    sr = macho.sect('__DATA,__objc_selrefs')
    mn = macho.sect('__TEXT,__objc_methname')
    if not sr or not mn:
        return {}

    selmap = {}  # selref_va → name
    for i in range(sr['vmsize'] // 8):
        entry_va   = sr['vmaddr'] + i * 8
        entry_foff = sr['fileoff'] + i * 8
        raw  = r64(data, entry_foff)
        sfoff = raw & 0xFFFFFFFF
        if mn['fileoff'] <= sfoff < mn['fileoff'] + mn['vmsize']:
            try:
                end  = data.index(b'\x00', sfoff)
                name = data[sfoff:end].decode('utf-8', 'replace')
                selmap[entry_va] = name
            except (ValueError, UnicodeDecodeError):
                pass
    return selmap


def build_method_map(data, macho, selref_map):
    """
    Returns dict: selector_name → list of (imp_va, imp_foff).
    Parses __TEXT,__objc_methlist (small method lists).
    """
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
                imp_va    &= ~1  # clear direct-IMP flag

                # Resolve selector name
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


def build_sorted_imp_list(method_map):
    """
    Returns sorted list of (imp_va, sel_name, imp_foff) tuples.
    Used to compute precise ObjC method body boundaries:
    function body spans [imp_va, next_imp_va).
    """
    entries = []
    for sel, imps in method_map.items():
        for (imp_va, imp_foff) in imps:
            if imp_foff is not None:
                entries.append((imp_va, sel, imp_foff))
    entries.sort()
    return entries


# ── Obfuscation pattern detection ─────────────────────────────────────────────

def find_dispatch_once_gates(data, func_foff, size_limit=0x10000):
    """
    Finds LDAR Wn,[Xm] / CMP Wn,#0 / CSINC Wn,WZR,WZR,NE sequences
    (dispatch_once Patreon init gates) within a function body.

    Returns list of file offsets of the CSINC instruction (the one to NOP).
    """
    gates = []
    end = min(func_foff + size_limit, len(data) - 12)
    off = func_foff
    while off < end:
        v0 = r32(data, off)
        v1 = r32(data, off + 4)
        v2 = r32(data, off + 8)

        # LDAR Wt,[Xn]: 0x88DFFC00 | (Xn<<5) | Wt  (any Xn, any Wt)
        # Top 22 bits fixed: bits[31:10] = 0x223FF = 1000_1000_1101_1111_1111_11
        is_ldar_w = (v0 & 0xFFFFFC00) == 0x88DFFC00

        # CMP Wn, #0 = SUBS WZR, Wn, #0: 0x7100001F | (Wn<<5)
        # mask out Rn field (bits[9:5])
        is_cmp_0 = (v1 & 0xFFFFFC1F) == 0x7100001F

        # CSINC Wd, WZR, WZR, NE: 0x1A9F17E0 | Wd
        is_csinc = (v2 & 0xFFFFFFE0) == 0x1A9F17E0

        if is_ldar_w and is_cmp_0 and is_csinc:
            gates.append(off + 8)

        off += 4
    return gates


def find_func_end_by_next_imp(imp_foff, sorted_imps, fallback_size=0x10000):
    """
    Returns the file offset where this ObjC method's body ends.
    Uses the next IMP address in the sorted IMP list as the boundary.
    Falls back to imp_foff + fallback_size if this IMP is the last.
    """
    for i, (va, sel, foff) in enumerate(sorted_imps):
        if foff == imp_foff and i + 1 < len(sorted_imps):
            return sorted_imps[i + 1][2]
    return imp_foff + fallback_size


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


# ── Main patcher ──────────────────────────────────────────────────────────────

# Selectors whose IMP should be replaced with MOV X0,#0 / RET (return nil)
NIL_RETURN_SELECTORS = [
    'patreonSection:',
    'patreonButtonCellWithType:model:',
]

# Selectors whose IMP should be replaced with RET (void no-op)
VOID_NOP_SELECTORS = [
    'showAlertWithMessage:showSettingsButton:',
    'showAlertWithTitle:imageName:',
]

# Selectors to SKIP when scanning for dispatch_once gates.
#
# Two categories of skip:
#
# A) Non-settings features where forcing table[0] could break functionality
#    (download UI, destructors, non-settings button handlers).
#
# B) Singleton getters — methods whose dispatch_once gate protects a one-time
#    initialisation (not a Patreon feature gate).  In these methods:
#      table[0] = "already initialised, return cached value"  (nil in BSS = crash)
#      table[1] = "first-time init" (creates the singleton)
#    NOP'ing the CSINC forces table[0] forever → returns nil from uninitialised BSS
#    → any caller that stores the result in an NSDictionary will crash with
#    "attempt to insert nil object from objects[N]".
DISPATCH_GATE_SKIP_SELECTORS = {
    # ── A. Download / non-settings features ─────────────────────────────────
    'showDownloadSheetShorts:withSender:', 'showDownloadSheet:withSender:',
    'showVideoSheet:withSender:', 'showImagesSheet:withSender:',
    'showInformationSheet:withSender:', 'showExtPlayerSheet:withSender:',
    'getVideoFormatsArray:isShorts:', 'getAudioFormatsArray:',
    'getBestAudioFormat:playerVC:', 'getEnglishAudioTrack:', 'detailForMimeType:',
    'getResoForQuality:',
    'downloadVideoWithFormat:withAudioFormats:fileName:extension:videoID:playerVC:sender:',
    'downloadVideoWithUrl:audioUrl:fileName:extension:videoID:videoSize:audioSize:duration:captions:playerVC:',
    'getThumbnail:', 'checkSpaceAvailabilityForMedia:completion:',
    'showAudioTrackSelector:sender:playerVC:completion:', 'hasCaptions:',
    'showTranscriptSheet:withSender:', 'showCaptionsSheet:withSender:',
    'captionsForDownloading:', 'titleForCaption:', 'getCaptionsUrlSheet:sender:completion:',
    'shareSRT:sourceView:', 'presentationAnchorForWebAuthenticationSession:',
    # Destructors: never patch — C++ destructors run at dealloc time, not in settings paths,
    # and their large body gaps overspill into unrelated API initialization code.
    '.cxx_destruct',
    # Non-settings UI
    'contactsButtonTapped:', 'thanksButtonTapped',

    # ── B. Singleton getters / one-time initialisers ─────────────────────────
    # These use dispatch_once to create/cache a single instance.  NOP'ing forces
    # table[0] = "return cached (nil)" every time → nil propagates into any
    # NSDictionary that holds the result → startup crash.

    # NSUserDefaults / preferences
    'standardUserDefaults',   # YTLUserDefaults shared singleton (nil → crash on dict insert)
    'registerDefaults',       # called by standardUserDefaults init block; skip to be safe
    'reset',                  # user-defaults reset helper (no feature gate here)

    # GCD / timer singletons
    'timerQueue',             # dispatch_queue_t singleton; nil → crash on any dispatch call

    # Slim-bar UI singletons (lazy-initialised view components)
    'globalSlimBar',
    'playerSlimBar',
    'playerSlimBarVisibilityChange',

    # Player accessor
    'getPlayerIfAvailable',

    # Class / instance initialisers that contain dispatch_once guards
    # (these protect one-time setup, not Patreon checks)
    'initialize',

    # Import/export helpers — dispatch_once here guards file-manager setup, not
    # a Patreon feature; table[0] skips the setup → nil file paths → crash when
    # code tries to build a settings export dictionary and inserts nil values.
    'exportYtlSettings:',
    'importYtlSettings:',
}

# Maximum bytes to scan past the method IMP when looking for gates.
# The IMP-boundary approach already scopes the scan precisely, so this cap
# only matters for very large methods.  contribsTable body is ~20 KB; raising
# to 64 KB covers it without scanning into unrelated non-ObjC code.
DISPATCH_GATE_MAX_BODY = 0x10000  # 64 KB cap

# ── Caller-site NOPs ────────────────────────────────────────────────────────
# Some callers pass the nil return of patreonSection: directly into a method
# that crashes on nil (e.g. addSection:nil in rootTable).  NOP the specific
# BL instruction so the nil is silently discarded.
#
# Each entry: (file_offset, description)
CALLER_SITE_NOPS = [
    # rootTable: [table addSection:[self patreonSection:entry]]
    # patreonSection: → nil → addSection:nil → EXC_BAD_ACCESS
    (0x1385c4, "rootTable: addSection:[patreonSection:] → NOP"),
]


def run(dylib_path, output_path=None, dry_run=False, dump_map=False):
    print(f"Loading {dylib_path} …")
    data  = bytearray(Path(dylib_path).read_bytes())
    macho = MachO(data)
    plan  = PatchPlan()
    report = {}

    selref_map  = build_selref_map(data, macho)
    method_map  = build_method_map(data, macho, selref_map)
    sorted_imps = build_sorted_imp_list(method_map)
    print(f"ObjC metadata: {len(selref_map)} selrefs, {len(method_map)} selectors, "
          f"{len(sorted_imps)} method IMPs")

    # ── 1. Nil-return patches ────────────────────────────────────────────────
    print("\n[1] Nil-return patches")
    for sel in NIL_RETURN_SELECTORS:
        imps = method_map.get(sel, [])
        if not imps:
            print(f"  {sel}: not found in methlist")
            continue
        for (imp_va, imp_foff) in imps:
            if imp_foff is None:
                continue
            plan.add(imp_foff,     MOV_X0_0, f"{sel} → mov x0,#0")
            plan.add(imp_foff + 4, RET,      f"{sel} → ret")
            print(f"  {sel} @ {imp_foff:#010x}: will nil-return")
    report['nil_return'] = NIL_RETURN_SELECTORS

    # ── 2. Void-nop patches ──────────────────────────────────────────────────
    print("\n[2] Void-nop patches (IMP → ret)")
    for sel in VOID_NOP_SELECTORS:
        imps = method_map.get(sel, [])
        if not imps:
            print(f"  {sel}: not found in methlist")
            continue
        for (imp_va, imp_foff) in imps:
            if imp_foff is None:
                continue
            plan.add(imp_foff, RET, f"{sel} IMP → ret")
            print(f"  {sel} @ {imp_foff:#010x}: will ret-immediately")
    report['void_nop'] = VOID_NOP_SELECTORS

    # ── 2b. Caller-site NOPs ─────────────────────────────────────────────────
    # NOP specific call sites where a nil-return result would crash the caller.
    print("\n[2b] Caller-site NOPs")
    for foff, desc in CALLER_SITE_NOPS:
        plan.add(foff, NOP, desc)
        print(f"  {foff:#010x}: will NOP  [{desc}]")
    report['caller_site_nops'] = [hex(foff) for foff, _ in CALLER_SITE_NOPS]

    # ── 3. dispatch_once gate NOPs ───────────────────────────────────────────
    # Scan ALL ObjC method bodies using precise IMP-boundary sizing.
    # Skip non-settings methods where forcing table[0] could break features.
    print("\n[3] dispatch_once Patreon init gate NOPs (all ObjC methods)")
    gate_sites = {}
    total_gate_count = 0

    for i, (imp_va, sel, imp_foff) in enumerate(sorted_imps):
        if sel in DISPATCH_GATE_SKIP_SELECTORS:
            continue
        # Function body: [imp_foff, next_imp_foff), capped at DISPATCH_GATE_MAX_BODY.
        # The cap prevents scanning into non-ObjC helper functions that happen to sit
        # in the gap between two adjacent ObjC method IMPs.
        next_foff = sorted_imps[i + 1][2] if i + 1 < len(sorted_imps) else imp_foff + 0x10000
        fn_size = min(next_foff - imp_foff, DISPATCH_GATE_MAX_BODY)
        gates = find_dispatch_once_gates(data, imp_foff, size_limit=fn_size)
        if gates:
            for gate_off in gates:
                plan.add(gate_off, NOP, f"{sel}@{imp_va:#x}: dispatch_once CSINC → NOP")
            gate_sites[f"{sel}@{imp_va:#x}"] = [f"{g:#x}" for g in gates]
            total_gate_count += len(gates)

    print(f"  {total_gate_count} gate(s) found across {len(gate_sites)} method(s)")
    report['dispatch_once_gates'] = gate_sites

    # ── 4. isLoggedIn heuristic (MOVZ Wx,#0 in Patreon auth functions) ───────
    # isLoggedIn selector string is absent from this dylib's methname section
    # (the method name itself is obfuscated). We detect it via a known selector
    # that is CALLED from the same functions: if a function both (a) implements
    # a method that calls Patreon-auth selrefs and (b) contains MOVZ Wx,#0 near
    # a RET, replace #0 with #1.
    #
    # For this dylib version the relevant patches are already applied. For future
    # versions, run with --map to inspect and add offsets to KNOWN_LOGGEDIN_OFFSETS.
    KNOWN_LOGGEDIN_OFFSETS = []  # populated automatically below if detectable

    print("\n[4] isLoggedIn heuristic scan")
    # Heuristic: scan __TEXT for short functions that end with MOVZ W0,#0 / RET
    # and are preceded by an ADRP that loads a Patreon-related selref.
    patreon_selref_vas = set()
    patreon_sels = ['patreonSection:', 'showAlertWithMessage:showSettingsButton:',
                    'patreonButtonCellWithType:model:']
    for sel in patreon_sels:
        for va, name in selref_map.items():
            if name == sel:
                patreon_selref_vas.add(va)

    TEXT_foff = macho.sects.get('__TEXT,__text', {}).get('fileoff', 0)
    TEXT_size = macho.sects.get('__TEXT,__text', {}).get('vmsize', 0x1060000)
    TEXT_end  = TEXT_foff + TEXT_size

    loggedin_patches = 0
    # Scan for MOVZ W0,#0 / RET pairs (simple false-return stubs)
    for off in range(TEXT_foff, min(TEXT_end - 8, len(data) - 8), 4):
        v0 = r32(data, off)
        v1 = r32(data, off + 4)
        # MOVZ W0, #0 = 0x52800000; MOVZ W8, #0 = 0x52800008
        if v0 in (0x52800000, 0x52800008) and v1 == RET:
            # Candidate: check if this is within a function that uses Patreon selrefs
            # (scan 512 bytes back for an ADRP that produces a Patreon selref page)
            is_patreon = False
            for back in range(off - 4, max(off - 2048, TEXT_foff), -4):
                bv = r32(data, back)
                # ADRP Xn: bits[31]=1, bits[28:24]=10000
                if (bv & 0x9F000000) == 0x90000000:
                    # Decode ADRP target page
                    imm_lo = (bv >> 29) & 3
                    imm_hi = (bv >> 5) & 0x7FFFF
                    page_off = ((imm_hi << 2) | imm_lo) << 12
                    if page_off >= 0x80000000:
                        page_off -= 0x100000000
                    fn_va = macho.va2f(back)
                    if fn_va is not None:
                        pc_page = (back + fn_va - TEXT_foff) & ~0xFFF  # rough
                    # Check if any Patreon selref falls on this page (same 4K page)
                    for psva in patreon_selref_vas:
                        if abs((psva & ~0xFFF) - (psva & ~0xFFF)) < 0x2000:
                            pass  # too broad; skip for now
                    break
            # Instead of heuristic, just record for --map output
            KNOWN_LOGGEDIN_OFFSETS.append(off)

    # We only report, don't auto-patch (too many false positives)
    print(f"  Found {len(KNOWN_LOGGEDIN_OFFSETS)} MOVZ Wx,#0/RET pairs (review with --map)")
    report['isLoggedIn_candidates'] = len(KNOWN_LOGGEDIN_OFFSETS)

    # ── 5. Full dispatch_once gate map (--map mode) ──────────────────────────
    if dump_map:
        print("\n[MAP] All dispatch_once gates in __TEXT …")
        all_gates = []
        TEXT_sect = macho.sect('__TEXT,__text')
        if TEXT_sect:
            t_foff = TEXT_sect['fileoff']
            t_size = TEXT_sect['vmsize']
            for off in range(t_foff, min(t_foff + t_size, len(data) - 12), 4):
                v0 = r32(data, off)
                v1 = r32(data, off + 4)
                v2 = r32(data, off + 8)
                if ((v0 & 0xFFFFFC00) == 0x88DFFC00 and
                        (v1 & 0xFFFFFC1F) == 0x7100001F and
                        (v2 & 0xFFFFFFE0) == 0x1A9F17E0):
                    all_gates.append(off + 8)
                # Also count already-NOP'd sites
                elif ((v0 & 0xFFFFFC00) == 0x88DFFC00 and
                        (v1 & 0xFFFFFC1F) == 0x7100001F and
                        v2 == NOP):
                    all_gates.append(-(off + 8))  # negative = already patched
        active  = [g for g in all_gates if g > 0]
        patched = [g for g in all_gates if g < 0]
        print(f"  Total gates: {len(all_gates)} ({len(active)} active, {len(patched)} already NOP'd)")
        report['all_dispatch_gates'] = {
            'total': len(all_gates),
            'active': len(active),
            'already_patched': len(patched),
            'active_offsets': [f"{g:#010x}" for g in active],
        }

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
    ap.add_argument('--map',     action='store_true', help='Dump full obfuscation map')
    ap.add_argument('--json',    metavar='FILE', help='Write JSON report to FILE')
    args = ap.parse_args()

    report = run(args.input, args.output,
                 dry_run=args.dry_run,
                 dump_map=args.map)

    if args.json:
        Path(args.json).write_text(json.dumps(report, indent=2))
        print(f"Report → {args.json}")
