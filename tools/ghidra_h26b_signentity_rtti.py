# -*- coding: utf-8 -*-
# Ghidra Jython: H-26 Plan B task #2 -- sign-ENTITY RTTI hunt.
#
# Sibling to ghidra_h26_sign_hunt.py (PR #9). That script catalogued the
# Frpg2RequestMessage protobuf DTO classes (Request*Sign / *Response). What
# we need now are the in-world sign ENTITY classes -- the things the engine
# normally builds when it parses a RequestGetSignListResponse and converts
# each sign record into a visible/interactable world object.
#
# Two pipeline differences from the PR #9 script:
#
#   1. Search space. We do an UN-NAMESPACED RTTI scan: every .?AV / .?AU
#      string containing the substring "Sign" or "Soapstone" anywhere,
#      filtering OUT the Frpg2RequestMessage namespace (already documented).
#      This catches CSOnline::*Sign, *SignEntity, SummonSignVfx, anything.
#
#   2. Constructor discovery. The PR #9 hunt's Section D came back EMPTY
#      because it only scanned for 8-byte qword refs to the vtable VA, but
#      MSVC vtable loads use `lea rax, [rip+disp32]` -- the disp32 is a
#      4-byte signed displacement, not the full vtable address. This script
#      adds a code-section LEA-RIP scan: find `48 8D 05 dd dd dd dd` where
#      disp32 + (inst_end_addr) == vtable_VA. That finds every constructor.
#
# Output: D:\Applications\DS2\Seamless\tools\ghidra_h26b_signentity_rtti_results.txt
#
#@runtime Jython

import jarray
import struct

OUT_PATH = r"D:\Applications\DS2\Seamless\tools\ghidra_h26b_signentity_rtti_results.txt"

program = currentProgram
listing = program.getListing()
memory = program.getMemory()
funcMgr = program.getFunctionManager()
baseAddr = program.getImageBase()
baseVA = baseAddr.getOffset()

results = []

def log(msg):
    results.append(str(msg))
    print(msg)

def exeOffset(addr):
    try:
        return long(addr.subtract(baseAddr))
    except:
        return 0

def addrFromVA(va):
    return baseAddr.add(va - baseVA)

def s8(v):
    return v if v < 128 else v - 256

def searchBytes(pat_bytes, max_hits=4096):
    pat = jarray.array([s8(b & 0xff) for b in pat_bytes], 'b')
    masks = jarray.array([-1] * len(pat_bytes), 'b')
    found = []
    for block in memory.getBlocks():
        if not block.isInitialized():
            continue
        start = block.getStart()
        end = block.getEnd()
        a = memory.findBytes(start, end, pat, masks, True, monitor)
        while a is not None and len(found) < max_hits:
            found.append(a)
            try:
                nxt = a.add(1)
                if nxt.compareTo(end) >= 0:
                    break
                a = memory.findBytes(nxt, end, pat, masks, True, monitor)
            except:
                break
    return found

def searchString(needle, max_hits=4096):
    return searchBytes([ord(c) for c in needle], max_hits)

def searchQword(qword_va, max_hits=128):
    return searchBytes([(qword_va >> (i*8)) & 0xff for i in range(8)], max_hits)

def searchDword(dword_rva, max_hits=128):
    return searchBytes([(dword_rva >> (i*8)) & 0xff for i in range(4)], max_hits)

def readU64(addr):
    try:
        b = jarray.zeros(8, 'b')
        memory.getBytes(addr, b)
        v = 0
        for i in range(8):
            v |= (b[i] & 0xff) << (i*8)
        return v
    except:
        return None

def readU32(addr):
    try:
        b = jarray.zeros(4, 'b')
        memory.getBytes(addr, b)
        v = 0
        for i in range(4):
            v |= (b[i] & 0xff) << (i*8)
        return v
    except:
        return None

def readCString(addr, max_len=200):
    try:
        out = []
        for i in range(max_len):
            b = memory.getByte(addr.add(i)) & 0xff
            if b == 0:
                break
            if b < 0x20 or b > 0x7e:
                return None
            out.append(chr(b))
        return ''.join(out)
    except:
        return None

# ============================================================================
log("=" * 72)
log("H-26 Plan B task #2: sign-ENTITY RTTI hunt")
log("=" * 72)
log("Image base: %s" % baseAddr)

# ============================================================================
# Step 1 -- broad scan for "Sign" / "Soapstone" inside RTTI strings,
#           filtering out the protobuf namespace (already documented).
EXCLUDE_NS = "Frpg2RequestMessage"
KEYWORDS = ["Sign", "Soapstone", "Bloodstain", "Marker", "Trace"]

candidates = []  # (str_addr, full_string)
seen = set()
for kw in KEYWORDS:
    hits = searchString(kw, max_hits=4096)
    for a in hits:
        # Walk backward up to 16 bytes looking for ".?AV" or ".?AU" prefix.
        prefix_addr = None
        for off in range(0, 80):
            cand = a.subtract(off)
            pref = readCString(cand, 4)
            if pref == ".?AV" or pref == ".?AU":
                prefix_addr = cand
                break
        if prefix_addr is None:
            continue
        full = readCString(prefix_addr, 200)
        if full is None:
            continue
        if EXCLUDE_NS in full:
            continue
        key = full
        if key in seen:
            continue
        seen.add(key)
        candidates.append((prefix_addr, full))

log("\n### A. Candidate RTTI strings (Sign/Soapstone/Bloodstain/Marker, non-protobuf) ###")
log("    %d candidates after filtering out '%s'" % (len(candidates), EXCLUDE_NS))
for ca, full in candidates:
    log("  %s (+0x%X)  \"%s\"" % (ca, exeOffset(ca), full))

# ============================================================================
# Step 2 -- TD/COL/vtable chain (same as PR #9 script).
log("\n### B. TD -> COL -> vtable chain ###")

class_data = []  # list of dicts: name, str_addr, td_addr, cols, vtables

for str_addr, full_name in candidates:
    td_addr = str_addr.subtract(0x10)
    td_rva = exeOffset(td_addr)
    log("\n  -- %s --" % full_name)
    log("     string @ +0x%X, TD @ +0x%X (RVA 0x%X)" % (
        exeOffset(str_addr), exeOffset(td_addr), td_rva))

    rva_hits = searchDword(td_rva, max_hits=64)
    col_addrs = []
    for h in rva_hits:
        cand_col = h.subtract(12)
        sig = readU32(cand_col)
        pself = readU32(cand_col.add(20))
        if sig == 1 and pself == exeOffset(cand_col):
            col_addrs.append(cand_col)
            log("     COL @ %s (+0x%X) sig=1 pSelf-OK" % (
                cand_col, exeOffset(cand_col)))

    vtables = []
    for col in col_addrs:
        col_va = col.getOffset()
        slot_hits = searchQword(col_va, max_hits=16)
        for sh in slot_hits:
            vt = sh.add(8)
            vtables.append(vt)
            log("     vtable @ %s (+0x%X) [COL slot @ %s]" % (
                vt, exeOffset(vt), sh))

    class_data.append({
        'name': full_name,
        'string_addr': str_addr,
        'td_addr': td_addr,
        'cols': col_addrs,
        'vtables': vtables,
    })

# ============================================================================
# Step 3 -- dump first 24 vtable slots.
log("\n### C. Vtable slots (first 24) ###")

def slot_func(vt, idx):
    qw = readU64(vt.add(idx * 8))
    if qw is None or qw == 0:
        return None, None
    if qw < baseVA or qw > baseVA + 0x10000000:
        return qw, None
    fa = addrFromVA(qw)
    fn = funcMgr.getFunctionContaining(fa)
    return qw, fn

for cd in class_data:
    if not cd['vtables']:
        continue
    log("\n  ==> %s" % cd['name'])
    for vt in cd['vtables']:
        log("    vtable @ %s (+0x%X)" % (vt, exeOffset(vt)))
        for i in range(24):
            qw, fn = slot_func(vt, i)
            if qw is None or qw == 0:
                log("      slot[%2d] = 0" % i)
                continue
            fname = fn.getName() if fn else "(no func)"
            fep = ("+0x%X" % exeOffset(fn.getEntryPoint())) if fn else "?"
            log("      slot[%2d] = 0x%X (%s @ %s)" % (i, qw, fname, fep))

# ============================================================================
# Step 4 -- find constructor sites via LEA-RIP encoding.
#   `lea rax, [rip+disp32]` = 48 8D 05 dd dd dd dd  (7 bytes)
#   disp32 is signed; absolute target = next_inst_addr + disp32.
# Also covers `lea rcx, [rip+disp32]` = 48 8D 0D ... and other regs by
# scanning the broader "48 8D ?5 dd dd dd dd" pattern where the modrm byte's
# bottom 3 bits are 5 (RIP-relative).
#
# We do this only inside executable memory blocks to avoid false positives.
log("\n### D. Constructor sites (LEA-RIP scan) ###")

# Pre-collect all executable blocks.
exec_blocks = []
for blk in memory.getBlocks():
    if blk.isInitialized() and blk.isExecute():
        exec_blocks.append(blk)

# Build a quick lookup: vtable_VA -> entity name.
vt_targets = {}
for cd in class_data:
    for vt in cd['vtables']:
        vt_targets[vt.getOffset()] = cd['name']

# Scan executable blocks byte-by-byte for the LEA-RIP signature.
# Cost: ~25MB of code, ~250K opcode-byte hits to check, fast enough.
def s8_(v):
    return v if v < 128 else v - 256

LEA_PREFIX = jarray.array([s8_(0x48), s8_(0x8d)], 'b')
LEA_MASK   = jarray.array([-1, -1], 'b')

hits_per_class = {}

for blk in exec_blocks:
    start = blk.getStart()
    end = blk.getEnd()
    a = memory.findBytes(start, end, LEA_PREFIX, LEA_MASK, True, monitor)
    while a is not None:
        # Need at least 7 bytes from 'a'.
        try:
            modrm = memory.getByte(a.add(2)) & 0xff
            # Bottom 3 bits == 5 means RIP-relative, mod field == 00.
            # We want modrm where (modrm & 0xC7) == 0x05.
            if (modrm & 0xC7) == 0x05:
                # disp32 at a+3, signed.
                d_bytes = jarray.zeros(4, 'b')
                memory.getBytes(a.add(3), d_bytes)
                disp = struct.unpack('<i', ''.join(chr(b & 0xff) for b in d_bytes))[0]
                next_inst = a.getOffset() + 7
                target_va = (next_inst + disp) & 0xffffffffffffffff
                if target_va in vt_targets:
                    name = vt_targets[target_va]
                    hits_per_class.setdefault(name, []).append((a, target_va))
        except:
            pass
        try:
            nxt = a.add(1)
            if nxt.compareTo(end) >= 0:
                break
            a = memory.findBytes(nxt, end, LEA_PREFIX, LEA_MASK, True, monitor)
        except:
            break

for cd in class_data:
    if not cd['vtables']:
        continue
    log("\n  ==> %s" % cd['name'])
    for vt in cd['vtables']:
        vt_va = vt.getOffset()
        log("    vtable VA: 0x%X" % vt_va)
        ctor_hits = hits_per_class.get(cd['name'], [])
        ctor_for_this_vt = [(a, t) for (a, t) in ctor_hits if t == vt_va]
        if not ctor_for_this_vt:
            log("      (no LEA-RIP refs found)")
            continue
        for site, _ in ctor_for_this_vt:
            fn = funcMgr.getFunctionContaining(site)
            fname = fn.getName() if fn else "(no func)"
            fep = ("+0x%X" % exeOffset(fn.getEntryPoint())) if fn else "?"
            log("      ctor ref @ %s (+0x%X) in %s @ %s" % (
                site, exeOffset(site), fname, fep))

log("\n" + "=" * 72)
log("Done.")
log("Next: pick the most-construct-rich class; its enclosing function is")
log("the in-world sign spawn primitive.")
log("=" * 72)

with open(OUT_PATH, 'w') as f:
    f.write('\n'.join(results))

print("\nSaved to %s (%d lines)" % (OUT_PATH, len(results)))
