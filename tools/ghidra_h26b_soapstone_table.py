# -*- coding: utf-8 -*-
# Ghidra Jython: follow up the task-#1 first pass.
#
# First-pass findings:
#   - Soapstone enumeration table at +0x10C3D70: 5 records of
#     (item_id : u32, index : u32). Item IDs 0..1 are White / Small-White
#     soapstones from include/addresses.h; 2..4 are unknown (likely Red,
#     Dragon, etc.).
#   - "ItemUseCheckWindowJob@FeInventoryJobFactory@@" RTTI fragment at
#     +0x155E81D. "ItemUseCheck@@" at +0x564E8B. These are inventory FSM
#     job classes; their full ".?AV" prefix should sit 4 bytes earlier.
#
# This pass:
#   A. Find all code refs (LEA / MOV ...) to the soapstone table head, so we
#      get the function(s) that iterate it on a use-item dispatch. Then
#      dump those functions in full.
#   B. Locate the full RTTI strings for the ItemUseCheck* classes and
#      walk their vtables (same approach as ghidra_h26_sign_hunt.py).
#
#@runtime Jython
#
# Output: D:\Applications\DS2\Seamless\tools\ghidra_h26b_soapstone_table_results.txt

import jarray

OUT_PATH = r"D:\Applications\DS2\Seamless\tools\ghidra_h26b_soapstone_table_results.txt"

program = currentProgram
memory = program.getMemory()
listing = program.getListing()
funcMgr = program.getFunctionManager()
refMgr = program.getReferenceManager()
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

def searchBytes(pat_bytes, max_hits=128):
    pat = jarray.array([s8(b & 0xff) for b in pat_bytes], 'b')
    masks = jarray.array([-1]*len(pat_bytes), 'b')
    found = []
    for block in memory.getBlocks():
        if not block.isInitialized():
            continue
        a = memory.findBytes(block.getStart(), block.getEnd(), pat, masks, True, monitor)
        while a is not None and len(found) < max_hits:
            found.append(a)
            try:
                nxt = a.add(1)
                if nxt.compareTo(block.getEnd()) >= 0:
                    break
                a = memory.findBytes(nxt, block.getEnd(), pat, masks, True, monitor)
            except:
                break
    return found

def searchQword(q, max_hits=64):
    return searchBytes([(q >> (i*8)) & 0xff for i in range(8)], max_hits)

def searchDword(d, max_hits=64):
    return searchBytes([(d >> (i*8)) & 0xff for i in range(4)], max_hits)

def readBytes(addr, count):
    try:
        b = jarray.zeros(count, 'b')
        memory.getBytes(addr, b)
        return [(x & 0xff) for x in b]
    except:
        return None

def readU64(addr):
    bs = readBytes(addr, 8)
    if bs is None: return None
    v = 0
    for i in range(8):
        v |= bs[i] << (i*8)
    return v

def readU32(addr):
    bs = readBytes(addr, 4)
    if bs is None: return None
    v = 0
    for i in range(4):
        v |= bs[i] << (i*8)
    return v

def dumpFuncFull(fn, max_inst=300):
    if fn is None:
        log("  (no function)")
        return
    ep = fn.getEntryPoint()
    body = fn.getBody()
    size = body.getNumAddresses() if body else 0
    log("\n--- %s @ +0x%X (%d bytes) ---" % (fn.getName(), exeOffset(ep), size))
    it = listing.getInstructions(ep, True)
    count = 0
    while it.hasNext() and count < max_inst:
        inst = it.next()
        if not body.contains(inst.getAddress()):
            break
        log("  %s (+0x%X)  %s" % (inst.getAddress(),
                                   exeOffset(inst.getAddress()),
                                   inst.toString()))
        count += 1

# ============================================================================
log("=" * 70)
log("H-26 Plan B task #1 (follow-up): soapstone table xrefs + ItemUse vtables")
log("=" * 70)

# ----------------------------------------------------------------------------
# A. Refs to the soapstone enumeration table at +0x10C3D70 (head of the
#    array; row 0 starts here, 5 rows of 8 bytes).
# ----------------------------------------------------------------------------
log("\n### A. Soapstone table xrefs ###")

TABLE_HEAD_RVA = 0x10C3D70

# The dispatcher may LEA the head OR row 0 (same address) OR the row of a
# specific item. Try a few candidates: -8 (in case there's an array
# descriptor 8 bytes before), 0 (head), +8, +16, ... (specific rows).
for delta in [-8, 0, 8, 16, 24, 32]:
    va = baseVA + TABLE_HEAD_RVA + delta
    log("\n  refs to +0x%X (delta %+d from table head):" %
        (TABLE_HEAD_RVA + delta, delta))
    refs = list(refMgr.getReferencesTo(addrFromVA(va)))
    if not refs:
        log("    (none)")
        continue
    for ref in refs[:32]:
        fa = ref.getFromAddress()
        rt = ref.getReferenceType()
        cf = funcMgr.getFunctionContaining(fa)
        cname = cf.getName() if cf else "(no func)"
        cep = ("+0x%X" % exeOffset(cf.getEntryPoint())) if cf else "?"
        log("    %s (+0x%X) in %s @ %s [%s]" % (
            fa, exeOffset(fa), cname, cep, rt))

# ----------------------------------------------------------------------------
# Dump any unique functions that referenced the table -- these are the
# soapstone-dispatch candidates.
# ----------------------------------------------------------------------------
log("\n### A.2 Function bodies of soapstone-table referencers ###")

dispatch_fns = set()
for delta in [-8, 0, 8, 16, 24, 32, 40]:
    va = baseVA + TABLE_HEAD_RVA + delta
    for ref in refMgr.getReferencesTo(addrFromVA(va)):
        cf = funcMgr.getFunctionContaining(ref.getFromAddress())
        if cf:
            dispatch_fns.add(exeOffset(cf.getEntryPoint()))

for off in sorted(dispatch_fns):
    fn = funcMgr.getFunctionContaining(addrFromVA(baseVA + off))
    dumpFuncFull(fn, max_inst=200)

# ----------------------------------------------------------------------------
# B. Recover the full RTTI strings for ItemUseCheck* classes.
# ----------------------------------------------------------------------------
log("\n\n### B. ItemUseCheck* RTTI strings (full form, vtables) ###")

# RTTI in MSVC x64 is ".?AV" + name + "@@". The first-pass found "ItemUse"
# substrings; the full strings (with .?AV prefix) are at the addresses
# reported - 4 bytes for the prefix.
RTTI_TAILS = [
    "ItemUseCheckWindowJob@FeInventoryJobFactory@@",
    "ItemUseCheck@@",
]

class_info = []  # (full_str, td_addr)

for tail in RTTI_TAILS:
    log("\n  -- tail '%s' --" % tail)
    hits = searchBytes([ord(c) for c in tail], max_hits=4)
    for tail_addr in hits:
        # The string starts 4 bytes earlier with .?AV
        prefix_addr = tail_addr.subtract(4)
        prefix_bs = readBytes(prefix_addr, 4)
        if prefix_bs is None:
            continue
        if not (prefix_bs[0] == ord(".") and prefix_bs[1] == ord("?") and
                prefix_bs[2] == ord("A") and prefix_bs[3] == ord("V")):
            log("    %s prefix is not .?AV (got %r) - skip" %
                (tail_addr, "".join(chr(b) for b in prefix_bs)))
            continue
        # Build the full string
        bs = readBytes(prefix_addr, 4 + len(tail) + 1)
        full = "".join(chr(b) for b in bs if b != 0)
        # TypeDescriptor sits 0x10 before the string
        td_addr = prefix_addr.subtract(0x10)
        log("    full RTTI %s (+0x%X)" % (prefix_addr, exeOffset(prefix_addr)))
        log("    TD @ %s (+0x%X)" % (td_addr, exeOffset(td_addr)))
        log("    text: \"%s\"" % full)
        class_info.append((full, td_addr))

# For each class, walk to vtables (same approach as h26_sign_hunt.py)
log("\n### B.2 Vtables for the ItemUseCheck* classes ###")

for full, td_addr in class_info:
    log("\n  ==> %s" % full)
    td_rva = exeOffset(td_addr)
    rva_hits = searchDword(td_rva, max_hits=16)
    cols = []
    for h in rva_hits:
        # COL+12 holds TD RVA. So COL = h - 12.
        cand_col = h.subtract(12)
        sig = readU32(cand_col)
        pself = readU32(cand_col.add(20))
        if sig == 1 and pself == exeOffset(cand_col):
            cols.append(cand_col)
    log("    COLs: %d" % len(cols))
    for col in cols:
        col_va = col.getOffset()
        log("    COL @ %s (+0x%X)" % (col, exeOffset(col)))
        # vtable[-1] points at COL, so search for qword = col_va. The next
        # qword is vtable[0].
        slot_hits = searchQword(col_va, max_hits=4)
        for sh in slot_hits:
            vt = sh.add(8)
            log("    vtable @ %s (+0x%X)" % (vt, exeOffset(vt)))
            # Print first 16 vtable slots
            for i in range(16):
                slot_va = readU64(vt.add(i * 8))
                if slot_va is None or slot_va == 0:
                    log("      slot[%2d] = 0" % i)
                    continue
                if not (baseVA <= slot_va < baseVA + 0x10000000):
                    log("      slot[%2d] = 0x%X (out of image)" % (i, slot_va))
                    continue
                fn = funcMgr.getFunctionContaining(addrFromVA(slot_va))
                fname = fn.getName() if fn else "(no func)"
                fep = ("+0x%X" % exeOffset(fn.getEntryPoint())) if fn else "?"
                log("      slot[%2d] = 0x%X (%s @ %s)" % (i, slot_va, fname, fep))

log("\n" + "=" * 70)
log("Done.")
log("=" * 70)

with open(OUT_PATH, 'w') as f:
    f.write('\n'.join(results))

print("\nSaved to %s (%d lines)" % (OUT_PATH, len(results)))
