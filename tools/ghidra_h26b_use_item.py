# -*- coding: utf-8 -*-
# Ghidra Jython: find DS2's soapstone-use handler (H-26 Plan B task #1).
#
# Two parallel strategies:
#
#   A. Item-ID literal search. The soapstone item IDs are known constants
#      from include/addresses.h:
#          WhiteSignSoapstone       = 0x03B280B0
#          SmallWhiteSignSoapstone  = 0x03B2A7C0
#      Any function that branches on these IDs in a use-item dispatcher
#      will load them via a MOV reg, imm32 (4-byte LE in the .text
#      section). Item-database tables in .rdata may also reference them
#      as record fields ({id, name, flags, ...}). Both are useful.
#
#   B. RTTI string search for sign/soapstone-related classes. DS2 may have
#      per-item handler classes (.?AVWhiteSignItem@@, .?AVSoapstoneUse@@,
#      etc.). If those exist, their vtables give us direct entry points.
#
# For each hit:
#   - If in code: dump the containing function head + caller list
#   - If in data: dump the surrounding 32-byte window so we can see the
#     record structure (and any function pointers in it)
#
#@runtime Jython
#
# Output: D:\Applications\DS2\Seamless\tools\ghidra_h26b_use_item_results.txt

import jarray

OUT_PATH = r"D:\Applications\DS2\Seamless\tools\ghidra_h26b_use_item_results.txt"

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

def searchBytes(pat_bytes, max_hits=256):
    pat = jarray.array([s8(b & 0xff) for b in pat_bytes], 'b')
    masks = jarray.array([-1] * len(pat_bytes), 'b')
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

def searchString(needle, max_hits=64):
    return searchBytes([ord(c) for c in needle], max_hits)

def searchDword(d, max_hits=256):
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
    if bs is None:
        return None
    v = 0
    for i in range(8):
        v |= bs[i] << (i*8)
    return v

def hexline(addr, bytes_list):
    return "%s  %s" % (
        addr, " ".join("%02X" % b for b in bytes_list))

def dumpDataWindow(addr, before=8, after=24):
    """Print a hexdump of memory around addr, useful for inspecting
    data-table records that contain an item ID."""
    start = addr.subtract(before)
    bs = readBytes(start, before + after)
    if bs is None:
        log("    (memory unreadable @ %s)" % start)
        return
    # Print in 16-byte rows
    row_size = 16
    for row in range(0, len(bs), row_size):
        chunk = bs[row:row + row_size]
        a = start.add(row)
        log("    %s  %s  %s" % (
            a, " ".join("%02X" % b for b in chunk),
            "".join(chr(b) if 0x20 <= b <= 0x7e else "." for b in chunk)))

def dumpFuncHead(fn, max_inst=120):
    if fn is None:
        log("    (no function resolved)")
        return
    ep = fn.getEntryPoint()
    body = fn.getBody()
    size = body.getNumAddresses() if body else 0
    log("\n    --- %s @ +0x%X (%d bytes) ---" %
        (fn.getName(), exeOffset(ep), size))
    it = listing.getInstructions(ep, True)
    count = 0
    while it.hasNext() and count < max_inst:
        inst = it.next()
        if not body.contains(inst.getAddress()):
            break
        log("      %s (+0x%X)  %s" % (
            inst.getAddress(), exeOffset(inst.getAddress()),
            inst.toString()))
        count += 1

def dumpCallers(fn, max_callers=20):
    if fn is None:
        return
    refs = list(refMgr.getReferencesTo(fn.getEntryPoint()))
    code_refs = [r for r in refs
                 if r.getReferenceType().isCall() or r.getReferenceType().isFlow()]
    log("    callers (code-flow refs): %d" % len(code_refs))
    for ref in code_refs[:max_callers]:
        fa = ref.getFromAddress()
        cf = funcMgr.getFunctionContaining(fa)
        cname = cf.getName() if cf else "(no func)"
        cep = ("+0x%X" % exeOffset(cf.getEntryPoint())) if cf else "?"
        log("      from %s (+0x%X) in %s @ %s" %
            (fa, exeOffset(fa), cname, cep))

# Item IDs from include/addresses.h
ITEM_IDS = [
    ("WhiteSignSoapstone",      0x03B280B0),
    ("SmallWhiteSignSoapstone", 0x03B2A7C0),
]

# RTTI keywords. ".?AV..." prefix is added by the search loop; we match the
# discriminator substring as a tail.
RTTI_KEYWORDS = [
    "Soapstone",
    "WhiteSign",
    "SmallWhiteSign",
    "ItemUse",
    "ConsumableUse",
    "UseItem",
    "SignItem",
    "SoapstoneItem",
    "SignSpawn",
    "PlaceSign",
    "PutSign",
]

log("=" * 70)
log("H-26 Plan B task #1: soapstone use-item handler hunt")
log("=" * 70)

# ============================================================================
# A. Item-ID literal search
# ============================================================================
log("\n### A. Item-ID literal occurrences ###")

for name, item_id in ITEM_IDS:
    log("\n  -- %s = 0x%08X --" % (name, item_id))
    hits = searchDword(item_id, max_hits=128)
    log("    occurrences: %d" % len(hits))
    if not hits:
        continue

    code_hits = []
    data_hits = []
    for h in hits:
        block = memory.getBlock(h)
        if block and block.isExecute():
            code_hits.append(h)
        else:
            data_hits.append(h)
    log("    code-section hits: %d  /  data-section hits: %d" %
        (len(code_hits), len(data_hits)))

    if code_hits:
        log("\n    Code-section hits (likely a use-handler branching on ID):")
        # Dedup by containing function
        fn_offsets_seen = set()
        for h in code_hits:
            cf = funcMgr.getFunctionContaining(h)
            if cf is None:
                log("      %s (+0x%X) -- no enclosing function" %
                    (h, exeOffset(h)))
                continue
            cep_off = exeOffset(cf.getEntryPoint())
            if cep_off in fn_offsets_seen:
                continue
            fn_offsets_seen.add(cep_off)
            log("      hit at %s (+0x%X) inside %s @ +0x%X" %
                (h, exeOffset(h), cf.getName(), cep_off))
            dumpFuncHead(cf, max_inst=80)
            dumpCallers(cf, max_callers=10)

    if data_hits:
        log("\n    Data-section hits (likely an item-DB record):")
        for h in data_hits[:16]:
            log("\n      hit at %s (+0x%X)" % (h, exeOffset(h)))
            dumpDataWindow(h, before=8, after=32)

# ============================================================================
# B. RTTI string search
# ============================================================================
log("\n\n### B. RTTI string occurrences ###")

interesting_classes = []

for kw in RTTI_KEYWORDS:
    hits = searchString(kw, max_hits=32)
    if not hits:
        continue
    log("\n  -- %s -- (%d hits)" % (kw, len(hits)))
    for a in hits[:16]:
        # Check if the prefix is an MSVC RTTI string
        prefix_addr = a.subtract(4)
        prefix_bs = readBytes(prefix_addr, 4)
        if prefix_bs is None:
            continue
        prefix_str = "".join(chr(b) for b in prefix_bs)
        is_rtti = prefix_str.startswith(".?AV") or prefix_str.startswith(".?AU")

        # Read the full string at the (possibly prefix-included) start
        full_start = prefix_addr if is_rtti else a
        full_bytes = readBytes(full_start, 160)
        if full_bytes is None:
            continue
        full = []
        for b in full_bytes:
            if b == 0:
                break
            if b < 0x20 or b > 0x7e:
                full = None
                break
            full.append(chr(b))
        if full is None:
            continue
        full_str = "".join(full)

        marker = "[RTTI]" if is_rtti else "[plain]"
        log("    %s %s (+0x%X)  \"%s\"" %
            (marker, full_start, exeOffset(full_start), full_str))

        if is_rtti:
            interesting_classes.append((full_str, full_start))

log("\n  Found %d RTTI class strings of interest" % len(interesting_classes))

log("\n" + "=" * 70)
log("Done. Look for in the output:")
log("  - Code hits inside functions whose disasm contains a switch/cmp")
log("    on the item ID followed by a CALL to an unfamiliar function:")
log("    that CALL target is the per-item handler.")
log("  - Data hits with a function pointer (qword starting with 0x14...)")
log("    a few bytes after the item ID: that's an item-DB record with an")
log("    inline use-handler pointer.")
log("  - RTTI classes named *Soapstone* / *Sign*Item / similar: walk")
log("    their vtables in a follow-up pass (similar to the Plan A sign")
log("    hunt at tools/ghidra_h26_sign_hunt.py).")
log("=" * 70)

with open(OUT_PATH, 'w') as f:
    f.write('\n'.join(results))

print("\nSaved to %s (%d lines)" % (OUT_PATH, len(results)))
