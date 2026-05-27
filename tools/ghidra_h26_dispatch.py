# -*- coding: utf-8 -*-
# Ghidra Jython: characterize the dispatch tables that hold the sign-send
# function pointers. Specifically:
#   - +0x1113320 area (immediately before RequestCreateSign vtable at +0x1113378)
#   - +0x140D16C..+0x140D424 area
#   - +0x190BFE8..+0x190C018 area
#
# For each table region, dump the surrounding 256 bytes as a list of qwords
# (8-byte function pointers). Then for each qword that points into the code
# section, resolve to a function name. The structure of the table will be
# obvious from that.
#
# Also: find every code-side ref to the table's start address. That ref is
# the dispatcher — i.e. the code that calls these RPC methods. From there
# we can trace up to the player-input layer.
#
#@runtime Jython
#
# Output: D:\Applications\DS2\Seamless\tools\ghidra_h26_dispatch_results.txt

import jarray

OUT_PATH = r"D:\Applications\DS2\Seamless\tools\ghidra_h26_dispatch_results.txt"

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

def s8(v):
    return v if v < 128 else v - 256

def searchQword(qword_va, max_hits=32):
    pat_bytes = [s8((qword_va >> (i*8)) & 0xff) for i in range(8)]
    pat = jarray.array(pat_bytes, 'b')
    masks = jarray.array([-1]*8, 'b')
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

def dumpQwordTable(label, start_rva, num_qwords=16, backup=0):
    log("\n--- %s table dump @ +0x%X (window: -%d..+%d qwords) ---" % (
        label, start_rva, backup, num_qwords))
    for i in range(-backup, num_qwords):
        addr = addrFromVA(baseVA + start_rva + i*8)
        qw = readU64(addr)
        if qw is None:
            log("  [+%d] %s  <unreadable>" % (i, addr))
            continue
        target = "?"
        if baseVA <= qw < baseVA + 0x10000000:
            ta = addrFromVA(qw)
            fn = funcMgr.getFunctionContaining(ta)
            if fn:
                fep_off = exeOffset(fn.getEntryPoint())
                target = "%s @ +0x%X" % (fn.getName(), fep_off)
                if fep_off != exeOffset(ta):
                    target = "%s + %d" % (target, exeOffset(ta) - fep_off)
            else:
                target = "(no func) (image+0x%X)" % (qw - baseVA)
        else:
            target = "0x%X" % qw
        marker = " <- HEAD" if i == 0 else ""
        log("  [%+3d] +0x%X  0x%016X  %s%s" % (
            i, exeOffset(addr), qw, target, marker))

def findCodeRefsTo(va):
    log("\n  Code-side qword refs to 0x%X:" % va)
    hits = searchQword(va, max_hits=32)
    for h in hits:
        block = memory.getBlock(h)
        kind = "CODE" if (block and block.isExecute()) else "data"
        fn = funcMgr.getFunctionContaining(h)
        fname = fn.getName() if fn else "(no func)"
        fep = ("+0x%X" % exeOffset(fn.getEntryPoint())) if fn else "?"
        log("    %s (+0x%X) %s in %s @ %s" % (
            h, exeOffset(h), kind, fname, fep))

log("=" * 70)
log("H-26 dispatch-table characterization")
log("=" * 70)

# Region 1: vtable for "SignServiceClient" or similar.
# Sign-send qwords are at offsets 0x1113320, 0x1113338, 0x1113340, 0x1113350,
# i.e. table head at ~0x1113318. Just before RequestCreateSign vtable at 0x1113378.
dumpQwordTable("Region 1 (near RequestCreateSign vtable)", 0x1113318, num_qwords=18)

# Region 2: 0x140D16C, 0x140D27C, 0x140D2EC, 0x140D424. Widely spaced -
# probably function-pointer fields in a larger struct. Dump a window
# around each occurrence so the struct layout is visible.
for off in [0x140D16C, 0x140D27C, 0x140D2EC, 0x140D424]:
    dumpQwordTable("Region 2 around +0x%X" % off,
                   off & ~7, num_qwords=4, backup=4)

# Region 3: 0x190BFE8, 0x190BFF4, 0x190C00C, 0x190C018.
# Note non-8-byte alignment - dump byte-level view.
for off in [0x190BFE8, 0x190BFF4, 0x190C00C, 0x190C018]:
    dumpQwordTable("Region 3 around +0x%X" % off,
                   off & ~7, num_qwords=3, backup=2)

# ============================================================================
# Find the dispatcher: code that loads the Region 1 table head and indexes
# into it. The table head VA is +0x1113318 (or wherever the first slot is).
# Whatever code computes `vtable + offset` then CALLs is the dispatcher.
log("\n" + "=" * 70)
log("Code refs to Region 1 table head and individual entries")
log("=" * 70)

# Try several candidate table-head addresses (the actual head depends on
# alignment of the first slot in the table)
for cand in [0x1113318, 0x1113320, 0x1113328, 0x1113330, 0x1113338,
             0x1113340, 0x1113348, 0x1113350, 0x1113358, 0x1113360]:
    va = baseVA + cand
    findCodeRefsTo(va)

# Also: the send functions themselves are referenced by the table at fixed
# offsets. Code that calls `tablePtr->methodN()` will load some "tablePtr"
# from a known global - searching for what calls FUN_1406a1de0 indirectly
# requires knowing the dispatcher pattern. As a proxy, dump every callsite
# in the binary that has a CALL [reg+const] where const matches the offset
# of a sign-send slot in Region 1.

# First identify the actual offsets of each send in Region 1:
sign_send_offsets_in_table = {
    "RequestCreateSign":     0x1113320,  # known from refMgr DATA refs
    "RequestRemoveSign":     0x1113338,
    "RequestGetSignList":    0x1113340,
    "RequestSummonSign":     0x1113350,
}

# Find a sensible table head: the qword at +0x1113318 may be a vtable head
# (e.g. dtor); we'll relate the slot offsets from the actual head.
head_candidates = [0x1113318, 0x1113310, 0x1113308, 0x1113300, 0x11132F8, 0x11132F0]
log("\nGuess at table head offsets (from various candidates):")
for head in head_candidates:
    log("  if head = +0x%X:" % head)
    for name, slot_off in sign_send_offsets_in_table.items():
        log("    %-25s = head + 0x%X" % (name, slot_off - head))

log("\n" + "=" * 70)
log("Done.")
log("=" * 70)

with open(OUT_PATH, 'w') as f:
    f.write('\n'.join(results))

print("\nSaved to %s (%d lines)" % (OUT_PATH, len(results)))
