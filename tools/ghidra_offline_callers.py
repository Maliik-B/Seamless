# -*- coding: utf-8 -*-
# Ghidra Jython: find EVERY reference (CALL, JMP, data, indirect) to
# FeSubStateOfflineModeWindow::OnEnter at exe+0x104DB0. Try-6 patched both
# known direct callers but the framerate popup persists, so there's a third
# path -- likely a polymorphic vtable dispatch where another FeSubState
# instance has OnEnter at +0x104DB0 in its slot[1] (inheritance / sharing).
#
#@runtime Jython
#
# Output: D:\Applications\DS2\Seamless\tools\ghidra_offline_callers_results.txt

import jarray

OUT_PATH = r"D:\Applications\DS2\Seamless\tools\ghidra_offline_callers_results.txt"

program = currentProgram
listing = program.getListing()
memory = program.getMemory()
refMgr = program.getReferenceManager()
funcMgr = program.getFunctionManager()
baseAddr = program.getImageBase()

results = []

def log(msg):
    results.append(str(msg))
    print(msg)

def exeOffset(addr):
    return addr.subtract(baseAddr)

def addrFromOffset(off):
    return baseAddr.add(off)

def s8(v):
    return v if v < 128 else v - 256

def searchUint64(target):
    pat = jarray.array([s8((target >> (i*8)) & 0xff) for i in range(8)], 'b')
    masks = jarray.array([-1]*8, 'b')
    found = []
    for block in memory.getBlocks():
        if not block.isInitialized():
            continue
        start = block.getStart()
        end = block.getEnd()
        a = memory.findBytes(start, end, pat, masks, True, monitor)
        while a is not None:
            found.append(a)
            try:
                nxt = a.add(1)
                if nxt.compareTo(end) >= 0:
                    break
                a = memory.findBytes(nxt, end, pat, masks, True, monitor)
            except:
                break
    return found

def readUInt64(addr):
    try:
        b = jarray.zeros(8, 'b')
        memory.getBytes(addr, b)
        v = 0
        for i in range(8):
            v |= (b[i] & 0xff) << (i * 8)
        return v
    except:
        return None

target_addr = addrFromOffset(0x104DB0)
target_va = target_addr.getOffset()

# ============================================================================
log("=" * 70)
log("Exhaustive xref scan for OfflineModeWindow::OnEnter @ +0x104DB0")
log("Target VA: 0x%X" % target_va)
log("=" * 70)

# A. Ghidra's known reference manager
log("\n### A. refMgr.getReferencesTo (Ghidra's analysis-time refs) ###")
refs = list(refMgr.getReferencesTo(target_addr))
log("  total: %d" % len(refs))
for ref in refs:
    fa = ref.getFromAddress()
    rt = ref.getReferenceType()
    fn = funcMgr.getFunctionContaining(fa)
    fname = fn.getName() if fn else "(no func)"
    fep = ("+0x%X" % long(exeOffset(fn.getEntryPoint()))) if fn else "?"
    log("    from %s (+0x%X) in %s @ %s [%s]" % (
        fa, long(exeOffset(fa)), fname, fep, rt))

# B. Raw 8-byte LE pattern scan: every place in the binary where the VA
# appears as a qword. This catches vtable slots, function pointers,
# anywhere the address is stored.
log("\n### B. Raw qword scan for 0x%X (vtable slots, fn pointers) ###" % target_va)
qword_refs = searchUint64(target_va)
log("  total qword occurrences: %d" % len(qword_refs))
for r in qword_refs:
    off = long(exeOffset(r))
    # If this is a vtable slot 1 (offset +8 from a vtable start), look at
    # the vtable's slot 0 and see if it's a known dtor pattern.
    log("    %s (+0x%X)" % (r, off))
    # Check if this looks like vtable slot 1: try reading the preceding
    # qword and see if it's a function pointer
    prev = readUInt64(r.subtract(8))
    if prev is not None and (prev >> 32) == 0x1:
        slot0_addr = addrFromOffset(prev - baseAddr.getOffset())
        fn0 = funcMgr.getFunctionContaining(slot0_addr)
        f0name = fn0.getName() if fn0 else "(no func)"
        log("      preceded by slot[0] = 0x%X (%s) -- looks like vtable slot 1" % (
            prev, f0name))
        # Walk forward: slot[2..9]
        for i in range(2, 12):
            ptr = readUInt64(r.add((i-1) * 8))
            if ptr is None or ptr == 0:
                break
            if (ptr >> 32) != 0x1:
                log("      slot[%d] = 0x%X (data?)" % (i, ptr))
                break
            pa = addrFromOffset(ptr - baseAddr.getOffset())
            fn = funcMgr.getFunctionContaining(pa)
            fname = fn.getName() if fn else "(no func)"
            log("      slot[%d] = 0x%X (%s)" % (i, ptr, fname))
        # Also check what COL precedes this vtable (vtable-8 holds COL ptr)
        col_ptr = readUInt64(r.subtract(0x10))
        if col_ptr is not None:
            log("      COL ptr (at vtable-0x10) = 0x%X" % col_ptr)

# C. Also dump ANY 4-byte RVA-style refs (rip-relative) -- common in CALL/LEA
log("\n### C. 32-bit rel addresses near suspect instructions ###")
log("  (Detecting CALL rel32 / LEA rel32 to +0x104DB0 by scanning .text)")
# For each CALL near rel32 that resolves to +0x104DB0, find the source.
# A CALL rel32 is 5 bytes: E8 xx xx xx xx where xx is signed offset from
# the byte after the instruction.
# Iterate over instructions instead of bytes for accuracy.
text_blocks = [b for b in memory.getBlocks() if b.isExecute() and b.isInitialized()]
found_calls = 0
for block in text_blocks:
    it = listing.getInstructions(block.getAddressRange(), True)
    while it.hasNext():
        inst = it.next()
        if inst.getMnemonicString().startswith("CALL"):
            for r in inst.getReferencesFrom():
                if r.getToAddress() and r.getToAddress().equals(target_addr):
                    found_calls += 1
                    fa = inst.getAddress()
                    fn = funcMgr.getFunctionContaining(fa)
                    fname = fn.getName() if fn else "(no func)"
                    fep = ("+0x%X" % long(exeOffset(fn.getEntryPoint()))) if fn else "?"
                    log("    CALL at %s (+0x%X) in %s @ %s -> %s" % (
                        fa, long(exeOffset(fa)), fname, fep, inst.toString()))
                    break
log("  total CALLs found by full disasm scan: %d" % found_calls)

# ============================================================================
log("\n" + "=" * 70)
log("Done.")
log("=" * 70)

with open(OUT_PATH, 'w') as f:
    f.write('\n'.join(results))

print("\nSaved to %s (%d lines)" % (OUT_PATH, len(results)))
