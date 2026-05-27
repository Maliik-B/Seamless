# -*- coding: utf-8 -*-
# Ghidra Jython: identify FUN_1400fd230 (the second caller of
# OfflineModeWindow::OnEnter), find its vtable owner class, and pick a
# patch site.
#
#@runtime Jython
#
# Output: D:\Applications\DS2\Seamless\tools\ghidra_fd230_results.txt

import jarray

OUT_PATH = r"D:\Applications\DS2\Seamless\tools\ghidra_fd230_results.txt"

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

def getXrefs(address):
    return list(refMgr.getReferencesTo(address))

def getFunctionContaining(address):
    return funcMgr.getFunctionContaining(address)

def getFunctionAt(address):
    return funcMgr.getFunctionAt(address)

def disassembleFunction(func, max_inst=200):
    out = []
    if func is None:
        return out
    body = func.getBody()
    it = listing.getInstructions(body, True)
    count = 0
    while it.hasNext() and count < max_inst:
        inst = it.next()
        out.append((inst.getAddress(), inst.toString()))
        count += 1
    return out

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

# ============================================================================
log("=" * 70)
log("FUN_1400fd230 identification + disassembly")
log("=" * 70)

addr = addrFromOffset(0xFD230)
fn = getFunctionAt(addr) or getFunctionContaining(addr)
if fn is None:
    log("  function NOT FOUND at +0xFD230")
else:
    log("  Entry: %s (+0x%X)" % (fn.getName(), long(exeOffset(fn.getEntryPoint()))))
    log("  Body bytes: %d" % fn.getBody().getNumAddresses())
    callers = []
    for ref in refMgr.getReferencesTo(fn.getEntryPoint()):
        if ref.getReferenceType().isCall():
            ca = ref.getFromAddress()
            cf = funcMgr.getFunctionContaining(ca)
            callers.append((ca, cf))
    log("  callers (CALL refs): %d" % len(callers))
    for (ca, cf) in callers[:10]:
        cname = cf.getName() if cf else "(no func)"
        cep = ("+0x%X" % long(exeOffset(cf.getEntryPoint()))) if cf else "?"
        log("    CALL at %s (+0x%X) from %s @ %s" % (
            ca, long(exeOffset(ca)), cname, cep))
    # Also look for non-call refs (vtable slot pointers)
    all_refs = list(refMgr.getReferencesTo(fn.getEntryPoint()))
    log("  ALL refs (including data/vtable): %d" % len(all_refs))
    for ref in all_refs[:15]:
        fa = ref.getFromAddress()
        rt = ref.getReferenceType()
        log("    from %s (+0x%X) [%s]" % (fa, long(exeOffset(fa)), rt))

    # Disassembly
    log("\n  --- disassembly ---")
    insts = disassembleFunction(fn, max_inst=150)
    for (a, t) in insts:
        log("    %s (+0x%X) %s" % (a, long(exeOffset(a)), t))

# Now: search ALL vtable references to fn (the function as a pointer in a
# vtable). If FUN_1400fd230 is in vtable slot 1 of some FeSubState class,
# we'll find that vtable.
log("\n### Searching for vtables that contain FUN_1400fd230 as a slot ###")

target = 0x1400FD230  # absolute VA
refs = searchUint64(target)
log("  qword refs to 0x%X: %d" % (target, len(refs)))
for r in refs:
    log("    %s (+0x%X)" % (r, long(exeOffset(r))))
    # Check what's nearby — is it a vtable?
    # A vtable's slot 1 (offset +8 from vtable start) means vtable_start = r - 8.
    # Slot 0 of that vtable is at vtable_start (= r - 8).
    # The complete-object-locator (COL) precedes the vtable at vtable_start - 8.

    # Try reading the 16 qwords starting 8 bytes before r (vtable_start)
    vt_start = r.subtract(8)
    log("      candidate vtable start: %s (+0x%X)" % (vt_start, long(exeOffset(vt_start))))
    # Print slot 0 + slot 1 (+8) + a few more
    for i in range(0, 10):
        try:
            b = jarray.zeros(8, 'b')
            memory.getBytes(vt_start.add(i*8), b)
            v = 0
            for j in range(8):
                v |= (b[j] & 0xff) << (j*8)
            if v == 0:
                log("        slot[%d] = 0 (end?)" % i)
                break
            if (v >> 32) != 0x1 and i > 0:
                log("        slot[%d] = 0x%X (non-function?)" % (i, v))
                break
            ptr_addr = addrFromOffset(v - baseAddr.getOffset()) if (v >> 32) == 0x1 else None
            if ptr_addr:
                fn2 = funcMgr.getFunctionContaining(ptr_addr)
                fname = fn2.getName() if fn2 else "(no func)"
                log("        slot[%d] = 0x%X (%s)" % (i, v, fname))
            else:
                log("        slot[%d] = 0x%X (non-funcptr — maybe COL)" % (i, v))
        except:
            break

# ============================================================================
log("\n" + "=" * 70)
log("Done.")
log("=" * 70)

with open(OUT_PATH, 'w') as f:
    f.write('\n'.join(results))

print("\nSaved to %s (%d lines)" % (OUT_PATH, len(results)))
