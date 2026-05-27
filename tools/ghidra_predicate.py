# -*- coding: utf-8 -*-
# Ghidra Jython: dump vtable slots 8..15 of the FeSubState classes and
# inspect the predicate function 0x140500580 + its callers.
#
#@runtime Jython
#
# Output: D:\Applications\DS2\Seamless\tools\ghidra_predicate_results.txt

import jarray

OUT_PATH = r"D:\Applications\DS2\Seamless\tools\ghidra_predicate_results.txt"

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

def disassembleFunction(func, max_inst=120):
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

# ============================================================================
log("=" * 70)
log("FeSubState vtable slot 8..15 + predicate inspection")
log("=" * 70)

vtables = [
    (0x10BD198, "FeSubStateTitleSteamNetworkCheck"),
    (0x10BD318, "FeSubStateTitleOnlineCheck"),
    (0x10BD388, "FeSubStateOfflineModeWindow"),
    (0x10BD3F8, "FeSubStateTitleSetOfflineMode"),
    (0x10BD258, "FeSubStateTitleGameServerLogin"),
    (0x10BDE58, "FeSubStateProcessWindowBase"),
]

slot8_funcs = set()

for (vt_off, name) in vtables:
    log("\n--- %s vtable @ +0x%X ---" % (name, vt_off))
    vt = addrFromOffset(vt_off)
    for i in range(0, 20):
        slot = vt.add(i * 8)
        ptr = readUInt64(slot)
        if ptr is None or ptr == 0:
            log("  slot[%2d] = (end / invalid)" % i)
            break
        # Heuristic: function pointers in this binary start with 0x14
        if (ptr >> 32) != 0x1:
            log("  slot[%2d] = 0x%X (probably end of vtable)" % (i, ptr))
            break
        ptr_addr = addrFromOffset(ptr - baseAddr.getOffset())
        fn = funcMgr.getFunctionContaining(ptr_addr)
        fname = fn.getName() if fn else "(no func)"
        fep = ("+0x%X" % exeOffset(fn.getEntryPoint())) if fn else "?"
        log("  slot[%2d] = 0x%X (%s @ %s)" % (i, ptr, fname, fep))
        if i == 8:
            slot8_funcs.add(ptr)

# ============================================================================
log("\n### Disassembly of slot 8 functions (the per-class predicate) ###")
# ============================================================================

for ptr in sorted(slot8_funcs):
    addr = addrFromOffset(ptr - baseAddr.getOffset())
    fn = funcMgr.getFunctionContaining(addr)
    if fn is None:
        log("\n  fn at 0x%X NOT FOUND" % ptr)
        continue
    log("\n  Function at 0x%X (%s @ +0x%X, %d bytes)" % (
        ptr, fn.getName(), exeOffset(fn.getEntryPoint()),
        fn.getBody().getNumAddresses()))
    insts = disassembleFunction(fn, max_inst=80)
    for (a, t) in insts:
        log("    %s (+0x%X) %s" % (a, exeOffset(a), t))

# ============================================================================
log("\n### Predicate 0x140500580 inspection ###")
# ============================================================================

pred_addr = addrFromOffset(0x500580)
pred_fn = getFunctionAt(pred_addr)
if pred_fn is not None:
    log("  Function @ +0x500580, %d bytes" % pred_fn.getBody().getNumAddresses())
    insts = disassembleFunction(pred_fn, max_inst=80)
    for (a, t) in insts:
        log("    %s (+0x%X) %s" % (a, exeOffset(a), t))
else:
    log("  Function at +0x500580 NOT FOUND as function entry")

# Callers
log("\n  Callers of +0x500580:")
xrefs = getXrefs(pred_addr)
log("    total: %d" % len(xrefs))
for ref in xrefs[:30]:
    fa = ref.getFromAddress()
    fn = getFunctionContaining(fa)
    fname = fn.getName() if fn else "(no func)"
    fep = ("+0x%X" % exeOffset(fn.getEntryPoint())) if fn else "?"
    log("    from %s (+0x%X) in %s @ %s [%s]" % (
        fa, exeOffset(fa), fname, fep, ref.getReferenceType()))

# Also inspect 0x140500440 (referenced in OfflineModeWindow slot[3])
log("\n### Predicate 0x140500440 inspection (referenced in OfflineModeWindow update) ###")
pred2_addr = addrFromOffset(0x500440)
pred2_fn = getFunctionAt(pred2_addr)
if pred2_fn is not None:
    log("  Function @ +0x500440, %d bytes" % pred2_fn.getBody().getNumAddresses())
    insts = disassembleFunction(pred2_fn, max_inst=60)
    for (a, t) in insts:
        log("    %s (+0x%X) %s" % (a, exeOffset(a), t))

# ============================================================================
log("\n" + "=" * 70)
log("Done.")
log("=" * 70)

with open(OUT_PATH, 'w') as f:
    f.write('\n'.join(results))

print("\nSaved to %s (%d lines)" % (OUT_PATH, len(results)))
