# -*- coding: utf-8 -*-
# Ghidra Jython: dump OnlineCheckFailWarn's constructor (+0xFD080) and
# its OnEnter (+0xFD370). Also list ctor callers so we know where in the
# FSM setup OnlineCheckFailWarn is built.
#
#@runtime Jython
#
# Output: D:\Applications\DS2\Seamless\tools\ghidra_failwarn2_results.txt

import jarray

OUT_PATH = r"D:\Applications\DS2\Seamless\tools\ghidra_failwarn2_results.txt"

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

def dumpFunc(off, label, max_inst=150):
    addr = addrFromOffset(off)
    fn = getFunctionAt(addr) or getFunctionContaining(addr)
    log("\n--- %s @ +0x%X ---" % (label, off))
    if fn is None:
        log("  not found")
        return
    log("  body bytes: %d" % fn.getBody().getNumAddresses())
    callers = []
    for ref in refMgr.getReferencesTo(fn.getEntryPoint()):
        if ref.getReferenceType().isCall():
            ca = ref.getFromAddress()
            caller_fn = funcMgr.getFunctionContaining(ca)
            callers.append((ca, caller_fn))
    log("  callers: %d" % len(callers))
    for (ca, cf) in callers[:10]:
        cname = cf.getName() if cf else "(no func)"
        cep = ("+0x%X" % long(exeOffset(cf.getEntryPoint()))) if cf else "?"
        log("    CALL at %s (+0x%X) from %s @ %s" % (
            ca, long(exeOffset(ca)), cname, cep))
    log("  --- disassembly ---")
    insts = disassembleFunction(fn, max_inst=max_inst)
    for (a, t) in insts:
        log("    %s (+0x%X) %s" % (a, long(exeOffset(a)), t))

# ============================================================================
log("=" * 70)
log("FailWarn ctor + OnEnter dumps")
log("=" * 70)

# Constructor
dumpFunc(0xFD080, "OnlineCheckFailWarn::ctor (vtable xrefs from this)", max_inst=80)

# OnEnter (slot 1 override)
dumpFunc(0xFD370, "OnlineCheckFailWarn::OnEnter (slot 1)", max_inst=200)

# slot 0 dtor (for reference)
dumpFunc(0xFD1D0, "OnlineCheckFailWarn::slot[0] (dtor candidate)", max_inst=50)

# slot 11 (called from OnEnter in shared OnEnter pattern — for reference)
dumpFunc(0xFD4C0, "OnlineCheckFailWarn::slot[11]", max_inst=80)

# Where the popup *actually* gets created -- look at OfflineModeWindow's
# OnEnter (+0x104DB0) to compare. It shares slots 2/3/5 with FailWarn.
# We've dumped OfflineModeWindow OnEnter earlier, but let me re-dump for
# direct comparison.
dumpFunc(0x104DB0, "OfflineModeWindow::OnEnter (reference comparison)", max_inst=80)

# ============================================================================
log("\n" + "=" * 70)
log("Done.")
log("=" * 70)

with open(OUT_PATH, 'w') as f:
    f.write('\n'.join(results))

print("\nSaved to %s (%d lines)" % (OUT_PATH, len(results)))
