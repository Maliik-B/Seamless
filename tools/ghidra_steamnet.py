# -*- coding: utf-8 -*-
# Ghidra Jython: dump SteamNetworkCheck's OnEnter + Update, plus 0x1404fe2a0
# (the function called in OfflineModeWindow's "<0" path) and 0x1404fe760
# (called in shared OnEnter's failure path).
#
#@runtime Jython
#
# Output: D:\Applications\DS2\Seamless\tools\ghidra_steamnet_results.txt

import jarray

OUT_PATH = r"D:\Applications\DS2\Seamless\tools\ghidra_steamnet_results.txt"

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

def dumpFunc(off, label, max_inst=120):
    addr = addrFromOffset(off)
    fn = getFunctionAt(addr)
    log("\n--- %s @ +0x%X ---" % (label, off))
    if fn is None:
        fn = getFunctionContaining(addr)
        if fn is None:
            log("  not found")
            return
        log("  (containing function: %s @ +0x%X)" % (
            fn.getName(), exeOffset(fn.getEntryPoint())))
    log("  body bytes: %d" % fn.getBody().getNumAddresses())
    log("  callers:")
    for (ca, caller_fn) in [(r.getFromAddress(),
                              funcMgr.getFunctionContaining(r.getFromAddress()))
                             for r in refMgr.getReferencesTo(fn.getEntryPoint())
                             if r.getReferenceType().isCall()][:10]:
        cname = caller_fn.getName() if caller_fn else "(no func)"
        cep = ("+0x%X" % exeOffset(caller_fn.getEntryPoint())) if caller_fn else "?"
        log("    CALL at %s (+0x%X) from %s @ %s" % (
            ca, exeOffset(ca), cname, cep))
    log("  --- disassembly ---")
    insts = disassembleFunction(fn, max_inst=max_inst)
    for (a, t) in insts:
        log("    %s (+0x%X) %s" % (a, exeOffset(a), t))

# ============================================================================
log("=" * 70)
log("Drill #4: SteamNetworkCheck OnEnter/Update + popup-suspect helpers")
log("=" * 70)

# SteamNetworkCheck vtable @ +0x10BD198
# slot[1] = +0xF8FB0  (custom OnEnter)
# slot[3] = +0xF8990  (custom Update)
dumpFunc(0xF8FB0, "SteamNetworkCheck::slot[1] OnEnter")
dumpFunc(0xF8990, "SteamNetworkCheck::slot[3] Update")

# 0x1404fe2a0 — called from OfflineModeWindow's slot[1] (.lt_zero path)
dumpFunc(0x4FE2A0, "FUN_1404fe2a0 (called from OfflineModeWindow lt_zero)")

# 0x1404fe760 — called from shared OnEnter's failure path
dumpFunc(0x4FE760, "FUN_1404fe760 (called from shared OnEnter failure)")

# Also dump GameServerLogin's slot[8] (the success-path successor of OnlineCheck)
# to confirm it's different from OnlineCheck's
dumpFunc(0xF9820, "GameServerLogin::slot[8]")

# Also UserPolicy's slot[8] -- since UserPolicy also runs in the boot chain
# Look at its vtable
log("\n--- UserPolicy vtable @ +0x10BD2C8 ---")
vt = addrFromOffset(0x10BD2C8)
import struct
for i in range(8, 14):
    slot = vt.add(i * 8)
    try:
        b = jarray.zeros(8, 'b')
        memory.getBytes(slot, b)
        v = 0
        for j in range(8):
            v |= (b[j] & 0xff) << (j * 8)
        if (v >> 32) != 0x1:
            log("  slot[%d] = 0x%X (end / invalid)" % (i, v))
            break
        ptr_addr = addrFromOffset(v - baseAddr.getOffset())
        fn = funcMgr.getFunctionContaining(ptr_addr)
        fname = fn.getName() if fn else "(no func)"
        log("  slot[%d] = 0x%X (%s)" % (i, v, fname))
    except:
        break

# ============================================================================
log("\n" + "=" * 70)
log("Done.")
log("=" * 70)

with open(OUT_PATH, 'w') as f:
    f.write('\n'.join(results))

print("\nSaved to %s (%d lines)" % (OUT_PATH, len(results)))
