# -*- coding: utf-8 -*-
# Ghidra Jython: H-26 Plan B task #2 stage 3c -- SignManager singleton hunt.
#
# Stage 3b found:
#   - SignManager ctor (FUN_140210950) called once from FUN_1401BD7F0 at
#     +0x1BDAFF. That call site is the allocation point; the result must be
#     stored somewhere -- a global, a member of another singleton, or inside
#     a service registry.
#
# This dump targets:
#   - FUN_1401BD7F0 around the +0x1BDAFF ctor call: 60 instructions before
#     and 60 after, so we see the alloc + ctor + store-back pattern.
#   - FUN_1401BD7F0 entry (first 30 instructions) so we know what RCX is on
#     entry -- that determines whether SignManager is stored on the call
#     site's "this" or in a separate global.
#
# Output: D:\Applications\DS2\Seamless\tools\ghidra_h26b_signmgr_singleton_results.txt
#
#@runtime Jython

import jarray

OUT_PATH = r"D:\Applications\DS2\Seamless\tools\ghidra_h26b_signmgr_singleton_results.txt"

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

def dumpFrom(start_va, max_inst, label):
    log("")
    log("-" * 76)
    log("%s  (+0x%X)" % (label, start_va - baseVA))
    log("-" * 76)
    fa = addrFromVA(start_va)
    fn = funcMgr.getFunctionContaining(fa)
    if fn is not None:
        body = fn.getBody()
        log("entry=%s body-min=%s body-max=%s name=%s" % (
            fn.getEntryPoint(), body.getMinAddress(),
            body.getMaxAddress(), fn.getName()))
    cur = fa
    i = 0
    while cur is not None and i < max_inst:
        if fn is not None and not fn.getBody().contains(cur):
            break
        instr = listing.getInstructionAt(cur)
        if instr is None:
            break
        mnem = instr.getMnemonicString()
        ops = []
        for j in range(instr.getNumOperands()):
            ops.append(instr.getDefaultOperandRepresentation(j))
        log("  %s (+0x%X)  %-8s %s" % (
            cur, exeOffset(cur), mnem, ", ".join(ops)))
        cur = instr.getMaxAddress().next()
        i += 1

# ============================================================================
log("=" * 78)
log("H-26 Plan B stage 3c: SignManager singleton hunt")
log("=" * 78)

# (A) FUN_1401BD7F0 entry -- first 30 instructions.
dumpFrom(0x1401BD7F0, 30, "FUN_1401BD7F0 entry (function prologue)")

# (B) Around the SignManager ctor call. Call is at +0x1BDAFF. Show 50
# instructions starting 0x40 before the call (covers the alloc) and 30
# instructions starting at the call return point (covers the store-back).
dumpFrom(0x1401BDAC0, 50,
    "FUN_1401BD7F0 around SignManager ctor call (~0x3F bytes before call)")

dumpFrom(0x1401BDB04, 40,
    "FUN_1401BD7F0 after SignManager ctor call (store-back pattern)")

log("\n" + "=" * 78)
log("Done.")
log("=" * 78)

with open(OUT_PATH, 'w') as f:
    f.write('\n'.join(results))

print("\nSaved to %s (%d lines)" % (OUT_PATH, len(results)))
