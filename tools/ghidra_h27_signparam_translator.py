# -*- coding: utf-8 -*-
# Ghidra Jython: H-27 Plan E -- dump the SummonSignParam translator.
#
# Phase 1 telemetry confirmed all 5 organic push_back_default fires came
# from the same caller PC: exe+0x20E563. That's INSIDE the function that
# translates RequestGetSignListResponse entries into SummonSignParam
# in-memory entries. Dumping its full body reveals which offsets are
# written with which fields, finally nailing down the SummonSignParam
# layout that Plan B couldn't get when RPC was dormant.
#
# Output: tools/ghidra_h27_signparam_translator_results.txt
#
#@runtime Jython

import jarray

OUT_PATH = r"D:\Applications\DS2\Seamless\tools\ghidra_h27_signparam_translator_results.txt"

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

def dumpFunction(start_va, max_inst, label):
    log("")
    log("=" * 78)
    log("%s @ +0x%X" % (label, start_va - baseVA))
    log("=" * 78)
    fa = addrFromVA(start_va)
    fn = funcMgr.getFunctionContaining(fa)
    if fn is not None:
        body = fn.getBody()
        log("entry=%s body-min=%s body-max=%s size=0x%X" % (
            fn.getEntryPoint(), body.getMinAddress(),
            body.getMaxAddress(),
            body.getMaxAddress().subtract(body.getMinAddress()) + 1))
        # Dump from function entry, not from the caller PC, so we see the
        # full function shape including the prologue.
        cur = fn.getEntryPoint()
    else:
        cur = fa
        log("(no enclosing function -- dumping from raw address)")
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
        # Mark the caller PC line so we can find it quickly in output.
        marker = ""
        if cur.getOffset() == start_va:
            marker = "  <-- push_back_default caller PC"
        log("  %s (+0x%X)  %-8s %s%s" % (
            cur, exeOffset(cur), mnem, ", ".join(ops), marker))
        cur = instr.getMaxAddress().next()
        i += 1

log("=" * 78)
log("H-27 Plan E -- SummonSignParam translator function dump")
log("Telemetry caller PC: exe+0x20E563 (all 5 push_back_default fires)")
log("=" * 78)

dumpFunction(0x14020E563, 250,
             "Translator function (containing caller PC exe+0x20E563)")

# Also dump the area around 0x20E5xx so we see surrounding helper functions
# (push_back_default's family lives in the same region).
log("")
log("=" * 78)
log("Surrounding helpers in the +0x20E0xx..+0x20EFxx region")
log("=" * 78)

for label, va in [
    ("FUN_~+0x20E000 region", 0x14020E000),
    ("FUN_~+0x20E200 region", 0x14020E200),
    ("FUN_~+0x20E400 region", 0x14020E400),
    ("FUN_~+0x20E500 region", 0x14020E500),
    ("FUN_~+0x20E700 region", 0x14020E700),
]:
    fa = addrFromVA(va)
    fn = funcMgr.getFunctionContaining(fa)
    if fn is None:
        # Try getting function AT that address (start)
        fn = funcMgr.getFunctionAt(fa)
    if fn is None:
        log("  %s: no function" % label)
        continue
    log("  %s: %s @ +0x%X size=0x%X" % (
        label, fn.getName(), exeOffset(fn.getEntryPoint()),
        fn.getBody().getMaxAddress().subtract(fn.getBody().getMinAddress()) + 1))

log("")
log("=" * 78)
log("Done.")
log("=" * 78)

with open(OUT_PATH, 'w') as f:
    f.write('\n'.join(results))

print("\nSaved to %s (%d lines)" % (OUT_PATH, len(results)))
