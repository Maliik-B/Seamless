# -*- coding: utf-8 -*-
# Ghidra Jython: dump the actual sign-add helpers identified from FindOrAdd.
#
# Stage 5 revealed FUN_140212D30 isn't FindOrAdd, it's UpdateExisting -- on
# both find_by_key failures it bails without adding. The real add happens
# inside its mode-0 branch via FUN_140213D30. We've never dumped this.
#
# Also dump:
#   - FUN_140213DD0 in full (slot[5] = push_back_take) -- we only had 80
#     instructions previously and the field writes are deeper
#   - FUN_140501180 / FUN_1405011B0 prologues (the publish-sign-event
#     calls from FindOrAdd's update path)
#
# Output: tools/ghidra_h26b_add_helper_results.txt
#
#@runtime Jython

import jarray

OUT_PATH = r"D:\Applications\DS2\Seamless\tools\ghidra_h26b_add_helper_results.txt"

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

def dumpFunction(va, max_inst, label):
    log("")
    log("=" * 78)
    log("%s @ +0x%X" % (label, va - baseVA))
    log("=" * 78)
    fa = addrFromVA(va)
    fn = funcMgr.getFunctionContaining(fa)
    if fn is not None:
        body = fn.getBody()
        log("entry=%s body-min=%s body-max=%s size=0x%X" % (
            fn.getEntryPoint(), body.getMinAddress(),
            body.getMaxAddress(),
            body.getMaxAddress().subtract(body.getMinAddress()) + 1))
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

log("=" * 78)
log("H-26 Plan B stage 6: add-helper + push_back_take full bodies")
log("=" * 78)

# FUN_140213D30 — the actual "add new sign" helper called from FindOrAdd's
# mode-0 branch (not-found path). We've never seen this one.
dumpFunction(0x140213D30, 200, "Add helper FUN_140213D30 (from FindOrAdd not-found branch)")

# FUN_140213DD0 — TSignSet vtable slot[5] = push_back_take(source). Earlier
# dump was 80 inst; full body is ~218 bytes / ~50 inst, but max it.
dumpFunction(0x140213DD0, 200, "TSignSet push_back_take slot[5] (FUN_140213DD0)")

# FUN_140501180 and FUN_1405011B0 — publish-sign-event helpers called from
# FindOrAdd. First 60 instructions to see arg layout.
dumpFunction(0x140501180, 60, "Publish helper FUN_140501180 (from FindOrAdd mode-0/1)")
dumpFunction(0x1405011B0, 60, "Publish helper FUN_1405011B0 (from FindOrAdd mode-1)")

log("")
log("=" * 78)
log("Done.")
log("=" * 78)

with open(OUT_PATH, 'w') as f:
    f.write('\n'.join(results))

print("\nSaved to %s (%d lines)" % (OUT_PATH, len(results)))
