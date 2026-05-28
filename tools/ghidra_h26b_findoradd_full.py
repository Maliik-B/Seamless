# -*- coding: utf-8 -*-
# Ghidra Jython: full body dump of SummonSignSetCtrl::FindOrAdd
# (FUN_140212D30) plus a few related receive-handlers we want to read.
#
# The auto-analysis-driven xref dump didn't surface indirect callers of
# push_back_default, but we don't actually need them: FindOrAdd takes a
# *prepared* SummonSignParam (RDX) from its caller, tries to find an
# existing entry matching the input's key, and on miss adds a new one
# while copying fields from the input. Dumping FindOrAdd in full reveals
# both the key-extraction pattern AND the copy-on-add pattern -- between
# them they tell us nearly the entire SummonSignParam layout.
#
# Also dumps:
#   - FUN_140204B40 (FindOrAdd via callers in earlier output - it's an
#     unrelated guess, kept commented)
#   - FUN_14026E9E0 / FUN_14026EA30 / FUN_140284150 (AbstractNetSvrMy-
#     SignManager methods that probably receive a SignData payload from
#     the network layer and translate it to a SummonSignParam call)
#
# Output: tools/ghidra_h26b_findoradd_full_results.txt
#
#@runtime Jython

import jarray

OUT_PATH = r"D:\Applications\DS2\Seamless\tools\ghidra_h26b_findoradd_full_results.txt"

program = currentProgram
listing = program.getListing()
memory = program.getMemory()
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

def dumpFunction(va, max_inst=400, label=None):
    log("")
    log("=" * 78)
    log("%s @ +0x%X" % (label or "FUN", va - baseVA))
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
log("H-26 Plan B stage 5: FindOrAdd full body + receive-handler bodies")
log("=" * 78)

# FUN_140212D30 = SummonSignSetCtrl::FindOrAdd (the canonical receive entry).
# Full body, ~100 instructions.
dumpFunction(0x140212D30, max_inst=200,
             label="SummonSignSetCtrl::FindOrAdd (FUN_140212D30)")

# FUN_14020E6F0 was identified as TSignSet::find-by-key earlier; included
# again for completeness with full body.
dumpFunction(0x14020E6F0, max_inst=100,
             label="TSignSet::find-by-key (FUN_14020E6F0)")

# AbstractNetSvrMySignManager vtable methods (from PR #9 + Strategy 1).
# These take a SignData/SUMMON_SIGN_ID and route to the sign-set layer.
dumpFunction(0x14026E9E0, max_inst=120,
             label="AbstractNetSvrMySignManager slot[8] (FUN_14026E9E0)")

dumpFunction(0x14026EA30, max_inst=120,
             label="AbstractNetSvrMySignManager slot[9] (FUN_14026EA30)")

dumpFunction(0x140284150, max_inst=120,
             label="AbstractNetSvrMySignManager slot[7] (FUN_140284150)")

# Get xrefs to FindOrAdd. With analysis populated, ALL callers should now
# show up (including any direct or indirect calls).
log("")
log("=" * 78)
log("Xrefs to FindOrAdd (FUN_140212D30) post-analysis")
log("=" * 78)
target = addrFromVA(0x140212D30)
refs = refMgr.getReferencesTo(target)
all_refs = []
for ref in refs:
    all_refs.append((ref.getFromAddress(), ref.getReferenceType()))
log("found %d refs (any type)" % len(all_refs))
for site, rtype in all_refs[:40]:
    fn = funcMgr.getFunctionContaining(site)
    fname = fn.getName() if fn else "(no func)"
    fep = ("+0x%X" % exeOffset(fn.getEntryPoint())) if fn else "?"
    log("  %s ref @ %s (+0x%X) in %s @ %s" % (
        rtype.getName(), site, exeOffset(site), fname, fep))

log("")
log("=" * 78)
log("Done.")
log("=" * 78)

with open(OUT_PATH, 'w') as f:
    f.write('\n'.join(results))

print("\nSaved to %s (%d lines)" % (OUT_PATH, len(results)))
