# -*- coding: utf-8 -*-
# Ghidra Jython: H-26 Plan B task #2 stage 4 -- post-analysis xref hunt
# for SummonSignParam field offsets.
#
# Run AFTER a full analysis pass (omit -noanalysis when invoking
# analyzeHeadless). With Ghidra's auto-analysis populated, getReferencesTo()
# returns indirect call xrefs that the previous -noanalysis runs couldn't see.
#
# Targets:
#   1. FUN_140213AC0 @ exe+0x213AC0 = TSignSet::push_back_default.
#      Find ALL callers (direct + vtable-dispatch). For each caller, dump
#      ~40 instructions starting at the CALL return point. The fill-in
#      pattern reveals SummonSignParam field offsets:
#         CALL push_back_default
#         MOV [RAX + ???], <something>   <-- this writes a field
#         MOVSS [RAX + ???], XMM0        <-- this writes a float
#         MOV [RAX + ???], RDX           <-- this writes a qword
#
#   2. FUN_140213DD0 @ exe+0x213DD0 = TSignSet vtable slot[5] (copy-spawn).
#      Same treatment -- its callers pass a *prepared* SummonSignParam
#      and the engine copies it in. The pre-call setup reveals what fields
#      the engine populates BEFORE the spawn.
#
#   3. FUN_140212D30 @ exe+0x212D30 = SummonSignSetCtrl slot[4] /
#      SignManager slot[10] (the "find or add" entry). Its callers tell us
#      the high-level "receive a sign" flow.
#
# Output: tools/ghidra_h26b_pushback_callers_results.txt
#
#@runtime Jython

import jarray

OUT_PATH = r"D:\Applications\DS2\Seamless\tools\ghidra_h26b_pushback_callers_results.txt"

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

def dumpRange(start_addr, max_inst, indent="    "):
    cur = start_addr
    fn = funcMgr.getFunctionContaining(cur)
    body = fn.getBody() if fn else None
    i = 0
    while cur is not None and i < max_inst:
        if body is not None and not body.contains(cur):
            break
        instr = listing.getInstructionAt(cur)
        if instr is None:
            break
        mnem = instr.getMnemonicString()
        ops = []
        for j in range(instr.getNumOperands()):
            ops.append(instr.getDefaultOperandRepresentation(j))
        log("%s%s (+0x%X)  %-8s %s" % (
            indent, cur, exeOffset(cur), mnem, ", ".join(ops)))
        cur = instr.getMaxAddress().next()
        i += 1

def dumpCallers(label, va, post_call_inst=40):
    log("")
    log("=" * 78)
    log("%s @ +0x%X" % (label, va - baseVA))
    log("=" * 78)
    targetAddr = addrFromVA(va)
    fn = funcMgr.getFunctionAt(targetAddr)
    if fn is None:
        fn = funcMgr.getFunctionContaining(targetAddr)
        log("WARNING: no function entry at %s (got containing %s)" % (
            targetAddr, fn.getName() if fn else "None"))
    log("target function: %s" % (fn.getName() if fn else "?"))

    # Collect references via the reference manager (post-analysis xrefs).
    refs = refMgr.getReferencesTo(targetAddr)
    callers = []
    for ref in refs:
        rtype = ref.getReferenceType()
        if rtype is None:
            continue
        if rtype.isCall() or rtype.isJump():
            callers.append((ref.getFromAddress(), rtype))

    log("found %d call/jump refs" % len(callers))
    if not callers:
        log("(no callers found -- either analysis didn't populate xrefs, or")
        log(" this function is only reached via vtable dispatch with type info")
        log(" the analyzer couldn't resolve)")
        return

    seen_funcs = set()
    for site, rtype in callers:
        caller_fn = funcMgr.getFunctionContaining(site)
        caller_name = caller_fn.getName() if caller_fn else "(no func)"
        caller_ep = ("+0x%X" % exeOffset(caller_fn.getEntryPoint())) if caller_fn else "?"
        log("")
        log("---- caller @ %s (+0x%X) in %s @ %s [%s] ----" % (
            site, exeOffset(site), caller_name, caller_ep,
            rtype.getName()))

        # Dump the call instruction and the post-call instructions. The
        # post-call writes are what populate the SummonSignParam fields.
        instr = listing.getInstructionAt(site)
        if instr is not None:
            after = instr.getMaxAddress().next()
            log("  pre/at call:")
            dumpRange(site, 3, indent="    ")
            log("  post-call writes:")
            dumpRange(after, post_call_inst, indent="    ")
        else:
            log("  (no instruction at call site)")

log("=" * 78)
log("H-26 Plan B stage 4: SummonSignParam field-offset xref hunt")
log("=" * 78)

dumpCallers("TSignSet::push_back_default (FUN_140213AC0)", 0x140213AC0, post_call_inst=40)
dumpCallers("TSignSet vtable slot[5] copy-spawn (FUN_140213DD0)", 0x140213DD0, post_call_inst=20)
dumpCallers("SummonSignSetCtrl::FindOrAdd (FUN_140212D30)", 0x140212D30, post_call_inst=30)

# Bonus: dump xrefs of TSignSet<SummonSignParam> vtable itself. Any code
# loading this vtable address into a register is constructing a TSignSet
# (which we already knew from Stage 2) -- but the surrounding context might
# reveal additional structure.
log("")
log("=" * 78)
log("LEA-RIP refs to TSignSet<SummonSignParam> vtable @ exe+0x10CB7E8")
log("=" * 78)
vtAddr = addrFromVA(0x1410CB7E8)
vtRefs = refMgr.getReferencesTo(vtAddr)
vtRefList = []
for ref in vtRefs:
    vtRefList.append(ref.getFromAddress())
log("found %d refs" % len(vtRefList))
for site in vtRefList[:20]:
    fn = funcMgr.getFunctionContaining(site)
    fname = fn.getName() if fn else "(no func)"
    fep = ("+0x%X" % exeOffset(fn.getEntryPoint())) if fn else "?"
    log("  ref @ %s (+0x%X) in %s @ %s" % (
        site, exeOffset(site), fname, fep))

log("")
log("=" * 78)
log("Done.")
log("=" * 78)

with open(OUT_PATH, 'w') as f:
    f.write('\n'.join(results))

print("\nSaved to %s (%d lines)" % (OUT_PATH, len(results)))
