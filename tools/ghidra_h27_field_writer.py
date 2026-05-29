# -*- coding: utf-8 -*-
# Ghidra Jython: H-27 Plan E -- dump the actual SummonSignParam field-write
# function and the caller chain.
#
# Stage 1: FUN_14020E4E0 was identified as the translator-wrapper that
# bumps the TSignSet via push_back_default and then calls FUN_14020CF00
# at +0x20E5B3 with (new_entry, packed_bitfield_ptr, source_ptr, args).
# Stage 2 (this script): dump FUN_14020CF00 to see the actual field
# writes, plus find callers of FUN_14020E4E0 to map arg meanings to
# protobuf SignData fields.
#
# Output: tools/ghidra_h27_field_writer_results.txt
#
#@runtime Jython

import jarray
import struct

OUT_PATH = r"D:\Applications\DS2\Seamless\tools\ghidra_h27_field_writer_results.txt"

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

def s8(v):
    return v if v < 128 else v - 256

exec_blocks = []
for blk in memory.getBlocks():
    if blk.isInitialized() and blk.isExecute():
        exec_blocks.append(blk)

def findCallSites(target_va, max_hits=64):
    pat = jarray.array([s8(0xE8)], 'b')
    masks = jarray.array([-1], 'b')
    sites = []
    for blk in exec_blocks:
        start = blk.getStart()
        end = blk.getEnd()
        a = memory.findBytes(start, end, pat, masks, True, monitor)
        while a is not None and len(sites) < max_hits:
            try:
                d_bytes = jarray.zeros(4, 'b')
                memory.getBytes(a.add(1), d_bytes)
                disp = struct.unpack(
                    '<i', ''.join(chr(b & 0xff) for b in d_bytes))[0]
                next_inst = a.getOffset() + 5
                tgt = (next_inst + disp) & 0xffffffffffffffff
                if tgt == target_va:
                    sites.append(a)
            except:
                pass
            try:
                nxt = a.add(1)
                if nxt.compareTo(end) >= 0:
                    break
                a = memory.findBytes(nxt, end, pat, masks, True, monitor)
            except:
                break
    return sites

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
        cur = fn.getEntryPoint()
    else:
        cur = fa
        log("(no enclosing function)")
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
log("H-27 Plan E stage 2 -- SummonSignParam field-writer hunt")
log("=" * 78)

dumpFunction(0x14020CF00, 400,
             "FUN_14020CF00 (field-write target, called from translator wrapper)")

log("")
log("=" * 78)
log("E8 CALL refs to FUN_14020CF00 (every translation site)")
log("=" * 78)
sites = findCallSites(0x14020CF00, max_hits=64)
log("found %d callers" % len(sites))
for s in sites:
    fn = funcMgr.getFunctionContaining(s)
    fname = fn.getName() if fn else "(no func)"
    fep = ("+0x%X" % exeOffset(fn.getEntryPoint())) if fn else "?"
    log("  call @ %s (+0x%X) in %s @ %s" % (
        s, exeOffset(s), fname, fep))

log("")
log("=" * 78)
log("E8 CALL refs to FUN_14020E4E0 (wrapper -- shows protobuf caller chain)")
log("=" * 78)
sites = findCallSites(0x14020E4E0, max_hits=64)
log("found %d callers" % len(sites))
for s in sites:
    fn = funcMgr.getFunctionContaining(s)
    fname = fn.getName() if fn else "(no func)"
    fep = ("+0x%X" % exeOffset(fn.getEntryPoint())) if fn else "?"
    log("  call @ %s (+0x%X) in %s @ %s" % (
        s, exeOffset(s), fname, fep))

log("")
log("=" * 78)
log("Done.")
log("=" * 78)

with open(OUT_PATH, 'w') as f:
    f.write('\n'.join(results))

print("\nSaved to %s (%d lines)" % (OUT_PATH, len(results)))
