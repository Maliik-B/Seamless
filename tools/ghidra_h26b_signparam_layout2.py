# -*- coding: utf-8 -*-
# Ghidra Jython: H-26 Plan B task #2 stage 3b -- follow-on dump.
#
# Stage 3a's gaps:
#   - Push_back is called via vtable dispatch, not direct E8 CALL, so the
#     E8 search returned no callers. Vtable-dispatch xrefs require full
#     Ghidra analysis (~30 min) -- deferring that unless this script falls
#     short.
#   - Stage 3a did find the SummonSignSetCtrl ctor's caller: FUN_14020FDB0
#     @ exe+0x20FDB0. Need to see what allocates that ctrl object so we
#     can trace back to the singleton location.
#
# This script: dump bodies of the key helpers we still don't understand.
#   - FUN_14020FDB0 (full, up to 200 inst) -- containing function of
#     SummonSignSetCtrl ctor call
#   - FUN_140212BD0 (called inside TSignSet slot[5] right after count bump
#     -- this is the THOROUGH init for new entries; should write defaults
#     into more fields than the simpler FUN_14020CB20)
#   - FUN_1402044B0 (called inside slot[5] right before the SIMD writes;
#     likely a "merge into SummonSignParam" helper)
#   - FUN_140212990 (called inside SummonSignSetCtrl slot[4] FUN_140212D30;
#     looks like a per-sign key extractor)
#   - FUN_140212bd0 also -- redundancy in case typo above
#   - E8 CALL search for SignManager ctor 0x140210950 (last time we did LEA-
#     RIP -- ctors are typically called via E8 CALL, not LEA-then-deref)
#   - E8 CALL search for SummonSignSetCtrl ctor 0x140212B30 -- already
#     established one caller; just confirm with re-search
#
# Output: D:\Applications\DS2\Seamless\tools\ghidra_h26b_signparam_layout2_results.txt
#
#@runtime Jython

import jarray
import struct

OUT_PATH = r"D:\Applications\DS2\Seamless\tools\ghidra_h26b_signparam_layout2_results.txt"

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

def addrFromOffset(off):
    return baseAddr.add(off)

def addrFromVA(va):
    return baseAddr.add(va - baseVA)

def s8(v):
    return v if v < 128 else v - 256

def readBytes(addr, n):
    try:
        b = jarray.zeros(n, 'b')
        memory.getBytes(addr, b)
        return ''.join(chr(x & 0xff) for x in b)
    except:
        return None

exec_blocks = []
for blk in memory.getBlocks():
    if blk.isInitialized() and blk.isExecute():
        exec_blocks.append(blk)

def findCallSites(target_va, max_hits=4096):
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

def dumpFromAddr(start_va, max_inst, label):
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
    if i == 0:
        log("  (no instruction listing -- raw bytes follow)")
        data = readBytes(fa, 128)
        if data:
            for line_off in range(0, len(data), 16):
                chunk = data[line_off:line_off + 16]
                hexbytes = " ".join("%02x" % (ord(c) & 0xff) for c in chunk)
                log("  %s (+0x%X)  %s" % (
                    fa.add(line_off),
                    (start_va - baseVA) + line_off,
                    hexbytes))

# ============================================================================
log("=" * 78)
log("H-26 Plan B task #2 stage 3b: caller + init-helper bodies")
log("=" * 78)

# (A) Re-search SignManager ctor 0x140210950 via E8 CALL.
log("\n### A. E8 CALL refs to SignManager ctor FUN_140210950 ###")
for v, label in [(0x140210950, "SignManager ctor"),
                 (0x140212B30, "SummonSignSetCtrl ctor"),
                 (0x14020F2A0, "SignSetCommonCtrl ctor (FUN_14020F2A0)"),
                 (0x14020E760, "FUN_14020E760 (validate/register)")]:
    sites = findCallSites(v)
    log("\n  %s @ 0x%X -- %d CALL E8 sites" % (label, v, len(sites)))
    for cs in sites[:25]:
        fn = funcMgr.getFunctionContaining(cs)
        fname = fn.getName() if fn else "(no func)"
        fep = ("+0x%X" % exeOffset(fn.getEntryPoint())) if fn else "?"
        log("    call @ %s (+0x%X) in %s @ %s" % (
            cs, exeOffset(cs), fname, fep))

# (B) Full body dumps of key helpers.
log("\n\n### B. Function bodies ###")

dumpFromAddr(0x14020FDB0, 200,
    "FUN_14020FDB0 (containing SummonSignSetCtrl ctor call)")
dumpFromAddr(0x140212BD0, 100,
    "FUN_140212BD0 (thorough new-entry init, called from slot[5])")
dumpFromAddr(0x1402044B0, 100,
    "FUN_1402044B0 (merge helper, called from slot[5])")
dumpFromAddr(0x140212990, 60,
    "FUN_140212990 (key extractor, called from slot[4] = SummonSignSetCtrl)")
dumpFromAddr(0x140210B70, 80,
    "FUN_140210B70 (called from SignManager dtor / slot[0])")

log("\n" + "=" * 78)
log("Done.")
log("=" * 78)

with open(OUT_PATH, 'w') as f:
    f.write('\n'.join(results))

print("\nSaved to %s (%d lines)" % (OUT_PATH, len(results)))
