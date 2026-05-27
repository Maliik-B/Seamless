# -*- coding: utf-8 -*-
# Ghidra Jython: H-26 Plan B task #2 stage 3 -- SummonSignParam offsets
# and SummonSignSetCtrl singleton location.
#
# Stage 2 established:
#   - FUN_140213AC0 @ exe+0x213AC0 = TSignSet<SummonSignParam>::push_back()
#     which returns a fresh SummonSignParam* (sizeof = 0x88).
#   - SummonSignSetCtrl owns two TSignSets at [ctrl+0x18] and [ctrl+0x20].
#   - SignManager ctor is FUN_140210950 @ exe+0x210950.
#
# Open questions before the C++ wrapper at src/features/sign_sync.cpp:
#   (A) Where in the 0x88-byte SummonSignParam are position, rotation,
#       sign_type, owner_id, name? Callers of push_back will write those
#       fields immediately after the call.
#   (B) Where does the SignManager (and therefore SummonSignSetCtrl) live
#       at runtime? LEA-RIP refs to the SignManager ctor reveal the
#       allocation site; tracing the store reveals the global.
#
# Strategy:
#   1. Find all callers of FUN_140213AC0 (push_back_default). For each, dump
#      the ~30 instructions following the CALL -- those instructions are
#      writes to the returned SummonSignParam, which tells us the layout.
#   2. Find LEA-RIP refs to FUN_140210950 (SignManager ctor). Each ctor call
#      site reveals where the allocated SignManager pointer ends up stored.
#   3. Find data-section qword refs to FUN_140210950 (in case it's stored
#      directly in a service-manager vtable rather than newed on the heap).
#   4. Find any global storage of SummonSignSetCtrl ctor (FUN_140212B30 /
#      FUN_140212CD0) -- the singleton may live more directly than via
#      SignManager.
#
# Output: D:\Applications\DS2\Seamless\tools\ghidra_h26b_signparam_layout_results.txt
#
#@runtime Jython

import jarray
import struct

OUT_PATH = r"D:\Applications\DS2\Seamless\tools\ghidra_h26b_signparam_layout_results.txt"

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

def readU64(addr):
    try:
        b = jarray.zeros(8, 'b')
        memory.getBytes(addr, b)
        v = 0
        for i in range(8):
            v |= (b[i] & 0xff) << (i*8)
        return v
    except:
        return None

def readBytes(addr, n):
    try:
        b = jarray.zeros(n, 'b')
        memory.getBytes(addr, b)
        return ''.join(chr(x & 0xff) for x in b)
    except:
        return None

# ============================================================================
# Pre-collect executable + initialized data blocks.
exec_blocks = []
data_blocks = []
for blk in memory.getBlocks():
    if not blk.isInitialized():
        continue
    if blk.isExecute():
        exec_blocks.append(blk)
    else:
        data_blocks.append(blk)

# ============================================================================
# Find CALL sites of a target absolute address.
#   Encoding: E8 dd dd dd dd  (5 bytes, rel32 signed)
#   target = next_inst_addr + disp32
# Optionally also relative JMP (E9 ...) -- but for our use case CALL is enough.
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

# Find LEA-RIP refs in code: 48 8D ?5 dd dd dd dd
def findLeaRipRefs(target_va, max_hits=4096):
    pat = jarray.array([s8(0x48), s8(0x8d)], 'b')
    masks = jarray.array([-1, -1], 'b')
    sites = []
    for blk in exec_blocks:
        start = blk.getStart()
        end = blk.getEnd()
        a = memory.findBytes(start, end, pat, masks, True, monitor)
        while a is not None and len(sites) < max_hits:
            try:
                modrm = memory.getByte(a.add(2)) & 0xff
                if (modrm & 0xC7) == 0x05:
                    d_bytes = jarray.zeros(4, 'b')
                    memory.getBytes(a.add(3), d_bytes)
                    disp = struct.unpack(
                        '<i', ''.join(chr(b & 0xff) for b in d_bytes))[0]
                    next_inst = a.getOffset() + 7
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

# Find qword refs to a VA in INITIALIZED but non-executable memory.
def findQwordRefsInData(va, max_hits=128):
    pat_bytes = [(va >> (i*8)) & 0xff for i in range(8)]
    pat = jarray.array([s8(b) for b in pat_bytes], 'b')
    masks = jarray.array([-1] * 8, 'b')
    hits = []
    for blk in data_blocks:
        start = blk.getStart()
        end = blk.getEnd()
        a = memory.findBytes(start, end, pat, masks, True, monitor)
        while a is not None and len(hits) < max_hits:
            hits.append(a)
            try:
                nxt = a.add(1)
                if nxt.compareTo(end) >= 0:
                    break
                a = memory.findBytes(nxt, end, pat, masks, True, monitor)
            except:
                break
    return hits

def dumpRange(start_addr, max_inst, label):
    log("    %s  start=%s" % (label, start_addr))
    cur = start_addr
    fn = funcMgr.getFunctionContaining(cur)
    if fn is None:
        log("      (no containing function)")
        data = readBytes(cur, 96)
        if data:
            for line_off in range(0, len(data), 16):
                chunk = data[line_off:line_off + 16]
                hexbytes = " ".join("%02x" % (ord(c) & 0xff) for c in chunk)
                log("      %s (+0x%X)  %s" % (
                    cur.add(line_off),
                    exeOffset(cur) + line_off,
                    hexbytes))
        return
    body = fn.getBody()
    i = 0
    while cur is not None and body.contains(cur) and i < max_inst:
        instr = listing.getInstructionAt(cur)
        if instr is None:
            break
        mnem = instr.getMnemonicString()
        ops = []
        for j in range(instr.getNumOperands()):
            ops.append(instr.getDefaultOperandRepresentation(j))
        log("      %s (+0x%X)  %-8s %s" % (
            cur, exeOffset(cur), mnem, ", ".join(ops)))
        cur = instr.getMaxAddress().next()
        i += 1

# ============================================================================
log("=" * 78)
log("H-26 Plan B task #2 stage 3: param layout + ctrl singleton")
log("=" * 78)

# ----------------------------------------------------------------------------
# (A) Find callers of FUN_140213AC0 (TSignSet push_back_default).
PUSHBACK_VA = 0x140213AC0
log("\n### A. Callers of FUN_140213AC0 = TSignSet push_back_default ###")
log("    target VA: 0x%X" % PUSHBACK_VA)
call_sites = findCallSites(PUSHBACK_VA)
log("    Found %d CALL E8 sites" % len(call_sites))
for cs in call_sites:
    fn = funcMgr.getFunctionContaining(cs)
    fname = fn.getName() if fn else "(no func)"
    fep = ("+0x%X" % exeOffset(fn.getEntryPoint())) if fn else "?"
    log("")
    log("  call @ %s (+0x%X) in %s @ %s" % (
        cs, exeOffset(cs), fname, fep))
    # Dump ~25 instructions starting from the address immediately after the CALL.
    # That's where the caller fills in the returned SummonSignParam.
    after = cs.add(5)
    dumpRange(after, max_inst=30, label="post-CALL writes")

# ----------------------------------------------------------------------------
# (B) Find LEA-RIP refs to FUN_140210950 (SignManager ctor).
SIGNMGR_CTOR_VA = 0x140210950
log("\n\n### B. Code refs to SignManager ctor FUN_140210950 (LEA-RIP) ###")
log("    target VA: 0x%X" % SIGNMGR_CTOR_VA)
ctor_refs = findLeaRipRefs(SIGNMGR_CTOR_VA)
log("    Found %d LEA-RIP refs" % len(ctor_refs))
for r in ctor_refs:
    fn = funcMgr.getFunctionContaining(r)
    fname = fn.getName() if fn else "(no func)"
    fep = ("+0x%X" % exeOffset(fn.getEntryPoint())) if fn else "?"
    log("")
    log("  LEA ref @ %s (+0x%X) in %s @ %s" % (
        r, exeOffset(r), fname, fep))
    dumpRange(r, max_inst=20, label="LEA context")

# ----------------------------------------------------------------------------
# (C) Find LEA-RIP code refs to SummonSignSetCtrl ctor FUN_140212B30.
# These ctor invocations reveal where the SummonSignSetCtrl object lives
# (often: allocated inside SignManager + offset, or as a member of a
# bigger context).
SUMMON_CTOR_VA = 0x140212B30
log("\n\n### C. Code refs to SummonSignSetCtrl ctor FUN_140212B30 (CALL E8) ###")
log("    target VA: 0x%X" % SUMMON_CTOR_VA)
sctor_calls = findCallSites(SUMMON_CTOR_VA)
log("    Found %d CALL sites" % len(sctor_calls))
for cs in sctor_calls:
    fn = funcMgr.getFunctionContaining(cs)
    fname = fn.getName() if fn else "(no func)"
    fep = ("+0x%X" % exeOffset(fn.getEntryPoint())) if fn else "?"
    log("")
    log("  call @ %s (+0x%X) in %s @ %s" % (
        cs, exeOffset(cs), fname, fep))
    # Dump ~20 instructions BEFORE the call to see how RCX (this) was set up.
    # That tells us where the ctrl object lives.
    pre = cs.add(-60)
    dumpRange(pre, max_inst=15, label="pre-CALL (RCX setup for ctor)")

# ----------------------------------------------------------------------------
# (D) qword data refs to SignManager vtable (1410CB668). These are typically
# in the ctor itself (writes to this->vptr) but might also be in static
# class-info tables or service-manager registries.
SIGNMGR_VTABLE_VA = 0x1410CB668
log("\n\n### D. qword refs to SignManager vtable 0x1410CB668 ###")
qref = findQwordRefsInData(SIGNMGR_VTABLE_VA)
log("    Found %d qword refs in DATA sections" % len(qref))
for r in qref:
    log("  qword @ %s (+0x%X)" % (r, exeOffset(r)))

# ----------------------------------------------------------------------------
# (E) Look at FUN_14020E6F0 -- the FindSign helper. Its first arg is a
# TSignSet*; its return is SummonSignParam*. Dumping its body will tell us
# how to iterate the set + what the key field is in SummonSignParam.
FIND_VA = 0x14020E6F0
log("\n\n### E. FUN_14020E6F0 (TSignSet::find by key) ###")
fa = addrFromVA(FIND_VA)
dumpRange(fa, max_inst=40, label="FUN_14020E6F0")

# ----------------------------------------------------------------------------
# (F) FUN_14020CB20 -- default-construct SummonSignParam. Called by
# push_back_default. Dumping its body shows what the default-init does:
# which fields it touches and to what values. That tells us a few offsets
# even without caller analysis.
INIT_VA = 0x14020CB20
log("\n\n### F. FUN_14020CB20 (SummonSignParam default-init) ###")
fa = addrFromVA(INIT_VA)
dumpRange(fa, max_inst=40, label="FUN_14020CB20")

log("\n" + "=" * 78)
log("Done.")
log("=" * 78)

with open(OUT_PATH, 'w') as f:
    f.write('\n'.join(results))

print("\nSaved to %s (%d lines)" % (OUT_PATH, len(results)))
