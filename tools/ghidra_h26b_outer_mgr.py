# -*- coding: utf-8 -*-
# Ghidra Jython: H-26 Plan B task #2 stage 3d -- find outer service-manager
# global that holds SignManager at offset +0x90.
#
# Stage 3c established:
#   - SignManager pointer is stored at `[outer + 0x90]` inside FUN_1401BD7F0
#     at +0x1BDB09.
#   - FUN_1401BD7F0's first arg (RCX -> RDI) is the outer service-manager.
#
# This script:
#   1. Find E8 CALL refs to FUN_1401BD7F0. Each caller passes the outer
#      manager in RCX -- the few instructions before the CALL tell us where
#      the outer manager lives.
#   2. Search the executable for any code that reads `[REG + 0x90]` after
#      loading a known global -- this finds "Get SignManager" helpers. The
#      simplest pattern that loads SignManager would be:
#          MOV RCX, qword ptr [some_global]
#          MOV RAX, qword ptr [RCX + 0x90]
#      The "some_global" is the outer-mgr storage. Check both globals we
#      know about (0x1416148F0 = GameManagerImp from PR #9, and 0x1416751F8
#      from FUN_1401BD7F0's prologue).
#   3. Dump the contents of both globals as qwords (just hex dump 0x20 bytes
#      each to see if they look like pointers).
#
# Output: D:\Applications\DS2\Seamless\tools\ghidra_h26b_outer_mgr_results.txt
#
#@runtime Jython

import jarray
import struct

OUT_PATH = r"D:\Applications\DS2\Seamless\tools\ghidra_h26b_outer_mgr_results.txt"

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

def s8(v):
    return v if v < 128 else v - 256

def readBytes(addr, n):
    try:
        b = jarray.zeros(n, 'b')
        memory.getBytes(addr, b)
        return ''.join(chr(x & 0xff) for x in b)
    except:
        return None

def readU64(addr):
    data = readBytes(addr, 8)
    if data is None:
        return None
    return struct.unpack('<Q', data)[0]

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

def dumpFrom(start_va, max_inst, label):
    log("")
    log("  --- %s  (+0x%X) ---" % (label, start_va - baseVA))
    fa = addrFromVA(start_va)
    fn = funcMgr.getFunctionContaining(fa)
    if fn is not None:
        body = fn.getBody()
        log("  (enclosing %s @ %s..%s)" % (
            fn.getName(), body.getMinAddress(), body.getMaxAddress()))
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
        log("    %s (+0x%X)  %-8s %s" % (
            cur, exeOffset(cur), mnem, ", ".join(ops)))
        cur = instr.getMaxAddress().next()
        i += 1

# ============================================================================
log("=" * 78)
log("H-26 Plan B stage 3d: outer service-manager hunt")
log("=" * 78)

# (A) E8 callers of FUN_1401BD7F0 with pre-call context.
SIGNMGR_INIT_VA = 0x1401BD7F0
log("\n### A. E8 callers of FUN_1401BD7F0 (the outer-mgr method that")
log("    allocates SignManager) ###")
sites = findCallSites(SIGNMGR_INIT_VA)
log("    Found %d callers" % len(sites))
for cs in sites[:20]:
    fn = funcMgr.getFunctionContaining(cs)
    fname = fn.getName() if fn else "(no func)"
    fep = ("+0x%X" % exeOffset(fn.getEntryPoint())) if fn else "?"
    log("")
    log("  call @ %s (+0x%X) in %s @ %s" % (
        cs, exeOffset(cs), fname, fep))
    # Dump ~20 instructions before the call to see RCX setup.
    dumpFrom(cs.getOffset() - 80, 25, "pre-call context")

# (B) Dump qwords at known global pointers.
log("\n\n### B. Known service-mgr globals (qword dumps) ###")
for ga, label in [(0x1416148F0, "GameManagerImp (used by PR #9)"),
                  (0x1416751F8, "ServiceMgr alt (FUN_1401BD7F0 prologue)"),
                  (0x141616CF8, "Inner-service container (PR #9 dispatch)")]:
    log("")
    log("  %s @ 0x%X" % (label, ga))
    a = addrFromVA(ga)
    v = readU64(a)
    log("    qword [0x%X] = 0x%X" % (ga, v if v is not None else 0))

# (C) Search for the byte pattern `48 8B 81 90 00 00 00` and similar -- this
# is `MOV RAX, [RCX + 0x90]`, the get-SignManager getter. There are MANY
# +0x90 dereferences in code, but if any happens immediately after a load
# of `[some_global]` that load tells us where outer_mgr lives.
#
# Pattern for accessing [RCX + 0x90]:
#   48 8B 81 90 00 00 00  ; MOV RAX, [RCX + 0x90]
#   48 8B 89 90 00 00 00  ; MOV RCX, [RCX + 0x90]
# Pattern for accessing [REG + 0x90] generically: 48 8B ?? 90 00 00 00
# We restrict to MOV with modrm in (0x81, 0x89, 0x91, 0x99, 0xA9, 0xB1, 0xB9
# == reg-from indices), but for simplicity scan 48 8B ?? 90 00 00 00 where
# modrm is in 0x80..0xBF (mod=10 dispsize=4).
log("\n\n### C. `MOV reg, [reg + 0x90]` sites near a global-load ###")
log("    (limit: 50 sites; might be noisy)")

MOV_PREFIX = jarray.array([s8(0x48), s8(0x8b)], 'b')
MOV_MASK   = jarray.array([-1, -1], 'b')

ninetyHits = 0
shown = 0
for blk in exec_blocks:
    if shown >= 50:
        break
    start = blk.getStart()
    end = blk.getEnd()
    a = memory.findBytes(start, end, MOV_PREFIX, MOV_MASK, True, monitor)
    while a is not None and shown < 50:
        try:
            modrm = memory.getByte(a.add(2)) & 0xff
            # Want mod=10 (disp32) -- modrm high bits = 10 -> 0x80..0xBF.
            # Also SIB-using forms have modrm.rm=4; ignore those for simplicity.
            if (modrm & 0xC0) == 0x80 and (modrm & 0x07) != 4:
                # Read disp32.
                d_bytes = jarray.zeros(4, 'b')
                memory.getBytes(a.add(3), d_bytes)
                disp = struct.unpack(
                    '<i', ''.join(chr(b & 0xff) for b in d_bytes))[0]
                if disp == 0x90:
                    ninetyHits += 1
                    # Look at the 32 bytes before this instruction to see if
                    # there's a global-load that precedes it.
                    fn = funcMgr.getFunctionContaining(a)
                    fname = fn.getName() if fn else "(no func)"
                    fep = ("+0x%X" % exeOffset(fn.getEntryPoint())) if fn else "?"
                    log("")
                    log("  +0x%X  in %s @ %s" % (
                        exeOffset(a), fname, fep))
                    # Dump 6 instructions BACKWARD (best-effort).
                    dumpFrom(a.getOffset() - 30, 8, "preceding")
                    shown += 1
        except:
            pass
        try:
            nxt = a.add(1)
            if nxt.compareTo(end) >= 0:
                break
            a = memory.findBytes(nxt, end, MOV_PREFIX, MOV_MASK, True, monitor)
        except:
            break

log("\n  Total +0x90 hits across all exec blocks: %d (showed first 50)" % ninetyHits)

log("\n" + "=" * 78)
log("Done.")
log("=" * 78)

with open(OUT_PATH, 'w') as f:
    f.write('\n'.join(results))

print("\nSaved to %s (%d lines)" % (OUT_PATH, len(results)))
