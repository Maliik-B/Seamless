# -*- coding: utf-8 -*-
# Ghidra Jython: H-26 Plan B task #2 -- sign-list receive-path hunt.
#
# Companion to ghidra_h26b_signentity_rtti.py. That script searches for
# in-world sign ENTITY classes; this one targets the consumption side of the
# protobuf flow.
#
# Premise: when DS2 normally receives a sign list from FROM's matchmaking
# server, the receive handler does roughly:
#
#     RequestGetSignListResponse resp;            // ctor here, vtable@+0x11136F8
#     resp.ParseFromArray(buf, len);              // (parse vtable slot)
#     for (sign in resp.signs) {                  // walk repeated field
#         in_world_array.push_back(spawn(sign));  // <-- THIS is what we need
#     }
#
# The ctor site (the `lea rax, [rip+vtable]; mov [rcx], rax` pattern) leaks
# the enclosing function's address. That function's body is the receive
# handler. Dumping ~200 instructions of it lets us spot the spawn call.
#
# We target ALL 12 sign-related protobuf vtables from PR #9, not just the
# GetSignListResponse one, because:
#   - CreateSignResponse echoes the placed sign back to the placer with a
#     server-issued sign ID + initial render data; its receive handler is a
#     parallel path that may also feed the in-world array.
#   - SummonSign / SummonSignResponse are the summon-time flows.
# Different vtables == different code paths == more chances to find the
# spawn primitive.
#
# Output: D:\Applications\DS2\Seamless\tools\ghidra_h26b_signarray_results.txt
#
#@runtime Jython

import jarray
import struct

OUT_PATH = r"D:\Applications\DS2\Seamless\tools\ghidra_h26b_signarray_results.txt"

program = currentProgram
listing = program.getListing()
memory = program.getMemory()
funcMgr = program.getFunctionManager()
baseAddr = program.getImageBase()
baseVA = baseAddr.getOffset()

# Protobuf class vtables from PR #9's ghidra_h26_sign_hunt_results.txt.
# Section C reports these as the resolved vtable VAs for each protobuf class.
TARGET_VTABLES = [
    (0x141113768, "RequestSummonSign"),
    (0x1412091A8, "RequestSummonSignResponse"),
    (0x141114388, "RequestSummonMirrorKnightSign"),
    (0x141209B48, "RequestSummonMirrorKnightSignResponse"),
    (0x1411134C8, "RequestRemoveSign"),
    (0x1412090C8, "RequestRemoveSignResponse"),
    (0x141113458, "RequestUpdateSign"),
    (0x141209058, "RequestUpdateSignResponse"),
    (0x141113378, "RequestCreateSign"),
    (0x1411133E8, "RequestCreateSignResponse"),
    (0x141113688, "RequestGetSignList"),
    (0x1411136F8, "RequestGetSignListResponse"),
]

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
log("=" * 72)
log("H-26 Plan B task #2: sign-protobuf RECEIVE-PATH hunt")
log("=" * 72)

# Step 1 -- find LEA-RIP refs to each protobuf vtable.
# Pattern: 48 8D ?5 dd dd dd dd where (modrm & 0xC7) == 0x05 and
# next_inst_addr + disp32 == vtable_VA.
LEA_PREFIX = jarray.array([s8(0x48), s8(0x8d)], 'b')
LEA_MASK   = jarray.array([-1, -1], 'b')

exec_blocks = []
for blk in memory.getBlocks():
    if blk.isInitialized() and blk.isExecute():
        exec_blocks.append(blk)

vt_targets = dict((va, name) for (va, name) in TARGET_VTABLES)
ctor_sites = {}  # vt_va -> list of (instr_addr, func_addr_or_None)

for blk in exec_blocks:
    start = blk.getStart()
    end = blk.getEnd()
    a = memory.findBytes(start, end, LEA_PREFIX, LEA_MASK, True, monitor)
    while a is not None:
        try:
            modrm = memory.getByte(a.add(2)) & 0xff
            if (modrm & 0xC7) == 0x05:
                d_bytes = jarray.zeros(4, 'b')
                memory.getBytes(a.add(3), d_bytes)
                disp = struct.unpack(
                    '<i', ''.join(chr(b & 0xff) for b in d_bytes))[0]
                next_inst = a.getOffset() + 7
                target_va = (next_inst + disp) & 0xffffffffffffffff
                if target_va in vt_targets:
                    fn = funcMgr.getFunctionContaining(a)
                    ctor_sites.setdefault(target_va, []).append((a, fn))
        except:
            pass
        try:
            nxt = a.add(1)
            if nxt.compareTo(end) >= 0:
                break
            a = memory.findBytes(nxt, end, LEA_PREFIX, LEA_MASK, True, monitor)
        except:
            break

# ============================================================================
log("\n### A. Ctor sites per protobuf class ###")
for vt_va, name in TARGET_VTABLES:
    sites = ctor_sites.get(vt_va, [])
    log("\n  %s @ 0x%X -- %d ctor refs" % (name, vt_va, len(sites)))
    for instr, fn in sites:
        fname = fn.getName() if fn else "(no func)"
        fep = ("+0x%X" % exeOffset(fn.getEntryPoint())) if fn else "?"
        log("    ref @ %s (+0x%X) in %s @ %s" % (
            instr, exeOffset(instr), fname, fep))

# ============================================================================
# Step 2 -- dump the bodies of the enclosing functions of the ctor refs.
# We dump the first ~120 instructions of each unique enclosing function.
log("\n### B. Enclosing-function bodies ###")

seen_funcs = set()
for vt_va, name in TARGET_VTABLES:
    sites = ctor_sites.get(vt_va, [])
    for instr, fn in sites:
        if fn is None:
            continue
        fep = fn.getEntryPoint()
        key = fep.getOffset()
        if key in seen_funcs:
            continue
        seen_funcs.add(key)

        log("\n  --- %s @ +0x%X (%s ctor in body) ---" % (
            fn.getName(), exeOffset(fep), name))
        cur = fep
        body = fn.getBody()
        max_iter = 200
        i = 0
        while cur is not None and body.contains(cur) and i < max_iter:
            instr = listing.getInstructionAt(cur)
            if instr is None:
                # No instruction listed (sparse listing under -noanalysis).
                # Try to walk forward by reading raw bytes.
                break
            mnemonic = instr.getMnemonicString()
            ops = []
            for j in range(instr.getNumOperands()):
                ops.append(instr.getDefaultOperandRepresentation(j))
            log("    %s (+0x%X)  %s %s" % (
                cur, exeOffset(cur), mnemonic, ", ".join(ops)))
            cur = instr.getMaxAddress().next()
            i += 1
        if i == 0:
            # Fallback: raw byte dump of first 256 bytes so we still see the
            # function's shape even without analysis.
            log("    (no instruction listing; raw bytes follow)")
            data = readBytes(fep, 256)
            if data:
                for line_off in range(0, len(data), 16):
                    chunk = data[line_off:line_off + 16]
                    hexbytes = " ".join("%02x" % (ord(c) & 0xff) for c in chunk)
                    log("    %s (+0x%X)  %s" % (
                        fep.add(line_off),
                        exeOffset(fep) + line_off,
                        hexbytes))

log("\n" + "=" * 72)
log("Done.")
log("Next: for the GetSignListResponse / CreateSignResponse ctor function,")
log("identify the CALL after parse -- that target is the receive-side sign")
log("spawn primitive (or its dispatcher).")
log("=" * 72)

with open(OUT_PATH, 'w') as f:
    f.write('\n'.join(results))

print("\nSaved to %s (%d lines)" % (OUT_PATH, len(results)))
