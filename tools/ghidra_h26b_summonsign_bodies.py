# -*- coding: utf-8 -*-
# Ghidra Jython: H-26 Plan B task #2 stage 2 -- function-body dump.
#
# Strategy 1's RTTI hunt converged on the sign-controller class hierarchy:
#
#   - SummonSignSetCtrl      vtable @ exe+0x10CB698 (concrete)
#   - SummonSignSetCtrl      vtable @ exe+0x10CB6E8 (interface base)
#   - TSignSet<SummonSignParam> vtable @ exe+0x10CB7E8 (the in-world list)
#   - SignManager            vtable @ exe+0x10CB668 (top-level manager)
#   - SignSetCommonCtrl      vtable @ exe+0x10CB458 (sibling, shared logic)
#
# What we still need: the function that ADDS a SummonSignParam to the in-
# world list. That's the spawn-sign primitive Plan B will call.
#
# This script disassembles ~80 instructions per candidate so we can read the
# function shapes and pick the Add/Insert/Register primitive.
#
# Output: D:\Applications\DS2\Seamless\tools\ghidra_h26b_summonsign_bodies_results.txt
#
#@runtime Jython

import jarray

OUT_PATH = r"D:\Applications\DS2\Seamless\tools\ghidra_h26b_summonsign_bodies_results.txt"

program = currentProgram
listing = program.getListing()
memory = program.getMemory()
funcMgr = program.getFunctionManager()
baseAddr = program.getImageBase()
baseVA = baseAddr.getOffset()

# Functions to dump, grouped. Tuples: (label, exe_offset).
# These are picked from the Strategy 1 results:
#   - section C vtable slots
#   - section D ctor sites
GROUPS = [
    ("SummonSignSetCtrl vtable @ +0x10CB698 slots", [
        ("slot[0]  FUN_140212CD0", 0x212CD0),
        ("slot[1]  FUN_140213960", 0x213960),
        ("slot[2]  thunk_FUN_14020f4b0 @ +0x213450", 0x213450),
        ("slot[3]  FUN_1402139D0", 0x2139D0),
        ("slot[4]  FUN_140212D30", 0x212D30),
        ("slot[5]  FUN_1402133F0", 0x2133F0),
        ("slot[6]  FUN_1402139A0", 0x2139A0),
        ("slot[7]  FUN_140213C80", 0x213C80),
        ("slot[8]  FUN_140213950", 0x213950),
        ("slot[10] FUN_140212C64 (odd alignment, possibly mid-func)", 0x212C64),
    ]),
    ("SummonSignSetCtrl ctor candidates", [
        ("ctor  FUN_140212B30", 0x212B30),
    ]),
    ("TSignSet<SummonSignParam> vtable @ +0x10CB7E8 slots", [
        ("slot[0]  FUN_140212C70", 0x212C70),
        ("slot[1]  FUN_140213B20", 0x213B20),
        ("slot[2]  FUN_140213D10", 0x213D10),
        ("slot[3]  FUN_140213D20", 0x213D20),
        ("slot[4]  FUN_140213AC0", 0x213AC0),
        ("slot[5]  FUN_140213DD0", 0x213DD0),
        ("slot[6]  FUN_140213B80", 0x213B80),
    ]),
    ("TSignSet<SummonSignParam> ctor candidate (non-slot)", [
        ("ctor  FUN_140212AC0", 0x212AC0),
    ]),
    ("SignManager vtable @ +0x10CB668 unique slots", [
        ("slot[0]  FUN_140210990 (probable dtor)", 0x210990),
        ("slot[6]  FUN_140212CD0 (same as SummonSignSetCtrl slot[0])", 0x212CD0),
        ("slot[7]  FUN_140213960", 0x213960),
        ("slot[8]  thunk_FUN_14020f4b0 @ +0x213450", 0x213450),
        ("slot[9]  FUN_1402139D0", 0x2139D0),
        ("slot[10] FUN_140212D30", 0x212D30),
    ]),
    ("SignManager ctor", [
        ("ctor  FUN_140210950", 0x210950),
    ]),
    ("Possibly-relevant ActiveSignManager methods", [
        ("ActiveSignMgr ctor  FUN_1402096a0", 0x2096A0),
        ("ActiveSignMgr vtable slot[0] / shared FUN_140209AE0", 0x209AE0),
        ("ActiveSignMgr slot[3] FUN_14020C2B0", 0x20C2B0),
    ]),
    ("SignSetCommonCtrl shared ops (parent class)", [
        ("FUN_14020F2F0 (vtable slot[0])", 0x20F2F0),
        ("FUN_14020F540 (slot[1])", 0x20F540),
        ("FUN_14020F4B0 (slot[2], shared with SummonSignSetCtrl[2] thunk)", 0x20F4B0),
        ("FUN_14020F5D0 (slot[3])", 0x20F5D0),
    ]),
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

def addrFromOffset(off):
    return baseAddr.add(off)

def readBytes(addr, n):
    try:
        b = jarray.zeros(n, 'b')
        memory.getBytes(addr, b)
        return ''.join(chr(x & 0xff) for x in b)
    except:
        return None

def dumpFunc(label, off, max_inst=80):
    log("")
    log("=" * 78)
    log("%s  (+0x%X)" % (label, off))
    log("=" * 78)
    fa = addrFromOffset(off)
    fn = funcMgr.getFunctionContaining(fa)
    if fn is None:
        log("(no function declared at this address)")
        # Raw byte fallback so we still see the prologue.
        data = readBytes(fa, 128)
        if data:
            for line_off in range(0, len(data), 16):
                chunk = data[line_off:line_off + 16]
                hexbytes = " ".join("%02x" % (ord(c) & 0xff) for c in chunk)
                log("  %s (+0x%X)  %s" % (
                    fa.add(line_off), off + line_off, hexbytes))
        return
    body = fn.getBody()
    log("entry=%s body-min=%s body-max=%s name=%s" % (
        fn.getEntryPoint(), body.getMinAddress(), body.getMaxAddress(),
        fn.getName()))
    cur = fa
    i = 0
    while cur is not None and body.contains(cur) and i < max_inst:
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
        # Raw byte fallback.
        log("  (no instruction listing under -noanalysis; raw bytes follow)")
        data = readBytes(fa, 128)
        if data:
            for line_off in range(0, len(data), 16):
                chunk = data[line_off:line_off + 16]
                hexbytes = " ".join("%02x" % (ord(c) & 0xff) for c in chunk)
                log("  %s (+0x%X)  %s" % (
                    fa.add(line_off), off + line_off, hexbytes))


log("=" * 78)
log("H-26 Plan B task #2 stage 2: SummonSignSetCtrl / TSignSet body dump")
log("=" * 78)

for group_label, items in GROUPS:
    log("")
    log("#" * 78)
    log("# %s" % group_label)
    log("#" * 78)
    for label, off in items:
        dumpFunc(label, off, max_inst=80)

with open(OUT_PATH, 'w') as f:
    f.write('\n'.join(results))

print("\nSaved to %s (%d lines)" % (OUT_PATH, len(results)))
