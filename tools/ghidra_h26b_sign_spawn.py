# -*- coding: utf-8 -*-
# Ghidra Jython: task #1 cleanup + task #2 entry hunt.
#
# Task #1 (done): identified FUN_1401a8f70 @ exe+0x1A8F70 as the soapstone-
# use dispatcher. Soapstone path calls FUN_14024F350 with EDX = soapstone
# index (0 = white, 1 = small-white, ...). This script:
#
#   A. Dump all 6 rows of the soapstone enumeration table at +0x10C3D70
#      cleanly. First-pass output only showed 5 of 6 rows; we want the
#      complete ID list so the task-#3 hook knows exactly which inputs to
#      route to mod-side spawn.
#
#   B. Dump FUN_14024F350 in full + the surrounding methods in the
#      0x24F3xx region (they appear to be members of the same class --
#      0x24F300, 0x24F320, 0x24F350, 0x24F3C0, 0x24F410, 0x24F420). The
#      goal is to find DS2's internal sign-spawn primitive that
#      FUN_14024F350 either IS or calls into.
#
#   C. Also dump direct callers of FUN_1401a8f70 (the dispatcher we
#      identified in task #1), so the right intercept layer is clear --
#      maybe the cleaner hook target is one of its callers rather than
#      FUN_14024F350.
#
#@runtime Jython
#
# Output: D:\Applications\DS2\Seamless\tools\ghidra_h26b_sign_spawn_results.txt

import jarray

OUT_PATH = r"D:\Applications\DS2\Seamless\tools\ghidra_h26b_sign_spawn_results.txt"

program = currentProgram
memory = program.getMemory()
listing = program.getListing()
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

def readBytes(addr, count):
    try:
        b = jarray.zeros(count, 'b')
        memory.getBytes(addr, b)
        return [(x & 0xff) for x in b]
    except:
        return None

def readU32(addr):
    bs = readBytes(addr, 4)
    if bs is None: return None
    v = 0
    for i in range(4):
        v |= bs[i] << (i*8)
    return v

def dumpFuncFull(fn, max_inst=300):
    if fn is None:
        log("  (no function)")
        return
    ep = fn.getEntryPoint()
    body = fn.getBody()
    size = body.getNumAddresses() if body else 0
    log("\n--- %s @ +0x%X (%d bytes) ---" %
        (fn.getName(), exeOffset(ep), size))
    it = listing.getInstructions(ep, True)
    count = 0
    while it.hasNext() and count < max_inst:
        inst = it.next()
        if not body.contains(inst.getAddress()):
            break
        log("  %s (+0x%X)  %s" % (inst.getAddress(),
                                   exeOffset(inst.getAddress()),
                                   inst.toString()))
        count += 1

def dumpCallers(fn, label):
    if fn is None: return
    refs = list(refMgr.getReferencesTo(fn.getEntryPoint()))
    code_refs = [r for r in refs
                 if r.getReferenceType().isCall() or r.getReferenceType().isFlow()]
    log("\n  %s callers (code-flow refs): %d" % (label, len(code_refs)))
    for ref in code_refs[:24]:
        fa = ref.getFromAddress()
        rt = ref.getReferenceType()
        cf = funcMgr.getFunctionContaining(fa)
        cname = cf.getName() if cf else "(no func)"
        cep = ("+0x%X" % exeOffset(cf.getEntryPoint())) if cf else "?"
        log("    from %s (+0x%X) in %s @ %s [%s]" %
            (fa, exeOffset(fa), cname, cep, rt))

# ============================================================================
log("=" * 70)
log("H-26 Plan B: full soapstone table + task #2 entry hunt")
log("=" * 70)

# ----------------------------------------------------------------------------
# A. Full 6-row soapstone table dump
# ----------------------------------------------------------------------------
log("\n### A. Soapstone enumeration table @ +0x10C3D70 ###")
log("    layout: each row = uint32 item_id + uint32 index, 8 bytes total")

KNOWN_NAMES = {
    0x03B280B0: "WhiteSignSoapstone",
    0x03B2A7C0: "SmallWhiteSignSoapstone",
}

for row in range(6):
    row_addr = addrFromVA(baseVA + 0x10C3D70 + row * 8)
    item_id = readU32(row_addr)
    idx = readU32(row_addr.add(4))
    if item_id is None or idx is None:
        log("  row %d @ %s: unreadable" % (row, row_addr))
        continue
    name = KNOWN_NAMES.get(item_id, "(unknown soapstone)")
    log("  row %d  +0x%X  itemId=0x%08X  idx=%d  %s" %
        (row, exeOffset(row_addr), item_id, idx, name))

# Also a few bytes after the table end to see if there's a sentinel or
# adjacent struct worth noting
log("\n  bytes immediately after table end (+0x10C3DA0):")
log_bs = readBytes(addrFromVA(baseVA + 0x10C3DA0), 32)
if log_bs is not None:
    for i in range(0, len(log_bs), 8):
        chunk = log_bs[i:i+8]
        log("    +0x%X  %s" % (
            0x10C3DA0 + i, " ".join("%02X" % b for b in chunk)))

# ----------------------------------------------------------------------------
# B. Task #2 entry: FUN_14024F350 + neighbors
# ----------------------------------------------------------------------------
log("\n\n### B. FUN_14024F350 -- soapstone-by-index dispatch ###")

METHOD_TARGETS = [
    ("Method @ +0x24F300", 0x24F300),
    ("Method @ +0x24F320", 0x24F320),
    ("Method @ +0x24F350 (soapstone-by-index dispatch -- task #2 entry)", 0x24F350),
    ("Method @ +0x24F3C0", 0x24F3C0),
    ("Method @ +0x24F410", 0x24F410),
    ("Method @ +0x24F420", 0x24F420),
]

for label, rva in METHOD_TARGETS:
    log("\n  -- %s --" % label)
    fn = funcMgr.getFunctionAt(addrFromVA(baseVA + rva))
    if fn is None:
        fn = funcMgr.getFunctionContaining(addrFromVA(baseVA + rva))
    dumpFuncFull(fn, max_inst=250)

# ----------------------------------------------------------------------------
# C. Callers of FUN_1401a8f70 (the soapstone-use dispatcher).
# ----------------------------------------------------------------------------
log("\n\n### C. Callers of FUN_1401a8f70 (the dispatcher itself) ###")

disp_fn = funcMgr.getFunctionAt(addrFromVA(baseVA + 0x1A8F70))
if disp_fn is None:
    disp_fn = funcMgr.getFunctionContaining(addrFromVA(baseVA + 0x1A8F70))
dumpCallers(disp_fn, "FUN_1401a8f70")

# Also: dump the heads of any unique caller functions so we can pick the
# best hook layer.
log("\n  Caller function heads (first ~40 inst):")
seen_caller_offsets = set()
if disp_fn:
    for ref in refMgr.getReferencesTo(disp_fn.getEntryPoint()):
        rt = ref.getReferenceType()
        if not (rt.isCall() or rt.isFlow()):
            continue
        cf = funcMgr.getFunctionContaining(ref.getFromAddress())
        if cf is None: continue
        off = exeOffset(cf.getEntryPoint())
        if off in seen_caller_offsets: continue
        seen_caller_offsets.add(off)
        dumpFuncFull(cf, max_inst=40)

log("\n" + "=" * 70)
log("Done.")
log("=" * 70)

with open(OUT_PATH, 'w') as f:
    f.write('\n'.join(results))

print("\nSaved to %s (%d lines)" % (OUT_PATH, len(results)))
