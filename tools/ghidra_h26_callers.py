# -*- coding: utf-8 -*-
# Ghidra Jython: find callers of the sign-protobuf-send wrappers and dump
# their full bodies so the predicate gating the CALL is visible.
#
# Targets (each is a "build + send <SignClass>" helper found in the prior pass):
#   +0x6A1DE0  FUN_1406a1de0  -- RequestCreateSign send (sign placement)
#   +0x6A2040  FUN_1406a2040  -- RequestGetSignList send (sign discovery)
#   +0x6A2610  FUN_1406a2610  -- RequestSummonSign send (summon a placed sign)
#   +0x6A24F0  FUN_1406a24f0  -- RequestRemoveSign send (remove our sign)
#
#@runtime Jython
#
# Output: D:\Applications\DS2\Seamless\tools\ghidra_h26_callers_results.txt

OUT_PATH = r"D:\Applications\DS2\Seamless\tools\ghidra_h26_callers_results.txt"

program = currentProgram
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

TARGETS = [
    ("RequestCreateSign_send",    0x6A1DE0),
    ("RequestGetSignList_send",   0x6A2040),
    ("RequestRemoveSign_send",    0x6A24F0),
    ("RequestSummonSign_send",    0x6A2610),
]

def dumpFunc(fn, max_inst=400):
    if fn is None:
        return
    ep = fn.getEntryPoint()
    body = fn.getBody()
    size = body.getNumAddresses() if body else 0
    log("\n--- %s @ +0x%X (%d bytes) ---" % (fn.getName(), exeOffset(ep), size))
    if size > 8000:
        log("  (size > 8000 bytes; dumping head only)")
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

log("=" * 70)
log("H-26 caller-tree: who invokes the sign send-wrappers?")
log("=" * 70)

caller_offsets = set()

for name, rva in TARGETS:
    tgt_addr = addrFromVA(baseVA + rva)
    log("\n=== %s @ +0x%X ===" % (name, rva))
    refs = list(refMgr.getReferencesTo(tgt_addr))
    log("  refMgr refs: %d" % len(refs))
    for ref in refs[:32]:
        fa = ref.getFromAddress()
        rt = ref.getReferenceType()
        cf = funcMgr.getFunctionContaining(fa)
        cname = cf.getName() if cf else "(no func)"
        cep_off = exeOffset(cf.getEntryPoint()) if cf else None
        cep = ("+0x%X" % cep_off) if cf else "?"
        log("    %s (+0x%X) in %s @ %s [%s]" % (
            fa, exeOffset(fa), cname, cep, rt))
        if cf and (rt.isCall() or rt.isFlow()):
            caller_offsets.add((cep_off, cname))

# Dedup and dump each unique caller body (limit 400 inst — these should be
# relatively small handler functions in the player-action layer)
log("\n" + "=" * 70)
log("Caller bodies (look for the predicate just above the CALL):")
log("=" * 70)

dumped = set()
for cep_off, cname in sorted(caller_offsets):
    if cep_off in dumped:
        continue
    dumped.add(cep_off)
    fn = funcMgr.getFunctionContaining(addrFromVA(baseVA + cep_off))
    if fn is None:
        continue
    dumpFunc(fn, max_inst=400)

log("\n" + "=" * 70)
log("Done.")
log("=" * 70)

with open(OUT_PATH, 'w') as f:
    f.write('\n'.join(results))

print("\nSaved to %s (%d lines)" % (OUT_PATH, len(results)))
