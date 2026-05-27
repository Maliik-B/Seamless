# -*- coding: utf-8 -*-
# Ghidra Jython: dump the "is_online" accessor candidates identified during
# H-33 reversing. The H-33 OnlineCheck predicate at +0xF98C0 does:
#   MOV RAX, [0x1416148f0]      ; GameManager singleton
#   MOV RBX, [RAX + 0x22f0]     ; serviceMgr ptr
#   MOV RCX, RBX
#   CALL 0x1405132a0            ; get inner-service object
#   MOV RCX, RBX
#   CALL 0x140513600            ; is_online_check(serviceMgr) -> AL
#
# Goal: dump:
#   (a) FUN_140513600  -- the is_online accessor. Find the field it reads.
#   (b) FUN_1405132a0  -- the inner-service resolver. Find the inner offset.
#   (c) FUN_1406a0ed0  -- SignProtocol vtable slot[0] / dtor. Confirm the
#                        class type by looking at COL/RTTI.
#   (d) FUN_1406a1de0  -- RequestCreateSign_send. Re-dump the head to see
#                        what predicate (if any) gates the send before the
#                        protobuf-build sequence. Earlier dump showed bounds
#                        checks but no online check; this re-confirms.
#
# Output: tools/ghidra_h26_online_accessor_results.txt
#
#@runtime Jython

import jarray

OUT_PATH = r"D:\Applications\DS2\Seamless\tools\ghidra_h26_online_accessor_results.txt"

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

def dumpFunc(fn, max_inst=400):
    if fn is None:
        log("  (function not resolved)")
        return
    ep = fn.getEntryPoint()
    body = fn.getBody()
    size = body.getNumAddresses() if body else 0
    log("\n--- %s @ +0x%X (%d bytes) ---" % (fn.getName(), exeOffset(ep), size))
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

def dumpCallers(fn, label="callers"):
    if fn is None:
        return
    refs = list(refMgr.getReferencesTo(fn.getEntryPoint()))
    code_refs = []
    for ref in refs:
        rt = ref.getReferenceType()
        if rt.isCall() or rt.isFlow():
            code_refs.append(ref)
    log("\n  %s: %d (refMgr code/flow refs)" % (label, len(code_refs)))
    for ref in code_refs[:20]:
        fa = ref.getFromAddress()
        rt = ref.getReferenceType()
        cf = funcMgr.getFunctionContaining(fa)
        cname = cf.getName() if cf else "(no func)"
        cep = ("+0x%X" % exeOffset(cf.getEntryPoint())) if cf else "?"
        log("    %s (+0x%X) in %s @ %s [%s]" % (
            fa, exeOffset(fa), cname, cep, rt))

TARGETS = [
    ("is_online_accessor",          0x513600),
    ("inner_service_resolver",      0x5132A0),
    ("SignProtocol_vtable_slot0",   0x6A0ED0),
]

log("=" * 70)
log("H-26 online-accessor + SignProtocol dtor inspection")
log("=" * 70)

# Also: the GameManager singleton is at 0x1416148f0. Dump what fields it
# accesses at the offset we know from H-33 work (+0x22f0).
log("\nKnown landmarks:")
log("  GameManager singleton ptr:  0x1416148F0")
log("  serviceMgr field offset:    +0x22F0 (in GameManager)")
log("  H-33 OnlineCheck predicate: +0xF98C0 (already patched)")

for name, rva in TARGETS:
    log("\n" + "=" * 70)
    log("=== %s @ +0x%X ===" % (name, rva))
    log("=" * 70)
    fn = funcMgr.getFunctionContaining(addrFromVA(baseVA + rva))
    if fn is None:
        # Try as an entry point
        fn = funcMgr.getFunctionAt(addrFromVA(baseVA + rva))
    dumpFunc(fn, max_inst=200)
    dumpCallers(fn)

# Look at FeSubStateOnlineCheck slot[8] predicate at +0xF98C0 (already
# patched but useful for context — verify it matches kOnlineCheckExpected)
log("\n" + "=" * 70)
log("=== OnlineCheck predicate (already H-33-patched) @ +0xF98C0 ===")
log("=" * 70)
fn = funcMgr.getFunctionAt(addrFromVA(baseVA + 0xF98C0))
dumpFunc(fn, max_inst=80)

# Dump start of RequestCreateSign send too just for one-page reference
log("\n" + "=" * 70)
log("=== RequestCreateSign_send @ +0x6A1DE0 (first 30 inst) ===")
log("=" * 70)
fn = funcMgr.getFunctionAt(addrFromVA(baseVA + 0x6A1DE0))
dumpFunc(fn, max_inst=30)

log("\n" + "=" * 70)
log("Done.")
log("=" * 70)

with open(OUT_PATH, 'w') as f:
    f.write('\n'.join(results))

print("\nSaved to %s (%d lines)" % (OUT_PATH, len(results)))
