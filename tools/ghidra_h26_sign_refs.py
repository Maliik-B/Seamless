# -*- coding: utf-8 -*-
# Ghidra Jython: H-26 part 2 — find code that constructs RequestSummonSign et al.
#
# Section D of the previous script (qword scan) returned nothing because x64
# vtable assignment uses LEA RIP-relative, not a 64-bit immediate. But the
# Ghidra project IS already analyzed (the FESM driver run picked up call refs
# successfully via refMgr.getReferencesTo). So we just need to query
# refMgr.getReferencesTo(vtable_addr) and (vtable+8 -> slot0_addr) directly.
#
# For RequestSummonSign in particular, the constructor that loads the vtable
# is the closest landmark to "code path that builds a sign-place request".
# We dump that function's first ~150 instructions so the predicate sitting
# just above the CALL to the ctor is visible.
#
#@runtime Jython
#
# Output: D:\Applications\DS2\Seamless\tools\ghidra_h26_sign_refs_results.txt

OUT_PATH = r"D:\Applications\DS2\Seamless\tools\ghidra_h26_sign_refs_results.txt"

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

# All sign-related vtables we discovered in the previous pass (sign_hunt_results.txt).
VTABLES = [
    ("RequestSummonSign",                 0x1113768),
    ("RequestSummonSignResponse",         0x12091A8),
    ("RequestSummonMirrorKnightSign",     0x1114388),
    ("RequestSummonMirrorKnightSignResp", 0x1209B48),
    ("RequestRemoveSign",                 0x11134C8),
    ("RequestRemoveSignResponse",         0x12090C8),
    ("RequestUpdateSign",                 0x1113458),
    ("RequestUpdateSignResponse",         0x1209058),
    ("RequestCreateSign",                 0x1113378),
    ("RequestCreateSignResponse",         0x11133E8),
    ("RequestGetSignList",                0x1113688),
    ("RequestGetSignListResponse",        0x11136F8),
]

# ============================================================================
log("=" * 70)
log("H-26 sign-class ref scan")
log("=" * 70)

# Direct refs to each vtable address.
constructor_caller_offsets = set()

for name, rva in VTABLES:
    vt_addr = addrFromVA(baseVA + rva)
    log("\n=== %s vtable @ +0x%X ===" % (name, rva))

    refs = list(refMgr.getReferencesTo(vt_addr))
    log("  refMgr refs to vtable: %d" % len(refs))
    for ref in refs[:24]:
        fa = ref.getFromAddress()
        rt = ref.getReferenceType()
        cf = funcMgr.getFunctionContaining(fa)
        cname = cf.getName() if cf else "(no func)"
        cep_off = exeOffset(cf.getEntryPoint()) if cf else None
        cep = ("+0x%X" % cep_off) if cf else "?"
        log("    %s (+0x%X) in %s @ %s [%s]" % (
            fa, exeOffset(fa), cname, cep, rt))
        if cf:
            constructor_caller_offsets.add(cep_off)

# ============================================================================
# Also: slot[0] of each vtable is the scalar dtor. CALLs to it from a
# function-prologue or a function-epilogue location reveal destruction sites.
log("\n" + "=" * 70)
log("Slot[0] (scalar-dtor) refs — destruction sites (less interesting but")
log("sometimes adjacent to construction sites in the same function)")
log("=" * 70)

for name, rva in VTABLES:
    vt_addr = addrFromVA(baseVA + rva)
    try:
        slot0_va = 0
        b = bytearray(8)
        from java.lang import Long
        for i in range(8):
            slot0_va |= (program.getMemory().getByte(vt_addr.add(i)) & 0xff) << (i*8)
    except:
        continue
    if slot0_va == 0:
        continue
    slot0_addr = addrFromVA(slot0_va)
    log("\n%s slot[0] @ 0x%X" % (name, slot0_va))
    refs = list(refMgr.getReferencesTo(slot0_addr))
    log("  refMgr refs to slot[0]: %d" % len(refs))
    for ref in refs[:12]:
        fa = ref.getFromAddress()
        rt = ref.getReferenceType()
        cf = funcMgr.getFunctionContaining(fa)
        cname = cf.getName() if cf else "(no func)"
        cep = ("+0x%X" % exeOffset(cf.getEntryPoint())) if cf else "?"
        log("    %s (+0x%X) in %s @ %s [%s]" % (
            fa, exeOffset(fa), cname, cep, rt))

# ============================================================================
# Dump the head of each unique constructor-caller function. Limit ~150 inst.
log("\n" + "=" * 70)
log("Disassembly head of each constructor-caller function (first ~150 inst)")
log("Look for: CALL <ctor>, with the predicate just above it.")
log("=" * 70)

def dumpFuncHead(fn, max_inst=150):
    if fn is None:
        return
    ep = fn.getEntryPoint()
    body = fn.getBody()
    size = body.getNumAddresses() if body else 0
    log("\n--- %s @ +0x%X (%d bytes) ---" % (fn.getName(), exeOffset(ep), size))
    if size > 4000:
        log("  (skipped — function too large; dumping first %d inst only)" % max_inst)
    it = listing.getInstructions(ep, True)
    count = 0
    while it.hasNext() and count < max_inst:
        inst = it.next()
        # Stop if we crossed out of this function
        if not body.contains(inst.getAddress()):
            break
        log("  %s (+0x%X)  %s" % (inst.getAddress(),
                                   exeOffset(inst.getAddress()),
                                   inst.toString()))
        count += 1

for off in sorted(constructor_caller_offsets):
    fn = funcMgr.getFunctionContaining(addrFromVA(baseVA + off))
    if fn is None:
        continue
    dumpFuncHead(fn, max_inst=150)

log("\n" + "=" * 70)
log("Done.")
log("=" * 70)

with open(OUT_PATH, 'w') as f:
    f.write('\n'.join(results))

print("\nSaved to %s (%d lines)" % (OUT_PATH, len(results)))
