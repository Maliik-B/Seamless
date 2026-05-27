# -*- coding: utf-8 -*-
# Ghidra Jython: find the state-machine setup / driver for the title-screen
# FeSubState classes. Plus inspect the shared base-class methods to see
# what virtual interface DS2 exposes for these states.
#
#@runtime Jython
#
# Output: D:\Applications\DS2\Seamless\tools\ghidra_fesm_driver_results.txt

import jarray

OUT_PATH = r"D:\Applications\DS2\Seamless\tools\ghidra_fesm_driver_results.txt"

program = currentProgram
listing = program.getListing()
memory = program.getMemory()
refMgr = program.getReferenceManager()
funcMgr = program.getFunctionManager()
baseAddr = program.getImageBase()

results = []

def log(msg):
    results.append(str(msg))
    print(msg)

def exeOffset(addr):
    return addr.subtract(baseAddr)

def addrFromOffset(off):
    return baseAddr.add(off)

def getXrefs(address):
    return list(refMgr.getReferencesTo(address))

def getFunctionContaining(address):
    return funcMgr.getFunctionContaining(address)

def getFunctionAt(address):
    return funcMgr.getFunctionAt(address)

def getCallers(func):
    out = []
    if func is None:
        return out
    entry = func.getEntryPoint()
    for ref in refMgr.getReferencesTo(entry):
        if ref.getReferenceType().isCall():
            caller = funcMgr.getFunctionContaining(ref.getFromAddress())
            out.append((ref.getFromAddress(), caller))
    return out

def disassembleFunction(func, max_inst=300):
    out = []
    if func is None:
        return out
    body = func.getBody()
    it = listing.getInstructions(body, True)
    count = 0
    while it.hasNext() and count < max_inst:
        inst = it.next()
        out.append((inst.getAddress(), inst.toString()))
        count += 1
    return out

# ============================================================================
log("=" * 70)
log("FeSubState state-machine driver hunt")
log("=" * 70)

# (constructor_offset, class_name)
constructors = [
    (0xF8C50, "FeSubStateTitleSteamNetworkCheck"),
    (0xF8B70, "FeSubStateTitleOnlineCheck"),
    (0xF8AF0, "FeSubStateOfflineModeWindow"),
    (0xF8C30, "FeSubStateTitleSetOfflineMode"),
    (0xF8B20, "FeSubStateTitleGameServerLogin"),
    (0xF8C70, "FeSubStateTitleUserPolicy"),
]

caller_to_classes = {}

for (ctor_off, cls_name) in constructors:
    ctor_addr = addrFromOffset(ctor_off)
    fn = getFunctionAt(ctor_addr)
    log("\n%s (ctor @ +0x%X)" % (cls_name, ctor_off))
    if fn is None:
        log("  ctor function NOT FOUND")
        continue
    callers = getCallers(fn)
    log("  callers: %d" % len(callers))
    for (ca, caller_fn) in callers[:10]:
        cname = caller_fn.getName() if caller_fn else "(no func)"
        cep_off = exeOffset(caller_fn.getEntryPoint()) if caller_fn else None
        cep = "+0x%X" % cep_off if cep_off is not None else "?"
        log("    CALL at %s (+0x%X) from %s @ %s" % (
            ca, exeOffset(ca), cname, cep))
        if caller_fn is not None:
            key = caller_fn.getEntryPoint().getOffset()
            caller_to_classes.setdefault(key, []).append(cls_name)

# ============================================================================
log("\n### Common callers (functions that construct multiple FeSubStates) ###")
# ============================================================================

sorted_callers = sorted(caller_to_classes.items(), key=lambda x: -len(x[1]))
for (addr_val, cls_list) in sorted_callers:
    if len(cls_list) >= 2:
        addr = baseAddr.add(addr_val - baseAddr.getOffset())
        log("\n  caller @ %s (+0x%X): constructs %d classes" % (
            addr, exeOffset(addr), len(cls_list)))
        for c in cls_list:
            log("    - %s" % c)

# ============================================================================
log("\n### Disassembly of top common caller ###")
# ============================================================================

if sorted_callers:
    (top_addr_val, top_classes) = sorted_callers[0]
    top_fn = funcMgr.getFunctionAt(baseAddr.add(top_addr_val - baseAddr.getOffset()))
    if top_fn is not None and len(top_classes) >= 2:
        log("\n  Top caller is %s, %d bytes" % (
            top_fn.getName(), top_fn.getBody().getNumAddresses()))
        log("  Full disassembly:")
        insts = disassembleFunction(top_fn, max_inst=600)
        for (a, t) in insts:
            log("    %s (+0x%X) %s" % (a, exeOffset(a), t))

# ============================================================================
log("\n### Shared vtable functions ###")
# ============================================================================

# These appear in many state vtables -- they are likely base-class virtual
# methods that derived states inherit unchanged. Knowing what they do tells
# us the virtual interface.
shared_funcs = [
    (0xF89A0, "shared slot[4]"),     # every state has it
    (0x1043A0, "shared slot[6]"),    # every state has it
    (0xF72C0, "shared slot[7]"),     # every state has it
    (0x104ED0, "shared slot[1] (in OnlineCheck/GameServerLogin/Base)"),
    (0x105110, "shared slot[2] (in OnlineCheck/GameServerLogin/Base)"),
    (0x105270, "shared slot[3] (in OnlineCheck/GameServerLogin/Base)"),
    (0x105090, "shared slot[5] (in OnlineCheck/GameServerLogin/Base)"),
]

for (off, label) in shared_funcs:
    addr = addrFromOffset(off)
    fn = getFunctionAt(addr)
    log("\n  %s @ +0x%X" % (label, off))
    if fn is None:
        log("    function NOT FOUND")
        continue
    log("    body bytes: %d" % fn.getBody().getNumAddresses())
    # Print first 20 instructions
    insts = disassembleFunction(fn, max_inst=20)
    for (a, t) in insts:
        log("    %s (+0x%X) %s" % (a, exeOffset(a), t))

# ============================================================================
log("\n### OfflineModeWindow-specific vtable functions (override candidates) ###")
# ============================================================================

# These appear only in FeSubStateOfflineModeWindow's vtable, NOT in
# FeSubStateProcessWindowBase. They are the OfflineModeWindow-specific
# overrides -- one of which is probably Update() that drives the popup
# rendering / transitions.
offline_specific = [
    (0xF8DA0, "OfflineModeWindow slot[0] (likely scalar deleting dtor)"),
    (0x104DB0, "OfflineModeWindow slot[1] override"),
    (0x1050A0, "OfflineModeWindow slot[2] override"),
    (0x105150, "OfflineModeWindow slot[3] override"),
    (0x104F30, "OfflineModeWindow slot[5] override"),
]

for (off, label) in offline_specific:
    addr = addrFromOffset(off)
    fn = getFunctionAt(addr)
    log("\n  %s @ +0x%X" % (label, off))
    if fn is None:
        log("    function NOT FOUND")
        continue
    log("    body bytes: %d" % fn.getBody().getNumAddresses())
    insts = disassembleFunction(fn, max_inst=30)
    for (a, t) in insts:
        log("    %s (+0x%X) %s" % (a, exeOffset(a), t))

# ============================================================================
log("\n" + "=" * 70)
log("Done.")
log("=" * 70)

with open(OUT_PATH, 'w') as f:
    f.write('\n'.join(results))

print("\nSaved to %s (%d lines)" % (OUT_PATH, len(results)))
