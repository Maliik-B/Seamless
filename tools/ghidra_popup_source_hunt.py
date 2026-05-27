# -*- coding: utf-8 -*-
# Ghidra Jython: identify the actual source of the "framerate" popup that
# persists after try-8 (OnlineCheck + SteamNetCheck + GameServerLogin all
# shortcut to success). Hypothesis: popup is fired by UserPolicy's own
# OnEnter (+0xF9040) OR by an FPS-guard at FUN_140C2CD00 (the function
# fps_hunt found using the 1/120.0 constant).
#
# Also dumps the three sibling vtables that share +0x104DB0 OnEnter, to
# name the polymorphic culprits if it turns out the popup goes through
# OfflineModeWindow's path via another class.
#
# @runtime Jython
#
# Output: D:\Applications\DS2\Seamless\tools\ghidra_popup_source_hunt_results.txt

import jarray

OUT_PATH = r"D:\Applications\DS2\Seamless\tools\ghidra_popup_source_hunt_results.txt"

program  = currentProgram
listing  = program.getListing()
memory   = program.getMemory()
refMgr   = program.getReferenceManager()
funcMgr  = program.getFunctionManager()
symTab   = program.getSymbolTable()
baseAddr = program.getImageBase()

results = []
# Write incrementally so a crash in one section doesn't lose the others.
_out_file = open(OUT_PATH, 'w')

def log(msg):
    line = str(msg)
    results.append(line)
    print(line)
    try:
        _out_file.write(line + '\n')
        _out_file.flush()
    except:
        pass

def section(label):
    log("\n" + "=" * 70)
    log(label)
    log("=" * 70)

def exeOffset(addr):
    return addr.subtract(baseAddr)

def addrFromOffset(off):
    return baseAddr.add(off)

def getFunctionAt(addr):
    return funcMgr.getFunctionAt(addr)

def getFunctionContaining(addr):
    return funcMgr.getFunctionContaining(addr)

def readQword(addr):
    b = jarray.zeros(8, 'b')
    memory.getBytes(addr, b)
    v = 0
    for j in range(8):
        v |= (b[j] & 0xff) << (j * 8)
    return v

def dumpFunc(off, label, max_inst=200):
    addr = addrFromOffset(off)
    fn = getFunctionAt(addr)
    log("\n--- %s @ +0x%X ---" % (label, off))
    if fn is None:
        fn = getFunctionContaining(addr)
        if fn is None:
            log("  not found")
            return None
        log("  (containing function: %s @ +0x%X)" % (
            fn.getName(), exeOffset(fn.getEntryPoint())))
    log("  body bytes: %d" % fn.getBody().getNumAddresses())
    all_callers = [r for r in refMgr.getReferencesTo(fn.getEntryPoint())
                   if r.getReferenceType().isCall()]
    log("  total callers: %d" % len(all_callers))
    log("  callers (first 8):")
    callers = [(r.getFromAddress(),
                funcMgr.getFunctionContaining(r.getFromAddress()))
               for r in all_callers][:8]
    for (ca, caller_fn) in callers:
        cname = caller_fn.getName() if caller_fn else "(no func)"
        cep = ("+0x%X" % exeOffset(caller_fn.getEntryPoint())) if caller_fn else "?"
        log("    CALL at %s (+0x%X) from %s @ %s" % (
            ca, exeOffset(ca), cname, cep))
    log("  --- disassembly ---")
    body = fn.getBody()
    it = listing.getInstructions(body, True)
    count = 0
    while it.hasNext() and count < max_inst:
        inst = it.next()
        log("    %s (+0x%X) %s" % (inst.getAddress(),
                                    exeOffset(inst.getAddress()),
                                    inst.toString()))
        count += 1
    return fn

# ---------------------------------------------------------------------------
log("=" * 70)
log("Popup source hunt (post-try-8 — framerate popup still firing)")
log("=" * 70)

# ===========================================================================
# 1) UserPolicy's own OnEnter (vtable slot[1] = +0xF9040, NOT shared +0x104ED0)
# ===========================================================================
log("\n### A) UserPolicy::slot[1] OnEnter ###")
dumpFunc(0xF9040, "UserPolicy::OnEnter (slot[1])", max_inst=160)

# Also its slot[2]/slot[3]/slot[5] (Tick/Update/Exit equivalents)
log("\n### A.1) UserPolicy other slots ###")
dumpFunc(0xF96B0, "UserPolicy::slot[2]", max_inst=80)
dumpFunc(0xF96F0, "UserPolicy::slot[3]", max_inst=80)
dumpFunc(0xF9510, "UserPolicy::slot[5]", max_inst=80)

# ===========================================================================
# 2) FPS-guard candidate FUN_140C2CD00 (uses 1/120.0)
# ===========================================================================
log("\n### B) FPS-guard candidate FUN_140C2CD00 ###")
dumpFunc(0xC2CD00, "FPS-guard candidate", max_inst=300)

# Caller chain — who calls FUN_140C2CD00?
fps_addr = addrFromOffset(0xC2CD00)
fps_fn = getFunctionAt(fps_addr)
if fps_fn:
    all_call = [r for r in refMgr.getReferencesTo(fps_fn.getEntryPoint())
                if r.getReferenceType().isCall()]
    log("\n  FPS-guard candidate total callers: %d (showing first 5)" % len(all_call))
    for r in all_call[:5]:
        ca = r.getFromAddress()
        caller_fn = getFunctionContaining(ca)
        cname = caller_fn.getName() if caller_fn else "(no func)"
        cep = ("+0x%X" % exeOffset(caller_fn.getEntryPoint())) if caller_fn else "?"
        log("    CALL at %s (+0x%X) from %s @ %s" % (ca, exeOffset(ca), cname, cep))

# ===========================================================================
# 3) Three sibling vtables sharing +0x104DB0 OnEnter — name them via RTTI
# ===========================================================================
log("\n### C) Three sibling vtables that share OfflineModeWindow's +0x104DB0 ###")
# vtable layouts to inspect: +0x10BD000, +0x10BD6D0, +0x10BDDF0
# COL (CompleteObjectLocator) sits in the slot at vtable - 8.
# The COL contains TypeDescriptor offset which has the RTTI mangled class name.

def rttiNameForVtable(vtable_off):
    """Try to extract RTTI class name for a vtable at given exe offset."""
    try:
        vt = addrFromOffset(vtable_off)
        # COL pointer is at vtable[-1] (8 bytes before vtable[0])
        col_ptr_addr = vt.add(-8)
        col_ptr = readQword(col_ptr_addr)
        if col_ptr == 0:
            return None, None
        # COL is at col_ptr (absolute); fields:
        #   +0x00 = signature
        #   +0x04 = offset
        #   +0x08 = cdOffset
        #   +0x0C = pTypeDescriptor (RVA)
        #   +0x10 = pClassDescriptor (RVA)
        col_addr = baseAddr.add(col_ptr - baseAddr.getOffset())
        b = jarray.zeros(0x14, 'b')
        memory.getBytes(col_addr, b)
        # pTypeDescriptor at offset 0x0C is an RVA
        td_rva = 0
        for j in range(4):
            td_rva |= (b[0x0C + j] & 0xff) << (j * 8)
        td_addr = baseAddr.add(td_rva)
        # TypeDescriptor: +0 vftable, +8 spare, +0x10 name (null-terminated)
        name_addr = td_addr.add(0x10)
        # Read the name
        chars = []
        for i in range(200):
            cb = jarray.zeros(1, 'b')
            memory.getBytes(name_addr.add(i), cb)
            c = cb[0] & 0xff
            if c == 0:
                break
            chars.append(chr(c))
        return (col_addr, ''.join(chars))
    except Exception as e:
        return (None, "ERR: " + str(e))

for vt_off in (0x10BD000, 0x10BD6D0, 0x10BDDF0):
    log("\n  --- vtable @ +0x%X ---" % vt_off)
    try:
        col, name = rttiNameForVtable(vt_off)
        if col:
            log("    COL @ %s" % col)
        log("    RTTI name: %s" % name)
    except Exception as e:
        log("    RTTI lookup failed: %s" % e)
    # Also dump first 8 slots
    vt = addrFromOffset(vt_off)
    for i in range(0, 8):
        try:
            slot_addr = vt.add(i * 8)
            v = readQword(slot_addr)
            if (v >> 40) != 0x14:  # ptrs look like 0x140xxxxxx in this image
                log("    slot[%d] = 0x%X (likely terminator/data)" % (i, v))
                break
            fn = getFunctionContaining(addrFromOffset(v - baseAddr.getOffset()))
            fname = fn.getName() if fn else "(no func)"
            log("    slot[%d] = 0x%X (%s)" % (i, v, fname))
        except Exception as e:
            log("    slot[%d] error: %s" % (i, e))
            break

# ===========================================================================
# 4) FUN_1405108E0 — struct-fetcher inside FUN_1404FE2A0 (popup builder)
# ===========================================================================
log("\n### D) FUN_1405108E0 — popup-struct builder ###")
dumpFunc(0x5108E0, "FUN_1405108E0 (popup struct builder)", max_inst=100)

# Also FUN_1405105F0 — the analogous builder in FUN_1404FE760's path
log("\n### D.1) FUN_1405105F0 — analogous builder (FailWarn path) ###")
dumpFunc(0x5105F0, "FUN_1405105F0", max_inst=80)

# ===========================================================================
# 5) Search RTTI for any FeSubState class containing "Pop", "Pause",
#    "FrameRate", "Performance", "Warning", "Window", "Splash", "Title"
# ===========================================================================
log("\n### E) Hunt FeSubState* RTTI names matching popup/perf candidates ###")
KEYWORDS = (b"FrameRate", b"Framerate", b"FpsWarn", b"Performance",
            b"WarningWindow", b"OnlineCheckFailWarn",
            b"InformationFailWarn", b"PauseWindow", b"PopupWindow",
            b"FailWarn", b"NetWarn", b"PerfWarn", b"TitlePop",
            b"ProcessWindow", b"WindowBase")

# Scan all defined data labels for ".?AV...@@" RTTI strings
for kw in KEYWORDS:
    found = program.getMemory().findBytes(
        baseAddr, kw, None, True, monitor)
    if found is None:
        continue
    log("  '%s' found at %s" % (kw.decode('ascii'), found))
    # Read string starting ~16 bytes before to capture the .?AV prefix
    chars = []
    start = found.add(-32)
    for i in range(80):
        cb = jarray.zeros(1, 'b')
        try:
            memory.getBytes(start.add(i), cb)
        except:
            break
        c = cb[0] & 0xff
        if c == 0:
            if chars:
                log("    nearby: '%s'" % ''.join(chars))
                chars = []
            continue
        if 32 <= c < 127:
            chars.append(chr(c))
        else:
            if chars:
                log("    nearby: '%s'" % ''.join(chars))
                chars = []

# ===========================================================================
log("\n" + "=" * 70)
log("Done.")
log("=" * 70)

_out_file.close()
print("\nSaved to %s (%d lines)" % (OUT_PATH, len(results)))
