# -*- coding: utf-8 -*-
# Ghidra Jython: locate vtables and constructors for the title-screen
# state-machine substate classes identified by the popup-drill RTTI scan.
#
#@runtime Jython
#
# Goal: name the functions that drive the boot sequence
#   FeSubStateTitleSteamNetworkCheck -> FeSubStateTitleOnlineCheck ->
#   FeSubStateOfflineModeWindow      -> FeSubStateTitleSetOfflineMode
# and find the transition predicate gating the OfflineModeWindow branch.
#
# Strategy:
#  1. For each interesting class, find its TypeDescriptor (a few bytes
#     before the .?AV... mangled name).
#  2. Find the CompleteObjectLocator by searching .rdata for a 32-bit RVA
#     that resolves to the TypeDescriptor.
#  3. From the COL, the previous qword in .rdata is the vtable start.
#  4. Get xrefs to the vtable (constructors / factory functions).
#  5. Dump first 8 vtable slots so we can identify Update / Enter / Exit
#     methods.
#
# Output: D:\Applications\DS2\Seamless\tools\ghidra_fesubstate_results.txt

import jarray

OUT_PATH = r"D:\Applications\DS2\Seamless\tools\ghidra_fesubstate_results.txt"

program = currentProgram
listing = program.getListing()
memory = program.getMemory()
refMgr = program.getReferenceManager()
funcMgr = program.getFunctionManager()
symTab = program.getSymbolTable()
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

def readUInt32(addr):
    try:
        b = jarray.zeros(4, 'b')
        memory.getBytes(addr, b)
        return ((b[0] & 0xff) | ((b[1] & 0xff) << 8) |
                ((b[2] & 0xff) << 16) | ((b[3] & 0xff) << 24))
    except:
        return None

def readUInt64(addr):
    try:
        b = jarray.zeros(8, 'b')
        memory.getBytes(addr, b)
        v = 0
        for i in range(8):
            v |= (b[i] & 0xff) << (i * 8)
        return v
    except:
        return None

def searchUint64(target):
    """Find every aligned 8-byte location holding target value."""
    b0 = target & 0xff
    b1 = (target >> 8) & 0xff
    b2 = (target >> 16) & 0xff
    b3 = (target >> 24) & 0xff
    b4 = (target >> 32) & 0xff
    b5 = (target >> 40) & 0xff
    b6 = (target >> 48) & 0xff
    b7 = (target >> 56) & 0xff
    def s8(v):
        return v if v < 128 else v - 256
    pat = jarray.array([s8(b0), s8(b1), s8(b2), s8(b3),
                        s8(b4), s8(b5), s8(b6), s8(b7)], 'b')
    masks = jarray.array([-1] * 8, 'b')
    found = []
    for block in memory.getBlocks():
        if not block.isInitialized():
            continue
        start = block.getStart()
        end = block.getEnd()
        a = memory.findBytes(start, end, pat, masks, True, monitor)
        while a is not None:
            found.append(a)
            try:
                nxt = a.add(1)
                if nxt.compareTo(end) >= 0:
                    break
                a = memory.findBytes(nxt, end, pat, masks, True, monitor)
            except:
                break
    return found

def searchUint32(target):
    """Find every location holding target value as 4-byte LE."""
    b0 = target & 0xff
    b1 = (target >> 8) & 0xff
    b2 = (target >> 16) & 0xff
    b3 = (target >> 24) & 0xff
    def s8(v):
        return v if v < 128 else v - 256
    pat = jarray.array([s8(b0), s8(b1), s8(b2), s8(b3)], 'b')
    masks = jarray.array([-1] * 4, 'b')
    found = []
    for block in memory.getBlocks():
        if not block.isInitialized():
            continue
        start = block.getStart()
        end = block.getEnd()
        a = memory.findBytes(start, end, pat, masks, True, monitor)
        while a is not None:
            found.append(a)
            try:
                nxt = a.add(1)
                if nxt.compareTo(end) >= 0:
                    break
                a = memory.findBytes(nxt, end, pat, masks, True, monitor)
            except:
                break
    return found

# Classes of interest -- (name, mangled string offset from popup hunt results)
classes = [
    ("FeSubStateTitleSteamNetworkCheck",  0x1566F88),
    ("FeSubStateTitleOnlineCheck",        0x1567060),
    ("FeSubStateOfflineModeWindow",       0x1567098),
    ("FeSubStateTitleSetOfflineMode",     0x15670D0),
    ("FeSubStateTitleGameServerLogin",    0x1566FF8),
    ("FeSubStateTitleUserPolicy",         0x1567030),
    ("FeSubStateProcessWindowBase",       0x1566F18),
]

# ============================================================================
log("=" * 70)
log("FeSubState class -> vtable -> caller chain")
log("Image base: %s" % baseAddr)
log("=" * 70)

# MSVC TypeDescriptor layout (x64):
#   +0x00  qword  pVFTable (always type_info::vtable)
#   +0x08  qword  spare (zero)
#   +0x10  char[] name (the .?AV...@@ mangled string)
#
# So TypeDescriptor start = name_addr - 0x10.

# MSVC CompleteObjectLocator layout (x64):
#   +0x00  dword  signature (1 for x64)
#   +0x04  dword  offset
#   +0x08  dword  cdOffset
#   +0x0C  dword  pTypeDescriptor (32-bit RVA from image base)
#   +0x10  dword  pClassDescriptor (RVA)
#   +0x14  dword  pSelf (RVA, x64 only)
#
# The vtable's first slot points to the function table; the COL pointer
# sits at vtable_address - 8.

for (cls_name, name_off) in classes:
    log("\n--- %s ---" % cls_name)
    td_off = name_off - 0x10
    td_addr = addrFromOffset(td_off)
    name_addr = addrFromOffset(name_off)
    log("  name string @ +0x%X" % name_off)
    log("  TypeDescriptor @ +0x%X" % td_off)

    # RVAs in COL are 32-bit offsets from the image base.
    td_rva = td_off  # Equivalent because image base is loaded
    cols = searchUint32(td_rva)
    cols_in_rdata = []
    for c in cols:
        # COL's pTypeDescriptor field is at offset +0x0C. So COL start
        # is at c - 0x0C.
        col_start = c.subtract(0x0C)
        # Validate by reading signature (should be 1)
        sig = readUInt32(col_start)
        if sig == 1:
            cols_in_rdata.append(col_start)

    log("  CompleteObjectLocator candidates: %d (validated by sig=1)" % len(cols_in_rdata))
    for col in cols_in_rdata[:5]:
        log("    COL @ %s (+0x%X)" % (col, exeOffset(col)))

        # vtable is at col_addr + 8 (because COL pointer precedes vtable
        # first slot by 8 bytes). So search for memory locations whose
        # qword equals col_addr -- those are at offset -8 from vtable.
        col_addr_val = col.getOffset()
        vt_predecessors = searchUint64(col_addr_val)
        for vp in vt_predecessors:
            vt_start = vp.add(8)
            log("      vtable @ %s (+0x%X)" % (vt_start, exeOffset(vt_start)))

            # First 8 slots
            for i in range(8):
                slot_addr = vt_start.add(i * 8)
                ptr = readUInt64(slot_addr)
                if ptr is None:
                    break
                # Try to identify a function at ptr
                ptr_addr = addrFromOffset(ptr - baseAddr.getOffset()) if (ptr >= baseAddr.getOffset()) else None
                if ptr_addr is not None:
                    fn = funcMgr.getFunctionContaining(ptr_addr)
                    fname = fn.getName() if fn else "(no func)"
                    log("        slot[%d] = 0x%X (%s @ %s)" % (
                        i, ptr, fname,
                        ("+0x%X" % exeOffset(fn.getEntryPoint())) if fn else "?"))

            # xrefs TO the vtable -- constructors / placement-new sites
            vt_xrefs = getXrefs(vt_start)
            log("      vtable xrefs: %d" % len(vt_xrefs))
            for ref in vt_xrefs[:10]:
                fa = ref.getFromAddress()
                fn = getFunctionContaining(fa)
                fname = fn.getName() if fn else "(no func)"
                fep = ("+0x%X" % exeOffset(fn.getEntryPoint())) if fn else "?"
                log("        from %s (+0x%X) in %s @ %s [%s]" % (
                    fa, exeOffset(fa), fname, fep, ref.getReferenceType()))

# ============================================================================
log("\n" + "=" * 70)
log("Done.")
log("=" * 70)

with open(OUT_PATH, 'w') as f:
    f.write('\n'.join(results))

print("\nSaved to %s (%d lines)" % (OUT_PATH, len(results)))
