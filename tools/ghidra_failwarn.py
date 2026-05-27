# -*- coding: utf-8 -*-
# Ghidra Jython: locate FeSubStateTitleOnlineCheckFailWarn's vtable,
# OnEnter, constructor, and the call site in FUN_1400f72e0 (setup) that
# decides when this state gets entered. Also try to identify the
# framerate-guard counter / flag the predicate consults.
#
#@runtime Jython
#
# Output: D:\Applications\DS2\Seamless\tools\ghidra_failwarn_results.txt

import jarray

OUT_PATH = r"D:\Applications\DS2\Seamless\tools\ghidra_failwarn_results.txt"

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

def s8(v):
    return v if v < 128 else v - 256

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

def searchBytes(byte_list):
    pat = jarray.array([s8(b) for b in byte_list], 'b')
    masks = jarray.array([-1] * len(byte_list), 'b')
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

def disassembleFunction(func, max_inst=120):
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
log("FeSubStateTitleOnlineCheckFailWarn — vtable / OnEnter / trigger")
log("=" * 70)

# Type-descriptor for OnlineCheckFailWarn: name string at +0x1567328
# (we found this in the all-class enum). TD start = name - 0x10 = +0x1567318.
TD_OFF = 0x1567318

# Find the COL: it's at some address where COL+0x0C contains an RVA pointing
# to TD. So search the binary for 4-byte LE = TD_OFF.
log("\nLooking for COL referencing TD at +0x%X..." % TD_OFF)

def s8(v):
    return v if v < 128 else v - 256

td_rva = TD_OFF
pat = jarray.array([s8(td_rva & 0xff), s8((td_rva >> 8) & 0xff),
                    s8((td_rva >> 16) & 0xff), s8((td_rva >> 24) & 0xff)], 'b')
masks = jarray.array([-1] * 4, 'b')
td_refs = []
for block in memory.getBlocks():
    if not block.isInitialized():
        continue
    start = block.getStart()
    end = block.getEnd()
    a = memory.findBytes(start, end, pat, masks, True, monitor)
    while a is not None:
        td_refs.append(a)
        try:
            nxt = a.add(1)
            if nxt.compareTo(end) >= 0:
                break
            a = memory.findBytes(nxt, end, pat, masks, True, monitor)
        except:
            break

log("  TD RVA refs: %d" % len(td_refs))
for r in td_refs:
    # COL pTypeDescriptor field is at offset +0x0C, so COL start = r - 0x0C
    col_start = r.subtract(0x0C)
    sig_bytes = jarray.zeros(4, 'b')
    try:
        memory.getBytes(col_start, sig_bytes)
        sig = (sig_bytes[0] & 0xff) | ((sig_bytes[1] & 0xff) << 8) | \
              ((sig_bytes[2] & 0xff) << 16) | ((sig_bytes[3] & 0xff) << 24)
    except:
        continue
    if sig != 1:
        continue
    log("    COL @ +0x%X" % long(exeOffset(col_start)))
    # vtable predecessor: address whose qword == col_start
    col_addr_val = col_start.getOffset()
    vt_pred_pat = jarray.array([
        s8(col_addr_val & 0xff),
        s8((col_addr_val >> 8) & 0xff),
        s8((col_addr_val >> 16) & 0xff),
        s8((col_addr_val >> 24) & 0xff),
        s8((col_addr_val >> 32) & 0xff),
        s8((col_addr_val >> 40) & 0xff),
        s8((col_addr_val >> 48) & 0xff),
        s8((col_addr_val >> 56) & 0xff),
    ], 'b')
    vt_pred_masks = jarray.array([-1] * 8, 'b')
    for block in memory.getBlocks():
        if not block.isInitialized():
            continue
        start = block.getStart()
        end = block.getEnd()
        a = memory.findBytes(start, end, vt_pred_pat, vt_pred_masks, True, monitor)
        while a is not None:
            vt_start = a.add(8)
            log("      vtable @ +0x%X" % long(exeOffset(vt_start)))
            # Dump first 20 slots
            for i in range(20):
                ptr = readUInt64(vt_start.add(i * 8))
                if ptr is None or (ptr >> 32) != 0x1:
                    break
                ptr_addr = addrFromOffset(ptr - baseAddr.getOffset())
                fn = funcMgr.getFunctionContaining(ptr_addr)
                fname = fn.getName() if fn else "(no func)"
                fep = ("+0x%X" % long(exeOffset(fn.getEntryPoint()))) if fn else "?"
                log("        slot[%2d] = %s @ %s" % (i, fname, fep))
            # vtable xrefs (constructor)
            vt_xrefs = getXrefs(vt_start)
            log("      vtable xrefs (constructors): %d" % len(vt_xrefs))
            for ref in vt_xrefs[:10]:
                fa = ref.getFromAddress()
                fn = funcMgr.getFunctionContaining(fa)
                fname = fn.getName() if fn else "(no func)"
                fep = ("+0x%X" % long(exeOffset(fn.getEntryPoint()))) if fn else "?"
                log("        from %s in %s @ %s" % (fa, fname, fep))
            try:
                nxt = a.add(1)
                if nxt.compareTo(end) >= 0:
                    break
                a = memory.findBytes(nxt, end, vt_pred_pat, vt_pred_masks, True, monitor)
            except:
                break

# Also enumerate constructor xrefs -> callers (the FSM setup site)
log("\nFinding constructor(s) and tracing callers...")
# After we know the vtable, the constructor is the function whose 2 xrefs to
# vtable identified it. From the loop above, we'll have logged them. To make
# this easier, the script above prints them inline.

# ============================================================================
log("\n" + "=" * 70)
log("Done.")
log("=" * 70)

with open(OUT_PATH, 'w') as f:
    f.write('\n'.join(results))

print("\nSaved to %s (%d lines)" % (OUT_PATH, len(results)))
