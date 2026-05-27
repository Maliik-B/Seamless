# -*- coding: utf-8 -*-
# Ghidra Jython drill-down for H-33 task #12.
#
#@runtime Jython
#
# Follow-up to ghidra_popup_hunt.py (top leads from results file). Targets:
#
# A. Three MessageBoxW callers identified at xrefs +0xAEF74C, +0xAA6522,
#    +0x8C38DD. For each: caller-function disassembly, function size,
#    and walk-up callers, with attention to early-boot strings nearby.
#
# B. The "ServiceMan" / "NetworkMan" / "LoginMan" / "MessageDialog" /
#    "SystemMessage" RTTI strings. For each: xrefs from code, naming the
#    class methods that consume them.
#
# C. The +0x1566FA0..+0x15672XX cluster (OnlineCheck / OfflineMode /
#    NetworkCheck). Dump the surrounding 0x200 bytes as ASCII to see if
#    it's a state-name table or function-name dict.
#
# Output: D:\Applications\DS2\Seamless\tools\ghidra_popup_drill_results.txt

import jarray

OUT_PATH = r"D:\Applications\DS2\Seamless\tools\ghidra_popup_drill_results.txt"

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

def disassembleFunction(func, max_inst=400):
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

def readBytes(addr, length):
    try:
        buf = jarray.zeros(length, 'b')
        memory.getBytes(addr, buf)
        return [(b & 0xff) for b in buf]
    except:
        return None

def renderAscii(bytes_list):
    out = []
    for b in bytes_list:
        if 32 <= b <= 126:
            out.append(chr(b))
        elif b == 0:
            out.append('.')
        else:
            out.append('?')
    return "".join(out)

def readUnicodeAt(addr, max_chars=200):
    """Best-effort: try to read a wide-char (UTF-16 LE) null-terminated
    string starting at addr."""
    try:
        bytes_ = readBytes(addr, max_chars * 2)
        if not bytes_:
            return None
        out = []
        i = 0
        while i + 1 < len(bytes_):
            lo = bytes_[i]
            hi = bytes_[i+1]
            if lo == 0 and hi == 0:
                break
            if hi == 0 and 32 <= lo <= 126:
                out.append(chr(lo))
            else:
                out.append("\\u%02x%02x" % (hi, lo))
            i += 2
        return "".join(out)
    except:
        return None

# ============================================================================
log("=" * 70)
log("H-33 task #12: drill into top popup-hunt leads")
log("=" * 70)

# ----------------------------------------------------------------------------
log("\n### A. MessageBoxW callers ###")
# ----------------------------------------------------------------------------

mbw_callers = [0xAEF500, 0xAA62E0, 0x8C3790]
mbw_call_sites = [0xAEF74C, 0xAA6522, 0x8C38DD]

for fn_off, call_site in zip(mbw_callers, mbw_call_sites):
    fn_ep = addrFromOffset(fn_off)
    fn = funcMgr.getFunctionAt(fn_ep)
    log("\n  Function FUN_140%X (+0x%X)" % (fn_off, fn_off))
    if fn is None:
        log("    NOT FOUND as function entry")
        continue
    log("    body bytes : %d" % fn.getBody().getNumAddresses())
    log("    return type: %s" % fn.getReturnType())
    log("    param count: %d" % fn.getParameterCount())
    callers = getCallers(fn)
    log("    callers    : %d" % len(callers))
    for (ca, caller_fn) in callers[:10]:
        cname = caller_fn.getName() if caller_fn else "(no func)"
        cep = ("+0x%X" % exeOffset(caller_fn.getEntryPoint())) if caller_fn else "?"
        log("      CALL at %s (+0x%X) from %s @ %s" % (
            ca, exeOffset(ca), cname, cep))

    # Dump disassembly around the MessageBoxW call (32 instructions before + 8 after)
    call_site_addr = addrFromOffset(call_site)
    body = fn.getBody()
    it = listing.getInstructions(body, True)
    all_inst = []
    while it.hasNext():
        all_inst.append(it.next())
    # Find call site in instruction stream
    idx = -1
    for (i, inst) in enumerate(all_inst):
        if inst.getAddress().equals(call_site_addr):
            idx = i
            break
    if idx >= 0:
        log("    --- around MessageBoxW call site at +0x%X ---" % call_site)
        start = max(0, idx - 32)
        end = min(len(all_inst), idx + 9)
        for i in range(start, end):
            inst = all_inst[i]
            marker = "  <-- CALL MessageBoxW" if i == idx else ""
            log("      %s (+0x%X) %s%s" % (
                inst.getAddress(), exeOffset(inst.getAddress()),
                inst.toString(), marker))

# ----------------------------------------------------------------------------
log("\n### B. RTTI/class-name string xrefs (from code only) ###")
# ----------------------------------------------------------------------------

# (offset, label) -- one address per string match
class_str_addrs = [
    (0x1142B09, "ServiceMan (1)"),
    (0x1142B57, "ServiceMan (2)"),
    (0x1142BBF, "ServiceMan (3)"),
    (0x1142C17, "ServiceMan (4)"),
    (0x15ACAEE, "ServiceMan (5)"),
    (0x15ACB26, "ServiceMan (6)"),
    (0x156E6CA, "NetworkMan (1)"),
    (0x156E6F7, "NetworkMan (2)"),
    (0x10AEB2D, "MessageDialog (1)"),
    (0x155D63B, "MessageDialog (2)"),
    (0x155DB5B, "MessageDialog (3)"),
    (0x15793AA, "LoginMan"),
    (0x15832FF, "SystemMessage"),
]
for (off, label) in class_str_addrs:
    a = addrFromOffset(off)
    xrefs = getXrefs(a)
    if not xrefs:
        log("  %s @ +0x%X -- no xrefs" % (label, off))
        continue
    # Also try a couple bytes after, in case the xref points to the
    # mid-string (RTTI marker prefix etc.)
    log("  %s @ +0x%X -- %d xrefs" % (label, off, len(xrefs)))
    for ref in xrefs[:8]:
        fa = ref.getFromAddress()
        fn = getFunctionContaining(fa)
        fname = fn.getName() if fn else "(no func)"
        fep = ("+0x%X" % exeOffset(fn.getEntryPoint())) if fn else "?"
        rtype = ref.getReferenceType()
        log("    from %s (+0x%X) in %s @ %s [%s]" % (
            fa, exeOffset(fa), fname, fep, rtype))

# ----------------------------------------------------------------------------
log("\n### C. State-name cluster at +0x15669XX..+0x15672XX ###")
# ----------------------------------------------------------------------------

# Dump 0x300 bytes from +0x1566F00 to see if it's a state-name table.
cluster_start = addrFromOffset(0x1566F00)
bytes_ = readBytes(cluster_start, 0x300)
if bytes_ is None:
    log("  failed to read cluster bytes")
else:
    # Walk through the buffer, splitting on null-terminators and
    # printing any ASCII runs >= 3 chars
    run = []
    rel = 0
    while rel < len(bytes_):
        b = bytes_[rel]
        if 32 <= b <= 126:
            run.append(chr(b))
        else:
            if len(run) >= 4:
                addr_here = cluster_start.add(rel - len(run))
                log("  %s (+0x%X) %s" % (
                    addr_here, exeOffset(addr_here), "".join(run)))
            run = []
        rel += 1
    if len(run) >= 4:
        addr_here = cluster_start.add(rel - len(run))
        log("  %s (+0x%X) %s" % (
            addr_here, exeOffset(addr_here), "".join(run)))

# Then get xrefs to a few of the keyword start addresses inside that cluster
log("\n  -- xrefs to keyword string starts in the cluster --")
keyword_offs = [
    (0x1566FA0, "NetworkCheck"),
    (0x1567073, "OnlineCheck (1)"),
    (0x156733B, "OnlineCheck (2)"),
    (0x15670A6, "OfflineMode (1)"),
    (0x15670E6, "OfflineMode (2)"),
]
for (off, label) in keyword_offs:
    a = addrFromOffset(off)
    xrefs = getXrefs(a)
    log("  %s @ +0x%X -- %d xrefs" % (label, off, len(xrefs)))
    for ref in xrefs[:6]:
        fa = ref.getFromAddress()
        fn = getFunctionContaining(fa)
        fname = fn.getName() if fn else "(no func)"
        fep = ("+0x%X" % exeOffset(fn.getEntryPoint())) if fn else "?"
        log("    from %s (+0x%X) in %s @ %s [%s]" % (
            fa, exeOffset(fa), fname, fep, ref.getReferenceType()))

# ----------------------------------------------------------------------------
log("\n### D. Read the actual MessageBoxW arguments (string args) ###")
# ----------------------------------------------------------------------------

# For each call site, look at the instructions immediately before to see
# what's loaded into RCX/RDX (hWnd/lpText) and R8 (lpCaption). String
# pointers should be visible as LEA reg,[const].
log("  (See section A disassembly; manual review of LEA loads is needed.)")

# ============================================================================
log("\n" + "=" * 70)
log("Done.")
log("=" * 70)

with open(OUT_PATH, 'w') as f:
    f.write('\n'.join(results))

print("\nSaved to %s (%d lines)" % (OUT_PATH, len(results)))
