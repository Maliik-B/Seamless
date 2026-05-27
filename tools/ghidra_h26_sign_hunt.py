# -*- coding: utf-8 -*-
# Ghidra Jython: H-26 sign-placement handler hunt (raw-scan version)
#
# The previous version relied on refMgr.getReferencesTo, which is empty
# under -noanalysis. This version uses raw memory scans (qword and 4-byte
# RVA) — same approach as ghidra_offline_callers.py — so it works on a
# fresh import without a full analysis pass.
#
# Pipeline:
#   1. Find each "Sign/Summon/Soapstone" RTTI string in .data
#      (format: ".?AV<ClassName>@@..."). The 4-byte ".?AV" prefix is
#      mandatory in MSVC x64 RTTI; if the keyword search matched a string
#      starting *inside* the prefix, the string really starts at addr-4.
#   2. For each string, the TypeDescriptor (TD) sits 0x10 before — TD
#      layout is: pVFTable(8) + spare(8) + name(...).
#   3. Find 4-byte LE occurrences of the TD's RVA — those are COL records
#      (RTTICompleteObjectLocator) pointing at this class.
#   4. For each COL candidate, find any qword = COL_address — those slots
#      live at `vtable - 8` (vtable[-1] is the COL pointer). The address
#      that follows in memory (COL_addr + 8 .. +N) is the vtable.
#   5. Print vtable[0..15] and any callers of vtable[0] (constructor) so
#      we can identify where instances of this class are built.
#
# Output: D:\Applications\DS2\Seamless\tools\ghidra_h26_sign_hunt_results.txt
#
#@runtime Jython

import jarray

OUT_PATH = r"D:\Applications\DS2\Seamless\tools\ghidra_h26_sign_hunt_results.txt"

program = currentProgram
listing = program.getListing()
memory = program.getMemory()
funcMgr = program.getFunctionManager()
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

def s8(v):
    return v if v < 128 else v - 256

def searchBytes(pat_bytes, max_hits=128):
    pat = jarray.array([s8(b & 0xff) for b in pat_bytes], 'b')
    masks = jarray.array([-1] * len(pat_bytes), 'b')
    found = []
    for block in memory.getBlocks():
        if not block.isInitialized():
            continue
        start = block.getStart()
        end = block.getEnd()
        a = memory.findBytes(start, end, pat, masks, True, monitor)
        while a is not None and len(found) < max_hits:
            found.append(a)
            try:
                nxt = a.add(1)
                if nxt.compareTo(end) >= 0:
                    break
                a = memory.findBytes(nxt, end, pat, masks, True, monitor)
            except:
                break
    return found

def searchString(needle, max_hits=64):
    return searchBytes([ord(c) for c in needle], max_hits)

def searchQword(qword_va, max_hits=64):
    return searchBytes([(qword_va >> (i*8)) & 0xff for i in range(8)], max_hits)

def searchDword(dword_rva, max_hits=64):
    return searchBytes([(dword_rva >> (i*8)) & 0xff for i in range(4)], max_hits)

def readU64(addr):
    try:
        b = jarray.zeros(8, 'b')
        memory.getBytes(addr, b)
        v = 0
        for i in range(8):
            v |= (b[i] & 0xff) << (i*8)
        return v
    except:
        return None

def readU32(addr):
    try:
        b = jarray.zeros(4, 'b')
        memory.getBytes(addr, b)
        v = 0
        for i in range(4):
            v |= (b[i] & 0xff) << (i*8)
        return v
    except:
        return None

def readCString(addr, max_len=160):
    try:
        out = []
        for i in range(max_len):
            b = memory.getByte(addr.add(i)) & 0xff
            if b == 0:
                break
            if b < 0x20 or b > 0x7e:
                return None
            out.append(chr(b))
        return ''.join(out)
    except:
        return None

# ============================================================================
log("=" * 70)
log("H-26 sign-placement handler hunt (raw-scan)")
log("=" * 70)

# Find sign/summon/soapstone-related RTTI strings.
# MSVC x64 RTTI strings start with ".?AV" (class) or ".?AU" (struct).
# We search for the substring *after* the prefix so we catch variants.
KEYWORDS = [
    "RequestSummonSign",
    "SummonSignReply",
    "RequestSummonMirrorKnightSign",
    "RequestRemoveSign",
    "RequestUpdateSign",
    "RequestCreateSign",
    "RequestPushSummonSign",
    "RequestPlaceSign",
    "RequestPutDownSign",
    "RequestGetSignList",
    "GetSignList",
    "SignListResponse",
    "SignListRequest",
    "PlaceSign",
    "PutSign",
    "Soapstone",
]

string_hits = []  # list of (kw, addr_of_string_start, full_string)
for kw in KEYWORDS:
    hits = searchString(kw, max_hits=32)
    for a in hits:
        # If the prefix ".?AV" is 4 bytes before, treat the string as starting there.
        prefix_addr = a.subtract(4)
        prefix = readCString(prefix_addr, 8)
        if prefix and prefix.startswith(".?AV"):
            start = prefix_addr
        elif prefix and prefix.startswith(".?AU"):
            start = prefix_addr
        else:
            start = a
        full = readCString(start, 160)
        if full is None:
            continue
        # Dedup
        if any(s[1].equals(start) for s in string_hits):
            continue
        string_hits.append((kw, start, full))

log("\n### A. Discovered class-name strings (%d total) ###" % len(string_hits))
for kw, addr, full in string_hits:
    log("  %s (+0x%X)  [matched on '%s']" % (addr, exeOffset(addr), kw))
    log("    \"%s\"" % full)

# ============================================================================
# For each RTTI string, derive the TypeDescriptor address (string - 0x10),
# scan for 4-byte LE RVAs of that TD — those occur in COL records.
log("\n### B. COL records pointing at each class ###")

# COL structure (RTTICompleteObjectLocator) layout for x64:
#   +0  uint32  signature           (== 1 for x64)
#   +4  uint32  offset
#   +8  uint32  cdOffset
#   +12 uint32  pTypeDescriptor     (RVA from module base)
#   +16 uint32  pClassDescriptor    (RVA)
#   +20 uint32  pSelf               (RVA of this COL itself)
#
# So a 4-byte match for the TD RVA is most often in COL+12 ⇒ COL = match-12.

class_data = []  # list of dicts with keys: name, string_addr, td_addr, cols, vtables

for kw, str_addr, full_name in string_hits:
    td_addr = str_addr.subtract(0x10)
    td_rva = exeOffset(td_addr)
    log("\n  -- %s --" % full_name)
    log("     string @ +0x%X, TD @ +0x%X (RVA 0x%X)" % (
        exeOffset(str_addr), exeOffset(td_addr), td_rva))

    rva_hits = searchDword(td_rva, max_hits=32)
    col_addrs = []
    for h in rva_hits:
        # COL+12 ⇒ COL = h-12. Verify by reading COL+0 = signature == 1.
        cand_col = h.subtract(12)
        sig = readU32(cand_col)
        # Also verify COL+20 (pSelf) RVA == cand_col's RVA.
        pself = readU32(cand_col.add(20))
        if sig == 1 and pself == exeOffset(cand_col):
            col_addrs.append(cand_col)
            log("     COL @ %s (+0x%X) signature=1 pSelf-OK" % (
                cand_col, exeOffset(cand_col)))
        else:
            log("     RVA hit at %s (+0x%X) - not a COL (sig=%s pSelf=%s)" % (
                h, exeOffset(h), sig, pself))

    # For each COL, find any qword = COL's full VA. That qword lives at vtable[-1].
    vtables = []
    for col in col_addrs:
        col_va = col.getOffset()
        slot_hits = searchQword(col_va, max_hits=16)
        for sh in slot_hits:
            # The vtable starts at sh + 8.
            vt = sh.add(8)
            vtables.append(vt)
            log("     vtable @ %s (+0x%X) [COL slot @ %s]" % (
                vt, exeOffset(vt), sh))

    class_data.append({
        'name': full_name,
        'string_addr': str_addr,
        'td_addr': td_addr,
        'cols': col_addrs,
        'vtables': vtables,
    })

# ============================================================================
# For each vtable found, print slots 0..15 and any callers of slot 0
# (which is typically the dtor / vtable head).
log("\n### C. Vtable slots + callers ###")

def slot_func(vt, idx):
    qw = readU64(vt.add(idx * 8))
    if qw is None or qw == 0:
        return None, None
    # Is it inside the image?
    if qw < baseVA or qw > baseVA + 0x10000000:
        return qw, None
    fa = addrFromVA(qw)
    fn = funcMgr.getFunctionContaining(fa)
    return qw, fn

def callersOfFunc(fn, limit=24):
    """Disabled in -noanalysis mode: instruction listing is sparse and the
    AddressSet API doesn't accept a range. Rely on section D's qword scan
    of the vtable address to find constructor sites instead."""
    return []

for cd in class_data:
    if not cd['vtables']:
        continue
    log("\n  ==> %s" % cd['name'])
    for vt in cd['vtables']:
        log("    vtable @ %s (+0x%X)" % (vt, exeOffset(vt)))
        for i in range(16):
            qw, fn = slot_func(vt, i)
            if qw is None or qw == 0:
                log("      slot[%2d] = 0" % i)
                continue
            fname = fn.getName() if fn else "(no func)"
            fep = ("+0x%X" % exeOffset(fn.getEntryPoint())) if fn else "?"
            log("      slot[%2d] = 0x%X (%s @ %s)" % (i, qw, fname, fep))

        # Callers of slot[0] (typically scalar-dtor) — these are sites that
        # construct OR destruct instances. Useful to find the constructor
        # caller, but easier: find callers of any non-trivial slot too.
        qw0, fn0 = slot_func(vt, 0)
        if fn0:
            log("    callers of vtable slot[0] (%s):" % fn0.getName())
            for ca, cf in callersOfFunc(fn0, limit=12):
                cname = cf.getName() if cf else "(no func)"
                cep = ("+0x%X" % exeOffset(cf.getEntryPoint())) if cf else "?"
                log("      from %s (+0x%X) in %s @ %s" % (
                    ca, exeOffset(ca), cname, cep))

# ============================================================================
# Also: find direct callers of the vtable itself (a 'MOV qword ptr [RAX], vtable'
# pattern is the canonical constructor. Searching for the vtable's full VA
# as a qword in code, near MOV instructions, finds the ctor.
log("\n### D. Constructors: qword refs to the vtable address itself ###")

for cd in class_data:
    if not cd['vtables']:
        continue
    log("\n  ==> %s" % cd['name'])
    for vt in cd['vtables']:
        vt_va = vt.getOffset()
        log("    vtable VA: 0x%X" % vt_va)
        # Search for the qword in code. We expect it to appear as the RIP-relative
        # source of a LEA loading vtable_ptr, then a MOV writing it to [this+0].
        qw_hits = searchQword(vt_va, max_hits=32)
        for h in qw_hits:
            block = memory.getBlock(h)
            is_code = block.isExecute() if block else False
            # Find the function (if any) that contains this address.
            fn = funcMgr.getFunctionContaining(h)
            fname = fn.getName() if fn else "(no func)"
            fep = ("+0x%X" % exeOffset(fn.getEntryPoint())) if fn else "?"
            kind = "CODE" if is_code else "data"
            log("      ref @ %s (+0x%X) %s - in %s @ %s" % (
                h, exeOffset(h), kind, fname, fep))

log("\n" + "=" * 70)
log("Done.")
log("Next step: pick a class above (RequestSummonSign / etc), look at the")
log("constructor caller list under section D, dump that caller, find the")
log("predicate above the constructor call.")
log("=" * 70)

with open(OUT_PATH, 'w') as f:
    f.write('\n'.join(results))

print("\nSaved to %s (%d lines)" % (OUT_PATH, len(results)))
