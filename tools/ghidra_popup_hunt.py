# -*- coding: utf-8 -*-
# Ghidra Jython script: find the "DARK SOULS II service is not available"
# popup-creation site in DarkSoulsII.exe for H-33 task #12.
#
#@runtime Jython
#
# Run from Ghidra: Window -> Python (Jython), then:
#   execfile(r"D:\Applications\DS2\Seamless\tools\ghidra_popup_hunt.py")
# Or headless:
#   analyzeHeadless <project> <name> -process DarkSoulsII.exe \
#     -scriptPath D:\Applications\DS2\Seamless\tools \
#     -postScript ghidra_popup_hunt.py -noanalysis
# Output: D:\Applications\DS2\Seamless\tools\ghidra_popup_hunt_results.txt
#
# CONTEXT (see docs/repro/h33-scope.md update #4)
# Tasks #9-#11 ruled out the ws2_32 connect surface, the Steamworks
# flat-C exports, and the most-likely Steamworks vtable slots. Hypothesis
# #3 -- popup fired from purely local DS2 state -- is the leading
# candidate. We need to find the popup-creation function and the
# predicate that gates it.
#
# DS2 stores user-visible text in FMG files (.bnd containers, message
# tables), NOT inline in DarkSoulsII.exe. So plain-text "service is not
# available" string-search will return nothing. We search for:
#
# 1. Internal/debug strings DS2 might have for the online check
#    (these tend to appear inline as logging text, even when the user
#    -visible message comes from FMG).
# 2. RTTI class names related to menu / dialog / online state.
# 3. Cross-refs to user32!MessageBoxW / DialogBoxParamW (low likelihood
#    but cheap to check).
# 4. Imports that smell like online-service checks (WinHTTP/WinINet
#    used outside the connect surface).
#
# OUTPUT
# Evidence only; no patches. We read the results and decide on a
# strategy, then write the actual patch in C++.

import jarray

OUT_PATH = r"D:\Applications\DS2\Seamless\tools\ghidra_popup_hunt_results.txt"

program = currentProgram
if program is None:
    raise RuntimeError(
        "currentProgram is None. Open DarkSoulsII.exe in the Ghidra "
        "CodeBrowser, then run Window -> Python from inside the "
        "CodeBrowser window (not from the project manager)."
    )
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

def getXrefs(address):
    return list(refMgr.getReferencesTo(address))

def getFunctionContaining(address):
    return funcMgr.getFunctionContaining(address)

def getCallers(func):
    callers = []
    if func is None:
        return callers
    entry = func.getEntryPoint()
    for ref in refMgr.getReferencesTo(entry):
        if ref.getReferenceType().isCall():
            caller = funcMgr.getFunctionContaining(ref.getFromAddress())
            callers.append((ref.getFromAddress(), caller))
    return callers

def searchString(s, ascii_only=True):
    """Find every occurrence of s as a byte sequence in initialised memory."""
    found = []
    pat = jarray.array([ord(c) for c in s], 'b')
    masks = jarray.array([-1] * len(s), 'b')
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

def searchUtf16(s):
    """Find every occurrence of s as little-endian UTF-16."""
    found = []
    bytes_ = []
    for c in s:
        bytes_.append(ord(c) & 0xff)
        bytes_.append((ord(c) >> 8) & 0xff)
    pat = jarray.array(bytes_, 'b')
    masks = jarray.array([-1] * len(bytes_), 'b')
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

def reportString(term, hits, max_xrefs=5):
    if not hits:
        return False
    log("  '%s': %d hits" % (term, len(hits)))
    for h in hits[:10]:
        log("    %s (+0x%X)" % (h, exeOffset(h)))
        xrefs = getXrefs(h)
        if xrefs:
            for ref in xrefs[:max_xrefs]:
                fa = ref.getFromAddress()
                fn = getFunctionContaining(fa)
                fname = fn.getName() if fn else "(no func)"
                fep = ("+0x%X" % exeOffset(fn.getEntryPoint())) if fn else "?"
                log("      xref from %s in %s @ %s [%s]" % (
                    fa, fname, fep, ref.getReferenceType()))
    return True

# ============================================================================
log("=" * 70)
log("H-33 task #12: DarkSoulsII.exe popup-creation site hunt")
log("Base: %s" % baseAddr)
log("=" * 70)

# ----------------------------------------------------------------------------
log("\n### 1. Imported Win32 APIs that build popups ###")
# ----------------------------------------------------------------------------

# Walk external function symbols for MessageBox* / DialogBox*. If DS2's popup
# is a Windows-level modal we'll see callers.
popup_apis = ["MessageBoxA", "MessageBoxW", "MessageBoxExA", "MessageBoxExW",
              "DialogBoxParamA", "DialogBoxParamW",
              "DialogBoxIndirectParamA", "DialogBoxIndirectParamW",
              "CreateDialogParamA", "CreateDialogParamW"]
for api in popup_apis:
    syms = list(symTab.getSymbols(api))
    for sym in syms:
        if sym.isExternal() or sym.getSymbolType().toString() == "External":
            ep = sym.getAddress()
            xrefs = getXrefs(ep)
            log("  %s @ %s -- %d xrefs" % (api, ep, len(xrefs)))
            for ref in xrefs[:8]:
                fa = ref.getFromAddress()
                fn = getFunctionContaining(fa)
                fname = fn.getName() if fn else "(no func)"
                fep = ("+0x%X" % exeOffset(fn.getEntryPoint())) if fn else "?"
                log("    xref from %s in %s @ %s" % (fa, fname, fep))

# ----------------------------------------------------------------------------
log("\n### 2. HTTP/WinINet imports (online-check candidates) ###")
# ----------------------------------------------------------------------------

http_apis = ["InternetOpenA", "InternetOpenW", "InternetOpenUrlA",
             "InternetOpenUrlW", "InternetReadFile", "HttpSendRequestA",
             "HttpSendRequestW", "HttpOpenRequestA", "HttpOpenRequestW",
             "WinHttpOpen", "WinHttpConnect", "WinHttpSendRequest",
             "WinHttpReadData", "WinHttpReceiveResponse"]
for api in http_apis:
    syms = list(symTab.getSymbols(api))
    for sym in syms:
        if sym.isExternal() or sym.getSymbolType().toString() == "External":
            ep = sym.getAddress()
            xrefs = getXrefs(ep)
            if xrefs:
                log("  %s @ %s -- %d xrefs" % (api, ep, len(xrefs)))
                for ref in xrefs[:5]:
                    fa = ref.getFromAddress()
                    fn = getFunctionContaining(fa)
                    fname = fn.getName() if fn else "(no func)"
                    fep = ("+0x%X" % exeOffset(fn.getEntryPoint())) if fn else "?"
                    log("    xref from %s in %s @ %s" % (fa, fname, fep))

# ----------------------------------------------------------------------------
log("\n### 3. Online/service/login internal debug strings ###")
# ----------------------------------------------------------------------------

# Strings the engine might log internally even when user-visible text
# lives in FMG files. Errs on the side of broader matching; we filter
# by xref count later.
online_terms = [
    "OnlineCheck", "OnlineStatus", "Online_Check", "CheckOnline",
    "ServiceCheck", "ServiceState", "ServiceStatus",
    "OfflineMode", "EnterOfflineMode", "GoOffline",
    "OnlineMode", "EnterOnlineMode",
    "NetworkCheck", "NetworkState", "ConnectivityCheck",
    "Login", "LoginCheck", "AuthCheck", "Authentication",
    "BNS", "Bandai", "GFWL", "LiveID",
    "MsgRepository", "SystemMessage", "MenuMan", "DialogMgr",
    "ServerStatus", "ServerCheck",
    "ServiceNotAvailable", "ServiceUnavailable",
    "frpg2", "FRPG2", "DARKSOULS2",
]
log("  Trying ASCII first; only UTF-16 fallback if a term has no ASCII hits.")
for term in online_terms:
    hits = searchString(term)
    if not hits:
        hits = searchUtf16(term)
        if hits:
            log("  (UTF-16) '%s':" % term)
    if hits:
        reportString(term, hits)

# ----------------------------------------------------------------------------
log("\n### 4. RTTI class names: menu / dialog / online managers ###")
# ----------------------------------------------------------------------------

class_terms = [
    "MenuMan", "MenuManImp", "ChrMenuMan",
    "DialogMan", "DialogManImp", "ModalDialog", "MessageDialog",
    "SystemMessage", "MessageBox", "MsgRepository",
    "OnlineMan", "OnlineManImp", "NetworkMan", "ServiceMan",
    "LoginMan", "LoginManImp",
    "FrpgNet", "FRPGNET", "Frpg2",
    "GFxValue", "ScaleformMan",
]
for cls in class_terms:
    hits = searchString(cls)
    reportString(cls, hits)

# ----------------------------------------------------------------------------
log("\n### 5. Numeric FMG IDs that may belong to the popup ###")
# ----------------------------------------------------------------------------

# FMG message IDs in DS2 are 32-bit ints. Known patterns from modding-
# community FMG dumps put online-service messages in the 350000 range.
# We scan code for MOV-immediate of these IDs followed by a CALL to the
# modal-dialog factory.
#
# Pure heuristic: anything within +/-50 of 350000 / 350100 / 350200 is
# worth pulling xrefs for once we know the factory address. We can't do
# this from scripting alone without knowing the factory -- list candidates
# so the human eye picks them out.
candidate_ids = [350000, 350100, 350200, 350300, 350400, 350500,
                 360000, 360100, 360200,
                 100000, 100100, 100200]
log("  (Scanning for candidate IDs in code -- xrefs need manual review)")
for cid in candidate_ids:
    # Pack as little-endian uint32 and search code blocks
    # jarray 'b' is signed; convert 0-255 -> -128..127
    def s8(v):
        return v if v < 128 else v - 256
    pat = jarray.array([s8(cid & 0xff), s8((cid >> 8) & 0xff),
                        s8((cid >> 16) & 0xff), s8((cid >> 24) & 0xff)], 'b')
    masks = jarray.array([-1, -1, -1, -1], 'b')
    hits = []
    for block in memory.getBlocks():
        if not block.isInitialized():
            continue
        if not block.isExecute():
            continue  # only scan code; data hits are too noisy
        start = block.getStart()
        end = block.getEnd()
        a = memory.findBytes(start, end, pat, masks, True, monitor)
        while a is not None:
            hits.append(a)
            try:
                nxt = a.add(1)
                if nxt.compareTo(end) >= 0:
                    break
                a = memory.findBytes(nxt, end, pat, masks, True, monitor)
            except:
                break
    if hits:
        log("  ID %d (0x%X): %d code occurrences" % (cid, cid, len(hits)))
        for h in hits[:6]:
            inst = listing.getInstructionContaining(h)
            iname = inst.toString() if inst else "(no instr)"
            fn = getFunctionContaining(h)
            fname = fn.getName() if fn else "(no func)"
            log("    %s (+0x%X) in %s : %s" % (h, exeOffset(h), fname, iname))

# ----------------------------------------------------------------------------
log("\n### 6. JP/KR popup body text (UTF-16 LE) ###")
# ----------------------------------------------------------------------------

# Long shot: if DS2 ever inlines any text, the JP build might. The English
# popup "DARK SOULS II service is not available" likely has JP equivalent
# starting with "DARK SOULS II" Latin chars followed by "のサービス"
# (no kanji needed for the search prefix -- the Latin half is enough).
candidate_unicode = [
    "DARK SOULS II",
    "service is not available",
    "DARKSOULSII",
    "DarkSoulsII",
    "Service Not Available",
]
for term in candidate_unicode:
    a_hits = searchString(term)
    u_hits = searchUtf16(term)
    if a_hits:
        log("  ASCII '%s': %d hits" % (term, len(a_hits)))
        for h in a_hits[:5]:
            log("    %s (+0x%X)" % (h, exeOffset(h)))
            for ref in getXrefs(h)[:3]:
                fa = ref.getFromAddress()
                fn = getFunctionContaining(fa)
                fname = fn.getName() if fn else "(no func)"
                log("      xref from %s in %s" % (fa, fname))
    if u_hits:
        log("  UTF-16 '%s': %d hits" % (term, len(u_hits)))
        for h in u_hits[:5]:
            log("    %s (+0x%X)" % (h, exeOffset(h)))
            for ref in getXrefs(h)[:3]:
                fa = ref.getFromAddress()
                fn = getFunctionContaining(fa)
                fname = fn.getName() if fn else "(no func)"
                log("      xref from %s in %s" % (fa, fname))

# ----------------------------------------------------------------------------
log("\n" + "=" * 70)
log("Done. Promising leads to follow up in the GUI:")
log(" 1. Section 1 (MessageBox/DialogBox) -- if any non-zero xref appears,")
log("    follow that caller; it is the most likely popup site.")
log(" 2. Section 3/4 strings with xrefs in code (not just data) -- those")
log("    callers are candidate predicates for the online-check.")
log(" 3. Section 5 candidate IDs -- correlate with the modal-dialog factory")
log("    once we know its address.")
log("=" * 70)

with open(OUT_PATH, 'w') as f:
    f.write('\n'.join(results))

print("\nSaved to %s (%d lines)" % (OUT_PATH, len(results)))
