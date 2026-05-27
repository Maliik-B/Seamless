# -*- coding: utf-8 -*-
# Ghidra Jython: locate the framerate-guard substate / function that fires
# the "unable to play in online mode due to a detected frame rate issue"
# popup. DS2 SOTFS is known to track average frame time and disable online
# mode if frames run too fast.
#
#@runtime Jython
#
# Strategy:
#   1. RTTI scan for "FrameRate" / "Fps" / "FrameTime" / "Performance"
#      class names following the FeSubState pattern.
#   2. Inline string search for diagnostic text ("frame rate", etc.).
#   3. Search for f64 constant 16.66666... (= 1/60) and 0x40140C... patterns
#      typical of 60Hz frame-time comparisons.
#   4. xrefs to any candidate class' vtable.
#
# Output: D:\Applications\DS2\Seamless\tools\ghidra_fps_hunt_results.txt

import jarray

OUT_PATH = r"D:\Applications\DS2\Seamless\tools\ghidra_fps_hunt_results.txt"

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

def s8(v):
    return v if v < 128 else v - 256

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

def searchAscii(s):
    return searchBytes([ord(c) for c in s])

def searchUtf16(s):
    bs = []
    for c in s:
        bs.append(ord(c) & 0xff)
        bs.append((ord(c) >> 8) & 0xff)
    return searchBytes(bs)

# ============================================================================
log("=" * 70)
log("Frame-rate guard hunt (H-33 try-4)")
log("=" * 70)

# ----------------------------------------------------------------------------
log("\n### A. RTTI class names (FeSubState* and similar) for FrameRate/Fps ###")
# ----------------------------------------------------------------------------

rtti_terms = [
    "FrameRate", "Framerate", "FrameTime", "framerate", "frameRate",
    "Fps", "FPS", "fpsCheck", "FpsCheck",
    "PerformanceCheck", "Performance",
    "OnlineProhibit", "ProhibitOnline",
    "FeSubStateTitleFrame",
    "FeSubStateFrameRate",
    "FeSubStateTitleFps",
]
for term in rtti_terms:
    hits = searchAscii(term)
    if hits:
        log("  '%s': %d ASCII hits" % (term, len(hits)))
        for h in hits[:6]:
            log("    %s (+0x%X)" % (h, exeOffset(h)))
            # Dump a window of bytes after to read the full mangled name
            try:
                buf = jarray.zeros(64, 'b')
                memory.getBytes(h, buf)
                # Stop at first null
                s = ""
                for b in buf:
                    bb = b & 0xff
                    if bb == 0:
                        break
                    if 32 <= bb <= 126:
                        s += chr(bb)
                    else:
                        s += "."
                log("      full: %s" % s)
            except:
                pass

# ----------------------------------------------------------------------------
log("\n### B. Inline error/log strings for the framerate popup ###")
# ----------------------------------------------------------------------------

inline_terms = [
    "frame rate", "frame rate issue", "Frame Rate", "framerate issue",
    "detected frame rate", "unable to play", "Unable to play",
    "online mode due to",
    "OnlineProhibit", "ONLINE_PROHIBIT",
    "FrameRateLog", "FpsLog",
]
for term in inline_terms:
    a_hits = searchAscii(term)
    u_hits = searchUtf16(term)
    if a_hits:
        log("  ASCII '%s': %d hits" % (term, len(a_hits)))
        for h in a_hits[:5]:
            log("    %s (+0x%X)" % (h, exeOffset(h)))
            for ref in getXrefs(h)[:5]:
                fa = ref.getFromAddress()
                fn = funcMgr.getFunctionContaining(fa)
                fname = fn.getName() if fn else "(no func)"
                fep = ("+0x%X" % exeOffset(fn.getEntryPoint())) if fn else "?"
                log("      xref %s in %s @ %s [%s]" % (
                    fa, fname, fep, ref.getReferenceType()))
    if u_hits:
        log("  UTF-16 '%s': %d hits" % (term, len(u_hits)))
        for h in u_hits[:5]:
            log("    %s (+0x%X)" % (h, exeOffset(h)))
            for ref in getXrefs(h)[:5]:
                fa = ref.getFromAddress()
                fn = funcMgr.getFunctionContaining(fa)
                fname = fn.getName() if fn else "(no func)"
                fep = ("+0x%X" % exeOffset(fn.getEntryPoint())) if fn else "?"
                log("      xref %s in %s @ %s [%s]" % (
                    fa, fname, fep, ref.getReferenceType()))

# ----------------------------------------------------------------------------
log("\n### C. 60Hz-related f64 constants ###")
# ----------------------------------------------------------------------------

# 1.0 / 60.0 = 0.016666... ; the IEEE-754 double encoding is
# 0x3F91111111111111 (little-endian: 11 11 11 11 11 11 91 3F).
# 16.6666... ms = 0x4030AAAAAAAAAAAB (little-endian: AB AA AA AA AA AA 30 40).
# Also try 1.0 / 30.0 (30 Hz) and 1.0 / 120.0.
const_patterns = [
    ("1.0/60.0 (0.01666...)",   [0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x91, 0x3F]),
    ("16.6666... ms",            [0xAB, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0x30, 0x40]),
    ("1.0/30.0",                 [0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0xA1, 0x3F]),
    ("1.0/120.0",                [0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x81, 0x3F]),
    ("0.016 (float32)",          [0xD7, 0xA3, 0x83, 0x3C]),  # 0.016f
]
for (label, pat) in const_patterns:
    hits = searchBytes(pat)
    if hits:
        log("  %s: %d hits" % (label, len(hits)))
        for h in hits[:8]:
            xrefs = getXrefs(h)
            log("    %s (+0x%X) -- %d xrefs" % (h, exeOffset(h), len(xrefs)))
            for ref in xrefs[:4]:
                fa = ref.getFromAddress()
                fn = funcMgr.getFunctionContaining(fa)
                fname = fn.getName() if fn else "(no func)"
                fep = ("+0x%X" % exeOffset(fn.getEntryPoint())) if fn else "?"
                log("      xref %s in %s @ %s" % (fa, fname, fep))

# ============================================================================
log("\n" + "=" * 70)
log("Done.")
log("=" * 70)

with open(OUT_PATH, 'w') as f:
    f.write('\n'.join(results))

print("\nSaved to %s (%d lines)" % (OUT_PATH, len(results)))
