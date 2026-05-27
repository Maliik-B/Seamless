# -*- coding: utf-8 -*-
# Ghidra Jython: enumerate ALL FeSubState* and FeState* classes in the
# binary via .?AV...@@ RTTI prefix matching, then pick out anything that
# looks framerate-, performance- or online-prohibit-related.
#
#@runtime Jython
#
# Output: D:\Applications\DS2\Seamless\tools\ghidra_fesubstate_all_results.txt

import jarray

OUT_PATH = r"D:\Applications\DS2\Seamless\tools\ghidra_fesubstate_all_results.txt"

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

def s8(v):
    return v if v < 128 else v - 256

def searchAscii(s):
    pat = jarray.array([s8(ord(c)) for c in s], 'b')
    masks = jarray.array([-1] * len(s), 'b')
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

def readCString(addr, max_len=200):
    try:
        buf = jarray.zeros(max_len, 'b')
        memory.getBytes(addr, buf)
        s = ""
        for b in buf:
            bb = b & 0xff
            if bb == 0:
                break
            if 32 <= bb <= 126:
                s += chr(bb)
            else:
                s += "?"
        return s
    except:
        return None

# ============================================================================
log("=" * 70)
log("Enumerate all .?AV*@@ class names in the binary")
log("=" * 70)

# All MSVC mangled type-info names start with ".?AV" (class) or ".?AU" (struct).
# Find every occurrence in initialized memory; uniqify by start address.
prefixes = [".?AVFe", ".?AVDLR", ".?AUDLR"]
seen = set()
all_names = []
for pfx in prefixes:
    hits = searchAscii(pfx)
    log("  prefix '%s': %d hits" % (pfx, len(hits)))
    for h in hits:
        off = long(exeOffset(h))
        if off in seen:
            continue
        seen.add(off)
        s = readCString(h)
        if s is not None:
            all_names.append((off, s))

all_names.sort()
log("\n  Unique names found: %d" % len(all_names))

# ----------------------------------------------------------------------------
log("\n### Names matching frame/fps/online/performance/prohibit keywords ###")
# ----------------------------------------------------------------------------

interesting_kw = [
    "Frame", "frame", "Fps", "FPS", "Performance",
    "Online", "Prohibit", "prohibit",
    "Scholar", "Param", "RateCheck", "Detect",
    "FpsGuard", "Guard",
]
matched = []
for (off, name) in all_names:
    for kw in interesting_kw:
        if kw in name:
            matched.append((off, name, kw))
            break
log("  matches: %d" % len(matched))
for (off, name, kw) in matched:
    log("    +0x%X [%s]: %s" % (off, kw, name))

# ----------------------------------------------------------------------------
log("\n### Full sorted list of FeSubState*/FeState* names ###")
# ----------------------------------------------------------------------------

for (off, name) in all_names:
    log("  +0x%X: %s" % (off, name))

# ============================================================================
log("\n" + "=" * 70)
log("Done.")
log("=" * 70)

with open(OUT_PATH, 'w') as f:
    f.write('\n'.join(results))

print("\nSaved to %s (%d lines)" % (OUT_PATH, len(results)))
