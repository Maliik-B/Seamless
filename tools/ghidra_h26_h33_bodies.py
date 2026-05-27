# -*- coding: utf-8 -*-
# Ghidra Jython: dump the H-33-patched functions in full + their immediate
# callees, so we can identify what state-writes the success paths do that
# our 5/10-byte prologue patches skipped past.
#
# Context: H-26 phase 2 hooks (FUN_1406a1de0 and FUN_140693cc0) confirmed
# the entire session/RPC layer stays dormant for the whole game session.
# Hypothesis: the H-33 patches we land in src/sync/player_sync.cpp's
# kSites table replace function prologues with early "state = 3 (success)"
# / "EAX = 0; RET" sequences. Whatever the original prologues + bodies
# would have done -- in particular any state-writes that would normally
# wake up the session manager / RPC subsystem -- never runs.
#
# We dump the FULL body of each patched function plus the first ~80
# instructions of each function it calls. We're hunting for:
#   - writes to other globals (not just [this+0x10])
#   - writes to inner-object state via [GameManager+0x22F0]+offset
#   - calls into the network/session subsystem ("Open", "Init", "Start",
#     "Connect", "Begin", "Activate", anything that smells like kickoff)
#
#@runtime Jython
#
# Output: D:\Applications\DS2\Seamless\tools\ghidra_h26_h33_bodies_results.txt

OUT_PATH = r"D:\Applications\DS2\Seamless\tools\ghidra_h26_h33_bodies_results.txt"

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

# The four H-33 patched functions. Labels mirror the BootPatchSite entries
# in src/sync/player_sync.cpp.
TARGETS = [
    ("OnlineCheck_slot8",        0xF98C0, "5-byte patch (XOR EAX,EAX; RET) -- offline-arm shortcut"),
    ("SteamNetCheck_OnEnter",    0xF8FB0, "10-byte patch ([RCX+0x10]=3; XOR EAX,EAX; RET)"),
    ("GameServerLogin_slot8",    0xF9820, "5-byte patch (XOR EAX,EAX; RET)"),
    ("UserPolicy_OnEnter",       0xF9040, "10-byte patch ([RCX+0x10]=3; XOR EAX,EAX; RET)"),
    # Also dump the shared OnEnter at +0x104ED0 used by GameServerLogin,
    # OnlineCheck, ProcessWindowBase. Not directly patched, but its
    # behaviour-after-predicate matters for understanding where success-
    # path session-init might live.
    ("SharedSubStateOnEnter",    0x104ED0, "Shared OnEnter (calls vtable[slot 8] then stores result)"),
]

def dumpFuncFull(fn, max_inst=600):
    if fn is None:
        log("  (function not resolved)")
        return []
    ep = fn.getEntryPoint()
    body = fn.getBody()
    size = body.getNumAddresses() if body else 0
    log("\n--- %s @ +0x%X (%d bytes) ---" % (fn.getName(), exeOffset(ep), size))
    callees = []
    it = listing.getInstructions(ep, True)
    count = 0
    while it.hasNext() and count < max_inst:
        inst = it.next()
        if not body.contains(inst.getAddress()):
            break
        log("  %s (+0x%X)  %s" % (inst.getAddress(),
                                   exeOffset(inst.getAddress()),
                                   inst.toString()))
        # Track CALL targets so we can dump them after the parent.
        mn = inst.getMnemonicString()
        if mn.startswith("CALL"):
            for r in inst.getReferencesFrom():
                ta = r.getToAddress()
                if ta is None:
                    continue
                tva = ta.getOffset()
                # Only follow direct calls inside the image
                if baseVA <= tva < baseVA + 0x10000000:
                    callees.append(tva)
        count += 1
    return callees

def dumpCalleeHead(target_va, max_inst=80):
    fn = funcMgr.getFunctionAt(addrFromVA(target_va))
    if fn is None:
        fn = funcMgr.getFunctionContaining(addrFromVA(target_va))
    if fn is None:
        log("\n  -- callee +0x%X: (no function resolved)" % (target_va - baseVA))
        return
    ep = fn.getEntryPoint()
    body = fn.getBody()
    size = body.getNumAddresses() if body else 0
    log("\n  -- callee %s @ +0x%X (%d bytes, head only) --" %
        (fn.getName(), exeOffset(ep), size))
    it = listing.getInstructions(ep, True)
    count = 0
    while it.hasNext() and count < max_inst:
        inst = it.next()
        if not body.contains(inst.getAddress()):
            break
        log("    %s (+0x%X)  %s" % (inst.getAddress(),
                                     exeOffset(inst.getAddress()),
                                     inst.toString()))
        count += 1

log("=" * 70)
log("H-33 patched functions: full bodies + first level of callees")
log("=" * 70)
log("Purpose: find state-writes in the success path that our prologue")
log("patches skipped. Hunting for writes that would normally wake up the")
log("session/RPC subsystem (currently confirmed dormant: 0 protobuf sent).")
log("=" * 70)

all_callees = set()
target_offsets = set(rva for _, rva, _ in TARGETS)

for label, rva, note in TARGETS:
    log("\n" + "=" * 70)
    log("=== %s @ +0x%X ===" % (label, rva))
    log("    %s" % note)
    log("=" * 70)
    fn = funcMgr.getFunctionAt(addrFromVA(baseVA + rva))
    if fn is None:
        fn = funcMgr.getFunctionContaining(addrFromVA(baseVA + rva))
    callees = dumpFuncFull(fn, max_inst=400)
    for c in callees:
        # Skip the targets themselves to avoid re-dumping
        if (c - baseVA) not in target_offsets:
            all_callees.add(c)

log("\n" + "=" * 70)
log("First-level callees (heads only, deduplicated)")
log("=" * 70)

for cva in sorted(all_callees):
    dumpCalleeHead(cva, max_inst=80)

log("\n" + "=" * 70)
log("Done.")
log("Next step in the txt file: look for instructions of the form")
log("  MOV [RAX/RCX/RDI + small_offset], imm32  (state writes)")
log("  MOV [global_va], reg                      (global writes)")
log("  CALL <function whose name/comment suggests Init/Start/Connect>")
log("=" * 70)

with open(OUT_PATH, 'w') as f:
    f.write('\n'.join(results))

print("\nSaved to %s (%d lines)" % (OUT_PATH, len(results)))
