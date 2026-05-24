// H-17: ParseHotkey moved out of src/core/mod.cpp so it can be exercised
// from a host-side test exe under AddressSanitizer. Behaviour is
// unchanged — see mod.h:43-52 for the declarations and tests/test_hotkey.cpp
// for the bad-input fuzz cases.

#include <Windows.h>

#include "../../include/mod.h"

#include <string>
#include <vector>

// ============================================================================
// H-20 — hotkey-string parser
// ----------------------------------------------------------------------------
// Parses "Ctrl+Shift+End" style chords. Whitespace and case are ignored.
// Modifiers go in any order; exactly one non-modifier key terminates the
// chord. Returns vkey==0 on parse failure.
// ============================================================================
DS2Coop::HotkeyChord DS2Coop::ParseHotkey(const std::string& spec) {
    HotkeyChord chord{};

    auto upper = [](std::string s) {
        for (auto& c : s) {
            if (c >= 'a' && c <= 'z') c = static_cast<char>(c - 'a' + 'A');
        }
        return s;
    };
    auto trim = [](std::string s) {
        size_t a = s.find_first_not_of(" \t");
        size_t b = s.find_last_not_of(" \t");
        if (a == std::string::npos) return std::string{};
        return s.substr(a, b - a + 1);
    };

    // Split on '+'.
    std::vector<std::string> parts;
    {
        std::string cur;
        for (char c : spec) {
            if (c == '+') { parts.push_back(trim(cur)); cur.clear(); }
            else          { cur.push_back(c); }
        }
        parts.push_back(trim(cur));
    }

    auto vkeyFromName = [&](const std::string& nameRaw) -> int {
        std::string n = upper(nameRaw);
        if (n.empty()) return 0;
        // Single A-Z
        if (n.size() == 1 && n[0] >= 'A' && n[0] <= 'Z') return n[0];
        // Single 0-9
        if (n.size() == 1 && n[0] >= '0' && n[0] <= '9') return n[0];
        // F1-F24
        if ((n.size() == 2 || n.size() == 3) && n[0] == 'F') {
            try {
                int idx = std::stoi(n.substr(1));
                if (idx >= 1 && idx <= 24) return VK_F1 + (idx - 1);
            } catch (...) { return 0; }
        }
        if (n == "END")        return VK_END;
        if (n == "HOME")       return VK_HOME;
        if (n == "INSERT" || n == "INS") return VK_INSERT;
        if (n == "DELETE" || n == "DEL") return VK_DELETE;
        if (n == "PAGEUP"   || n == "PGUP") return VK_PRIOR;
        if (n == "PAGEDOWN" || n == "PGDN") return VK_NEXT;
        if (n == "ESCAPE" || n == "ESC")    return VK_ESCAPE;
        if (n == "TAB")        return VK_TAB;
        if (n == "BACKSPACE" || n == "BKSP") return VK_BACK;
        if (n == "SPACE")      return VK_SPACE;
        if (n == "ENTER" || n == "RETURN")  return VK_RETURN;
        return 0;
    };

    for (const auto& partRaw : parts) {
        std::string p = upper(partRaw);
        if (p.empty()) continue;
        if (p == "CTRL" || p == "CONTROL") { chord.need_ctrl  = true; continue; }
        if (p == "SHIFT")                  { chord.need_shift = true; continue; }
        if (p == "ALT")                    { chord.need_alt   = true; continue; }
        // Non-modifier — must be the terminating key. Reject duplicates.
        if (chord.vkey != 0) {
            chord.vkey = 0;
            return chord;
        }
        chord.vkey = vkeyFromName(partRaw);
        if (chord.vkey == 0) return chord;
    }

    return chord;
}
