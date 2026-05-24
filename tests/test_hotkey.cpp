// H-17: bad-input fuzz for DS2Coop::ParseHotkey. ASan is the witness —
// each case must return either a valid chord or a chord with vkey==0
// (parse failure), without UAF / OOB / heap corruption.

#include "test_runner.h"

#include "../include/mod.h"

#include <string>

using DS2Coop::HotkeyChord;
using DS2Coop::ParseHotkey;

TEST(hotkey, empty_string) {
    HotkeyChord c = ParseHotkey("");
    ASSERT_EQ(c.vkey, 0);
    ASSERT_FALSE(c.need_ctrl);
    ASSERT_FALSE(c.need_shift);
    ASSERT_FALSE(c.need_alt);
}

TEST(hotkey, just_plus) {
    HotkeyChord c = ParseHotkey("+");
    ASSERT_EQ(c.vkey, 0);
}

TEST(hotkey, trailing_plus) {
    HotkeyChord c = ParseHotkey("Ctrl+");
    ASSERT_EQ(c.vkey, 0);
    ASSERT_TRUE(c.need_ctrl);
}

TEST(hotkey, leading_plus) {
    HotkeyChord c = ParseHotkey("+End");
    // "+End" → ["", "End"] → empty part skipped, End sets vkey to VK_END.
    ASSERT_NE(c.vkey, 0);
}

TEST(hotkey, duplicate_modifier) {
    // Documented expectation: the parser collapses duplicate modifiers
    // (Ctrl+Ctrl just sets need_ctrl twice). No vkey assignment fails.
    HotkeyChord c = ParseHotkey("Ctrl+Ctrl+End");
    ASSERT_TRUE(c.need_ctrl);
    ASSERT_NE(c.vkey, 0);
}

TEST(hotkey, two_nonmod_terminators) {
    // Two non-modifier keys → parser must reject (sets vkey=0 on the
    // second one).
    HotkeyChord c = ParseHotkey("Ctrl+Shift+A+B");
    ASSERT_EQ(c.vkey, 0);
}

TEST(hotkey, unknown_fkey) {
    HotkeyChord c = ParseHotkey("Ctrl+F99");
    ASSERT_EQ(c.vkey, 0);
}

TEST(hotkey, f25_boundary) {
    // F24 is valid (boundary); F25 is not.
    ASSERT_NE(ParseHotkey("F24").vkey, 0);
    ASSERT_EQ(ParseHotkey("F25").vkey, 0);
}

TEST(hotkey, overlong_pluses) {
    // 4096 '+' characters → 4097 empty parts → no crash, no OOB.
    std::string s(4096, '+');
    HotkeyChord c = ParseHotkey(s);
    ASSERT_EQ(c.vkey, 0);
}

TEST(hotkey, embedded_nul) {
    // std::string preserves embedded NUL; the parser must not treat it
    // as a terminator (uses range-for over the contents).
    std::string s("Ctrl+\0End", 9);
    HotkeyChord c = ParseHotkey(s);
    // Just assert no crash + no UAF (ASan is the witness); the exact
    // accept/reject choice doesn't matter for this regression test.
    (void)c;
    ASSERT_TRUE(true);
}

TEST(hotkey, non_ascii_byte) {
    // Latin-1 'ñ' (0xF1) — must not crash the upper() lambda or stoi.
    std::string s = "Ctrl+\xC3\xB1";
    HotkeyChord c = ParseHotkey(s);
    ASSERT_EQ(c.vkey, 0);  // unknown name
}
