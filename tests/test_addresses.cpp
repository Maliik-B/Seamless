// H-17: regression test for CODE_REVIEW.md §2 (offset collision).
//
// Historical bug: in Offsets::GameManager, HP and PositionY were both
// 0x34 — they shared the PlayerData base, so one of them was silently
// reading garbage. The fix at addresses.h:192-193 set Health=0x3C and
// MaxHealth=0x40, with comments calling out the old wrong values.
//
// This file static_asserts that the PlayerData-relative offset set is
// pairwise distinct. Any future re-introduction of the bug (e.g.
// "constexpr uint32_t Whatever = 0x3C") becomes a build break, not a
// runtime test failure that has to actually run.
//
// NOTE: the test deliberately does NOT compare Position*/RotationY
// against the stats — those are documented as living under a separate
// base (player entity, not PlayerData). Same value at the same numeric
// offset is intentional there. We assert distinctness only within a
// group of offsets known to share a base.

#include "test_runner.h"

#include "../include/addresses.h"

#include <array>

namespace {

constexpr std::array<uint32_t, 19> kPlayerDataOffsets = {
    DS2Coop::Addresses::Offsets::GameManager::Level,
    DS2Coop::Addresses::Offsets::GameManager::Health,
    DS2Coop::Addresses::Offsets::GameManager::MaxHealth,
    DS2Coop::Addresses::Offsets::GameManager::Stamina,
    DS2Coop::Addresses::Offsets::GameManager::SoulMemory,
    DS2Coop::Addresses::Offsets::GameManager::CharacterName,
    DS2Coop::Addresses::Offsets::GameManager::Covenant,
    DS2Coop::Addresses::Offsets::GameManager::TeamType,
    DS2Coop::Addresses::Offsets::GameManager::LastBonfire,
    DS2Coop::Addresses::Offsets::GameManager::Hollowing,
    DS2Coop::Addresses::Offsets::GameManager::Stats,
    DS2Coop::Addresses::Offsets::GameManager::Vigor,
    DS2Coop::Addresses::Offsets::GameManager::Endurance,
    DS2Coop::Addresses::Offsets::GameManager::Vitality,
    DS2Coop::Addresses::Offsets::GameManager::Strength,
    DS2Coop::Addresses::Offsets::GameManager::Dexterity,
    DS2Coop::Addresses::Offsets::GameManager::Intelligence,
    DS2Coop::Addresses::Offsets::GameManager::Faith,
    DS2Coop::Addresses::Offsets::GameManager::Adaptability,
};

constexpr bool AllPairwiseDistinct() {
    for (std::size_t i = 0; i < kPlayerDataOffsets.size(); ++i) {
        for (std::size_t j = i + 1; j < kPlayerDataOffsets.size(); ++j) {
            if (kPlayerDataOffsets[i] == kPlayerDataOffsets[j]) return false;
        }
    }
    return true;
}

static_assert(AllPairwiseDistinct(),
    "CODE_REVIEW.md §2 regression: two PlayerData-relative offsets collide. "
    "See addresses.h:192-193 — Health was 0x0 / MaxHealth was 0x1C; "
    "HP/PositionY both used to be 0x34. Fix the new collision before merging.");

// Also belt-and-suspenders the AC-named values explicitly so a reviewer
// sees them.
static_assert(DS2Coop::Addresses::Offsets::GameManager::Health    == 0x3C,
    "Health offset moved away from 0x3C — re-verify against Bob Edition CT.");
static_assert(DS2Coop::Addresses::Offsets::GameManager::MaxHealth == 0x40,
    "MaxHealth offset moved away from 0x40 — re-verify against Bob Edition CT.");

} // namespace

TEST(addresses, no_playerdata_collision) {
    // The real check is the static_assert above. This runtime body lets
    // ctest report the test name explicitly when iterating the suite.
    ASSERT_TRUE(AllPairwiseDistinct());
}
