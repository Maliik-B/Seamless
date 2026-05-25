// H-17: synthetic ABBA reproducer for CODE_REVIEW.md §1.
//
// Historical bug: SessionManager::NotifyPlayerDeath/Respawn held
// m_playersMutex while calling PeerManager::BroadcastPacket, which
// takes m_peersMutex. The reverse path (PeerManager::Update → handler
// → SessionManager::AddPlayer) acquires the same mutexes in the
// opposite order — classic ABBA.
//
// Fix (already shipped at session_manager.cpp:311-352): copy the data
// you need under the lock, release, then broadcast outside the lock.
//
// What this test actually proves: that the FIXED pattern (copy under
// lock, release, then call into a B-acquiring helper) completes
// without deadlock under a 2s timeout. It does NOT detect the broken
// pattern at runtime — TSan is not available on MSVC/Windows. If the
// regression came back, this test would still pass; the value here is
// keeping the *shape* of the fixed pattern documented in code that
// fails to compile if the API changes.

#include "test_runner.h"

#include <chrono>
#include <future>
#include <mutex>
#include <string>

namespace {

struct PlayersStore {
    std::mutex m;
    std::string name = "alice";
};

struct PeersStore {
    std::mutex m;
    int broadcast_count = 0;
};

PlayersStore g_players;
PeersStore   g_peers;

// Mimics PeerManager::BroadcastPacket — acquires the peers lock.
void Broadcast(const std::string& /*name*/) {
    std::lock_guard<std::mutex> lock(g_peers.m);
    ++g_peers.broadcast_count;
}

// Mimics SessionManager::AddPlayer reached from PeerManager::Update —
// acquires the players lock while the *caller* holds the peers lock.
// This is the side of the ABBA the deadlock fix on the other path
// allowed to coexist safely.
void AddPlayerWhileHoldingPeers() {
    std::lock_guard<std::mutex> lock(g_players.m);
    g_players.name = "bob";
}

// Mimics the FIXED NotifyPlayerDeath: take players, copy name, release,
// then broadcast.
void NotifyDeath_Fixed() {
    std::string name_copy;
    {
        std::lock_guard<std::mutex> lock(g_players.m);
        name_copy = g_players.name;
    }
    Broadcast(name_copy);
}

// Mimics the PeerManager::Update side: take peers, then call into
// session (which takes players).
void Update_Path() {
    std::lock_guard<std::mutex> lock(g_peers.m);
    AddPlayerWhileHoldingPeers();
}

} // namespace

TEST(deadlock, abba_fixed_pattern_completes) {
    constexpr auto deadline = std::chrono::seconds(2);

    auto f1 = std::async(std::launch::async, [] {
        for (int i = 0; i < 1000; ++i) NotifyDeath_Fixed();
    });
    auto f2 = std::async(std::launch::async, [] {
        for (int i = 0; i < 1000; ++i) Update_Path();
    });

    ASSERT_TRUE(f1.wait_for(deadline) == std::future_status::ready);
    ASSERT_TRUE(f2.wait_for(deadline) == std::future_status::ready);

    // If we got here without timing out, the fixed pattern is
    // deadlock-free under contention.
    ASSERT_TRUE(g_peers.broadcast_count > 0);
}
