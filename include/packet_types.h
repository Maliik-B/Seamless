#pragma once

// H-17: pure POD packet types, host-buildable (no Winsock / mutex / vector).
// Included by network.h for backwards compatibility, by the core_lib packet
// validator, and by tests/test_packet.cpp.

#include <cstdint>

namespace DS2Coop::Network {

// Packet types for communication
enum class PacketType : uint8_t {
    // Connection management
    Handshake = 0x01,
    Disconnect = 0x02,
    Heartbeat = 0x03,

    // Session management
    SessionCreate = 0x10,
    SessionJoin = 0x11,
    SessionLeave = 0x12,
    SessionUpdate = 0x13,

    // Player synchronization
    PlayerPosition = 0x20,
    PlayerAction = 0x21,
    PlayerState = 0x22,
    PlayerDeath = 0x23,
    PlayerRespawn = 0x24,

    // Game state synchronization
    BossDefeated = 0x30,
    BonfireRest = 0x31,
    FogGateTransition = 0x32,
    ItemPickup = 0x33,
    EventFlag = 0x34,

    // Custom data
    ChatMessage = 0x40,
    CustomData = 0x41
};

// Base packet structure
#pragma pack(push, 1)
struct PacketHeader {
    uint32_t magic;          // Magic number for validation
    PacketType type;         // Packet type
    uint32_t size;           // Total packet size including header
    uint32_t sequence;       // Sequence number
    uint64_t timestamp;      // Timestamp
};
#pragma pack(pop)

// Packet data structures
#pragma pack(push, 1)
struct HandshakePacket {
    PacketHeader header;
    uint32_t version;
    uint64_t playerId;
    char playerName[32];
    char password[64];
};

struct PlayerPositionPacket {
    PacketHeader header;
    uint64_t playerId;
    float x, y, z;
    float rotX, rotY, rotZ;
    uint32_t animation;
};

struct PlayerStatePacket {
    PacketHeader header;
    uint64_t playerId;
    int32_t health;
    int32_t maxHealth;
    int32_t stamina;
    int32_t maxStamina;
    uint32_t souls;
    uint32_t soulLevel;
};

struct BossDefeatedPacket {
    PacketHeader header;
    uint32_t bossId;
    uint64_t defeatTime;
};

struct EventFlagPacket {
    PacketHeader header;
    uint32_t flagId;
    bool flagValue;
};
#pragma pack(pop)

// Magic number used by every DS2 Seamless co-op packet ("DS2C" little-endian).
constexpr uint32_t PACKET_MAGIC = 0x44533243;

} // namespace DS2Coop::Network
