#pragma once

#include "packet_types.h"  // PacketType, PacketHeader, per-opcode POD structs

#include <cstdint>
#include <vector>
#include <string>
#include <memory>
#include <mutex>

namespace DS2Coop::Network {

// Peer information
struct PeerInfo {
    uint64_t playerId;
    std::string playerName;
    uint32_t address;
    uint16_t port;
    uint64_t lastHeartbeat;
    bool connected;
};

// Peer manager for handling connections
class PeerManager {
public:
    static PeerManager& GetInstance();
    
    bool Initialize(uint16_t port);
    void Shutdown();
    
    bool CreateSession(const std::string& password);
    bool JoinSession(const std::string& address, uint16_t port, const std::string& password);
    void LeaveSession();
    
    void Update();
    
    bool SendPacket(const PacketHeader* packet, uint64_t targetPlayerId = 0);
    void BroadcastPacket(const PacketHeader* packet);
    
    const std::vector<PeerInfo>& GetPeers() const { return m_peers; }
    bool IsHost() const { return m_isHost; }
    bool IsConnected() const { return m_connected; }

    uint64_t GetLocalPlayerId() const { return m_localPlayerId; }
    const std::string& GetSessionPassword() const { return m_sessionPassword; }

private:
    PeerManager() = default;
    ~PeerManager() = default;
    PeerManager(const PeerManager&) = delete;
    PeerManager& operator=(const PeerManager&) = delete;

    void HandleIncomingPackets();
    void HandleHandshakePacket(const struct HandshakePacket* hs, const struct sockaddr_in& senderAddr);
    void SendHeartbeats();
    void CheckTimeouts();

    bool m_initialized = false;
    bool m_isHost = false;
    bool m_connected = false;
    uint64_t m_localPlayerId = 0;
    uint16_t m_port = 27015;
    std::string m_sessionPassword;
    std::vector<PeerInfo> m_peers;
    mutable std::recursive_mutex m_peersMutex;
    void* m_socket = nullptr;
    uint64_t m_lastHeartbeatMs = 0;
    uint64_t m_connectingTimestampMs = 0; // for handshake timeout
    bool m_handshakeConfirmed = false;    // set true when host responds
};

// Packet handler for processing received packets
class PacketHandler {
public:
    static PacketHandler& GetInstance();
    
    void HandlePacket(const PacketHeader* packet, const PeerInfo& sender);

private:
    PacketHandler() = default;
    ~PacketHandler() = default;
    PacketHandler(const PacketHandler&) = delete;
    PacketHandler& operator=(const PacketHandler&) = delete;
    
    void HandleHandshake(const HandshakePacket* packet, const PeerInfo& sender);
    void HandlePlayerPosition(const PlayerPositionPacket* packet);
    void HandlePlayerState(const PlayerStatePacket* packet);
    void HandleBossDefeated(const BossDefeatedPacket* packet);
    void HandleEventFlag(const EventFlagPacket* packet);
};

} // namespace DS2Coop::Network

