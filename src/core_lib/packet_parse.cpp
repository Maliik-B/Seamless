// H-17: pure incoming-packet validator. See packet_parse.h for the
// threat model and tests/test_packet.cpp for the bad-input fuzz cases.

#include "packet_parse.h"

#include <cstring>

namespace DS2Coop::Network {

namespace {

// Per-opcode minimum buffer size for known packet types. Returns
// sizeof(PacketHeader) for unknown opcodes — caller will accept them with
// an empty body (preserves the recv loop's "ignore unknown" behaviour).
std::size_t MinSizeFor(PacketType t) {
    switch (t) {
        case PacketType::Handshake:       return sizeof(HandshakePacket);
        case PacketType::Disconnect:      return sizeof(PacketHeader);
        case PacketType::Heartbeat:       return sizeof(PacketHeader);
        case PacketType::SessionCreate:   return sizeof(PacketHeader);
        case PacketType::SessionJoin:     return sizeof(PacketHeader);
        case PacketType::SessionLeave:    return sizeof(PacketHeader);
        case PacketType::SessionUpdate:   return sizeof(PacketHeader);
        case PacketType::PlayerPosition:  return sizeof(PlayerPositionPacket);
        case PacketType::PlayerAction:    return sizeof(PacketHeader);
        case PacketType::PlayerState:     return sizeof(PlayerStatePacket);
        case PacketType::PlayerDeath:     return sizeof(PacketHeader);
        case PacketType::PlayerRespawn:   return sizeof(PacketHeader);
        case PacketType::BossDefeated:    return sizeof(BossDefeatedPacket);
        case PacketType::BonfireRest:     return sizeof(PacketHeader);
        case PacketType::FogGateTransition: return sizeof(PacketHeader);
        case PacketType::ItemPickup:      return sizeof(PacketHeader);
        case PacketType::EventFlag:       return sizeof(EventFlagPacket);
        case PacketType::ChatMessage:     return sizeof(PacketHeader);
        case PacketType::CustomData:      return sizeof(PacketHeader);
    }
    return sizeof(PacketHeader);
}

} // namespace

std::optional<ParsedPacket> ParseIncomingPacket(const uint8_t* buf, std::size_t len) {
    if (buf == nullptr) return std::nullopt;
    if (len < sizeof(PacketHeader)) return std::nullopt;

    // Copy the header out instead of aliasing the (possibly unaligned)
    // buffer through a typed pointer before we've validated the magic.
    PacketHeader header{};
    std::memcpy(&header, buf, sizeof(header));

    if (header.magic != PACKET_MAGIC) return std::nullopt;

    // header.size is attacker-controlled — validate against buffer length
    // BEFORE any downstream reinterpret_cast that trusts it.
    if (header.size < sizeof(PacketHeader)) return std::nullopt;
    if (header.size > len) return std::nullopt;

    const std::size_t min_size = MinSizeFor(header.type);
    if (header.size < min_size) return std::nullopt;
    // Also reject buffers that are physically shorter than the per-opcode
    // minimum, even if header.size lied small. (header.size >= min_size and
    // header.size <= len together imply len >= min_size, but spell it out.)
    if (len < min_size) return std::nullopt;

    ParsedPacket parsed{};
    parsed.type      = header.type;
    parsed.header    = reinterpret_cast<const PacketHeader*>(buf);
    parsed.body      = (header.size > sizeof(PacketHeader))
                         ? buf + sizeof(PacketHeader)
                         : nullptr;
    parsed.body_size = header.size - sizeof(PacketHeader);
    return parsed;
}

} // namespace DS2Coop::Network
