#pragma once

// H-17: pure validator for incoming P2P packets. The recv loop in
// peer_manager.cpp used to check only the magic field, then forward the
// buffer to PacketHandler::HandlePacket which trusts the attacker-
// controlled header->size when reinterpret_cast'ing into per-opcode
// POD structs — that's an OOB read if a peer lies about header.size.
// Calling ParseIncomingPacket gates entry on header.size <= buflen.

#include "../../include/packet_types.h"

#include <cstddef>
#include <cstdint>
#include <optional>

namespace DS2Coop::Network {

struct ParsedPacket {
    PacketType        type;
    const PacketHeader* header;     // points into the caller's buffer
    const uint8_t*    body;         // first byte past the header (may be null)
    std::size_t       body_size;    // header.size - sizeof(PacketHeader)
};

// Returns nullopt if the packet should be dropped (bad magic, truncated,
// header.size lies about the buffer length, header.size < min for the
// opcode). Known opcodes whose buffer is at least the per-opcode minimum
// are accepted; unknown opcodes are accepted with body=nullptr,
// body_size=0 to preserve the recv loop's "ignore unknown" behaviour.
std::optional<ParsedPacket> ParseIncomingPacket(const uint8_t* buf, std::size_t len);

} // namespace DS2Coop::Network
