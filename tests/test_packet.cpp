// H-17: malformed-input fuzz for ParseIncomingPacket. ASan is the
// witness — each case must reject (nullopt) without OOB read or UAF.
//
// The bug this closes: HandleIncomingPackets used to check only the
// magic field, then forward the buffer to PacketHandler::HandlePacket
// which reinterpret_cast'd it into per-opcode POD structs using the
// attacker-controlled header->size field to gate the cast. A peer who
// sent a small UDP datagram with a large header.size could trigger
// OOB reads up to ~64 bytes past the buffer end.

#include "test_runner.h"

#include "../src/core_lib/packet_parse.h"
#include "../include/packet_types.h"

#include <array>
#include <cstring>
#include <random>
#include <vector>

using namespace DS2Coop::Network;

namespace {

PacketHeader MakeGoodHeader(PacketType t = PacketType::Heartbeat,
                            uint32_t size_override = 0) {
    PacketHeader h{};
    h.magic     = PACKET_MAGIC;
    h.type      = t;
    h.size      = size_override == 0 ? sizeof(PacketHeader) : size_override;
    h.sequence  = 0;
    h.timestamp = 0;
    return h;
}

std::vector<uint8_t> AsBytes(const PacketHeader& h) {
    std::vector<uint8_t> v(sizeof(h));
    std::memcpy(v.data(), &h, sizeof(h));
    return v;
}

} // namespace

TEST(packet, null_buffer) {
    ASSERT_FALSE(ParseIncomingPacket(nullptr, 64).has_value());
}

TEST(packet, zero_length) {
    uint8_t one_byte = 0;
    ASSERT_FALSE(ParseIncomingPacket(&one_byte, 0).has_value());
}

TEST(packet, one_byte) {
    uint8_t b = 0;
    ASSERT_FALSE(ParseIncomingPacket(&b, 1).has_value());
}

TEST(packet, smaller_than_header) {
    std::array<uint8_t, sizeof(PacketHeader) - 1> buf{};
    ASSERT_FALSE(ParseIncomingPacket(buf.data(), buf.size()).has_value());
}

TEST(packet, bad_magic) {
    PacketHeader h = MakeGoodHeader();
    h.magic = 0xDEADBEEF;
    auto v = AsBytes(h);
    ASSERT_FALSE(ParseIncomingPacket(v.data(), v.size()).has_value());
}

TEST(packet, header_size_below_minimum) {
    PacketHeader h = MakeGoodHeader();
    h.size = 0;
    auto v = AsBytes(h);
    ASSERT_FALSE(ParseIncomingPacket(v.data(), v.size()).has_value());

    h.size = 1;
    v = AsBytes(h);
    ASSERT_FALSE(ParseIncomingPacket(v.data(), v.size()).has_value());
}

TEST(packet, header_size_exceeds_buflen) {
    // *** The latent OOB-read case. ***
    // Physical buffer is sizeof(PacketHeader). Attacker sets
    // header.size = sizeof(HandshakePacket) (much bigger). Validator
    // must reject before any downstream reinterpret_cast happens.
    PacketHeader h = MakeGoodHeader(PacketType::Handshake,
                                    sizeof(HandshakePacket));
    auto v = AsBytes(h);  // only sizeof(PacketHeader) bytes
    ASSERT_FALSE(ParseIncomingPacket(v.data(), v.size()).has_value());
}

TEST(packet, unknown_opcode_accepted) {
    PacketHeader h = MakeGoodHeader();
    h.type = static_cast<PacketType>(0xFE);
    auto v = AsBytes(h);
    auto parsed = ParseIncomingPacket(v.data(), v.size());
    ASSERT_TRUE(parsed.has_value());
    if (parsed) {
        ASSERT_EQ(parsed->body_size, std::size_t{0});
    }
}

TEST(packet, handshake_body_truncated) {
    // header.size advertises a full HandshakePacket, but the buffer is
    // only sizeof(PacketHeader)+1 bytes. Validator must reject —
    // otherwise PacketHandler::HandleHandshake reads ~144 bytes past
    // the end.
    PacketHeader h = MakeGoodHeader(PacketType::Handshake,
                                    sizeof(HandshakePacket));
    std::vector<uint8_t> buf(sizeof(PacketHeader) + 1);
    std::memcpy(buf.data(), &h, sizeof(h));
    ASSERT_FALSE(ParseIncomingPacket(buf.data(), buf.size()).has_value());
}

TEST(packet, well_formed_heartbeat_accepted) {
    PacketHeader h = MakeGoodHeader(PacketType::Heartbeat);
    auto v = AsBytes(h);
    auto parsed = ParseIncomingPacket(v.data(), v.size());
    ASSERT_TRUE(parsed.has_value());
}

TEST(packet, random_garbage_fuzz) {
    // 1 KiB of fixed-seed PRNG output. Most rejections; the rare case
    // where magic happens to match should still respect header.size
    // bounds. ASan validates that nothing reads past buflen.
    std::mt19937 rng(0xC0FFEEu);
    std::vector<uint8_t> buf(1024);
    for (auto& b : buf) b = static_cast<uint8_t>(rng() & 0xFF);

    // Run a sliding window over the buffer at various lengths.
    for (std::size_t len : {std::size_t{0}, std::size_t{4}, std::size_t{16},
                            sizeof(PacketHeader),
                            sizeof(PacketHeader) + 7,
                            buf.size()}) {
        auto parsed = ParseIncomingPacket(buf.data(), len);
        // We don't assert reject/accept — random bytes might happen to
        // match magic + a valid header.size. ASan validates safety; this
        // is a "didn't crash" gate.
        (void)parsed;
    }
    ASSERT_TRUE(true);
}
