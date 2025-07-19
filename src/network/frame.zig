const std = @import("std");
const cbor = @import("../utils/cbor.zig");

/// Cardano network message framing
/// The protocol uses a simple length-prefixed framing with multiplexing
pub const Frame = struct {
    /// Frame header size (8 bytes)
    pub const HEADER_SIZE: usize = 8;

    /// Maximum frame payload size (64KB)
    pub const MAX_PAYLOAD_SIZE: usize = 65536;

    /// Protocol ID for mini-protocols
    pub const ProtocolId = enum(u16) {
        handshake = 0,
        chain_sync = 2,
        block_fetch = 3,
        tx_submission = 4,
        keep_alive = 8,
    };

    /// Frame header
    pub const Header = struct {
        /// Transmission time (microseconds since epoch)
        timestamp: u32,
        /// Protocol ID
        protocol_id: ProtocolId,
        /// Payload length
        payload_length: u16,

        pub fn encode(self: Header) [HEADER_SIZE]u8 {
            var bytes: [HEADER_SIZE]u8 = undefined;

            // Timestamp (4 bytes, big-endian)
            std.mem.writeInt(u32, bytes[0..4], self.timestamp, .big);

            // Protocol ID (2 bytes, big-endian)
            std.mem.writeInt(u16, bytes[4..6], @intFromEnum(self.protocol_id), .big);

            // Payload length (2 bytes, big-endian)
            std.mem.writeInt(u16, bytes[6..8], self.payload_length, .big);

            return bytes;
        }

        pub fn decode(bytes: [HEADER_SIZE]u8) !Header {
            const protocol_id_raw = std.mem.readInt(u16, bytes[4..6], .big);
            const protocol_id = std.meta.intToEnum(ProtocolId, protocol_id_raw) catch {
                std.log.err("Unknown protocol ID: {}", .{protocol_id_raw});
                std.log.err("Header bytes: {x}", .{std.fmt.fmtSliceHexLower(&bytes)});
                return error.UnknownProtocolId;
            };

            return Header{
                .timestamp = std.mem.readInt(u32, bytes[0..4], .big),
                .protocol_id = protocol_id,
                .payload_length = std.mem.readInt(u16, bytes[6..8], .big),
            };
        }
    };

    /// Complete frame
    pub const Message = struct {
        header: Header,
        payload: []const u8,
        allocator: std.mem.Allocator,

        pub fn deinit(self: *Message) void {
            self.allocator.free(self.payload);
        }
    };

    /// Frame encoder
    pub const Encoder = struct {
        allocator: std.mem.Allocator,

        pub fn init(allocator: std.mem.Allocator) Encoder {
            return .{ .allocator = allocator };
        }

        /// Encode a message with framing
        pub fn encode(self: Encoder, protocol_id: ProtocolId, payload: []const u8) ![]u8 {
            if (payload.len > MAX_PAYLOAD_SIZE) {
                return error.PayloadTooLarge;
            }

            // Use lower 32 bits of microsecond timestamp
            const timestamp = @as(u32, @truncate(@as(u64, @intCast(std.time.microTimestamp()))));

            const header = Header{
                .timestamp = timestamp,
                .protocol_id = protocol_id,
                .payload_length = @intCast(payload.len),
            };

            var frame = try self.allocator.alloc(u8, HEADER_SIZE + payload.len);

            // Write header
            const header_bytes = header.encode();
            @memcpy(frame[0..HEADER_SIZE], &header_bytes);

            // Write payload
            @memcpy(frame[HEADER_SIZE..], payload);

            return frame;
        }
    };

    /// Frame decoder
    pub const Decoder = struct {
        allocator: std.mem.Allocator,

        pub fn init(allocator: std.mem.Allocator) Decoder {
            return .{ .allocator = allocator };
        }

        /// Decode a frame header
        pub fn decodeHeader(self: Decoder, stream: anytype) !Header {
            _ = self;
            var header_bytes: [HEADER_SIZE]u8 = undefined;
            _ = try stream.read(&header_bytes);
            return try Header.decode(header_bytes);
        }

        /// Decode a complete frame
        pub fn decode(self: Decoder, stream: anytype) !Message {
            const header = try self.decodeHeader(stream);

            if (header.payload_length > MAX_PAYLOAD_SIZE) {
                return error.PayloadTooLarge;
            }

            const payload = try self.allocator.alloc(u8, header.payload_length);
            errdefer self.allocator.free(payload);

            _ = try stream.read(payload);

            return Message{
                .header = header,
                .payload = payload,
                .allocator = self.allocator,
            };
        }
    };
};

// Tests
test "Frame encoding and decoding" {
    const allocator = std.testing.allocator;

    // Create encoder and decoder
    const encoder = Frame.Encoder.init(allocator);
    const decoder = Frame.Decoder.init(allocator);

    // Test payload
    const payload = "Hello, Cardano!";

    // Encode frame
    const frame = try encoder.encode(.handshake, payload);
    defer allocator.free(frame);

    // Decode frame
    var stream = std.io.fixedBufferStream(frame);
    var message = try decoder.decode(stream.reader());
    defer message.deinit();

    // Verify
    try std.testing.expectEqual(Frame.ProtocolId.handshake, message.header.protocol_id);
    try std.testing.expectEqual(@as(u16, payload.len), message.header.payload_length);
    try std.testing.expectEqualStrings(payload, message.payload);
}

test "Frame header encoding" {
    const header = Frame.Header{
        .timestamp = 0x12345678,
        .protocol_id = .chain_sync,
        .payload_length = 0x1234,
    };

    const bytes = header.encode();

    // Check timestamp
    try std.testing.expectEqual(@as(u8, 0x12), bytes[0]);
    try std.testing.expectEqual(@as(u8, 0x34), bytes[1]);
    try std.testing.expectEqual(@as(u8, 0x56), bytes[2]);
    try std.testing.expectEqual(@as(u8, 0x78), bytes[3]);

    // Check protocol ID (chain_sync = 2)
    try std.testing.expectEqual(@as(u8, 0x00), bytes[4]);
    try std.testing.expectEqual(@as(u8, 0x02), bytes[5]);

    // Check payload length
    try std.testing.expectEqual(@as(u8, 0x12), bytes[6]);
    try std.testing.expectEqual(@as(u8, 0x34), bytes[7]);

    // Decode and verify
    const decoded = try Frame.Header.decode(bytes);
    try std.testing.expectEqual(header.timestamp, decoded.timestamp);
    try std.testing.expectEqual(header.protocol_id, decoded.protocol_id);
    try std.testing.expectEqual(header.payload_length, decoded.payload_length);
}
