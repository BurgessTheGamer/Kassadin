const std = @import("std");
const network = @import("network.zig");

/// Cardano Network Multiplexer (Mux) Protocol
///
/// Implements the ouroboros-network multiplexing layer that allows multiple
/// mini-protocols to share a single TCP connection.
///
/// Frame format (8 bytes):
/// +--------------------------------+
/// | Transmission Time (32 bits)    |
/// +--------------------------------+
/// | M | Protocol ID (15) | Len(16) |
/// +--------------------------------+
///
/// All fields are big-endian.
pub const MuxError = error{
    InvalidFrame,
    FrameTooLarge,
    ProtocolIdTooLarge,
    PayloadTooLarge,
};

/// Maximum SDU (Service Data Unit) size
pub const MAX_SDU_SIZE: u16 = 0xffff; // 65535 bytes

/// Mini-protocol IDs
pub const ProtocolId = enum(u16) {
    handshake = 0,
    chain_sync = 2,
    block_fetch = 3,
    tx_submission = 4,
    keep_alive = 8,
    local_tx_submission = 6,
    local_state_query = 7,
    _,
};

/// Direction of communication
pub const Direction = enum(u1) {
    initiator = 0, // Client
    responder = 1, // Server
};

/// Mux frame header
pub const MuxHeader = struct {
    /// Transmission time in microseconds
    timestamp: u32,
    /// Direction bit (initiator/responder)
    direction: Direction,
    /// Mini-protocol ID (15 bits max)
    protocol_id: u16,
    /// Payload length in bytes
    length: u16,

    /// Encode header to bytes (big-endian)
    pub fn encode(self: MuxHeader) [8]u8 {
        var buf: [8]u8 = undefined;

        // Timestamp (32 bits)
        std.mem.writeInt(u32, buf[0..4], self.timestamp, .big);

        // Protocol ID with direction bit (16 bits total)
        // Format: M (1 bit) | Protocol ID (15 bits)
        const protocol_with_dir = (@as(u16, @intFromEnum(self.direction)) << 15) | (self.protocol_id & 0x7FFF);
        std.mem.writeInt(u16, buf[4..6], protocol_with_dir, .big);

        // Length (16 bits)
        std.mem.writeInt(u16, buf[6..8], self.length, .big);

        return buf;
    }

    /// Decode header from bytes (big-endian)
    pub fn decode(buf: [8]u8) MuxError!MuxHeader {
        // Timestamp
        const timestamp = std.mem.readInt(u32, buf[0..4], .big);

        // Protocol ID with direction bit
        const protocol_with_dir = std.mem.readInt(u16, buf[4..6], .big);
        const direction: Direction = @enumFromInt((protocol_with_dir >> 15) & 1);
        const protocol_id = protocol_with_dir & 0x7FFF;

        // Length
        const length = std.mem.readInt(u16, buf[6..8], .big);

        return MuxHeader{
            .timestamp = timestamp,
            .direction = direction,
            .protocol_id = protocol_id,
            .length = length,
        };
    }
};

/// Mux frame (header + payload)
pub const MuxFrame = struct {
    header: MuxHeader,
    payload: []const u8,

    pub fn deinit(self: *MuxFrame, allocator: std.mem.Allocator) void {
        allocator.free(self.payload);
    }
};

/// Mux connection wraps a TCP stream
pub const MuxConnection = struct {
    stream: std.net.Stream,
    allocator: std.mem.Allocator,
    /// Current timestamp in microseconds (for RemoteClockModel)
    current_time: u32,
    /// Our role in the connection
    our_direction: Direction,

    pub fn init(stream: std.net.Stream, allocator: std.mem.Allocator, is_initiator: bool) MuxConnection {
        return .{
            .stream = stream,
            .allocator = allocator,
            .current_time = 0,
            .our_direction = if (is_initiator) .initiator else .responder,
        };
    }

    /// Get current timestamp in microseconds
    /// For now, we use a simple incrementing counter
    fn getTimestamp(self: *MuxConnection) u32 {
        self.current_time += 1;
        return self.current_time;
    }

    /// Send a frame with the given protocol and payload
    pub fn sendFrame(self: *MuxConnection, protocol_id: ProtocolId, payload: []const u8) !void {
        if (payload.len > MAX_SDU_SIZE) {
            return MuxError.PayloadTooLarge;
        }

        const header = MuxHeader{
            .timestamp = self.getTimestamp(),
            .direction = self.our_direction,
            .protocol_id = @intFromEnum(protocol_id),
            .length = @intCast(payload.len),
        };

        const header_bytes = header.encode();

        // Log what we're sending
        const logger = @import("../utils/logger.zig");
        logger.debug("Mux sending frame: timestamp={}, dir={}, protocol={}, len={}", .{
            header.timestamp,
            @intFromEnum(header.direction),
            header.protocol_id,
            header.length,
        });
        logger.debug("Mux header bytes: {x}", .{std.fmt.fmtSliceHexLower(&header_bytes)});

        // Send header
        const header_written = try self.stream.write(&header_bytes);
        logger.debug("Mux wrote {} header bytes", .{header_written});

        // Send payload
        if (payload.len > 0) {
            const payload_written = try self.stream.write(payload);
            logger.debug("Mux wrote {} payload bytes", .{payload_written});
        }
    }
    /// Receive a frame from the connection
    pub fn recvFrame(self: *MuxConnection) !MuxFrame {
        // Read header
        var header_buf: [8]u8 = undefined;
        const bytes_read = self.stream.read(&header_buf) catch |err| {
            const logger = @import("../utils/logger.zig");
            logger.debug("Mux read error: {}", .{err});
            return err;
        };

        const logger = @import("../utils/logger.zig");

        if (bytes_read == 0) {
            logger.debug("Mux received 0 bytes - connection closed", .{});
            return error.ConnectionClosed;
        }

        logger.debug("Mux received {} header bytes: {x}", .{ bytes_read, std.fmt.fmtSliceHexLower(header_buf[0..bytes_read]) });
        const header = try MuxHeader.decode(header_buf);

        logger.debug("Mux decoded frame: timestamp={}, dir={}, protocol={}, len={}", .{
            header.timestamp,
            @intFromEnum(header.direction),
            header.protocol_id,
            header.length,
        });

        // Validate length
        if (header.length > MAX_SDU_SIZE) {
            return MuxError.FrameTooLarge;
        }

        // Read payload
        const payload = try self.allocator.alloc(u8, header.length);
        errdefer self.allocator.free(payload);

        if (header.length > 0) {
            _ = try self.stream.read(payload);
        }

        return MuxFrame{
            .header = header,
            .payload = payload,
        };
    }
    /// Send raw bytes for a specific protocol
    pub fn send(self: *MuxConnection, protocol_id: ProtocolId, data: []const u8) !void {
        try self.sendFrame(protocol_id, data);
    }

    /// Receive raw bytes for any protocol
    pub fn recv(self: *MuxConnection) !MuxFrame {
        return try self.recvFrame();
    }
};

// Tests
test "MuxHeader encode/decode" {
    const original = MuxHeader{
        .timestamp = 0x12345678,
        .direction = .initiator,
        .protocol_id = 42,
        .length = 1234,
    };

    const encoded = original.encode();
    const decoded = try MuxHeader.decode(encoded);

    try std.testing.expectEqual(original.timestamp, decoded.timestamp);
    try std.testing.expectEqual(original.direction, decoded.direction);
    try std.testing.expectEqual(original.protocol_id, decoded.protocol_id);
    try std.testing.expectEqual(original.length, decoded.length);
}

test "MuxHeader with responder direction" {
    const original = MuxHeader{
        .timestamp = 0xAABBCCDD,
        .direction = .responder,
        .protocol_id = 0x7FFF, // Max protocol ID (15 bits)
        .length = 0xFFFF, // Max length
    };

    const encoded = original.encode();
    const decoded = try MuxHeader.decode(encoded);

    try std.testing.expectEqual(original.timestamp, decoded.timestamp);
    try std.testing.expectEqual(original.direction, decoded.direction);
    try std.testing.expectEqual(original.protocol_id, decoded.protocol_id);
    try std.testing.expectEqual(original.length, decoded.length);
}
