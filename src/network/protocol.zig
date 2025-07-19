const std = @import("std");
const network = @import("network.zig");
const block = @import("../ledger/block.zig");
const transaction = @import("../ledger/transaction.zig");
const crypto = @import("../crypto/crypto.zig");

/// Cardano node-to-node wire protocol implementation
pub const Protocol = struct {
    /// Message types in the Cardano protocol
    pub const MessageType = enum(u16) {
        // Handshake protocol
        msg_propose_versions = 0,
        msg_accept_version = 1,
        msg_refuse = 2,

        // Chain sync protocol
        msg_request_next = 3,
        msg_await_reply = 4,
        msg_roll_forward = 5,
        msg_roll_backward = 6,
        msg_find_intersection = 7,
        msg_intersect_found = 8,
        msg_intersect_not_found = 9,
        msg_done = 10,

        // Block fetch protocol
        msg_request_range = 11,
        msg_start_batch = 12,
        msg_no_blocks = 13,
        msg_block = 14,
        msg_batch_done = 15,

        // TxSubmission protocol
        msg_request_tx_ids = 16,
        msg_reply_tx_ids = 17,
        msg_request_txs = 18,
        msg_reply_txs = 19,

        // Keep-alive protocol
        msg_keep_alive = 20,
        msg_keep_alive_response = 21,
    };

    /// Protocol message header
    pub const MessageHeader = struct {
        timestamp: u32,
        msg_type: MessageType,
        payload_size: u32,

        pub const SIZE = 10; // 4 + 2 + 4 bytes

        pub fn encode(self: MessageHeader, writer: anytype) !void {
            try writer.writeInt(u32, self.timestamp, .big);
            try writer.writeInt(u16, @intFromEnum(self.msg_type), .big);
            try writer.writeInt(u32, self.payload_size, .big);
        }

        pub fn decode(reader: anytype) !MessageHeader {
            return MessageHeader{
                .timestamp = try reader.readInt(u32, .big),
                .msg_type = @enumFromInt(try reader.readInt(u16, .big)),
                .payload_size = try reader.readInt(u32, .big),
            };
        }
    };

    /// Handshake message
    pub const HandshakeMsg = struct {
        network_magic: network.Network.NetworkMagic,
        versions: []const network.Network.ProtocolVersion,

        pub fn encode(self: HandshakeMsg, allocator: std.mem.Allocator) ![]u8 {
            var buffer = std.ArrayList(u8).init(allocator);
            defer buffer.deinit();

            const magic_bytes = self.network_magic.toBytes();
            try buffer.appendSlice(&magic_bytes);
            try buffer.writer().writeInt(u16, @intCast(self.versions.len), .big);

            for (self.versions) |ver| {
                try buffer.writer().writeInt(u16, ver.major, .big);
                try buffer.writer().writeInt(u16, ver.minor, .big);
            }

            return buffer.toOwnedSlice();
        }

        pub fn decode(allocator: std.mem.Allocator, data: []const u8) !HandshakeMsg {
            var stream = std.io.fixedBufferStream(data);
            const reader = stream.reader();

            var magic_bytes: [4]u8 = undefined;
            _ = try reader.read(&magic_bytes);
            const magic_value = (@as(u32, magic_bytes[0]) << 24) |
                (@as(u32, magic_bytes[1]) << 16) |
                (@as(u32, magic_bytes[2]) << 8) |
                @as(u32, magic_bytes[3]);

            const version_count = try reader.readInt(u16, .big);
            var versions = try allocator.alloc(network.Network.ProtocolVersion, version_count);

            for (0..version_count) |i| {
                versions[i] = .{
                    .major = try reader.readInt(u16, .big),
                    .minor = try reader.readInt(u16, .big),
                };
            }

            return HandshakeMsg{
                .network_magic = @enumFromInt(magic_value),
                .versions = versions,
            };
        }
    };

    /// Chain sync messages
    pub const ChainSyncMsg = union(enum) {
        request_next: void,
        await_reply: void,
        roll_forward: struct {
            block_header: block.BlockHeader,
            tip: ChainTip,
        },
        roll_backward: struct {
            point: ChainPoint,
            tip: ChainTip,
        },
        find_intersection: struct {
            points: []const ChainPoint,
        },
        intersect_found: struct {
            point: ChainPoint,
            tip: ChainTip,
        },
        intersect_not_found: struct {
            tip: ChainTip,
        },
        done: void,
    };

    /// Point on the chain
    pub const ChainPoint = union(enum) {
        genesis: void,
        block_point: struct {
            slot: u64,
            hash: crypto.Crypto.Hash256,
        },

        pub fn encode(self: ChainPoint, writer: anytype) !void {
            switch (self) {
                .genesis => try writer.writeByte(0),
                .block_point => |point| {
                    try writer.writeByte(1);
                    try writer.writeInt(u64, point.slot, .big);
                    try writer.writeAll(&point.hash.bytes);
                },
            }
        }
    };

    /// Chain tip information
    pub const ChainTip = struct {
        slot: u64,
        hash: crypto.Crypto.Hash256,
        block_number: u64,

        pub fn encode(self: ChainTip, writer: anytype) !void {
            try writer.writeInt(u64, self.slot, .big);
            try writer.writeAll(&self.hash.bytes);
            try writer.writeInt(u64, self.block_number, .big);
        }
    };

    /// Block fetch messages
    pub const BlockFetchMsg = union(enum) {
        request_range: struct {
            from: ChainPoint,
            to: ChainPoint,
        },
        start_batch: void,
        no_blocks: void,
        block: []const u8, // Raw block data
        batch_done: void,
    };

    /// Transaction submission messages
    pub const TxSubmissionMsg = union(enum) {
        request_tx_ids: struct {
            blocking: bool,
            ack_count: u16,
            req_count: u16,
        },
        reply_tx_ids: struct {
            tx_ids: []const crypto.Crypto.Hash256,
        },
        request_txs: struct {
            tx_ids: []const crypto.Crypto.Hash256,
        },
        reply_txs: struct {
            txs: []const []const u8, // Raw transaction data
        },
    };

    /// Complete protocol message
    pub const Message = union(MessageType) {
        // Handshake
        msg_propose_versions: HandshakeMsg,
        msg_accept_version: network.Network.ProtocolVersion,
        msg_refuse: struct { reason: []const u8 },

        // Chain sync
        msg_request_next: void,
        msg_await_reply: void,
        msg_roll_forward: struct {
            block_header: block.BlockHeader,
            tip: ChainTip,
        },
        msg_roll_backward: struct {
            point: ChainPoint,
            tip: ChainTip,
        },
        msg_find_intersection: struct {
            points: []const ChainPoint,
        },
        msg_intersect_found: struct {
            point: ChainPoint,
            tip: ChainTip,
        },
        msg_intersect_not_found: struct {
            tip: ChainTip,
        },
        msg_done: void,

        // Block fetch
        msg_request_range: struct {
            from: ChainPoint,
            to: ChainPoint,
        },
        msg_start_batch: void,
        msg_no_blocks: void,
        msg_block: []const u8,
        msg_batch_done: void,

        // Tx submission
        msg_request_tx_ids: struct {
            blocking: bool,
            ack: u16,
            req: u16,
        },
        msg_reply_tx_ids: struct {
            tx_ids: []const crypto.Crypto.Hash256,
        },
        msg_request_txs: struct {
            tx_ids: []const crypto.Crypto.Hash256,
        },
        msg_reply_txs: struct {
            txs: []const transaction.Transaction,
        },

        // Keep-alive
        msg_keep_alive: void,
        msg_keep_alive_response: void,
    };
};

test "Protocol message encoding/decoding" {
    const allocator = std.testing.allocator;

    // Test handshake encoding
    const handshake = Protocol.HandshakeMsg{
        .network_magic = .mainnet,
        .versions = &[_]network.Network.ProtocolVersion{
            .{ .major = 11, .minor = 0 },
            .{ .major = 10, .minor = 0 },
        },
    };

    const encoded = try handshake.encode(allocator);
    defer allocator.free(encoded);

    const decoded = try Protocol.HandshakeMsg.decode(allocator, encoded);
    defer allocator.free(decoded.versions);

    try std.testing.expectEqual(handshake.network_magic, decoded.network_magic);
    try std.testing.expectEqual(handshake.versions.len, decoded.versions.len);
    try std.testing.expectEqual(handshake.versions[0].major, decoded.versions[0].major);
}
