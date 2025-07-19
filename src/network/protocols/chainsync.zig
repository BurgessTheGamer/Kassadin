const std = @import("std");
const cbor = @import("../../utils/cbor.zig");
const block = @import("../../ledger/block.zig");
const logger = @import("../../utils/logger.zig");

/// Cardano chain-sync mini-protocol implementation
/// This protocol allows downloading headers and blocks from peers
pub const ChainSync = struct {
    /// Protocol states
    pub const State = enum {
        idle,
        intersect,
        can_await,
        must_reply,
        done,
    };

    /// Message types in the protocol
    pub const MessageType = enum(u8) {
        // Client messages
        request_next = 0,
        await_reply = 1,
        roll_forward = 2,
        roll_backward = 3,
        find_intersect = 4,
        intersect_found = 5,
        intersect_not_found = 6,
        done = 7,
    };

    /// Point on the chain (slot + hash)
    pub const Point = struct {
        slot: u64,
        hash: [32]u8,

        pub fn encode(self: Point, encoder: *cbor.CBOR.Encoder) !void {
            // Check if this is origin/genesis (slot 0 and null/empty hash)
            const is_origin = self.slot == 0 and std.mem.allEqual(u8, &self.hash, 0);

            if (is_origin) {
                // Origin is encoded as empty array
                try encoder.encodeArrayHeader(0);
            } else {
                // Regular point is [slot, hash]
                try encoder.encodeArrayHeader(2);
                try encoder.encodeUint(self.slot);
                try encoder.encodeBytes(&self.hash);
            }
        }
        pub fn decode(decoder: *cbor.CBOR.Decoder) !Point {
            // Check if it's an empty array (origin)
            const peek_type = try decoder.peekType();

            if (peek_type == .array) {
                const len = try decoder.decodeArrayHeader();

                if (len == 0) {
                    // Origin point
                    return Point{
                        .slot = 0,
                        .hash = [_]u8{0} ** 32,
                    };
                } else if (len == 2) {
                    // Regular point
                    const slot = try decoder.decodeUint();
                    const hash_bytes = try decoder.decodeBytes();
                    if (hash_bytes.len != 32) return error.InvalidHashLength;

                    var hash: [32]u8 = undefined;
                    @memcpy(&hash, hash_bytes);

                    return Point{
                        .slot = slot,
                        .hash = hash,
                    };
                } else {
                    return error.InvalidPoint;
                }
            } else {
                return error.InvalidPoint;
            }
        }
    };

    /// Tip information
    pub const Tip = struct {
        point: Point,
        block_number: u64,

        pub fn encode(self: Tip, encoder: *cbor.CBOR.Encoder) !void {
            try encoder.encodeArrayHeader(2);
            try self.point.encode(encoder);
            try encoder.encodeUint(self.block_number);
        }

        pub fn decode(decoder: *cbor.CBOR.Decoder) !Tip {
            const len = try decoder.decodeArrayHeader();
            if (len != 2) return error.InvalidTip;

            const point = try Point.decode(decoder);
            const block_number = try decoder.decodeUint();

            return Tip{
                .point = point,
                .block_number = block_number,
            };
        }
    };

    allocator: std.mem.Allocator,
    state: State,
    their_tip: ?Tip,
    last_block_number: u64,

    pub fn init(allocator: std.mem.Allocator) ChainSync {
        return .{
            .allocator = allocator,
            .state = .idle,
            .their_tip = null,
            .last_block_number = 0,
        };
    }

    /// Create a FindIntersect message to find common chain point
    pub fn createFindIntersect(self: *ChainSync, points: []const Point) ![]u8 {
        var encoder = cbor.CBOR.Encoder.init(self.allocator);
        defer encoder.deinit();

        // Message format: [msgType, [points]]
        try encoder.encodeArrayHeader(2);
        try encoder.encodeUint(@intFromEnum(MessageType.find_intersect));

        // Encode points array
        try encoder.encodeArrayHeader(points.len);
        for (points) |point| {
            try point.encode(&encoder);
        }

        const bytes = try self.allocator.dupe(u8, encoder.toBytes());
        self.state = .intersect;
        return bytes;
    }

    /// Create a RequestNext message to get next block
    pub fn createRequestNext(self: *ChainSync) ![]u8 {
        if (self.state != .idle and self.state != .can_await) {
            return error.InvalidState;
        }

        var encoder = cbor.CBOR.Encoder.init(self.allocator);
        defer encoder.deinit();

        // Simple message: [msgType]
        try encoder.encodeArrayHeader(1);
        try encoder.encodeUint(@intFromEnum(MessageType.request_next));

        const bytes = try self.allocator.dupe(u8, encoder.toBytes());
        self.state = .must_reply;
        return bytes;
    }

    /// Create a Done message to end the protocol
    pub fn createDone(self: *ChainSync) ![]u8 {
        var encoder = cbor.CBOR.Encoder.init(self.allocator);
        defer encoder.deinit();

        // Simple message: [msgType]
        try encoder.encodeArrayHeader(1);
        try encoder.encodeUint(@intFromEnum(MessageType.done));

        const bytes = try self.allocator.dupe(u8, encoder.toBytes());
        self.state = .done;
        return bytes;
    }

    /// Process incoming chain-sync message
    pub fn processMessage(self: *ChainSync, data: []const u8) !void {
        logger.debug("Processing chain-sync message, {} bytes, current state: {s}", .{ data.len, @tagName(self.state) });

        var decoder = cbor.CBOR.Decoder.init(data);
        const array_len = decoder.decodeArrayHeader() catch |err| {
            logger.err("Failed to decode array header: {}", .{err});
            return err;
        };
        if (array_len < 1) return error.InvalidMessage;

        const msg_type_int = decoder.decodeUint() catch |err| {
            logger.err("Failed to decode message type: {}", .{err});
            return err;
        };
        const msg_type = std.meta.intToEnum(MessageType, msg_type_int) catch return error.UnknownMessageType;

        logger.debug("Received message type: {s} ({})", .{ @tagName(msg_type), msg_type_int });
        switch (msg_type) {
            .roll_forward => {
                if (self.state != .must_reply) return error.UnexpectedMessage;

                // In NtN mode, the header is wrapped in an array
                // Format: [era, header_bytes] where era might be 0 for Byron
                const header_array_len = decoder.decodeArrayHeader() catch |err| {
                    std.debug.print("DEBUG: Failed to decode header array: {}\n", .{err});
                    return err;
                };
                if (header_array_len != 2) {
                    std.debug.print("DEBUG: Invalid header array length: {}\n", .{header_array_len});
                    return error.InvalidMessage;
                }

                const era = decoder.decodeUint() catch |err| {
                    std.debug.print("DEBUG: Failed to decode era: {}\n", .{err});
                    return err;
                };
                // For Byron era (0), the header might be wrapped differently
                // Let's check what we actually have
                const header_data = if (era == 0) blk: {
                    // Peek at the next type to see what we're dealing with
                    const next_type = decoder.peekType() catch |err| {
                        std.debug.print("DEBUG: Failed to peek type: {}\n", .{err});
                        return err;
                    };

                    if (next_type == .array) {
                        const byron_array_len = decoder.decodeArrayHeader() catch |err| {
                            std.debug.print("DEBUG: Failed to decode Byron array: {}\n", .{err});
                            return err;
                        };

                        if (byron_array_len == 2) {
                            // Format: [[type, size], Tag{24, header}]
                            // First element is metadata array
                            const metadata_len = decoder.decodeArrayHeader() catch |err| {
                                std.debug.print("DEBUG: Failed to decode Byron metadata array: {}\n", .{err});
                                return err;
                            };

                            if (metadata_len != 2) {
                                std.debug.print("DEBUG: Invalid metadata array length: {}\n", .{metadata_len});
                                return error.InvalidMessage;
                            }

                            const byron_type = decoder.decodeUint() catch |err| {
                                std.debug.print("DEBUG: Failed to decode Byron type: {}\n", .{err});
                                return err;
                            };
                            const byron_size = decoder.decodeUint() catch |err| {
                                std.debug.print("DEBUG: Failed to decode Byron size: {}\n", .{err});
                                return err;
                            };

                            // Second element is a CBOR tag (24) containing the header
                            const tag_type = decoder.peekType() catch |err| {
                                std.debug.print("DEBUG: Failed to peek tag type: {}\n", .{err});
                                return err;
                            };

                            if (tag_type == .tag) {
                                const tag_num = decoder.decodeTag() catch |err| {
                                    std.debug.print("DEBUG: Failed to decode tag: {}\n", .{err});
                                    return err;
                                };
                                if (tag_num != 24) {
                                    std.debug.print("DEBUG: Unexpected tag number: {}\n", .{tag_num});
                                    return error.InvalidMessage;
                                }
                            }

                            const header_bytes = decoder.decodeBytes() catch |err| {
                                std.debug.print("DEBUG: Failed to decode Byron header bytes: {}\n", .{err});
                                return err;
                            };

                            logger.debug("Byron block - type: {}, size: {}, header len: {}", .{ byron_type, byron_size, header_bytes.len });
                            break :blk header_bytes;
                        } else {
                            std.debug.print("DEBUG: Unexpected Byron array length: {}\n", .{byron_array_len});
                            return error.InvalidMessage;
                        }
                    } else {
                        // Maybe it's just raw bytes?
                        const header_bytes = decoder.decodeBytes() catch |err| {
                            std.debug.print("DEBUG: Failed to decode Byron header as bytes: {}\n", .{err});
                            return err;
                        };
                        break :blk header_bytes;
                    }
                } else decoder.decodeBytes() catch |err| {
                    std.debug.print("DEBUG: Failed to decode header bytes for era {}: {}\n", .{ era, err });
                    return err;
                };
                const tip = Tip.decode(&decoder) catch |err| {
                    std.debug.print("DEBUG: Failed to decode tip: {}\n", .{err});
                    return err;
                };

                self.their_tip = tip;
                self.state = .idle;

                // Only log if this is a new block
                if (tip.block_number > self.last_block_number) {
                    logger.info("ChainSync: Block #{} at slot {} (era {})", .{ tip.block_number, tip.point.slot, era });
                    self.last_block_number = tip.block_number;
                }

                // TODO: Process the block header based on era
                _ = header_data;
            },
            .roll_backward => {
                if (self.state != .must_reply) return error.UnexpectedMessage;

                // Decode rollback point and tip
                const point = try Point.decode(&decoder);
                const tip = try Tip.decode(&decoder);

                self.their_tip = tip;
                self.state = .idle;

                logger.info("ChainSync: Rolled back to slot {}", .{point.slot});
            },

            .await_reply => {
                if (self.state != .must_reply) return error.UnexpectedMessage;
                self.state = .can_await;
                logger.debug("ChainSync: Peer is waiting (no new blocks)", .{});
            },

            .intersect_found => {
                if (self.state != .intersect) return error.UnexpectedMessage;

                // Decode intersection point and tip
                const point = try Point.decode(&decoder);
                const tip = try Tip.decode(&decoder);

                self.their_tip = tip;
                self.state = .idle;

                logger.info("ChainSync: Found intersection at slot {}", .{point.slot});
            },

            .intersect_not_found => {
                if (self.state != .intersect) return error.UnexpectedMessage;

                // Decode tip
                const tip = try Tip.decode(&decoder);

                self.their_tip = tip;
                self.state = .idle;

                logger.warn("ChainSync: No intersection found", .{});
            },

            else => return error.UnexpectedMessageType,
        }
    }

    /// Get current protocol state
    pub fn getState(self: ChainSync) State {
        return self.state;
    }

    /// Check if we can request next block
    pub fn canRequestNext(self: ChainSync) bool {
        return self.state == .idle or self.state == .can_await;
    }
};

// Tests
test "ChainSync message creation" {
    const allocator = std.testing.allocator;
    var cs = ChainSync.init(allocator);

    // Test FindIntersect
    const points = [_]ChainSync.Point{
        .{ .slot = 1000, .hash = [_]u8{0} ** 32 },
        .{ .slot = 2000, .hash = [_]u8{1} ** 32 },
    };

    const intersect_msg = try cs.createFindIntersect(&points);
    defer allocator.free(intersect_msg);

    try std.testing.expect(intersect_msg.len > 0);
    try std.testing.expectEqual(ChainSync.State.intersect, cs.state);

    // Test RequestNext
    cs.state = .idle;
    const next_msg = try cs.createRequestNext();
    defer allocator.free(next_msg);

    try std.testing.expect(next_msg.len > 0);
    try std.testing.expectEqual(ChainSync.State.must_reply, cs.state);
}

test "ChainSync point encoding/decoding" {
    const allocator = std.testing.allocator;
    var encoder = cbor.CBOR.Encoder.init(allocator);
    defer encoder.deinit();

    const point = ChainSync.Point{
        .slot = 12345,
        .hash = [_]u8{0xAB} ** 32,
    };

    try point.encode(&encoder);

    var decoder = cbor.CBOR.Decoder.init(encoder.toBytes());
    const decoded = try ChainSync.Point.decode(&decoder);

    try std.testing.expectEqual(point.slot, decoded.slot);
    try std.testing.expectEqualSlices(u8, &point.hash, &decoded.hash);
}
