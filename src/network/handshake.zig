const std = @import("std");
const cbor = @import("../utils/cbor.zig");
const network = @import("network.zig");
const crypto = @import("../crypto/crypto.zig");
const logger = @import("../utils/logger.zig");

/// Cardano node-to-node handshake protocol implementation
pub const Handshake = struct {
    /// Protocol versions we support
    /// Based on Cardano node responses, they support versions 13 and 14
    /// Let's only offer what they explicitly support
    pub const PROTOCOL_VERSIONS = [_]u16{ 14, 13 };

    /// Handshake message types
    pub const MessageType = enum(u8) {
        propose_versions = 0,
        accept_version = 1,
        refuse = 2,
        query_reply = 3,
    };

    /// Protocol parameters for a version
    pub const ProtocolParams = struct {
        network_magic: u32,
        initiator_only: bool = false,
    };

    /// Handshake state
    pub const State = enum {
        initial,
        proposed,
        confirmed,
        refused,
        done,
    };

    state: State,
    our_versions: []const u16,
    agreed_version: ?u16,
    network_magic: u32,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, network_magic: u32) Handshake {
        return .{
            .state = .initial,
            .our_versions = &PROTOCOL_VERSIONS,
            .agreed_version = null,
            .network_magic = network_magic,
            .allocator = allocator,
        };
    }

    /// Create propose versions message
    pub fn createProposeVersions(self: *Handshake) ![]u8 {
        var encoder = cbor.CBOR.Encoder.init(self.allocator);
        defer encoder.deinit();

        // Message is array [messageType, versionMap]
        try encoder.encodeArrayHeader(2);

        // Message type
        try encoder.encodeUint(@intFromEnum(MessageType.propose_versions));

        // Version map
        try encoder.encodeMapHeader(self.our_versions.len);

        for (self.our_versions) |version| {
            // Version number
            try encoder.encodeUint(version);

            // For node-to-node protocol, the version data is just the network magic
            // as a simple integer (no array, no encoding tricks)
            try encoder.encodeUint(self.network_magic);
        }
        const bytes = try self.allocator.dupe(u8, encoder.toBytes());
        return bytes;
    }

    /// Create accept version message
    pub fn createAcceptVersion(self: *Handshake, version: u16) ![]u8 {
        var encoder = cbor.CBOR.Encoder.init(self.allocator);
        defer encoder.deinit();

        // Message is array [messageType, version, params]
        try encoder.encodeArrayHeader(3);

        // Message type
        try encoder.encodeUint(@intFromEnum(MessageType.accept_version));

        // Accepted version
        try encoder.encodeUint(version);

        // Network magic as simple integer
        try encoder.encodeUint(self.network_magic);
        const bytes = try self.allocator.dupe(u8, encoder.toBytes());
        return bytes;
    }

    /// Create refuse message
    pub fn createRefuse(self: *Handshake, reason: []const u8) ![]u8 {
        var encoder = cbor.CBOR.Encoder.init(self.allocator);
        defer encoder.deinit();

        // Message is array [messageType, reason]
        try encoder.encodeArrayHeader(2);

        // Message type
        try encoder.encodeUint(@intFromEnum(MessageType.refuse));

        // Refusal reason
        try encoder.encodeText(reason);

        const bytes = try self.allocator.dupe(u8, encoder.toBytes());
        return bytes;
    }

    /// Process incoming handshake message
    pub fn processMessage(self: *Handshake, data: []const u8) !void {
        var decoder = cbor.CBOR.Decoder.init(data);

        // Decode message array
        const array_len = try decoder.decodeArrayHeader();
        if (array_len < 2) return error.InvalidHandshakeMessage;

        // Get message type
        const msg_type_int = try decoder.decodeUint();
        const msg_type = std.meta.intToEnum(MessageType, msg_type_int) catch return error.UnknownMessageType;

        switch (msg_type) {
            .propose_versions => {
                if (self.state != .initial) return error.UnexpectedMessage;

                // Decode version map
                const map_len = try decoder.decodeMapHeader();

                var best_version: ?u16 = null;
                var i: usize = 0;
                while (i < map_len) : (i += 1) {
                    const version = @as(u16, @intCast(try decoder.decodeUint()));

                    // Version data is just the network magic as an integer
                    const their_magic = @as(u32, @intCast(try decoder.decodeUint()));
                    // Check if we support this version and network magic matches
                    if (their_magic == self.network_magic) {
                        for (self.our_versions) |our_version| {
                            if (our_version == version) {
                                if (best_version == null or version > best_version.?) {
                                    best_version = version;
                                }
                                break;
                            }
                        }
                    }
                }

                if (best_version) |version| {
                    self.agreed_version = version;
                    self.state = .confirmed;
                    logger.info("Handshake: agreed on version {}", .{version});
                } else {
                    self.state = .refused;
                    logger.warn("Handshake: no compatible version found", .{});
                }
            },

            .accept_version => {
                if (self.state != .proposed) return error.UnexpectedMessage;

                const version = @as(u16, @intCast(try decoder.decodeUint()));

                // Verify this is one of our proposed versions
                var found = false;
                for (self.our_versions) |our_version| {
                    if (our_version == version) {
                        found = true;
                        break;
                    }
                }

                if (!found) return error.UnacceptableVersion;

                self.agreed_version = version;
                self.state = .done;
                logger.info("Handshake: peer accepted version {}", .{version});
            },

            .refuse => {
                // Cardano sends refuse with version data, not text
                // The format is [versionMap] where versionMap shows supported versions
                const value_type = try decoder.peekType();

                if (value_type == .text_string) {
                    // Text reason (older protocol)
                    const reason = try decoder.decodeText();
                    logger.warn("Handshake refused: {s}", .{reason});
                } else if (value_type == .array) {
                    // Version data - decode to see what versions they support
                    const arr_len = try decoder.decodeArrayHeader();
                    if (arr_len > 0) {
                        const their_versions = try decoder.decodeArrayHeader();
                        logger.warn("Handshake refused. Peer supports versions:", .{});
                        var i: usize = 0;
                        while (i < their_versions) : (i += 1) {
                            const v = try decoder.decodeUint();
                            logger.warn("  - Version {}", .{v});
                        }
                    }
                } else {
                    logger.warn("Handshake refused with unknown reason type", .{});
                }

                self.state = .refused;
            },

            .query_reply => {
                // Query/reply is used for querying protocol parameters
                // For now, we don't implement this
                return error.NotImplemented;
            },
        }
    }

    /// Perform handshake as initiator
    pub fn performAsInitiator(self: *Handshake, send_fn: anytype, recv_fn: anytype) !u16 {
        // Send propose versions
        const propose_msg = try self.createProposeVersions();
        defer self.allocator.free(propose_msg);

        try send_fn(propose_msg);
        self.state = .proposed;

        // Wait for response
        const response = try recv_fn();
        defer self.allocator.free(response);

        try self.processMessage(response);

        if (self.state == .confirmed) {
            // Send accept version
            const accept_msg = try self.createAcceptVersion(self.agreed_version.?);
            defer self.allocator.free(accept_msg);

            try send_fn(accept_msg);
            self.state = .done;

            return self.agreed_version.?;
        } else if (self.state == .refused) {
            return error.HandshakeRefused;
        } else {
            return error.HandshakeFailed;
        }
    }

    /// Perform handshake as responder
    pub fn performAsResponder(self: *Handshake, send_fn: anytype, recv_fn: anytype) !u16 {
        // Wait for propose versions
        const propose_msg = try recv_fn();
        defer self.allocator.free(propose_msg);

        try self.processMessage(propose_msg);

        if (self.state == .confirmed) {
            // Send accept version
            const accept_msg = try self.createAcceptVersion(self.agreed_version.?);
            defer self.allocator.free(accept_msg);

            try send_fn(accept_msg);

            // Wait for their accept
            const their_accept = try recv_fn();
            defer self.allocator.free(their_accept);

            self.state = .done;
            return self.agreed_version.?;
        } else {
            // Send refuse
            const refuse_msg = try self.createRefuse("No compatible version");
            defer self.allocator.free(refuse_msg);

            try send_fn(refuse_msg);
            return error.HandshakeRefused;
        }
    }
};

// Add missing decodeBool to CBOR decoder
fn addDecodeBoolToCBOR() void {
    // This would be added to cbor.zig
}

test "Handshake message creation" {
    const allocator = std.testing.allocator;

    var handshake = Handshake.init(allocator, 764824073); // mainnet magic

    // Test propose versions message
    const propose_msg = try handshake.createProposeVersions();
    defer allocator.free(propose_msg);

    var decoder = cbor.CBOR.Decoder.init(propose_msg);

    const array_len = try decoder.decodeArrayHeader();
    try std.testing.expectEqual(@as(u64, 2), array_len);

    const msg_type = try decoder.decodeUint();
    try std.testing.expectEqual(@as(u64, 0), msg_type); // propose_versions

    const map_len = try decoder.decodeMapHeader();
    try std.testing.expectEqual(@as(u64, 3), map_len); // 3 versions
}

test "Handshake version negotiation" {
    const allocator = std.testing.allocator;

    var handshake = Handshake.init(allocator, 764824073);

    // Create a mock propose versions message with version 11
    var encoder = cbor.CBOR.Encoder.init(allocator);
    defer encoder.deinit();

    try encoder.encodeArrayHeader(2);
    try encoder.encodeUint(0); // propose_versions
    try encoder.encodeMapHeader(1);
    try encoder.encodeUint(11); // version 11
    try encoder.encodeArrayHeader(2);
    try encoder.encodeUint(764824073); // mainnet magic
    try encoder.encodeBool(false);

    const msg = encoder.toBytes();
    try handshake.processMessage(msg);

    try std.testing.expectEqual(Handshake.State.confirmed, handshake.state);
    try std.testing.expectEqual(@as(u16, 11), handshake.agreed_version.?);
}
