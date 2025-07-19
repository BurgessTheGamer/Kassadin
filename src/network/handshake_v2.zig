const std = @import("std");
const cbor = @import("../utils/cbor.zig");
const network = @import("network.zig");
const logger = @import("../utils/logger.zig");

/// Cardano node-to-node handshake protocol v2
/// Based on analysis of actual Cardano node behavior
pub const HandshakeV2 = struct {
    /// Protocol versions - based on Cardano's current implementation
    pub const PROTOCOL_VERSIONS = [_]u16{ 13, 14 };

    /// Node-to-node version data structure
    pub const NodeToNodeVersionData = struct {
        network_magic: u32,
        initiator_only: bool,
        peer_sharing: u8, // 0 = NoPeerSharing, 1 = PeerSharingPrivate, 2 = PeerSharingPublic
        query: bool,
    };

    /// Handshake message types
    pub const MessageType = enum(u8) {
        propose_versions = 0,
        accept_version = 1,
        refuse = 2,
        query_reply = 3,
    };

    state: State,
    network_magic: u32,
    allocator: std.mem.Allocator,
    agreed_version: ?u16,

    pub const State = enum {
        initial,
        proposed,
        confirmed,
        refused,
        done,
    };

    pub fn init(allocator: std.mem.Allocator, network_magic: u32) HandshakeV2 {
        return .{
            .state = .initial,
            .network_magic = network_magic,
            .allocator = allocator,
            .agreed_version = null,
        };
    }

    /// Create propose versions message with proper encoding for v13/v14
    pub fn createProposeVersions(self: *HandshakeV2) ![]u8 {
        var encoder = cbor.CBOR.Encoder.init(self.allocator);
        defer encoder.deinit();

        // Message is array [messageType, versionMap]
        try encoder.encodeArrayHeader(2);

        // Message type
        try encoder.encodeUint(@intFromEnum(MessageType.propose_versions));

        // Version map
        try encoder.encodeMapHeader(PROTOCOL_VERSIONS.len);

        for (PROTOCOL_VERSIONS) |version| {
            // Version number as key
            try encoder.encodeUint(version);

            // Version data as value
            // For versions 13 and 14, encode as a 4-element array
            try encoder.encodeArrayHeader(4);

            // 1. Network magic
            try encoder.encodeUint(self.network_magic);

            // 2. Initiator only (false for node-to-node)
            try encoder.encodeBool(false);

            // 3. Peer sharing mode (0 = NoPeerSharing)
            try encoder.encodeUint(0);

            // 4. Query mode (false)
            try encoder.encodeBool(false);
        }

        const bytes = try self.allocator.dupe(u8, encoder.toBytes());
        return bytes;
    }

    /// Process incoming handshake message
    pub fn processMessage(self: *HandshakeV2, data: []const u8) !void {
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

                    // Decode version data array
                    const data_len = try decoder.decodeArrayHeader();
                    if (data_len != 4) return error.InvalidVersionData;

                    const their_magic = @as(u32, @intCast(try decoder.decodeUint()));
                    const initiator_only = try decoder.decodeBool();
                    const peer_sharing = @as(u8, @intCast(try decoder.decodeUint()));
                    const query = try decoder.decodeBool();

                    _ = initiator_only;
                    _ = peer_sharing;
                    _ = query;

                    // Check if we support this version and network magic matches
                    if (their_magic == self.network_magic) {
                        for (PROTOCOL_VERSIONS) |our_version| {
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
                for (PROTOCOL_VERSIONS) |our_version| {
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
                // Handle refuse message - it can have various formats
                self.state = .refused;
                logger.warn("Handshake refused by peer", .{});
            },

            .query_reply => {
                // Handle query reply
                logger.info("Received query reply", .{});
            },
        }
    }

    /// Create accept version message
    pub fn createAcceptVersion(self: *HandshakeV2, version: u16) ![]u8 {
        var encoder = cbor.CBOR.Encoder.init(self.allocator);
        defer encoder.deinit();

        // Message is array [messageType, version, versionData]
        try encoder.encodeArrayHeader(3);

        // Message type
        try encoder.encodeUint(@intFromEnum(MessageType.accept_version));

        // Accepted version
        try encoder.encodeUint(version);

        // Version data (4-element array)
        try encoder.encodeArrayHeader(4);
        try encoder.encodeUint(self.network_magic);
        try encoder.encodeBool(false); // initiator_only
        try encoder.encodeUint(0); // peer_sharing
        try encoder.encodeBool(false); // query

        const bytes = try self.allocator.dupe(u8, encoder.toBytes());
        return bytes;
    }
};

// Tests
test "HandshakeV2 createProposeVersions" {
    const allocator = std.testing.allocator;
    var hs = HandshakeV2.init(allocator, 1); // preprod magic

    const msg = try hs.createProposeVersions();
    defer allocator.free(msg);

    // Verify it's valid CBOR
    var decoder = cbor.CBOR.Decoder.init(msg);
    const arr_len = try decoder.decodeArrayHeader();
    try std.testing.expectEqual(@as(usize, 2), arr_len);

    const msg_type = try decoder.decodeUint();
    try std.testing.expectEqual(@as(u64, 0), msg_type);
}
