const std = @import("std");
const crypto = @import("../crypto/crypto.zig");
const ledger = @import("../ledger/ledger.zig");
const transaction = @import("../ledger/transaction.zig");
const block = @import("../ledger/block.zig");
const consensus = @import("../consensus/praos.zig");

/// Main network module for P2P communication
pub const Network = struct {
    /// Network magic for mainnet/testnet identification
    pub const NetworkMagic = enum(u32) {
        mainnet = 764824073,
        testnet = 1097911063,
        preprod = 1,
        preview = 2,

        pub fn toBytes(self: NetworkMagic) [4]u8 {
            const value = @intFromEnum(self);
            return .{
                @intCast(value >> 24),
                @intCast((value >> 16) & 0xFF),
                @intCast((value >> 8) & 0xFF),
                @intCast(value & 0xFF),
            };
        }
    };

    /// Peer address information
    pub const PeerAddr = struct {
        ip: std.net.Address,
        node_id: ?[32]u8 = null,

        pub fn format(self: PeerAddr, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
            _ = fmt;
            _ = options;
            try writer.print("{}", .{self.ip});
        }
    };

    /// Connection state
    pub const ConnectionState = enum {
        connecting,
        handshaking,
        established,
        closing,
        closed,
    };

    /// Protocol version
    pub const ProtocolVersion = struct {
        major: u16,
        minor: u16,

        pub const CURRENT = ProtocolVersion{ .major = 11, .minor = 0 };

        pub fn isCompatible(self: ProtocolVersion, other: ProtocolVersion) bool {
            return self.major == other.major;
        }
    };

    /// Node-to-node protocol parameters
    pub const ProtocolParams = struct {
        network_magic: NetworkMagic,
        max_transmission_unit: u32 = 65536,
        max_concurrency: u32 = 2048,
        ping_interval_ms: u64 = 30000,
        handshake_timeout_ms: u64 = 10000,
    };

    /// Peer capabilities
    pub const PeerCapabilities = struct {
        protocol_version: ProtocolVersion,
        services: Services,

        pub const Services = packed struct {
            full_node: bool = true,
            relay: bool = true,
            reserved: u30 = 0,
        };
    };

    /// Network statistics
    pub const Stats = struct {
        messages_sent: u64 = 0,
        messages_received: u64 = 0,
        bytes_sent: u64 = 0,
        bytes_received: u64 = 0,
        peers_connected: u32 = 0,
        peers_discovered: u32 = 0,

        pub fn update(self: *Stats, sent: bool, bytes: usize) void {
            if (sent) {
                self.messages_sent += 1;
                self.bytes_sent += bytes;
            } else {
                self.messages_received += 1;
                self.bytes_received += bytes;
            }
        }
    };

    /// Error types
    pub const Error = error{
        InvalidMagic,
        IncompatibleVersion,
        HandshakeTimeout,
        InvalidMessage,
        ConnectionClosed,
        PeerMisbehaving,
        ResourceExhausted,
    };
};

test "Network types" {
    const magic = Network.NetworkMagic.mainnet;
    const bytes = magic.toBytes();
    try std.testing.expectEqual(@as(u8, 45), bytes[0]);
    try std.testing.expectEqual(@as(u8, 150), bytes[1]);
    try std.testing.expectEqual(@as(u8, 74), bytes[2]);
    try std.testing.expectEqual(@as(u8, 9), bytes[3]);

    const version = Network.ProtocolVersion.CURRENT;
    try std.testing.expect(version.isCompatible(.{ .major = 11, .minor = 5 }));
    try std.testing.expect(!version.isCompatible(.{ .major = 10, .minor = 0 }));
}
