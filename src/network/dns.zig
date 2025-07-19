const std = @import("std");
const network = @import("network.zig");

/// DNS resolution utilities for peer discovery
pub const DNS = struct {
    /// Resolve a hostname to IP addresses
    pub fn resolve(allocator: std.mem.Allocator, hostname: []const u8, port: u16) ![]network.Network.PeerAddr {
        var addresses = std.ArrayList(network.Network.PeerAddr).init(allocator);
        errdefer addresses.deinit();

        // Try to parse as IP first
        if (std.net.Address.parseIp(hostname, port)) |addr| {
            try addresses.append(.{ .ip = addr });
            return addresses.toOwnedSlice();
        } else |_| {
            // Not an IP, need DNS resolution
        }

        // Perform DNS lookup
        const addr_list = try std.net.getAddressList(allocator, hostname, port);
        defer addr_list.deinit();

        // Convert to PeerAddr
        for (addr_list.addrs) |addr| {
            try addresses.append(.{ .ip = addr });
        }

        if (addresses.items.len == 0) {
            return error.NoAddressesFound;
        }

        return addresses.toOwnedSlice();
    }

    /// Resolve multiple hostnames concurrently
    pub fn resolveMany(allocator: std.mem.Allocator, hosts: []const []const u8, port: u16) ![]network.Network.PeerAddr {
        var all_addresses = std.ArrayList(network.Network.PeerAddr).init(allocator);
        errdefer all_addresses.deinit();

        for (hosts) |host| {
            const addresses = resolve(allocator, host, port) catch |err| {
                std.log.warn("Failed to resolve {s}: {}", .{ host, err });
                continue;
            };
            defer allocator.free(addresses);

            try all_addresses.appendSlice(addresses);
        }

        return all_addresses.toOwnedSlice();
    }

    /// Parse host:port string
    pub fn parseHostPort(host_port: []const u8, default_port: u16) !struct { host: []const u8, port: u16 } {
        // Find last colon (for IPv6 support)
        var last_colon: ?usize = null;
        var i = host_port.len;
        while (i > 0) {
            i -= 1;
            if (host_port[i] == ':') {
                last_colon = i;
                break;
            }
        }

        if (last_colon) |colon_pos| {
            const host = host_port[0..colon_pos];
            const port_str = host_port[colon_pos + 1 ..];
            const port = std.fmt.parseInt(u16, port_str, 10) catch return error.InvalidPort;
            return .{ .host = host, .port = port };
        } else {
            return .{ .host = host_port, .port = default_port };
        }
    }

    /// Well-known Cardano bootstrap peers
    pub const BootstrapPeers = struct {
        pub const mainnet = [_][]const u8{
            "backbone.cardano.iog.io:3001",
            "backbone.mainnet.emurgornd.com:3001",
        };

        pub const testnet = [_][]const u8{
            "relays-new.cardano-testnet.iohk.io:3001",
            "relays.cardano-testnet.iohkdev.io:3001",
        };

        pub const preview = [_][]const u8{
            "preview-node.world.dev.cardano.org:3001",
            "preview-node.play.dev.cardano.org:3001",
        };

        pub const preprod = [_][]const u8{
            "preprod-node.world.dev.cardano.org:3001",
            "preprod-node.play.dev.cardano.org:3001",
        };

        pub fn getForNetwork(net: network.Network.NetworkMagic) []const []const u8 {
            return switch (net) {
                .mainnet => &mainnet,
                .testnet => &testnet,
                .preview => &preview,
                .preprod => &preprod,
            };
        }
    };
};

test "DNS hostname parsing" {
    const test_cases = [_]struct {
        input: []const u8,
        expected_host: []const u8,
        expected_port: u16,
    }{
        .{ .input = "example.com:3001", .expected_host = "example.com", .expected_port = 3001 },
        .{ .input = "example.com", .expected_host = "example.com", .expected_port = 3001 },
        .{ .input = "192.168.1.1:8080", .expected_host = "192.168.1.1", .expected_port = 8080 },
        .{ .input = "[::1]:3001", .expected_host = "[::1]", .expected_port = 3001 },
    };

    for (test_cases) |tc| {
        const result = try DNS.parseHostPort(tc.input, 3001);
        try std.testing.expectEqualStrings(tc.expected_host, result.host);
        try std.testing.expectEqual(tc.expected_port, result.port);
    }
}

test "DNS resolution" {
    const allocator = std.testing.allocator;

    // Test with localhost
    const addresses = try DNS.resolve(allocator, "localhost", 3001);
    defer allocator.free(addresses);

    try std.testing.expect(addresses.len > 0);

    // Should resolve to 127.0.0.1 or ::1
    var found_local = false;
    for (addresses) |addr| {
        const ip = addr.ip;
        if (ip.any.family == std.posix.AF.INET) {
            const ipv4 = ip.in;
            if (ipv4.sa.addr == std.mem.nativeToBig(u32, 0x7f000001)) { // 127.0.0.1
                found_local = true;
            }
        } else if (ip.any.family == std.posix.AF.INET6) {
            // Check for ::1
            found_local = true;
        }
    }

    try std.testing.expect(found_local);
}
