const std = @import("std");
const node = @import("node.zig");
const crypto = @import("crypto/crypto.zig");
const network = @import("network/network.zig");
const dns = @import("network/dns.zig");
const peer = @import("network/peer.zig");
const logger = @import("utils/logger.zig");

/// Demo connecting to Cardano testnet
pub fn main() !void {
    // Enable debug logging to see CBOR bytes
    logger.setLevel(.debug);
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.log.info("=== Kassadin Testnet Connection Demo ===", .{});
    std.log.info("", .{});

    // Initialize crypto
    try crypto.Crypto.init();

    // Create node configuration for preprod (since those are the nodes we have)
    const config = node.Node.Config{
        .network = .preprod,
        .data_dir = "./preprod_data",
        .listen_port = 3002,
        .max_peers = 5,
        .log_level = .debug,
    };

    std.log.info("Configuration:", .{});
    std.log.info("  Network: {s}", .{config.network.toString()});
    std.log.info("  Port: {}", .{config.listen_port});
    std.log.info("  Max peers: {}", .{config.max_peers});
    std.log.info("", .{});

    // Test DNS resolution first
    try testDnsResolution(allocator);

    // Test direct peer connection
    try testPeerConnection(allocator);

    // Test full node startup
    try testNodeStartup(allocator, config);

    std.log.info("", .{});
    std.log.info("Testnet connection demo completed!", .{});
}

fn testDnsResolution(allocator: std.mem.Allocator) !void {
    std.log.info("1. Testing DNS Resolution", .{});
    std.log.info("------------------------", .{});

    const testnet_peers = dns.DNS.BootstrapPeers.testnet;

    for (testnet_peers) |peer_str| {
        const parsed = dns.DNS.parseHostPort(peer_str, 3001) catch |err| {
            std.log.err("Failed to parse {s}: {}", .{ peer_str, err });
            continue;
        };

        std.log.info("  Resolving {s}:{}", .{ parsed.host, parsed.port });

        const addresses = dns.DNS.resolve(allocator, parsed.host, parsed.port) catch |err| {
            std.log.err("  Failed to resolve: {}", .{err});
            continue;
        };
        defer allocator.free(addresses);

        std.log.info("  Found {} addresses:", .{addresses.len});
        for (addresses) |addr| {
            std.log.info("    - {}", .{addr.ip});
        }
    }

    std.log.info("", .{});
}

fn testPeerConnection(allocator: std.mem.Allocator) !void {
    std.log.info("2. Testing Peer Connection", .{});
    std.log.info("-------------------------", .{});

    // Create network parameters for preprod
    const params = network.Network.ProtocolParams{
        .network_magic = .preprod,
        .max_transmission_unit = 65536,
        .max_concurrency = 10,
        .ping_interval_ms = 30000,
        .handshake_timeout_ms = 10000,
    };

    // Create peer manager
    var peer_manager = peer.Peer.Manager.init(allocator, params);
    defer peer_manager.deinit();

    // Try to connect to a testnet peer
    const test_peer = "relays-new.cardano-testnet.iohk.io:3001";
    const parsed = try dns.DNS.parseHostPort(test_peer, 3001);

    std.log.info("  Attempting to connect to {s}:{}", .{ parsed.host, parsed.port });

    // Resolve address
    const addresses = dns.DNS.resolve(allocator, parsed.host, parsed.port) catch |err| {
        std.log.err("  DNS resolution failed: {}", .{err});
        return;
    };
    defer allocator.free(addresses);

    if (addresses.len == 0) {
        std.log.err("  No addresses found", .{});
        return;
    }

    // Try first address
    const addr = addresses[0];
    std.log.info("  Connecting to {}", .{addr.ip});

    // Attempt connection
    const conn = peer_manager.connect(addr) catch |err| {
        std.log.err("  Connection failed: {}", .{err});
        if (err == error.ConnectionResetByPeer) {
            std.log.info("  Connection was reset by peer - this usually means protocol mismatch", .{});
            std.log.info("  We're now using the Cardano Mux protocol layer", .{});
        }
        return;
    };
    defer peer_manager.disconnect(conn);

    std.log.info("  Connection established!", .{});
    std.log.info("  Peer state: {s}", .{@tagName(conn.state)});
    if (conn.capabilities) |cap| {
        std.log.info("  Protocol version: {}.{}", .{ cap.protocol_version.major, cap.protocol_version.minor });
    }

    std.log.info("", .{});
}

fn testNodeStartup(allocator: std.mem.Allocator, config: node.Node.Config) !void {
    std.log.info("3. Testing Node Startup", .{});
    std.log.info("----------------------", .{});

    // Create node
    const test_node = try node.Node.init(allocator, config);
    defer test_node.deinit();

    std.log.info("  Node initialized successfully", .{});

    // Get initial status
    const status = test_node.getStatus();
    std.log.info("  Initial status:", .{});
    std.log.info("    State: {s}", .{@tagName(status.state)});
    std.log.info("    Network: {s}", .{@tagName(status.network)});
    std.log.info("    Peers: {}", .{status.peer_count});
    std.log.info("    Sync progress: {:.1}%", .{status.sync_progress * 100});

    // Start node in a separate thread
    std.log.info("  Starting node...", .{});

    const NodeRunner = struct {
        fn run(n: *node.Node) void {
            n.start() catch |err| {
                std.log.err("Node start failed: {}", .{err});
            };
        }
    };

    const thread = try std.Thread.spawn(.{}, NodeRunner.run, .{test_node});

    // Let it run for a few seconds
    std.log.info("  Waiting for sync to start...", .{});
    std.time.sleep(5 * std.time.ns_per_s);

    // Check status again
    const final_status = test_node.getStatus();
    std.log.info("  Status after 5 seconds:", .{});
    std.log.info("    State: {s}", .{@tagName(final_status.state)});
    std.log.info("    Peers: {}", .{final_status.peer_count});
    std.log.info("    Sync progress: {:.1}%", .{final_status.sync_progress * 100});

    // Wait longer to see sync progress
    std.log.info("  Waiting for sync progress...", .{});
    std.time.sleep(15 * std.time.ns_per_s);

    // Check final sync stats
    const sync_stats = test_node.sync_manager.sync_manager.getStats();
    std.log.info("  Final sync stats:", .{});
    std.log.info("    Is syncing: {}", .{sync_stats.is_syncing});
    std.log.info("    Blocks received: {}", .{sync_stats.blocks_received});
    std.log.info("    Active peers: {}", .{sync_stats.active_peers});
    std.log.info("    Progress: {:.1}%", .{sync_stats.sync_progress * 100});

    // Stop node
    test_node.stop();
    thread.join();

    std.log.info("  Node stopped successfully", .{});
    std.log.info("", .{});
}
