const std = @import("std");
const network = @import("network/network.zig");
const protocol = @import("network/protocol.zig");
const peer = @import("network/peer.zig");
const sync = @import("network/sync.zig");
const chain = @import("consensus/chain.zig");
const block = @import("ledger/block.zig");
const crypto = @import("crypto/crypto.zig");

/// Simulated network demo showing P2P functionality
pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    std.log.info("=== Kassadin Network Demo ===", .{});
    std.log.info("", .{});
    
    // Create network parameters
    const params = network.Network.ProtocolParams{
        .network_magic = .mainnet,
        .max_transmission_unit = 65536,
        .max_concurrency = 10,
        .ping_interval_ms = 30000,
        .handshake_timeout_ms = 10000,
    };
    
    // Demo 1: Protocol message encoding/decoding
    try demoProtocolMessages(allocator);
    
    // Demo 2: Peer connection simulation
    try demoPeerConnection(allocator, params);
    
    // Demo 3: Chain synchronization simulation
    try demoChainSync(allocator, params);
    
    std.log.info("", .{});
    std.log.info("Network demo completed successfully!", .{});
}

fn demoProtocolMessages(allocator: std.mem.Allocator) !void {
    std.log.info("1. Protocol Message Demo", .{});
    std.log.info("------------------------", .{});
    
    // Create a handshake message
    const handshake = protocol.Protocol.HandshakeMsg{
        .network_magic = .mainnet,
        .versions = &[_]network.Network.ProtocolVersion{
            .{ .major = 11, .minor = 0 },
            .{ .major = 10, .minor = 0 },
        },
    };
    
    // Encode the message
    const encoded = try handshake.encode(allocator);
    defer allocator.free(encoded);
    
    std.log.info("  Encoded handshake: {} bytes", .{encoded.len});
    
    // Decode it back
    const decoded = try protocol.Protocol.HandshakeMsg.decode(allocator, encoded);
    defer allocator.free(decoded.versions);
    
    std.log.info("  Network magic: {}", .{decoded.network_magic});
    std.log.info("  Supported versions:", .{});
    for (decoded.versions) |ver| {
        std.log.info("    - v{}.{}", .{ ver.major, ver.minor });
    }
    
    // Create a chain tip
    const tip = protocol.Protocol.ChainTip{
        .slot = 95_000_000,
        .hash = crypto.Crypto.Hash256.zero(),
        .block_number = 8_500_000,
    };
    
    var tip_buffer = std.ArrayList(u8).init(allocator);
    defer tip_buffer.deinit();
    try tip.encode(tip_buffer.writer());
    
    std.log.info("  Chain tip encoded: {} bytes", .{tip_buffer.items.len});
    std.log.info("", .{});
}

fn demoPeerConnection(allocator: std.mem.Allocator, params: network.Network.ProtocolParams) !void {
    std.log.info("2. Peer Connection Demo", .{});
    std.log.info("-----------------------", .{});
    
    // Create peer manager
    var peer_manager = peer.Peer.Manager.init(allocator, params);
    defer peer_manager.deinit();
    
    std.log.info("  Peer manager initialized", .{});
    std.log.info("  Active peers: {}", .{peer_manager.activePeerCount()});
    
    // Simulate peer statistics
    const test_stats = network.Network.Stats{
        .messages_sent = 1523,
        .messages_received = 1489,
        .bytes_sent = 15_234_567,
        .bytes_received = 14_987_234,
        .peers_connected = 8,
        .peers_discovered = 45,
    };
    
    std.log.info("  Network statistics:", .{});
    std.log.info("    Messages: {} sent, {} received", .{ test_stats.messages_sent, test_stats.messages_received });
    std.log.info("    Data: {:.2} MB sent, {:.2} MB received", .{
        @as(f64, @floatFromInt(test_stats.bytes_sent)) / 1024.0 / 1024.0,
        @as(f64, @floatFromInt(test_stats.bytes_received)) / 1024.0 / 1024.0,
    });
    std.log.info("    Peers: {} connected, {} discovered", .{ test_stats.peers_connected, test_stats.peers_discovered });
    
    // Simulate connection states
    const states = [_]network.Network.ConnectionState{ .connecting, .handshaking, .established, .closing, .closed };
    std.log.info("  Connection states:", .{});
    for (states) |state| {
        std.log.info("    - {s}", .{@tagName(state)});
    }
    
    std.log.info("", .{});
}

fn demoChainSync(allocator: std.mem.Allocator, params: network.Network.ProtocolParams) !void {
    std.log.info("3. Chain Synchronization Demo", .{});
    std.log.info("-----------------------------", .{});
    
    // Create a mock chain
    var test_chain = try chain.Chain.init(allocator);
    defer test_chain.deinit();
    
    // Create peer manager
    var peer_manager = peer.Peer.Manager.init(allocator, params);
    defer peer_manager.deinit();
    
    // Create sync manager
    var sync_manager = try sync.Sync.Manager.init(allocator, &test_chain, &peer_manager);
    defer sync_manager.deinit();
    
    std.log.info("  Sync manager initialized", .{});
    std.log.info("  Initial state: {s}", .{@tagName(sync_manager.state)});
    
    // Simulate sync progress
    const sync_scenarios = [_]struct {
        current: u64,
        target: u64,
        headers: u64,
        blocks: u64,
    }{
        .{ .current = 0, .target = 8_500_000, .headers = 0, .blocks = 0 },
        .{ .current = 1_000_000, .target = 8_500_000, .headers = 1_000_000, .blocks = 950_000 },
        .{ .current = 4_250_000, .target = 8_500_000, .headers = 4_500_000, .blocks = 4_250_000 },
        .{ .current = 8_499_900, .target = 8_500_000, .headers = 8_500_000, .blocks = 8_499_900 },
        .{ .current = 8_500_000, .target = 8_500_000, .headers = 8_500_000, .blocks = 8_500_000 },
    };
    
    std.log.info("  Sync progress simulation:", .{});
    for (sync_scenarios) |scenario| {
        sync_manager.stats.current_height = scenario.current;
        sync_manager.stats.target_height = scenario.target;
        sync_manager.stats.headers_downloaded = scenario.headers;
        sync_manager.stats.blocks_downloaded = scenario.blocks;
        
        const progress = sync_manager.stats.syncProgress() * 100.0;
        std.log.info("    Height {}/{} ({:.1}%) - {} headers, {} blocks", .{
            scenario.current,
            scenario.target,
            progress,
            scenario.headers,
            scenario.blocks,
        });
    }
    
    // Simulate sync states
    const sync_states = [_]sync.Sync.State{
        .idle,
        .finding_intersection,
        .downloading_headers,
        .downloading_blocks,
        .validating,
        .caught_up,
    };
    
    std.log.info("  Sync state progression:", .{});
    for (sync_states) |state| {
        std.log.info("    -> {s}", .{@tagName(state)});
    }
    
    std.log.info("", .{});
}