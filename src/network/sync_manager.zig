const std = @import("std");
const network = @import("network.zig");
const peer = @import("peer.zig");
const chainsync = @import("protocols/chainsync.zig");
const block = @import("../ledger/block.zig");
const chain = @import("../consensus/chain.zig");
const mux = @import("mux.zig");
const logger = @import("../utils/logger.zig");

/// Manages chain synchronization with multiple peers
pub const SyncManager = struct {
    allocator: std.mem.Allocator,
    chain_manager: *chain.ChainManager,
    peer_manager: *peer.Peer.Manager,
    sync_states: std.AutoHashMap(*peer.Peer.Connection, *SyncState),
    is_syncing: bool,
    target_tip: ?chainsync.ChainSync.Tip,

    /// Per-peer sync state
    pub const SyncState = struct {
        chain_sync: chainsync.ChainSync,
        last_activity: i64,
        blocks_received: u64,
        start_time: i64,

        pub fn init(allocator: std.mem.Allocator) SyncState {
            return .{
                .chain_sync = chainsync.ChainSync.init(allocator),
                .last_activity = std.time.milliTimestamp(),
                .blocks_received = 0,
                .start_time = std.time.milliTimestamp(),
            };
        }
    };

    pub fn init(
        allocator: std.mem.Allocator,
        chain_manager: *chain.ChainManager,
        peer_manager: *peer.Peer.Manager,
    ) SyncManager {
        return .{
            .allocator = allocator,
            .chain_manager = chain_manager,
            .peer_manager = peer_manager,
            .sync_states = std.AutoHashMap(*peer.Peer.Connection, *SyncState).init(allocator),
            .is_syncing = false,
            .target_tip = null,
        };
    }

    pub fn deinit(self: *SyncManager) void {
        var iter = self.sync_states.iterator();
        while (iter.next()) |entry| {
            self.allocator.destroy(entry.value_ptr.*);
        }
        self.sync_states.deinit();
    }

    /// Start synchronization process
    pub fn startSync(self: *SyncManager) !void {
        if (self.is_syncing) return;
        self.is_syncing = true;

        logger.info("Starting chain synchronization", .{});

        // Get connected peers
        const peers = self.peer_manager.getConnectedPeers();
        if (peers.len == 0) {
            return error.NoPeersAvailable;
        }

        // Initialize sync state for each peer
        for (peers) |peer_conn| {
            const sync_state = try self.allocator.create(SyncState);
            sync_state.* = SyncState.init(self.allocator);
            try self.sync_states.put(peer_conn, sync_state);

            // Start by finding intersection
            try self.findIntersection(peer_conn, sync_state);
        }
    }

    /// Find intersection point with a peer
    fn findIntersection(self: *SyncManager, peer_conn: *peer.Peer.Connection, sync_state: *SyncState) !void {
        // Get our recent points for intersection
        const our_points = try self.getIntersectionPoints();
        defer self.allocator.free(our_points);

        const msg = try sync_state.chain_sync.createFindIntersect(our_points);
        defer self.allocator.free(msg);

        logger.debug("Sending FindIntersect with {} points, CBOR: {x}", .{ our_points.len, std.fmt.fmtSliceHexLower(msg) });
        try peer_conn.mux_conn.sendFrame(.chain_sync, msg);
        logger.info("Sent FindIntersect to peer {}", .{peer_conn.address});
    }

    /// Get points from our chain for intersection
    fn getIntersectionPoints(self: *SyncManager) ![]chainsync.ChainSync.Point {
        var points = std.ArrayList(chainsync.ChainSync.Point).init(self.allocator);

        // Get our current tip
        const our_tip = self.chain_manager.getTip();
        const tip_hash = our_tip.header.hash();
        try points.append(.{
            .slot = our_tip.header.slot,
            .hash = tip_hash.bytes,
        });

        // Add genesis point
        try points.append(.{
            .slot = 0,
            .hash = [_]u8{0} ** 32, // Genesis hash
        });

        // TODO: Add more intermediate points for better intersection

        return points.toOwnedSlice();
    }

    /// Process incoming chain-sync message from a peer
    pub fn processMessage(self: *SyncManager, peer_conn: *peer.Peer.Connection, data: []const u8) !void {
        const sync_state = self.sync_states.get(peer_conn) orelse return error.UnknownPeer;

        logger.debug("Processing chain-sync message from {} ({} bytes)", .{ peer_conn.address, data.len });

        // Check if this is a roll forward message (we can peek at the CBOR)
        const was_must_reply = sync_state.chain_sync.getState() == .must_reply;

        try sync_state.chain_sync.processMessage(data);
        sync_state.last_activity = std.time.milliTimestamp();

        // Count blocks received - if we were in must_reply and now idle, we got a block
        const current_state = sync_state.chain_sync.getState();
        if (was_must_reply and current_state == .idle) {
            sync_state.blocks_received += 1;
            logger.info("Block received from {}, total: {} blocks", .{ peer_conn.address, sync_state.blocks_received });

            // Process the block if we have tip info
            if (sync_state.chain_sync.their_tip) |tip| {
                // TODO: Actually parse the block header and add to chain
                // For now, just update our tracking
                _ = tip;
            }
        }
        // Handle state transitions
        switch (sync_state.chain_sync.getState()) {
            .idle => {
                // Request next block
                logger.debug("Chain sync in idle state, requesting next block from {}", .{peer_conn.address});
                try self.requestNext(peer_conn, sync_state);
            },
            .can_await => {
                // Peer has no new blocks, wait a bit
                logger.debug("Peer {} has no new blocks", .{peer_conn.address});
            },
            .done => {
                logger.info("Chain sync completed with peer {}", .{peer_conn.address});
            },
            else => {},
        }

        // Update target tip if we got one
        if (sync_state.chain_sync.their_tip) |tip| {
            if (self.target_tip == null or tip.block_number > self.target_tip.?.block_number) {
                self.target_tip = tip;
                logger.info("New target tip: block #{} at slot {}", .{ tip.block_number, tip.point.slot });
            }
        }
    }

    /// Request next block from peer
    fn requestNext(self: *SyncManager, peer_conn: *peer.Peer.Connection, sync_state: *SyncState) !void {
        if (!sync_state.chain_sync.canRequestNext()) {
            return;
        }

        const msg = try sync_state.chain_sync.createRequestNext();
        defer self.allocator.free(msg);

        logger.debug("Sending RequestNext message ({} bytes) to {}", .{ msg.len, peer_conn.address });
        try peer_conn.mux_conn.sendFrame(.chain_sync, msg);
    }

    /// Get sync progress (0.0 to 1.0)
    pub fn getSyncProgress(self: *SyncManager) f32 {
        if (self.target_tip == null) return 0.0;

        const our_tip = self.chain_manager.getTip();
        const our_block = our_tip.header.block_number;
        const target_block = self.target_tip.?.block_number;

        if (target_block == 0) return 1.0;

        // For now, use blocks received as a proxy for progress
        // since we're not actually updating the chain yet
        var total_blocks: u64 = 0;
        var iter = self.sync_states.iterator();
        while (iter.next()) |entry| {
            total_blocks += entry.value_ptr.*.blocks_received;
        }

        if (total_blocks > 0 and target_block > 0) {
            const progress = @as(f32, @floatFromInt(@min(total_blocks, target_block))) / @as(f32, @floatFromInt(target_block));
            return @min(progress, 1.0);
        }

        return @as(f32, @floatFromInt(our_block)) / @as(f32, @floatFromInt(target_block));
    }

    /// Check if we're fully synced
    pub fn isSynced(self: *SyncManager) bool {
        return self.getSyncProgress() >= 0.99;
    }

    /// Get sync statistics
    pub fn getStats(self: *SyncManager) SyncStats {
        var total_blocks: u64 = 0;
        var active_peers: u32 = 0;

        var iter = self.sync_states.iterator();
        while (iter.next()) |entry| {
            total_blocks += entry.value_ptr.*.blocks_received;
            if (entry.value_ptr.*.chain_sync.getState() != .done) {
                active_peers += 1;
            }
        }

        // Calculate blocks per second
        var blocks_per_second: f32 = 0.0;
        if (total_blocks > 0) {
            const now = std.time.milliTimestamp();
            var earliest_start: i64 = now;
            var iter2 = self.sync_states.iterator();
            while (iter2.next()) |entry| {
                if (entry.value_ptr.*.start_time < earliest_start) {
                    earliest_start = entry.value_ptr.*.start_time;
                }
            }
            const elapsed_seconds = @as(f32, @floatFromInt(now - earliest_start)) / 1000.0;
            if (elapsed_seconds > 0) {
                blocks_per_second = @as(f32, @floatFromInt(total_blocks)) / elapsed_seconds;
            }
        }

        return .{
            .is_syncing = self.is_syncing,
            .sync_progress = self.getSyncProgress(),
            .blocks_received = total_blocks,
            .active_peers = active_peers,
            .target_tip = self.target_tip,
            .blocks_per_second = blocks_per_second,
        };
    }

    pub const SyncStats = struct {
        is_syncing: bool,
        sync_progress: f32,
        blocks_received: u64,
        active_peers: u32,
        target_tip: ?chainsync.ChainSync.Tip,
        blocks_per_second: f32,
    };
};

// Tests
test "SyncManager initialization" {
    const allocator = std.testing.allocator;

    // Create mock dependencies
    const ledger = @import("../ledger/ledger.zig");
    var test_ledger = ledger.Ledger.init(allocator);
    defer test_ledger.deinit();

    var chain_manager = chain.ChainManager.init(allocator, &test_ledger, .{});
    defer chain_manager.deinit();
    var peer_manager = peer.Peer.Manager.init(allocator, .{
        .network_magic = .testnet,
        .max_transmission_unit = 65536,
        .max_concurrency = 10,
        .ping_interval_ms = 30000,
        .handshake_timeout_ms = 10000,
    });
    defer peer_manager.deinit();

    var sync_manager = SyncManager.init(allocator, &chain_manager, &peer_manager);
    defer sync_manager.deinit();

    try std.testing.expectEqual(false, sync_manager.is_syncing);
    try std.testing.expectEqual(@as(f32, 0.0), sync_manager.getSyncProgress());
}
