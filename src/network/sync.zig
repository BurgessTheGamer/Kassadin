const std = @import("std");
const network = @import("network.zig");
const peer = @import("peer.zig");
const protocol = @import("protocol.zig");
const block = @import("../ledger/block.zig");
const chain = @import("../consensus/chain.zig");
const logger = @import("../utils/logger.zig");
const sync_manager = @import("sync_manager.zig");

/// Chain synchronization coordinator
pub const ChainSync = struct {
    allocator: std.mem.Allocator,
    sync_manager: *sync_manager.SyncManager,
    sync_thread: ?std.Thread,
    should_stop: std.atomic.Value(bool),

    pub fn init(
        allocator: std.mem.Allocator,
        chain_manager: *chain.ChainManager,
        peer_manager: *peer.Peer.Manager,
    ) !*ChainSync {
        const self = try allocator.create(ChainSync);

        const sm = try allocator.create(sync_manager.SyncManager);
        sm.* = sync_manager.SyncManager.init(allocator, chain_manager, peer_manager);

        self.* = .{
            .allocator = allocator,
            .sync_manager = sm,
            .sync_thread = null,
            .should_stop = std.atomic.Value(bool).init(false),
        };

        return self;
    }

    pub fn deinit(self: *ChainSync) void {
        self.stop();
        self.sync_manager.deinit();
        self.allocator.destroy(self.sync_manager);
        self.allocator.destroy(self);
    }

    /// Start synchronization
    pub fn start(self: *ChainSync) !void {
        if (self.sync_thread != null) return;

        // Check if we have peers
        const stats = self.sync_manager.peer_manager.stats;
        if (stats.peers_connected == 0) {
            return error.NoPeersAvailable;
        }

        self.should_stop.store(false, .seq_cst);

        // Start sync manager
        try self.sync_manager.startSync();

        // Start sync thread
        self.sync_thread = try std.Thread.spawn(.{}, syncLoop, .{self});

        logger.info("Chain synchronization started", .{});
    }

    /// Stop synchronization
    pub fn stop(self: *ChainSync) void {
        self.should_stop.store(true, .seq_cst);
        if (self.sync_thread) |thread| {
            thread.join();
            self.sync_thread = null;
        }
    }

    /// Main synchronization loop
    fn syncLoop(self: *ChainSync) void {
        logger.info("Sync thread started", .{});

        while (!self.should_stop.load(.seq_cst)) {
            // Get sync stats
            const stats = self.sync_manager.getStats();

            if (stats.is_syncing) {
                if (stats.target_tip) |tip| {
                    const eta_seconds = if (stats.blocks_per_second > 0)
                        @as(u64, @intFromFloat(@as(f32, @floatFromInt(tip.block_number - stats.blocks_received)) / stats.blocks_per_second))
                    else
                        0;

                    logger.info("Sync: {d:.1}% | Blocks: {}/{} | Speed: {d:.1} blocks/s | Peers: {} | ETA: {}s", .{
                        stats.sync_progress * 100,
                        stats.blocks_received,
                        tip.block_number,
                        stats.blocks_per_second,
                        stats.active_peers,
                        eta_seconds,
                    });
                } else {
                    logger.info("Sync progress: {d:.1}% (blocks: {}, peers: {})", .{
                        stats.sync_progress * 100,
                        stats.blocks_received,
                        stats.active_peers,
                    });
                }

                if (self.sync_manager.isSynced()) {
                    logger.info("Chain fully synchronized!", .{});
                }
            } else {
                logger.debug("Sync not active yet (is_syncing=false)", .{});
            }

            // Sleep for a bit
            std.time.sleep(5 * std.time.ns_per_s);
        }

        logger.info("Sync thread stopped", .{});
    }

    /// Get sync progress (0.0 to 1.0)
    pub fn getSyncProgress(self: *ChainSync) f32 {
        return self.sync_manager.getSyncProgress();
    }

    /// Check if synced
    pub fn isSynced(self: *ChainSync) bool {
        return self.sync_manager.isSynced();
    }
};
