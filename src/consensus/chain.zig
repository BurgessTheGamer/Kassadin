const std = @import("std");
const crypto = @import("../crypto/crypto.zig");
const block_mod = @import("../ledger/block.zig");
const ledger_mod = @import("../ledger/ledger.zig");
const transaction = @import("../ledger/transaction.zig");
const praos = @import("praos.zig");
const logger = @import("../utils/logger.zig");

/// Chain management - handles forks, rollbacks, and chain selection
pub const ChainManager = struct {
    /// Main chain
    main_chain: Chain,

    /// Alternative chains (forks)
    forks: std.ArrayList(Chain),

    /// Ledger state for main chain
    ledger: *ledger_mod.Ledger,

    /// Consensus parameters
    consensus_params: praos.Praos.Parameters,

    /// Allocator
    allocator: std.mem.Allocator,

    /// Initialize chain manager
    pub fn init(
        allocator: std.mem.Allocator,
        ledger: *ledger_mod.Ledger,
        consensus_params: praos.Praos.Parameters,
    ) ChainManager {
        return .{
            .main_chain = Chain.init(allocator),
            .forks = std.ArrayList(Chain).init(allocator),
            .ledger = ledger,
            .consensus_params = consensus_params,
            .allocator = allocator,
        };
    }

    /// Clean up resources
    pub fn deinit(self: *ChainManager) void {
        self.main_chain.deinit();
        for (self.forks.items) |*fork| {
            fork.deinit();
        }
        self.forks.deinit();
    }

    /// Add a new block
    pub fn addBlock(self: *ChainManager, block: block_mod.Block) !void {
        // First, validate the block
        try self.validateBlock(block);

        // Check if block extends main chain
        if (self.main_chain.getTip()) |tip| {
            if (block.extendsFrom(tip.hash)) {
                // Block extends main chain
                try self.main_chain.addBlock(block);
                try self.applyBlockToLedger(block);
                logger.info("Added block {} to main chain", .{block.header.block_number});
                return;
            }
        } else {
            // Genesis block
            try self.main_chain.addBlock(block);
            try self.applyBlockToLedger(block);
            logger.info("Added genesis block", .{});
            return;
        }

        // Check if block extends any fork
        for (self.forks.items) |*fork| {
            if (fork.getTip()) |tip| {
                if (block.extendsFrom(tip.hash)) {
                    try fork.addBlock(block);
                    logger.info("Added block {} to fork", .{block.header.block_number});

                    // Check if this fork is now better than main chain
                    try self.checkChainSelection();
                    return;
                }
            }
        }

        // Block creates a new fork
        try self.createFork(block);
    }

    /// Validate a block
    fn validateBlock(self: *ChainManager, block: block_mod.Block) !void {
        // Basic block validation
        try block.validate();

        // TODO: Consensus validation (VRF, KES, etc.)
        _ = self;
    }

    /// Apply block to ledger
    fn applyBlockToLedger(self: *ChainManager, block: block_mod.Block) !void {
        // Apply all transactions in the block
        for (block.body.transactions) |tx| {
            try self.ledger.applyTransaction(tx);
        }

        // Update ledger slot
        self.ledger.updateSlot(block.header.slot);
    }

    /// Create a new fork
    fn createFork(self: *ChainManager, block: block_mod.Block) !void {
        // Find where this block branches from main chain
        const branch_point = self.findBranchPoint(block) orelse {
            return error.OrphanBlock;
        };

        logger.info("Creating fork at block {}", .{branch_point});

        // Create new fork starting from branch point
        var fork = Chain.init(self.allocator);

        // Copy blocks from main chain up to branch point
        for (self.main_chain.blocks.items[0 .. branch_point + 1]) |main_block| {
            try fork.addBlock(main_block);
        }

        // Add the new block
        try fork.addBlock(block);

        try self.forks.append(fork);
    }

    /// Find where a block branches from main chain
    fn findBranchPoint(self: *ChainManager, block: block_mod.Block) ?usize {
        // Search backwards through main chain
        var i = self.main_chain.blocks.items.len;
        while (i > 0) {
            i -= 1;
            const main_block = self.main_chain.blocks.items[i];
            if (block.header.prev_hash.eql(main_block.id())) {
                return i;
            }
        }
        return null;
    }

    /// Check if we need to switch to a better chain
    fn checkChainSelection(self: *ChainManager) !void {
        // Find best chain among main and forks
        var best_chain = &self.main_chain;
        var best_score = self.main_chain.getScore();
        var best_fork_index: ?usize = null;

        for (self.forks.items, 0..) |*fork, i| {
            const score = fork.getScore();
            if (score > best_score) {
                best_chain = fork;
                best_score = score;
                best_fork_index = i;
            }
        }

        // If a fork is better, switch to it
        if (best_fork_index) |fork_index| {
            logger.info("Switching to fork with score {}", .{best_score});

            // Find common ancestor
            const common_ancestor = self.findCommonAncestor(&self.main_chain, best_chain) orelse 0;

            // Rollback main chain to common ancestor
            try self.rollbackToBlock(common_ancestor);

            // Apply blocks from fork
            for (best_chain.blocks.items[common_ancestor + 1 ..]) |block| {
                try self.applyBlockToLedger(block);
            }

            // Swap chains
            const old_main = self.main_chain;
            self.main_chain = self.forks.swapRemove(fork_index);

            // Old main becomes a fork
            try self.forks.append(old_main);
        }
    }

    /// Find common ancestor of two chains
    fn findCommonAncestor(self: *ChainManager, chain1: *const Chain, chain2: *const Chain) ?usize {
        _ = self;

        // Find shorter chain length
        const min_len = @min(chain1.blocks.items.len, chain2.blocks.items.len);

        // Search backwards for common block
        var i = min_len;
        while (i > 0) {
            i -= 1;
            if (chain1.blocks.items[i].id().eql(chain2.blocks.items[i].id())) {
                return i;
            }
        }

        return null;
    }

    /// Rollback ledger to specific block
    fn rollbackToBlock(self: *ChainManager, block_index: usize) !void {
        // In real implementation, we'd restore from snapshot
        // For now, just log
        logger.warn("Rolling back to block {}", .{block_index});
        _ = self;
    }

    /// Get current chain tip
    pub fn getChainTip(self: *ChainManager) ?block_mod.ChainTip {
        return self.main_chain.getTip();
    }

    /// Get tip block (for sync.zig compatibility)
    pub fn getTip(self: *ChainManager) block_mod.Block {
        if (self.main_chain.blocks.items.len > 0) {
            return self.main_chain.blocks.items[self.main_chain.blocks.items.len - 1];
        }
        // Return genesis block if chain is empty
        return block_mod.Block{
            .header = .{
                .slot = 0,
                .block_number = 0,
                .prev_hash = crypto.Crypto.Hash256.zero(),
                .body_hash = crypto.Crypto.Hash256.zero(),
                .issuer_vkey = crypto.Crypto.PublicKey.zero(),
                .vrf_output = .{
                    .output = [_]u8{0} ** 64,
                    .proof = [_]u8{0} ** 80,
                },
                .block_size = 0,
                .operational_cert = .{
                    .hot_vkey = [_]u8{0} ** 32,
                    .sequence_number = 0,
                    .kes_period = 0,
                    .sigma = crypto.Crypto.Signature.zero(),
                },
                .protocol_version = .{
                    .major = 8,
                    .minor = 0,
                },
            },
            .body = .{
                .transactions = &[_]transaction.Transaction{},
            },
        };
    }

    /// Add block header (for sync.zig compatibility)
    pub fn addBlockHeader(self: *ChainManager, header: block_mod.BlockHeader) !void {
        // For now, create a block with empty body
        const blk = block_mod.Block{
            .header = header,
            .body = .{
                .transactions = &[_]transaction.Transaction{},
            },
        };
        try self.addBlock(blk);
    }

    /// Rollback to a specific slot (for sync.zig compatibility)
    pub fn rollbackTo(self: *ChainManager, slot: u64) !void {
        // Find the block with this slot
        var block_index: ?usize = null;
        for (self.main_chain.blocks.items, 0..) |blk, i| {
            if (blk.header.slot == slot) {
                block_index = i;
                break;
            }
        }

        if (block_index) |idx| {
            // Remove blocks after this point
            while (self.main_chain.blocks.items.len > idx + 1) {
                _ = self.main_chain.blocks.pop();
            }

            // Update tip
            if (self.main_chain.blocks.items.len > 0) {
                const last_block = self.main_chain.blocks.items[self.main_chain.blocks.items.len - 1];
                self.main_chain.tip = block_mod.ChainTip{
                    .hash = last_block.id(),
                    .block_number = last_block.header.block_number,
                    .slot = last_block.header.slot,
                    .density = self.main_chain.calculateDensity(),
                };
            } else {
                self.main_chain.tip = null;
            }
        }
    }

    /// Get chain statistics
    pub fn getStats(self: *ChainManager) ChainStats {
        return .{
            .main_chain_length = self.main_chain.blocks.items.len,
            .num_forks = self.forks.items.len,
            .total_blocks = self.getTotalBlocks(),
        };
    }

    fn getTotalBlocks(self: *ChainManager) usize {
        var total = self.main_chain.blocks.items.len;
        for (self.forks.items) |fork| {
            total += fork.blocks.items.len;
        }
        return total;
    }
};

/// A blockchain
pub const Chain = struct {
    /// Blocks in the chain
    blocks: std.ArrayList(block_mod.Block),

    /// Chain tip
    tip: ?block_mod.ChainTip,

    /// Allocator
    allocator: std.mem.Allocator,

    /// Initialize empty chain
    pub fn init(allocator: std.mem.Allocator) Chain {
        return .{
            .blocks = std.ArrayList(block_mod.Block).init(allocator),
            .tip = null,
            .allocator = allocator,
        };
    }

    /// Clean up resources
    pub fn deinit(self: *Chain) void {
        self.blocks.deinit();
    }

    /// Add a block to the chain
    pub fn addBlock(self: *Chain, block: block_mod.Block) !void {
        try self.blocks.append(block);

        self.tip = block_mod.ChainTip{
            .hash = block.id(),
            .block_number = block.header.block_number,
            .slot = block.header.slot,
            .density = self.calculateDensity(),
        };
    }

    /// Calculate chain density
    fn calculateDensity(self: *Chain) f32 {
        if (self.blocks.items.len == 0) return 0.0;

        const first_slot = self.blocks.items[0].header.slot;
        const last_slot = self.blocks.items[self.blocks.items.len - 1].header.slot;

        if (last_slot <= first_slot) return 1.0;

        const slots_spanned = last_slot - first_slot + 1;
        return @as(f32, @floatFromInt(self.blocks.items.len)) /
            @as(f32, @floatFromInt(slots_spanned));
    }

    /// Get chain tip
    pub fn getTip(self: *const Chain) ?block_mod.ChainTip {
        return self.tip;
    }

    /// Get chain score (for selection)
    pub fn getScore(self: *const Chain) u64 {
        // For now, use chain length
        // Could incorporate density or other metrics
        return self.blocks.items.len;
    }

    /// Get block at index
    pub fn getBlock(self: *const Chain, index: usize) ?block_mod.Block {
        if (index >= self.blocks.items.len) return null;
        return self.blocks.items[index];
    }
};

/// Chain statistics
pub const ChainStats = struct {
    main_chain_length: usize,
    num_forks: usize,
    total_blocks: usize,
};

// Tests
test "Chain operations" {
    try crypto.Crypto.init();

    var chain = Chain.init(std.testing.allocator);
    defer chain.deinit();

    // Create a test block
    const header = block_mod.BlockHeader{
        .block_number = 1,
        .slot = 100,
        .prev_hash = crypto.Crypto.Hash256.fromBytes([_]u8{0} ** 32),
        .body_hash = crypto.Crypto.Hash256.fromBytes([_]u8{1} ** 32),
        .issuer_vkey = crypto.Crypto.PublicKey.fromBytes([_]u8{2} ** 32),
        .vrf_output = block_mod.VrfOutput{
            .output = [_]u8{0} ** 64,
            .proof = [_]u8{0} ** 80,
        },
        .block_size = 1000,
        .operational_cert = block_mod.OperationalCert{
            .hot_vkey = [_]u8{0} ** 32,
            .sequence_number = 0,
            .kes_period = 0,
            .sigma = crypto.Crypto.Signature.fromBytes([_]u8{0} ** 64),
        },
        .protocol_version = block_mod.ProtocolVersion{ .major = 8, .minor = 0 },
    };

    const block = block_mod.Block{
        .header = header,
        .body = block_mod.BlockBody{ .transactions = &.{} },
    };

    try chain.addBlock(block);

    try std.testing.expectEqual(@as(usize, 1), chain.blocks.items.len);
    try std.testing.expect(chain.tip != null);
    try std.testing.expectEqual(@as(u64, 1), chain.tip.?.block_number);
}

test "Chain manager initialization" {
    try crypto.Crypto.init();

    var ledger = ledger_mod.Ledger.init(std.testing.allocator);
    defer ledger.deinit();

    const params = praos.Praos.Parameters{};

    var manager = ChainManager.init(std.testing.allocator, &ledger, params);
    defer manager.deinit();

    const stats = manager.getStats();
    try std.testing.expectEqual(@as(usize, 0), stats.main_chain_length);
    try std.testing.expectEqual(@as(usize, 0), stats.num_forks);
}

// Export the ChainManager as Chain for use in other modules
// pub const Chain = ChainManager; // Commented out - use ChainManager directly
