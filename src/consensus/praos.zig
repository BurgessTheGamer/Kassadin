const std = @import("std");
const crypto = @import("../crypto/crypto.zig");
const vrf_mod = @import("../crypto/vrf.zig");
const block_mod = @import("../ledger/block.zig");
const tx_mod = @import("../ledger/transaction.zig");
const logger = @import("../utils/logger.zig");

/// Ouroboros Praos consensus implementation
pub const Praos = struct {
    /// Consensus parameters
    pub const Parameters = struct {
        /// Active slot coefficient (f) - probability of slot having a leader
        active_slot_coefficient: f64 = 0.05, // 5% of slots
        
        /// Security parameter (k) - number of blocks for finality
        security_parameter: u32 = 2160,
        
        /// Maximum block size
        max_block_size: u32 = 90_112, // ~88KB
        
        /// Slot duration in milliseconds
        slot_duration_ms: u64 = 1000, // 1 second
        
        /// Slots per epoch
        slots_per_epoch: u64 = 432_000, // 5 days
    };
    
    /// Stake distribution for an epoch
    pub const StakeDistribution = struct {
        /// Total stake in the system
        total_stake: u64,
        
        /// Stake pools and their stake
        pools: std.AutoHashMap(PoolId, PoolStake),
        
        /// Get stake for a pool
        pub fn getPoolStake(self: *const StakeDistribution, pool_id: PoolId) ?u64 {
            if (self.pools.get(pool_id)) |pool| {
                return pool.stake;
            }
            return null;
        }
        
        pub fn deinit(self: *StakeDistribution) void {
            self.pools.deinit();
        }
    };
    
    /// Pool identifier
    pub const PoolId = struct {
        hash_value: crypto.Crypto.Hash224,
        
        pub fn eql(self: PoolId, other: PoolId) bool {
            return std.mem.eql(u8, &self.hash_value.bytes, &other.hash_value.bytes);
        }
        
        pub fn hash(self: PoolId, hasher: anytype) void {
            hasher.update(&self.hash_value.bytes);
        }
    };
    
    /// Pool stake information
    pub const PoolStake = struct {
        /// Pool's total stake
        stake: u64,
        /// Pool's VRF key
        vrf_vkey: vrf_mod.VRF.PublicKey,
        /// Pool's cold key
        cold_vkey: crypto.Crypto.PublicKey,
    };
    
    /// Praos state for a node
    pub const State = struct {
        /// Current slot
        current_slot: u64,
        
        /// Current epoch
        current_epoch: u32,
        
        /// Chain tip
        chain_tip: block_mod.ChainTip,
        
        /// Consensus parameters
        params: Parameters,
        
        /// Current stake distribution
        stake_distribution: ?*StakeDistribution,
        
        /// Our pool's credentials (if we're a stake pool)
        pool_credentials: ?PoolCredentials,
        
        /// Initialize Praos state
        pub fn init(params: Parameters) State {
            return .{
                .current_slot = 0,
                .current_epoch = 0,
                .chain_tip = block_mod.ChainTip{
                    .hash = crypto.Crypto.Hash256.fromBytes([_]u8{0} ** 32),
                    .block_number = 0,
                    .slot = 0,
                    .density = 0.0,
                },
                .params = params,
                .stake_distribution = null,
                .pool_credentials = null,
            };
        }
        
        /// Update current slot
        pub fn updateSlot(self: *State, slot: u64) void {
            self.current_slot = slot;
            self.current_epoch = @intCast(slot / self.params.slots_per_epoch);
        }
        
        /// Check if we're the slot leader for the current slot
        pub fn isSlotLeader(self: *State) !bool {
            // Must have pool credentials
            const creds = self.pool_credentials orelse return false;
            
            // Must have stake distribution
            const stake_dist = self.stake_distribution orelse return false;
            
            // Get our pool's stake
            const our_stake = stake_dist.getPoolStake(creds.pool_id) orelse return false;
            
            // Create VRF input (slot number + epoch nonce)
            var vrf_input: [40]u8 = undefined;
            std.mem.writeInt(u64, vrf_input[0..8], self.current_slot, .big);
            @memcpy(vrf_input[8..40], &self.getEpochNonce());
            
            // Evaluate VRF
            const vrf_result = try vrf_mod.VRF.evaluate(&vrf_input, creds.vrf_skey);
            
            // Check if we won the lottery
            return vrf_mod.VRF.isSlotLeader(
                vrf_result.output,
                our_stake,
                stake_dist.total_stake,
                self.params.active_slot_coefficient,
            );
        }
        
        /// Get epoch nonce (randomness for the epoch)
        fn getEpochNonce(self: *State) [32]u8 {
            _ = self;
            // In real implementation, this would be computed from previous epochs
            // For now, return a fixed value
            return [_]u8{0x42} ** 32;
        }
        
        /// Create a block if we're the leader
        pub fn createBlock(
            self: *State,
            transactions: []const tx_mod.Transaction,
            allocator: std.mem.Allocator,
        ) !?block_mod.Block {
            // Check if we're the slot leader
            if (!try self.isSlotLeader()) {
                return null;
            }
            
            const creds = self.pool_credentials.?;
            
            logger.info("We are slot leader for slot {}!", .{self.current_slot});
            
            // Create VRF proof
            var vrf_input: [40]u8 = undefined;
            std.mem.writeInt(u64, vrf_input[0..8], self.current_slot, .big);
            @memcpy(vrf_input[8..40], &self.getEpochNonce());
            
            const vrf_result = try vrf_mod.VRF.evaluate(&vrf_input, creds.vrf_skey);
            
            // Create block body
            const body = block_mod.BlockBody{
                .transactions = transactions,
            };
            
            // Create block header
            const header = block_mod.BlockHeader{
                .block_number = self.chain_tip.block_number + 1,
                .slot = self.current_slot,
                .prev_hash = self.chain_tip.hash,
                .body_hash = body.hash(),
                .issuer_vkey = creds.cold_vkey,
                .vrf_output = block_mod.VrfOutput{
                    .output = vrf_result.output.bytes,
                    .proof = vrf_result.proof.bytes,
                },
                .block_size = body.estimateSize(),
                .operational_cert = creds.operational_cert,
                .protocol_version = block_mod.ProtocolVersion{
                    .major = 8,
                    .minor = 0,
                },
            };
            
            const block = block_mod.Block{
                .header = header,
                .body = body,
            };
            
            // Validate our own block
            try block.validate();
            
            // Update chain tip
            self.chain_tip = block_mod.ChainTip{
                .hash = block.id(),
                .block_number = header.block_number,
                .slot = header.slot,
                .density = self.calculateChainDensity(),
            };
            
            _ = allocator;
            return block;
        }
        
        /// Calculate chain density (blocks per slot)
        fn calculateChainDensity(self: *State) f32 {
            if (self.current_slot == 0) return 0.0;
            return @as(f32, @floatFromInt(self.chain_tip.block_number)) / 
                   @as(f32, @floatFromInt(self.current_slot));
        }
        
        /// Validate a block according to Praos rules
        pub fn validateBlock(self: *State, block: block_mod.Block) !void {
            // 1. Check block is for a slot we haven't seen
            if (block.header.slot <= self.chain_tip.slot) {
                return error.BlockTooOld;
            }
            
            // 2. Check block extends our chain
            if (!block.extendsFrom(self.chain_tip.hash)) {
                return error.BlockDoesNotExtendChain;
            }
            
            // 3. Verify VRF proof
            const stake_dist = self.stake_distribution orelse return error.NoStakeDistribution;
            
            // Find issuer's pool
            var issuer_pool: ?PoolStake = null;
            var iter = stake_dist.pools.iterator();
            while (iter.next()) |entry| {
                if (entry.value_ptr.cold_vkey.eql(block.header.issuer_vkey)) {
                    issuer_pool = entry.value_ptr.*;
                    break;
                }
            }
            
            const pool = issuer_pool orelse return error.UnknownBlockIssuer;
            
            // Create VRF input
            var vrf_input: [40]u8 = undefined;
            std.mem.writeInt(u64, vrf_input[0..8], block.header.slot, .big);
            @memcpy(vrf_input[8..40], &self.getEpochNonce());
            
            // Verify VRF proof
            const vrf_valid = try vrf_mod.VRF.verify(
                &vrf_input,
                pool.vrf_vkey,
                vrf_mod.VRF.Output.fromBytes(block.header.vrf_output.output),
                vrf_mod.VRF.Proof.fromBytes(block.header.vrf_output.proof),
            );
            
            if (!vrf_valid) {
                return error.InvalidVrfProof;
            }
            
            // 4. Check if issuer was actually eligible
            const vrf_output = vrf_mod.VRF.Output.fromBytes(block.header.vrf_output.output);
            const eligible = vrf_mod.VRF.isSlotLeader(
                vrf_output,
                pool.stake,
                stake_dist.total_stake,
                self.params.active_slot_coefficient,
            );
            
            if (!eligible) {
                return error.IssuerNotEligible;
            }
            
            // 5. Verify operational certificate
            // TODO: Implement KES verification
            
            // 6. Check protocol version
            if (block.header.protocol_version.major != 8) {
                return error.UnsupportedProtocolVersion;
            }
            
            logger.info("Block {} validated successfully", .{block.header.block_number});
        }
    };
    
    /// Pool credentials for block production
    pub const PoolCredentials = struct {
        /// Pool ID
        pool_id: PoolId,
        /// VRF secret key
        vrf_skey: vrf_mod.VRF.SecretKey,
        /// Cold verification key
        cold_vkey: crypto.Crypto.PublicKey,
        /// Operational certificate
        operational_cert: block_mod.OperationalCert,
        
        pub fn deinit(self: *PoolCredentials) void {
            self.vrf_skey.deinit();
        }
    };
    
    /// Chain selection rule - choose the longest valid chain
    pub fn selectBestChain(
        chains: []const Chain,
        params: Parameters,
    ) !*const Chain {
        if (chains.len == 0) return error.NoChains;
        
        var best_chain = &chains[0];
        var best_score = calculateChainScore(best_chain, params);
        
        for (chains[1..]) |*chain| {
            const score = calculateChainScore(chain, params);
            if (score > best_score) {
                best_chain = chain;
                best_score = score;
            }
        }
        
        return best_chain;
    }
    
    /// Calculate chain score (for chain selection)
    fn calculateChainScore(chain: *const Chain, params: Parameters) u64 {
        _ = params;
        // For Praos, we use chain length (number of blocks)
        // More sophisticated scoring could consider chain density
        return chain.length;
    }
    
    /// A blockchain
    pub const Chain = struct {
        /// Blocks in the chain
        blocks: []const block_mod.Block,
        /// Chain length
        length: u64,
        /// Chain tip
        tip: block_mod.ChainTip,
    };
};

// Tests
test "Praos state initialization" {
    const params = Praos.Parameters{};
    const state = Praos.State.init(params);
    
    try std.testing.expectEqual(@as(u64, 0), state.current_slot);
    try std.testing.expectEqual(@as(u32, 0), state.current_epoch);
}

test "Slot and epoch updates" {
    const params = Praos.Parameters{};
    var state = Praos.State.init(params);
    
    // Update to slot 432000 (start of epoch 1)
    state.updateSlot(432000);
    
    try std.testing.expectEqual(@as(u64, 432000), state.current_slot);
    try std.testing.expectEqual(@as(u32, 1), state.current_epoch);
}

test "Chain density calculation" {
    const params = Praos.Parameters{};
    var state = Praos.State.init(params);
    
    state.current_slot = 100;
    state.chain_tip.block_number = 5;
    
    const density = state.calculateChainDensity();
    try std.testing.expectEqual(@as(f32, 0.05), density);
}

test "Pool ID equality" {
    const id1 = Praos.PoolId{
        .hash_value = crypto.Crypto.Hash224.fromBytes([_]u8{1} ** 28),
    };
    const id2 = Praos.PoolId{
        .hash_value = crypto.Crypto.Hash224.fromBytes([_]u8{1} ** 28),
    };
    const id3 = Praos.PoolId{
        .hash_value = crypto.Crypto.Hash224.fromBytes([_]u8{2} ** 28),
    };
    
    try std.testing.expect(id1.eql(id2));
    try std.testing.expect(!id1.eql(id3));
}