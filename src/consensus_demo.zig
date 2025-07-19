const std = @import("std");
const crypto = @import("crypto/crypto.zig");
const vrf_mod = @import("crypto/vrf.zig");
const address = @import("crypto/address.zig");
const tx_mod = @import("ledger/transaction.zig");
const ledger_mod = @import("ledger/ledger.zig");
const block_mod = @import("ledger/block.zig");
const praos = @import("consensus/praos.zig");
const chain_mod = @import("consensus/chain.zig");

pub fn main() !void {
    const stdout = std.io.getStdOut().writer();
    
    // Initialize
    try crypto.Crypto.init();
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    try stdout.print("\nKassadin Consensus Demo\n", .{});
    try stdout.print("=======================\n\n", .{});
    
    // Create some stake pools
    try stdout.print("1. Creating stake pools...\n", .{});
    
    var pool_a_vrf = try vrf_mod.VRF.KeyPair.generate();
    defer pool_a_vrf.deinit();
    var pool_a_cold = try crypto.Crypto.KeyPair.generate();
    defer pool_a_cold.deinit();
    
    var pool_b_vrf = try vrf_mod.VRF.KeyPair.generate();
    defer pool_b_vrf.deinit();
    var pool_b_cold = try crypto.Crypto.KeyPair.generate();
    defer pool_b_cold.deinit();
    
    var pool_c_vrf = try vrf_mod.VRF.KeyPair.generate();
    defer pool_c_vrf.deinit();
    var pool_c_cold = try crypto.Crypto.KeyPair.generate();
    defer pool_c_cold.deinit();
    
    try stdout.print("   ✓ Created 3 stake pools\n", .{});
    
    // Create stake distribution
    try stdout.print("\n2. Setting up stake distribution...\n", .{});
    
    var stake_dist = praos.Praos.StakeDistribution{
        .total_stake = 1_000_000_000_000, // 1 million ADA total
        .pools = std.AutoHashMap(praos.Praos.PoolId, praos.Praos.PoolStake).init(allocator),
    };
    defer stake_dist.deinit();
    
    // Pool A has 40% stake
    const pool_a_id = praos.Praos.PoolId{
        .hash_value = crypto.Crypto.Hash224.fromBytes([_]u8{1} ** 28),
    };
    try stake_dist.pools.put(pool_a_id, praos.Praos.PoolStake{
        .stake = 400_000_000_000,
        .vrf_vkey = pool_a_vrf.public,
        .cold_vkey = pool_a_cold.public,
    });
    
    // Pool B has 35% stake
    const pool_b_id = praos.Praos.PoolId{
        .hash_value = crypto.Crypto.Hash224.fromBytes([_]u8{2} ** 28),
    };
    try stake_dist.pools.put(pool_b_id, praos.Praos.PoolStake{
        .stake = 350_000_000_000,
        .vrf_vkey = pool_b_vrf.public,
        .cold_vkey = pool_b_cold.public,
    });
    
    // Pool C has 25% stake
    const pool_c_id = praos.Praos.PoolId{
        .hash_value = crypto.Crypto.Hash224.fromBytes([_]u8{3} ** 28),
    };
    try stake_dist.pools.put(pool_c_id, praos.Praos.PoolStake{
        .stake = 250_000_000_000,
        .vrf_vkey = pool_c_vrf.public,
        .cold_vkey = pool_c_cold.public,
    });
    
    try stdout.print("   ✓ Pool A: 40% stake (400k ADA)\n", .{});
    try stdout.print("   ✓ Pool B: 35% stake (350k ADA)\n", .{});
    try stdout.print("   ✓ Pool C: 25% stake (250k ADA)\n", .{});
    
    // Simulate slot leader election
    try stdout.print("\n3. Simulating slot leader election (100 slots)...\n", .{});
    
    const f: f64 = 0.05; // 5% active slot coefficient
    var slot_leaders = std.ArrayList(struct { slot: u64, pool: u8 }).init(allocator);
    defer slot_leaders.deinit();
    
    var slot: u64 = 1;
    while (slot <= 100) : (slot += 1) {
        // Check each pool
        const pools = [_]struct {
            id: u8,
            stake: u64,
            vrf_key: vrf_mod.VRF.SecretKey,
        }{
            .{ .id = 'A', .stake = 400_000_000_000, .vrf_key = pool_a_vrf.secret },
            .{ .id = 'B', .stake = 350_000_000_000, .vrf_key = pool_b_vrf.secret },
            .{ .id = 'C', .stake = 250_000_000_000, .vrf_key = pool_c_vrf.secret },
        };
        
        for (pools) |pool| {
            // Create VRF input
            var vrf_input: [40]u8 = undefined;
            std.mem.writeInt(u64, vrf_input[0..8], slot, .big);
            @memset(vrf_input[8..40], 0x42); // Epoch nonce
            
            const vrf_result = try vrf_mod.VRF.evaluate(&vrf_input, pool.vrf_key);
            
            if (vrf_mod.VRF.isSlotLeader(vrf_result.output, pool.stake, stake_dist.total_stake, f)) {
                try slot_leaders.append(.{ .slot = slot, .pool = pool.id });
                break; // Only one leader per slot
            }
        }
    }
    
    try stdout.print("   ✓ Found {} slot leaders in 100 slots\n", .{slot_leaders.items.len});
    
    // Count leaders per pool
    var pool_a_leads: u32 = 0;
    var pool_b_leads: u32 = 0;
    var pool_c_leads: u32 = 0;
    
    for (slot_leaders.items) |leader| {
        switch (leader.pool) {
            'A' => pool_a_leads += 1,
            'B' => pool_b_leads += 1,
            'C' => pool_c_leads += 1,
            else => {},
        }
    }
    
    try stdout.print("   ✓ Pool A won {} slots (~{d:.1}%)\n", .{ 
        pool_a_leads, 
        @as(f64, @floatFromInt(pool_a_leads)) * 100.0 / @as(f64, @floatFromInt(slot_leaders.items.len)) 
    });
    try stdout.print("   ✓ Pool B won {} slots (~{d:.1}%)\n", .{ 
        pool_b_leads, 
        @as(f64, @floatFromInt(pool_b_leads)) * 100.0 / @as(f64, @floatFromInt(slot_leaders.items.len)) 
    });
    try stdout.print("   ✓ Pool C won {} slots (~{d:.1}%)\n", .{ 
        pool_c_leads, 
        @as(f64, @floatFromInt(pool_c_leads)) * 100.0 / @as(f64, @floatFromInt(slot_leaders.items.len)) 
    });
    
    // Create a blockchain
    try stdout.print("\n4. Building a blockchain...\n", .{});
    
    var ledger = ledger_mod.Ledger.init(allocator);
    defer ledger.deinit();
    
    const consensus_params = praos.Praos.Parameters{
        .active_slot_coefficient = f,
    };
    
    var chain_manager = chain_mod.ChainManager.init(allocator, &ledger, consensus_params);
    defer chain_manager.deinit();
    
    // Create genesis block
    const genesis_body = block_mod.BlockBody{ .transactions = &.{} };
    const genesis_header = block_mod.BlockHeader{
        .block_number = 0,
        .slot = 0,
        .prev_hash = crypto.Crypto.Hash256.fromBytes([_]u8{0} ** 32),
        .body_hash = genesis_body.hash(),
        .issuer_vkey = pool_a_cold.public,
        .vrf_output = block_mod.VrfOutput{
            .output = [_]u8{0} ** 64,
            .proof = [_]u8{0} ** 80,
        },
        .block_size = 100,
        .operational_cert = block_mod.OperationalCert{
            .hot_vkey = [_]u8{0} ** 32,
            .sequence_number = 0,
            .kes_period = 0,
            .sigma = crypto.Crypto.Signature.fromBytes([_]u8{0} ** 64),
        },
        .protocol_version = block_mod.ProtocolVersion{ .major = 8, .minor = 0 },
    };
    
    const genesis_block = block_mod.Block{
        .header = genesis_header,
        .body = genesis_body,
    };
    
    try chain_manager.addBlock(genesis_block);
    
    // Add some more blocks
    var prev_hash = genesis_block.id();
    for (slot_leaders.items[0..@min(5, slot_leaders.items.len)]) |leader| {
        const body = block_mod.BlockBody{ .transactions = &.{} };
        const header = block_mod.BlockHeader{
            .block_number = leader.slot,
            .slot = leader.slot,
            .prev_hash = prev_hash,
            .body_hash = body.hash(),
            .issuer_vkey = switch (leader.pool) {
                'A' => pool_a_cold.public,
                'B' => pool_b_cold.public,
                'C' => pool_c_cold.public,
                else => unreachable,
            },
            .vrf_output = block_mod.VrfOutput{
                .output = [_]u8{@intCast(leader.slot)} ** 64,
                .proof = [_]u8{@intCast(leader.slot)} ** 80,
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
            .body = body,
        };
        
        try chain_manager.addBlock(block);
        prev_hash = block.id();
        
        try stdout.print("   ✓ Block {} created by Pool {} at slot {}\n", .{
            header.block_number,
            leader.pool,
            leader.slot,
        });
    }
    
    // Show chain statistics
    try stdout.print("\n5. Chain statistics:\n", .{});
    const stats = chain_manager.getStats();
    try stdout.print("   ✓ Main chain length: {} blocks\n", .{stats.main_chain_length});
    try stdout.print("   ✓ Number of forks: {}\n", .{stats.num_forks});
    
    if (chain_manager.getChainTip()) |tip| {
        try stdout.print("   ✓ Chain tip at slot: {}\n", .{tip.slot});
        try stdout.print("   ✓ Chain density: {d:.2}%\n", .{tip.density * 100});
    }
    
    try stdout.print("\n✅ Consensus demo completed successfully!\n", .{});
    try stdout.print("\nKey Insights:\n", .{});
    try stdout.print("- With f=5%, we expect ~5 blocks per 100 slots\n", .{});
    try stdout.print("- Pools win slots proportional to their stake\n", .{});
    try stdout.print("- VRF ensures randomness is verifiable\n", .{});
    try stdout.print("- Chain selection follows longest chain rule\n\n", .{});
}