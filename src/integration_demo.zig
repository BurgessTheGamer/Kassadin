const std = @import("std");
const node = @import("node.zig");
const crypto = @import("crypto/crypto.zig");
const ledger = @import("ledger/ledger.zig");
const transaction = @import("ledger/transaction.zig");
const block = @import("ledger/block.zig");
const praos = @import("consensus/praos.zig");
const chain = @import("consensus/chain.zig");

/// Integration demo showing all components working together
pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    std.log.info("=== Kassadin Integration Demo ===", .{});
    std.log.info("", .{});
    
    // Initialize crypto
    try crypto.Crypto.init();
    
    // Demo 1: Create a mini blockchain
    try demoMiniBlockchain(allocator);
    
    // Demo 2: Simulate node lifecycle
    try demoNodeLifecycle(allocator);
    
    // Demo 3: Show full transaction flow
    try demoTransactionFlow(allocator);
    
    std.log.info("", .{});
    std.log.info("Integration demo completed successfully!", .{});
}

fn demoMiniBlockchain(allocator: std.mem.Allocator) !void {
    std.log.info("1. Mini Blockchain Demo", .{});
    std.log.info("-----------------------", .{});
    
    // Create chain
    // Create ledger first
    var test_ledger = ledger.Ledger.init(allocator);
    defer test_ledger.deinit();
    
    // Create chain
    var test_chain = chain.ChainManager.init(allocator, &test_ledger, .{});
    defer test_chain.deinit();
    
    // Create consensus
    var consensus = praos.Praos.init(allocator);
    defer consensus.deinit();
    
    // Create stake distribution
    var stake_dist = praos.Praos.StakeDistribution{
        .pools = std.AutoHashMap(praos.Praos.PoolId, praos.Praos.PoolStake).init(allocator),
        .total_stake = 1_000_000_000,
    };
    defer stake_dist.deinit();
    
    // Create a pool
    const pool_keys = try crypto.Crypto.KeyPair.generate();
    const pool_vrf = try crypto.Crypto.VRF.KeyPair.generate();
    const pool_id = praos.Praos.PoolId{
        .hash_value = crypto.Crypto.Hash224.fromBytes([_]u8{1} ** 28),
    };
    
    try stake_dist.pools.put(pool_id, .{
        .stake = 500_000_000,
        .vrf_vkey = pool_vrf.public,
        .cold_vkey = pool_keys.public,
    });
    
    std.log.info("  Created pool with 50% stake", .{});
    
    // Generate blocks
    var current_slot: u64 = 1000;
    var blocks_created: u32 = 0;
    
    std.log.info("  Generating blocks...", .{});
    
    for (0..20) |_| {
        // Check if we're slot leader
        const leader_check = consensus.checkSlotLeader(
            current_slot,
            pool_vrf.secret,
            500_000_000,
            1_000_000_000,
        ) catch null;
        
        if (leader_check) |proof| {
            // Create block
            const prev_block = test_chain.getTip();
            
            var new_block = block.Block{
                .header = .{
                    .slot = current_slot,
                    .block_number = prev_block.header.block_number + 1,
                    .prev_hash = prev_block.header.hash(),
                    .issuer_vkey = pool_keys.public,
                    .vrf_vkey = pool_vrf.public,
                    .vrf_proof = proof,
                    .block_body_size = 0,
                    .block_body_hash = crypto.Crypto.Hash256.zero(),
                    .operational_cert = .{
                        .hot_vkey = pool_keys.public,
                        .sequence_number = 0,
                        .kes_period = 0,
                        .sigma = crypto.Crypto.Signature.zero(),
                    },
                    .protocol_version = .{ .major = 8, .minor = 0 },
                },
                .body = .{
                    .tx_bodies = &[_]transaction.Transaction{},
                    .tx_witnesses = &[_]transaction.Transaction.WitnessSet{},
                    .auxiliary_data = &[_]transaction.Transaction.AuxiliaryData{},
                },
            };
            
            // Sign block
            new_block.header.signature = try pool_keys.sign(&new_block.header.hash().bytes);
            
            // Add to chain
            try test_chain.addBlock(&new_block);
            blocks_created += 1;
            
            std.log.info("    Slot {}: Created block #{}", .{ current_slot, new_block.header.block_number });
        }
        
        current_slot += 1;
    }
    
    std.log.info("  Created {} blocks in 20 slots", .{blocks_created});
    std.log.info("  Chain height: {}", .{test_chain.getTip().header.block_number});
    std.log.info("", .{});
}

fn demoNodeLifecycle(allocator: std.mem.Allocator) !void {
    std.log.info("2. Node Lifecycle Demo", .{});
    std.log.info("----------------------", .{});
    
    // Create node configuration
    const config = node.Node.Config{
        .network = .testnet,
        .data_dir = "/tmp/kassadin-demo",
        .listen_port = 3002,
        .max_peers = 10,
        .log_level = .info,
    };
    
    std.log.info("  Creating node with config:", .{});
    std.log.info("    Network: {s}", .{config.network.toString()});
    std.log.info("    Port: {}", .{config.listen_port});
    std.log.info("    Max peers: {}", .{config.max_peers});
    
    // Initialize node
    const test_node = try node.Node.init(allocator, config);
    defer test_node.deinit();
    
    std.log.info("  Node initialized", .{});
    
    // Check initial status
    const initial_status = test_node.getStatus();
    std.log.info("  Initial status:", .{});
    std.log.info("    State: {s}", .{@tagName(initial_status.state)});
    std.log.info("    Sync progress: {:.1}%", .{initial_status.sync_progress * 100});
    std.log.info("    Peers: {}", .{initial_status.peer_count});
    std.log.info("    UTXOs: {}", .{initial_status.utxo_count});
    
    // Simulate some activity
    std.log.info("  Simulating node activity...", .{});
    
    // Add some UTXOs
    const alice_keys = try crypto.Crypto.KeyPair.generate();
    const alice_addr = crypto.Crypto.Address{
        .payment_cred = .{ .key_hash = crypto.Crypto.hash224(&alice_keys.public.bytes) },
        .staking_cred = null,
        .network = 0,
    };
    
    for (0..5) |i| {
        const tx_id = crypto.Crypto.Hash256.fromBytes([_]u8{@intCast(i)} ** 32);
        const utxo = transaction.Transaction.Output{
            .address = alice_addr,
            .amount = .{ .lovelace = 1000000 * (i + 1) },
            .datum_hash = null,
            .script_ref = null,
        };
        
        try test_node.ledger_state.addUtxo(.{ .tx_id = tx_id, .index = 0 }, utxo);
    }
    
    // Check updated status
    const updated_status = test_node.getStatus();
    std.log.info("  Updated status:", .{});
    std.log.info("    UTXOs: {}", .{updated_status.utxo_count});
    
    std.log.info("", .{});
}

fn demoTransactionFlow(allocator: std.mem.Allocator) !void {
    std.log.info("3. Full Transaction Flow Demo", .{});
    std.log.info("-----------------------------", .{});
    
    // Create participants
    const alice = try crypto.Crypto.KeyPair.generate();
    const bob = try crypto.Crypto.KeyPair.generate();
    const charlie = try crypto.Crypto.KeyPair.generate();
    
    const alice_addr = crypto.Crypto.Address{
        .payment_cred = .{ .key_hash = crypto.Crypto.hash224(&alice.public.bytes) },
        .staking_cred = null,
        .network = 0,
    };
    
    const bob_addr = crypto.Crypto.Address{
        .payment_cred = .{ .key_hash = crypto.Crypto.hash224(&bob.public.bytes) },
        .staking_cred = null,
        .network = 0,
    };
    
    const charlie_addr = crypto.Crypto.Address{
        .payment_cred = .{ .key_hash = crypto.Crypto.hash224(&charlie.public.bytes) },
        .staking_cred = null,
        .network = 0,
    };
    
    std.log.info("  Created 3 participants", .{});
    
    // Create ledger
    var test_ledger = ledger.Ledger.init(allocator);
    defer test_ledger.deinit();
    
    // Initial funding
    const genesis_tx = crypto.Crypto.Hash256.fromBytes([_]u8{0} ** 32);
    try test_ledger.addUtxo(
        .{ .tx_id = genesis_tx, .index = 0 },
        .{
            .address = alice_addr,
            .amount = .{ .lovelace = 10_000_000 },
            .datum_hash = null,
            .script_ref = null,
        },
    );
    
    std.log.info("  Alice funded with 10 ADA", .{});
    
    // Transaction 1: Alice sends to Bob and Charlie
    std.log.info("  Transaction 1: Alice → Bob (6 ADA) + Charlie (3 ADA)", .{});
    
    // Create transaction body first
    const tx1_body = transaction.Transaction.Body{
            .inputs = &[_]transaction.Transaction.Input{
                .{ .tx_id = genesis_tx, .index = 0 },
            },
            .outputs = &[_]transaction.Transaction.Output{
                .{
                    .address = bob_addr,
                    .amount = .{ .lovelace = 6_000_000 },
                    .datum_hash = null,
                    .script_ref = null,
                },
                .{
                    .address = charlie_addr,
                    .amount = .{ .lovelace = 3_000_000 },
                    .datum_hash = null,
                    .script_ref = null,
                },
                .{
                    .address = alice_addr,
                    .amount = .{ .lovelace = 800_000 }, // Change minus fee
                    .datum_hash = null,
                    .script_ref = null,
                },
            },
            .fee = 200_000,
            .ttl = null,
            .certs = &[_]transaction.Transaction.Certificate{},
            .withdrawals = std.AutoHashMap(transaction.Transaction.RewardAccount, u64).init(allocator),
            .update = null,
            .auxiliary_data_hash = null,
            .validity_interval_start = null,
            .mint = std.AutoHashMap(crypto.Crypto.Hash224, transaction.Transaction.MintAssets).init(allocator),
            .script_data_hash = null,
            .collateral = &[_]transaction.Transaction.Input{},
            .required_signers = &[_]crypto.Crypto.Hash224{},
            .network_id = null,
            .collateral_return = null,
            .total_collateral = null,
            .reference_inputs = &[_]transaction.Transaction.Input{},
        };
    
    // Sign the transaction body
    const tx1_body_hash = tx1_body.hash();
    
    const tx1 = transaction.Transaction{
        .body = tx1_body,
        .witness_set = .{
            .vkey_witnesses = &[_]transaction.Transaction.VKeyWitness{
                .{
                    .vkey = alice.public,
                    .signature = try alice.sign(&tx1_body_hash.bytes),
                },
            },
            .native_scripts = &[_]transaction.Transaction.NativeScript{},
            .bootstrap_witnesses = &[_]transaction.Transaction.BootstrapWitness{},
            .plutus_scripts_v1 = &[_][]const u8{},
            .plutus_data = &[_]transaction.Transaction.PlutusData{},
            .redeemers = &[_]transaction.Transaction.Redeemer{},
            .plutus_scripts_v2 = &[_][]const u8{},
        },
        .is_valid = true,
        .auxiliary_data = null,
    };
    
    // Apply transaction
    try test_ledger.applyTransaction(&tx1);
    const tx1_id = tx1.body.hash();
    
    std.log.info("    Transaction applied: {x}", .{std.fmt.fmtSliceHexLower(&tx1_id.bytes[0..8])});
    std.log.info("    Ledger state: {} UTXOs", .{test_ledger.getUtxoCount()});
    
    // Transaction 2: Bob sends to Charlie
    std.log.info("  Transaction 2: Bob → Charlie (2 ADA)", .{});
    
    // Create transaction body first
    const tx2_body = transaction.Transaction.Body{
            .inputs = &[_]transaction.Transaction.Input{
                .{ .tx_id = tx1_id, .index = 0 }, // Bob's UTXO from tx1
            },
            .outputs = &[_]transaction.Transaction.Output{
                .{
                    .address = charlie_addr,
                    .amount = .{ .lovelace = 2_000_000 },
                    .datum_hash = null,
                    .script_ref = null,
                },
                .{
                    .address = bob_addr,
                    .amount = .{ .lovelace = 3_800_000 }, // Change minus fee
                    .datum_hash = null,
                    .script_ref = null,
                },
            },
            .fee = 200_000,
            .ttl = null,
            .certs = &[_]transaction.Transaction.Certificate{},
            .withdrawals = std.AutoHashMap(transaction.Transaction.RewardAccount, u64).init(allocator),
            .update = null,
            .auxiliary_data_hash = null,
            .validity_interval_start = null,
            .mint = std.AutoHashMap(crypto.Crypto.Hash224, transaction.Transaction.MintAssets).init(allocator),
            .script_data_hash = null,
            .collateral = &[_]transaction.Transaction.Input{},
            .required_signers = &[_]crypto.Crypto.Hash224{},
            .network_id = null,
            .collateral_return = null,
            .total_collateral = null,
            .reference_inputs = &[_]transaction.Transaction.Input{},
        };
    
    // Sign the transaction body
    const tx2_body_hash = tx2_body.hash();
    
    const tx2 = transaction.Transaction{
        .body = tx2_body,
        .witness_set = .{
            .vkey_witnesses = &[_]transaction.Transaction.VKeyWitness{
                .{
                    .vkey = bob.public,
                    .signature = try bob.sign(&tx2_body_hash.bytes),
                },
            },
            .native_scripts = &[_]transaction.Transaction.NativeScript{},
            .bootstrap_witnesses = &[_]transaction.Transaction.BootstrapWitness{},
            .plutus_scripts_v1 = &[_][]const u8{},
            .plutus_data = &[_]transaction.Transaction.PlutusData{},
            .redeemers = &[_]transaction.Transaction.Redeemer{},
            .plutus_scripts_v2 = &[_][]const u8{},
        },
        .is_valid = true,
        .auxiliary_data = null,
    };
    
    // Apply transaction
    try test_ledger.applyTransaction(&tx2);
    const tx2_id = tx2.body.hash();
    
    std.log.info("    Transaction applied: {x}", .{std.fmt.fmtSliceHexLower(&tx2_id.bytes[0..8])});
    std.log.info("    Final ledger state: {} UTXOs", .{test_ledger.getUtxoCount()});
    
    // Show final balances
    std.log.info("  Final balances:", .{});
    
    var alice_balance: u64 = 0;
    var bob_balance: u64 = 0;
    var charlie_balance: u64 = 0;
    
    var iter = test_ledger.utxos.iterator();
    while (iter.next()) |entry| {
        const output = entry.value_ptr.*;
        if (std.meta.eql(output.address, alice_addr)) {
            alice_balance += output.amount.lovelace;
        } else if (std.meta.eql(output.address, bob_addr)) {
            bob_balance += output.amount.lovelace;
        } else if (std.meta.eql(output.address, charlie_addr)) {
            charlie_balance += output.amount.lovelace;
        }
    }
    
    std.log.info("    Alice: {} lovelace ({:.2} ADA)", .{ alice_balance, @as(f64, @floatFromInt(alice_balance)) / 1_000_000 });
    std.log.info("    Bob: {} lovelace ({:.2} ADA)", .{ bob_balance, @as(f64, @floatFromInt(bob_balance)) / 1_000_000 });
    std.log.info("    Charlie: {} lovelace ({:.2} ADA)", .{ charlie_balance, @as(f64, @floatFromInt(charlie_balance)) / 1_000_000 });
    
    std.log.info("", .{});
}