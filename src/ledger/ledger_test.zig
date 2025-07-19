const std = @import("std");
const crypto = @import("../crypto/crypto.zig");
const tx_mod = @import("transaction.zig");
const address = @import("../crypto/address.zig");
const ledger_mod = @import("ledger.zig");

test "Ledger basic operations" {
    try crypto.Crypto.init();
    
    var ledger = ledger_mod.Ledger.init(std.testing.allocator);
    defer ledger.deinit();
    
    // Create a genesis UTXO
    const genesis_tx_id = crypto.Crypto.Hash256.fromBytes([_]u8{0} ** 32);
    const genesis_input = tx_mod.TransactionInput{
        .tx_id = genesis_tx_id,
        .output_index = 0,
    };
    
    const genesis_output = tx_mod.TransactionOutput{
        .address = address.Address{
            .network = .testnet,
            .payment = .{ .key_hash = [_]u8{1} ** 28 },
            .staking = null,
        },
        .value = tx_mod.Value{ .lovelace = 1_000_000_000 }, // 1000 ADA
    };
    
    // Manually add genesis UTXO
    try ledger.utxos.put(genesis_input, genesis_output);
    ledger.stats.total_utxos = 1;
    ledger.stats.total_lovelace = genesis_output.value.lovelace;
    
    try std.testing.expectEqual(@as(usize, 1), ledger.getUtxoCount());
    try std.testing.expectEqual(@as(u128, 1_000_000_000), ledger.getTotalLovelace());
}

test "Transaction validation and application" {
    try crypto.Crypto.init();
    
    var ledger = ledger_mod.Ledger.init(std.testing.allocator);
    defer ledger.deinit();
    
    // Create initial UTXO
    const initial_tx_id = crypto.Crypto.Hash256.fromBytes([_]u8{1} ** 32);
    const initial_input = tx_mod.TransactionInput{
        .tx_id = initial_tx_id,
        .output_index = 0,
    };
    
    const initial_output = tx_mod.TransactionOutput{
        .address = address.Address{
            .network = .testnet,
            .payment = .{ .key_hash = [_]u8{1} ** 28 },
            .staking = null,
        },
        .value = tx_mod.Value{ .lovelace = 10_000_000 }, // 10 ADA
    };
    
    try ledger.utxos.put(initial_input, initial_output);
    ledger.stats.total_utxos = 1;
    ledger.stats.total_lovelace = initial_output.value.lovelace;
    
    // Create a transaction that spends this UTXO
    const inputs = [_]tx_mod.TransactionInput{initial_input};
    const outputs = [_]tx_mod.TransactionOutput{
        tx_mod.TransactionOutput{
            .address = address.Address{
                .network = .testnet,
                .payment = .{ .key_hash = [_]u8{2} ** 28 },
                .staking = null,
            },
            .value = tx_mod.Value{ .lovelace = 5_000_000 }, // 5 ADA
        },
        tx_mod.TransactionOutput{
            .address = address.Address{
                .network = .testnet,
                .payment = .{ .key_hash = [_]u8{3} ** 28 },
                .staking = null,
            },
            .value = tx_mod.Value{ .lovelace = 4_800_000 }, // 4.8 ADA (change)
        },
    };
    
    // Create witness (simplified)
    var keypair = try crypto.Crypto.KeyPair.generate();
    defer keypair.deinit();
    
    const witnesses = [_]tx_mod.VKeyWitness{
        tx_mod.VKeyWitness{
            .vkey = keypair.public,
            .signature = try crypto.Crypto.sign("dummy", keypair.secret),
        },
    };
    
    const tx = tx_mod.Transaction{
        .body = tx_mod.TransactionBody{
            .inputs = &inputs,
            .outputs = &outputs,
            .fee = 200_000, // 0.2 ADA fee
            .ttl = 1000,
        },
        .witnesses = tx_mod.TransactionWitnessSet{
            .vkey_witnesses = &witnesses,
        },
    };
    
    // Apply transaction
    try ledger.applyTransaction(tx);
    
    // Check results
    try std.testing.expectEqual(@as(usize, 2), ledger.getUtxoCount());
    try std.testing.expectEqual(@as(u128, 9_800_000), ledger.getTotalLovelace());
    
    // Original UTXO should be gone
    try std.testing.expect(ledger.getUtxo(initial_input) == null);
    
    // New UTXOs should exist
    const tx_id = tx.id();
    const new_input1 = tx_mod.TransactionInput{ .tx_id = tx_id, .output_index = 0 };
    const new_input2 = tx_mod.TransactionInput{ .tx_id = tx_id, .output_index = 1 };
    
    try std.testing.expect(ledger.getUtxo(new_input1) != null);
    try std.testing.expect(ledger.getUtxo(new_input2) != null);
}

test "Transaction validation errors" {
    try crypto.Crypto.init();
    
    var ledger = ledger_mod.Ledger.init(std.testing.allocator);
    defer ledger.deinit();
    
    // Test 1: Spending non-existent UTXO
    {
        const inputs = [_]tx_mod.TransactionInput{
            tx_mod.TransactionInput{
                .tx_id = crypto.Crypto.Hash256.fromBytes([_]u8{99} ** 32),
                .output_index = 0,
            },
        };
        
        const outputs = [_]tx_mod.TransactionOutput{
            tx_mod.TransactionOutput{
                .address = address.Address{
                    .network = .testnet,
                    .payment = .{ .key_hash = [_]u8{1} ** 28 },
                    .staking = null,
                },
                .value = tx_mod.Value{ .lovelace = 1_000_000 },
            },
        };
        
        const tx = tx_mod.Transaction{
            .body = tx_mod.TransactionBody{
                .inputs = &inputs,
                .outputs = &outputs,
                .fee = 100_000,
            },
            .witnesses = tx_mod.TransactionWitnessSet{},
        };
        
        try std.testing.expectError(error.UtxoNotFound, ledger.validateTransaction(tx));
    }
    
    // Test 2: Value not preserved
    {
        // Add a UTXO to spend
        const utxo_input = tx_mod.TransactionInput{
            .tx_id = crypto.Crypto.Hash256.fromBytes([_]u8{1} ** 32),
            .output_index = 0,
        };
        
        try ledger.utxos.put(utxo_input, tx_mod.TransactionOutput{
            .address = address.Address{
                .network = .testnet,
                .payment = .{ .key_hash = [_]u8{1} ** 28 },
                .staking = null,
            },
            .value = tx_mod.Value{ .lovelace = 5_000_000 }, // 5 ADA
        });
        
        const inputs = [_]tx_mod.TransactionInput{utxo_input};
        const outputs = [_]tx_mod.TransactionOutput{
            tx_mod.TransactionOutput{
                .address = address.Address{
                    .network = .testnet,
                    .payment = .{ .key_hash = [_]u8{2} ** 28 },
                    .staking = null,
                },
                .value = tx_mod.Value{ .lovelace = 6_000_000 }, // 6 ADA (more than input!)
            },
        };
        
        const tx = tx_mod.Transaction{
            .body = tx_mod.TransactionBody{
                .inputs = &inputs,
                .outputs = &outputs,
                .fee = 100_000,
            },
            .witnesses = tx_mod.TransactionWitnessSet{},
        };
        
        try std.testing.expectError(error.ValueNotPreserved, ledger.validateTransaction(tx));
    }
}

test "Ledger snapshot and restore" {
    try crypto.Crypto.init();
    
    var ledger = ledger_mod.Ledger.init(std.testing.allocator);
    defer ledger.deinit();
    
    // Add some UTXOs
    var i: u32 = 0;
    while (i < 5) : (i += 1) {
        const input = tx_mod.TransactionInput{
            .tx_id = crypto.Crypto.Hash256.fromBytes([_]u8{@intCast(i)} ** 32),
            .output_index = 0,
        };
        
        const output = tx_mod.TransactionOutput{
            .address = address.Address{
                .network = .testnet,
                .payment = .{ .key_hash = [_]u8{@intCast(i)} ** 28 },
                .staking = null,
            },
            .value = tx_mod.Value{ .lovelace = 1_000_000 * (i + 1) },
        };
        
        try ledger.utxos.put(input, output);
        ledger.stats.total_utxos += 1;
        ledger.stats.total_lovelace += output.value.lovelace;
    }
    
    ledger.updateSlot(12345);
    
    // Create snapshot
    var snapshot = try ledger.createSnapshot(std.testing.allocator);
    defer snapshot.deinit();
    
    // Modify ledger
    ledger.utxos.clearAndFree();
    ledger.stats.total_utxos = 0;
    ledger.stats.total_lovelace = 0;
    ledger.updateSlot(99999);
    
    try std.testing.expectEqual(@as(usize, 0), ledger.getUtxoCount());
    
    // Restore from snapshot
    try ledger.restoreFromSnapshot(snapshot);
    
    // Verify restoration
    try std.testing.expectEqual(@as(usize, 5), ledger.getUtxoCount());
    try std.testing.expectEqual(@as(u64, 12345), ledger.current_slot);
    try std.testing.expectEqual(@as(u128, 15_000_000), ledger.getTotalLovelace());
}

test "Protocol parameters" {
    const params = ledger_mod.Ledger.ProtocolParameters{};
    
    // Test fee calculation
    const fee_small = params.calculateMinFee(200); // 200 byte transaction
    const fee_large = params.calculateMinFee(10000); // 10KB transaction
    
    try std.testing.expect(fee_small < fee_large);
    try std.testing.expect(fee_small >= params.min_fee_b);
}