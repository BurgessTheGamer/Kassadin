const std = @import("std");
const crypto = @import("crypto/crypto.zig");
const address = @import("crypto/address.zig");
const tx_mod = @import("ledger/transaction.zig");
const ledger_mod = @import("ledger/ledger.zig");
const block_mod = @import("ledger/block.zig");

pub fn main() !void {
    const stdout = std.io.getStdOut().writer();
    
    // Initialize
    try crypto.Crypto.init();
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    try stdout.print("\nKassadin Ledger Demo\n", .{});
    try stdout.print("====================\n\n", .{});
    
    // Create ledger
    var ledger = ledger_mod.Ledger.init(allocator);
    defer ledger.deinit();
    
    // Create some keypairs for our actors
    try stdout.print("1. Creating actors...\n", .{});
    var alice = try crypto.Crypto.KeyPair.generate();
    defer alice.deinit();
    var bob = try crypto.Crypto.KeyPair.generate();
    defer bob.deinit();
    var charlie = try crypto.Crypto.KeyPair.generate();
    defer charlie.deinit();
    
    const alice_addr = address.enterpriseAddress(.testnet, alice.public);
    const bob_addr = address.enterpriseAddress(.testnet, bob.public);
    const charlie_addr = address.enterpriseAddress(.testnet, charlie.public);
    
    try stdout.print("   ✓ Alice, Bob, and Charlie created\n", .{});
    
    // Create genesis UTXO for Alice (she starts with 1000 ADA)
    try stdout.print("\n2. Creating genesis UTXO...\n", .{});
    const genesis_tx_id = crypto.Crypto.Hash256.fromBytes([_]u8{0} ** 32);
    const genesis_input = tx_mod.TransactionInput{
        .tx_id = genesis_tx_id,
        .output_index = 0,
    };
    const genesis_output = tx_mod.TransactionOutput{
        .address = alice_addr,
        .value = tx_mod.Value{ .lovelace = 1_000_000_000 }, // 1000 ADA
    };
    
    try ledger.utxos.put(genesis_input, genesis_output);
    ledger.stats.total_utxos = 1;
    ledger.stats.total_lovelace = genesis_output.value.lovelace;
    
    try stdout.print("   ✓ Alice starts with 1000 ADA\n", .{});
    try stdout.print("   ✓ Total UTXOs: {}\n", .{ledger.getUtxoCount()});
    try stdout.print("   ✓ Total ADA: {}\n", .{ledger.getTotalLovelace() / 1_000_000});
    
    // Alice sends 100 ADA to Bob
    try stdout.print("\n3. Alice sends 100 ADA to Bob...\n", .{});
    
    const tx1_inputs = [_]tx_mod.TransactionInput{genesis_input};
    const tx1_outputs = [_]tx_mod.TransactionOutput{
        // Bob gets 100 ADA
        tx_mod.TransactionOutput{
            .address = bob_addr,
            .value = tx_mod.Value{ .lovelace = 100_000_000 },
        },
        // Alice gets change (899.8 ADA after 0.2 ADA fee)
        tx_mod.TransactionOutput{
            .address = alice_addr,
            .value = tx_mod.Value{ .lovelace = 899_800_000 },
        },
    };
    
    const tx1_witnesses = [_]tx_mod.VKeyWitness{
        tx_mod.VKeyWitness{
            .vkey = alice.public,
            .signature = try crypto.Crypto.sign("tx1", alice.secret),
        },
    };
    
    const tx1 = tx_mod.Transaction{
        .body = tx_mod.TransactionBody{
            .inputs = &tx1_inputs,
            .outputs = &tx1_outputs,
            .fee = 200_000, // 0.2 ADA
            .ttl = 1000,
        },
        .witnesses = tx_mod.TransactionWitnessSet{
            .vkey_witnesses = &tx1_witnesses,
        },
    };
    
    try ledger.applyTransaction(tx1);
    const tx1_id = tx1.id();
    
    try stdout.print("   ✓ Transaction applied\n", .{});
    const tx1_id_slice = tx1_id.bytes[0..8];
    try stdout.print("   ✓ TX ID: {x}\n", .{std.fmt.fmtSliceHexLower(tx1_id_slice)});
    try stdout.print("   ✓ Total UTXOs: {}\n", .{ledger.getUtxoCount()});
    
    // Bob sends 50 ADA to Charlie
    try stdout.print("\n4. Bob sends 50 ADA to Charlie...\n", .{});
    
    const bob_input = tx_mod.TransactionInput{
        .tx_id = tx1_id,
        .output_index = 0, // Bob's output from tx1
    };
    
    const tx2_inputs = [_]tx_mod.TransactionInput{bob_input};
    const tx2_outputs = [_]tx_mod.TransactionOutput{
        // Charlie gets 50 ADA
        tx_mod.TransactionOutput{
            .address = charlie_addr,
            .value = tx_mod.Value{ .lovelace = 50_000_000 },
        },
        // Bob gets change (49.8 ADA after 0.2 ADA fee)
        tx_mod.TransactionOutput{
            .address = bob_addr,
            .value = tx_mod.Value{ .lovelace = 49_800_000 },
        },
    };
    
    const tx2_witnesses = [_]tx_mod.VKeyWitness{
        tx_mod.VKeyWitness{
            .vkey = bob.public,
            .signature = try crypto.Crypto.sign("tx2", bob.secret),
        },
    };
    
    const tx2 = tx_mod.Transaction{
        .body = tx_mod.TransactionBody{
            .inputs = &tx2_inputs,
            .outputs = &tx2_outputs,
            .fee = 200_000,
            .ttl = 2000,
        },
        .witnesses = tx_mod.TransactionWitnessSet{
            .vkey_witnesses = &tx2_witnesses,
        },
    };
    
    try ledger.applyTransaction(tx2);
    const tx2_id = tx2.id();
    
    try stdout.print("   ✓ Transaction applied\n", .{});
    const tx2_id_slice = tx2_id.bytes[0..8];
    try stdout.print("   ✓ TX ID: {x}\n", .{std.fmt.fmtSliceHexLower(tx2_id_slice)});
    
    // Create a block with these transactions
    try stdout.print("\n5. Creating a block...\n", .{});
    
    const transactions = [_]tx_mod.Transaction{ tx1, tx2 };
    const block_body = block_mod.BlockBody{
        .transactions = &transactions,
    };
    
    const block_header = block_mod.BlockHeader{
        .block_number = 1,
        .slot = 100,
        .prev_hash = crypto.Crypto.Hash256.fromBytes([_]u8{0} ** 32),
        .body_hash = block_body.hash(),
        .issuer_vkey = alice.public, // Alice is the block producer
        .vrf_output = block_mod.VrfOutput{
            .output = [_]u8{0} ** 64,
            .proof = [_]u8{0} ** 80,
        },
        .block_size = block_body.estimateSize(),
        .operational_cert = block_mod.OperationalCert{
            .hot_vkey = [_]u8{0} ** 32,
            .sequence_number = 0,
            .kes_period = 0,
            .sigma = crypto.Crypto.Signature.fromBytes([_]u8{0} ** 64),
        },
        .protocol_version = block_mod.ProtocolVersion{ .major = 8, .minor = 0 },
    };
    
    const block = block_mod.Block{
        .header = block_header,
        .body = block_body,
    };
    
    try block.validate();
    const block_id = block.id();
    
    try stdout.print("   ✓ Block created and validated\n", .{});
    const block_id_slice = block_id.bytes[0..8];
    try stdout.print("   ✓ Block ID: {x}\n", .{std.fmt.fmtSliceHexLower(block_id_slice)});
    try stdout.print("   ✓ Block contains {} transactions\n", .{block.body.transactions.len});
    try stdout.print("   ✓ Total fees: {} lovelace\n", .{block.body.totalFees()});
    
    // Final state
    try stdout.print("\n6. Final ledger state:\n", .{});
    try stdout.print("   ✓ Total UTXOs: {}\n", .{ledger.getUtxoCount()});
    try stdout.print("   ✓ Total ADA: {} (excluding fees)\n", .{ledger.getTotalLovelace() / 1_000_000});
    try stdout.print("   ✓ Transactions processed: {}\n", .{ledger.stats.transactions_processed});
    
    // Show final balances
    try stdout.print("\n7. Final balances:\n", .{});
    
    // Count UTXOs per address (simplified)
    var alice_balance: u64 = 0;
    var bob_balance: u64 = 0;
    var charlie_balance: u64 = 0;
    
    var iter = ledger.utxos.iterator();
    while (iter.next()) |entry| {
        const output = entry.value_ptr.*;
        if (output.address.payment.key_hash[0] == alice_addr.payment.key_hash[0]) {
            alice_balance += output.value.lovelace;
        } else if (output.address.payment.key_hash[0] == bob_addr.payment.key_hash[0]) {
            bob_balance += output.value.lovelace;
        } else if (output.address.payment.key_hash[0] == charlie_addr.payment.key_hash[0]) {
            charlie_balance += output.value.lovelace;
        }
    }
    
    try stdout.print("   ✓ Alice: {} ADA\n", .{alice_balance / 1_000_000});
    try stdout.print("   ✓ Bob: {} ADA\n", .{bob_balance / 1_000_000});
    try stdout.print("   ✓ Charlie: {} ADA\n", .{charlie_balance / 1_000_000});
    try stdout.print("   ✓ Fees collected: {} ADA\n", .{@as(u64, 400_000) / 1_000_000});
    
    try stdout.print("\n✅ Ledger demo completed successfully!\n\n", .{});
}