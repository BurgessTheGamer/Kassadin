const std = @import("std");
const storage = @import("storage/storage.zig");
const file_store = @import("storage/file_store.zig");
const crypto = @import("crypto/crypto.zig");
const address = @import("crypto/address.zig");
const transaction = @import("ledger/transaction.zig");
const block = @import("ledger/block.zig");

/// Storage demo showing persistence functionality
pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    std.log.info("=== Kassadin Storage Demo ===", .{});
    std.log.info("", .{});
    
    // Initialize crypto
    try crypto.Crypto.init();
    
    // Demo 1: File-based key-value store
    try demoFileStore(allocator);
    
    // Demo 2: Block storage
    try demoBlockStorage(allocator);
    
    // Demo 3: UTXO storage
    try demoUtxoStorage(allocator);
    
    std.log.info("", .{});
    std.log.info("Storage demo completed successfully!", .{});
}

fn demoFileStore(allocator: std.mem.Allocator) !void {
    std.log.info("1. File-based Key-Value Store Demo", .{});
    std.log.info("----------------------------------", .{});
    
    // Create store
    const fs = try file_store.FileStore.init(allocator, "demo_data");
    var store = fs.toStore();
    defer store.close();
    
    // Store some data
    const test_data = [_]struct { key: []const u8, value: []const u8 }{
        .{ .key = "config:network", .value = "mainnet" },
        .{ .key = "config:port", .value = "3001" },
        .{ .key = "state:height", .value = "8500000" },
        .{ .key = "state:tip", .value = "abc123def456" },
    };
    
    std.log.info("  Storing {} key-value pairs...", .{test_data.len});
    
    for (test_data) |kv| {
        try store.put(kv.key, kv.value);
        std.log.info("    Stored: {s} = {s}", .{ kv.key, kv.value });
    }
    
    // Retrieve data
    std.log.info("  Retrieving stored data...", .{});
    
    for (test_data) |kv| {
        const value = try store.get(kv.key, allocator);
        defer if (value) |v| allocator.free(v);
        
        if (value) |v| {
            std.log.info("    Retrieved: {s} = {s}", .{ kv.key, v });
            try std.testing.expectEqualStrings(kv.value, v);
        }
    }
    
    // Test persistence by creating new store instance
    std.log.info("  Testing persistence with new store instance...", .{});
    store.close();
    
    const fs2 = try file_store.FileStore.init(allocator, "demo_data");
    var store2 = fs2.toStore();
    defer store2.close();
    
    const height = try store2.get("state:height", allocator);
    defer if (height) |h| allocator.free(h);
    
    if (height) |h| {
        std.log.info("    Data persisted correctly: height = {s}", .{h});
    }
    
    // Clean up
    std.fs.cwd().deleteTree("demo_data") catch {};
    
    std.log.info("", .{});
}

fn demoBlockStorage(allocator: std.mem.Allocator) !void {
    std.log.info("2. Block Storage Demo", .{});
    std.log.info("--------------------", .{});
    
    // Create store
    const fs = try file_store.FileStore.init(allocator, "block_data");
    var store = fs.toStore();
    defer store.close();
    
    // Create block store
    var block_store = storage.Storage.BlockStore.init(allocator, &store);
    
    // Create a test block
    const keys = try crypto.Crypto.KeyPair.generate();
    const vrf_keys = try crypto.Crypto.VRF.KeyPair.generate();
    
    var test_block = block.Block{
        .header = .{
            .slot = 95_000_000,
            .block_number = 8_500_000,
            .prev_hash = crypto.Crypto.Hash256.zero(),
            .issuer_vkey = keys.public,
            .vrf_vkey = vrf_keys.public,
            .vrf_proof = crypto.Crypto.VRF.Proof.zero(),
            .block_body_size = 0,
            .block_body_hash = crypto.Crypto.Hash256.zero(),
            .operational_cert = .{
                .hot_vkey = keys.public,
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
    
    // Sign the block
    test_block.header.signature = try keys.sign(&test_block.header.hash().bytes);
    
    const block_hash = test_block.header.hash();
    std.log.info("  Created block #{} with hash: {}", .{
        test_block.header.block_number,
        std.fmt.fmtSliceHexLower(&block_hash.bytes[0..8]),
    });
    
    // Store the block
    try block_store.putBlock(&test_block);
    std.log.info("  Stored block in storage", .{});
    
    // Store chain tip
    try block_store.putTip(block_hash);
    std.log.info("  Updated chain tip", .{});
    
    // Retrieve chain tip
    const tip = try block_store.getTip();
    if (tip) |t| {
        std.log.info("  Retrieved chain tip: {}", .{std.fmt.fmtSliceHexLower(&t.bytes[0..8])});
        try std.testing.expect(std.meta.eql(block_hash, t));
    }
    
    // Clean up
    std.fs.cwd().deleteTree("block_data") catch {};
    
    std.log.info("", .{});
}

fn demoUtxoStorage(allocator: std.mem.Allocator) !void {
    std.log.info("3. UTXO Storage Demo", .{});
    std.log.info("-------------------", .{});
    
    // Create store
    const fs = try file_store.FileStore.init(allocator, "utxo_data");
    var store = fs.toStore();
    defer store.close();
    
    // Create UTXO store
    var utxo_store = storage.Storage.UtxoStore.init(allocator, &store);
    
    // Create test addresses
    const alice_keys = try crypto.Crypto.KeyPair.generate();
    const alice_addr = address.Address{
        .payment_cred = .{ .key_hash = crypto.Crypto.hash224(&alice_keys.public.bytes) },
        .staking_cred = null,
        .network = 0,
    };
    
    // Create test UTXOs
    const tx_id = crypto.Crypto.Hash256.fromBytes([_]u8{1} ** 32);
    
    const utxos = [_]struct {
        input: transaction.TransactionInput,
        output: transaction.TransactionOutput,
    }{
        .{
            .input = .{ .tx_id = tx_id, .index = 0 },
            .output = .{
                .address = alice_addr,
                .value = .{ .lovelace = 10_000_000 },
                .datum_hash = null,
            },
        },
        .{
            .input = .{ .tx_id = tx_id, .index = 1 },
            .output = .{
                .address = alice_addr,
                .value = .{ .lovelace = 5_000_000 },
                .datum_hash = null,
            },
        },
    };
    
    std.log.info("  Storing {} UTXOs...", .{utxos.len});
    
    for (utxos) |utxo| {
        try utxo_store.putUtxo(utxo.input, utxo.output);
        std.log.info("    Stored UTXO: {}:{} = {} lovelace", .{
            std.fmt.fmtSliceHexLower(&utxo.input.tx_id.bytes[0..8]),
            utxo.input.index,
            utxo.output.value.lovelace,
        });
    }
    
    // Retrieve UTXOs
    std.log.info("  Retrieving UTXOs...", .{});
    
    for (utxos) |utxo| {
        const output = try utxo_store.getUtxo(utxo.input);
        if (output) |out| {
            std.log.info("    Retrieved UTXO: {} lovelace", .{out.value.lovelace});
            try std.testing.expectEqual(utxo.output.value.lovelace, out.value.lovelace);
        }
    }
    
    // Delete a UTXO (simulate spending)
    std.log.info("  Simulating UTXO spending...", .{});
    try utxo_store.deleteUtxo(utxos[0].input);
    
    const deleted = try utxo_store.getUtxo(utxos[0].input);
    try std.testing.expect(deleted == null);
    std.log.info("    UTXO successfully spent (deleted)", .{});
    
    // Clean up
    std.fs.cwd().deleteTree("utxo_data") catch {};
    
    std.log.info("", .{});
}