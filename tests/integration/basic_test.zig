const std = @import("std");
const node = @import("../../src/node.zig");
const crypto = @import("../../src/crypto/crypto.zig");
const ledger = @import("../../src/ledger/ledger.zig");

test "full node initialization and shutdown" {
    const config = node.Node.Config{
        .network = .testnet,
        .log_level = .debug,
        .listen_port = 13001, // Use non-standard port for testing
    };
    
    var kassadin = try node.Node.init(std.testing.allocator, config);
    defer kassadin.deinit();

    // Verify initial state
    try std.testing.expectEqual(node.Node.State.initializing, kassadin.state);
    
    const status = kassadin.getStatus();
    try std.testing.expectEqual(node.Node.NetworkType.testnet, status.network);
    try std.testing.expectEqual(@as(usize, 0), status.peer_count);
    try std.testing.expectEqual(@as(usize, 0), status.utxo_count);
}

test "crypto integration" {
    try crypto.Crypto.init();
    
    // Test hash function
    const data = "Hello, Cardano!";
    const hash1 = crypto.Crypto.hash256(data);
    const hash2 = crypto.Crypto.hash256(data);
    
    // Hashes should be deterministic
    try std.testing.expectEqualSlices(u8, &hash1.bytes, &hash2.bytes);
}

test "ledger operations" {
    var ledger_state = ledger.Ledger.init(std.testing.allocator);
    defer ledger_state.deinit();
    
    // Create a test UTXO
    const tx_id = crypto.Crypto.Hash256.fromBytes([_]u8{0xAB} ** 32);
    const input = ledger.Ledger.TxInput{
        .tx_id = tx_id,
        .output_index = 0,
    };
    
    const addr_bytes = try std.testing.allocator.dupe(u8, "addr_test1234567890");
    const output = ledger.Ledger.TxOutput{
        .address = ledger.Ledger.Address{
            .bytes = addr_bytes,
            .allocator = std.testing.allocator,
        },
        .value = ledger.Ledger.Value{
            .lovelace = 1000000, // 1 ADA
        },
    };
    
    // Add and verify
    try ledger_state.addUtxo(input, output);
    try std.testing.expectEqual(@as(usize, 1), ledger_state.count());
    
    // Lookup
    const found = ledger_state.getUtxo(input);
    try std.testing.expect(found != null);
    try std.testing.expectEqual(@as(u64, 1000000), found.?.value.lovelace);
    
    // Remove
    try ledger_state.removeUtxo(input);
    try std.testing.expectEqual(@as(usize, 0), ledger_state.count());
}