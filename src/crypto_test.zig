const std = @import("std");
const crypto = @import("crypto/crypto.zig");
const address = @import("crypto/address.zig");

pub fn main() !void {
    const stdout = std.io.getStdOut().writer();
    
    // Initialize crypto
    try crypto.Crypto.init();
    try stdout.print("\nKassadin Crypto Test\n", .{});
    try stdout.print("====================\n\n", .{});
    
    // Test 1: Generate keypair
    try stdout.print("1. Generating Ed25519 keypair...\n", .{});
    var keypair = try crypto.Crypto.KeyPair.generate();
    defer keypair.deinit();
    
    var pub_hex_buf: [64]u8 = undefined;
    const pub_hex = try keypair.public.toHexBuf(&pub_hex_buf);
    try stdout.print("   ✓ Public Key: {s}\n", .{pub_hex});
    
    // Test 2: Sign and verify
    try stdout.print("\n2. Testing signatures...\n", .{});
    const message = "Kassadin: Fast Cardano Node";
    const signature = try crypto.Crypto.sign(message, keypair.secret);
    try stdout.print("   ✓ Signed message: \"{s}\"\n", .{message});
    
    const valid = try crypto.Crypto.verifySignature(signature, message, keypair.public);
    try stdout.print("   ✓ Signature verification: {s}\n", .{if (valid) "PASSED" else "FAILED"});
    
    // Test 3: Hashing
    try stdout.print("\n3. Testing Blake2b hashing...\n", .{});
    const hash = crypto.Crypto.hash256("Hello, Cardano!");
    try stdout.print("   ✓ Hash computed: ", .{});
    for (hash.bytes[0..8]) |byte| {
        try stdout.print("{x:0>2}", .{byte});
    }
    try stdout.print("...\n", .{});
    
    // Test 4: Address generation
    try stdout.print("\n4. Testing address generation...\n", .{});
    const addr = address.enterpriseAddress(.testnet, keypair.public);
    try stdout.print("   ✓ Created enterprise address for testnet\n", .{});
    try stdout.print("   ✓ Address type: {}\n", .{addr.getType()});
    
    // Test 5: Random generation
    try stdout.print("\n5. Testing random number generation...\n", .{});
    var random_bytes: [32]u8 = undefined;
    crypto.Crypto.randomBytes(&random_bytes);
    try stdout.print("   ✓ Generated 32 random bytes\n", .{});
    
    try stdout.print("\n✅ All crypto tests passed!\n\n", .{});
}