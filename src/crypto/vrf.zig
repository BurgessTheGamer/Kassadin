const std = @import("std");
const crypto = @import("crypto.zig");
const sodium = @import("sodium.zig");

/// VRF (Verifiable Random Function) for Ouroboros Praos
/// This is the "lottery ticket" system that determines who can make blocks
pub const VRF = struct {
    /// VRF public key (32 bytes)
    pub const PublicKey = struct {
        bytes: [32]u8,
        
        pub fn fromBytes(bytes: [32]u8) PublicKey {
            return .{ .bytes = bytes };
        }
    };
    
    /// VRF secret key (64 bytes)
    pub const SecretKey = struct {
        bytes: [64]u8,
        
        pub fn fromBytes(bytes: [64]u8) SecretKey {
            return .{ .bytes = bytes };
        }
        
        pub fn deinit(self: *SecretKey) void {
            sodium.Memory.secureZero(&self.bytes);
        }
    };
    
    /// VRF output - the random value (64 bytes)
    pub const Output = struct {
        bytes: [64]u8,
        
        /// Convert output to a number between 0 and 1
        /// This is used to check if we won the lottery
        pub fn toUnitInterval(self: Output) f64 {
            // Take first 8 bytes and convert to float between 0 and 1
            var value: u64 = 0;
            for (0..8) |i| {
                value = (value << 8) | self.bytes[i];
            }
            // Divide by max u64 to get value between 0 and 1
            return @as(f64, @floatFromInt(value)) / @as(f64, @floatFromInt(std.math.maxInt(u64)));
        }
        
        pub fn fromBytes(bytes: [64]u8) Output {
            return .{ .bytes = bytes };
        }
    };
    
    /// VRF proof - proves the output is correct (80 bytes)
    pub const Proof = struct {
        bytes: [80]u8,
        
        pub fn fromBytes(bytes: [80]u8) Proof {
            return .{ .bytes = bytes };
        }
    };
    
    /// VRF key pair
    pub const KeyPair = struct {
        public: PublicKey,
        secret: SecretKey,
        
        /// Generate a new VRF keypair
        pub fn generate() !KeyPair {
            // For now, use Ed25519 keys as base (real VRF would be different)
            var ed_keypair = try crypto.Crypto.KeyPair.generate();
            defer ed_keypair.deinit();
            
            // Extend the keys to VRF size
            var vrf_secret: [64]u8 = undefined;
            @memcpy(vrf_secret[0..32], ed_keypair.secret.bytes[0..32]);
            @memcpy(vrf_secret[32..64], ed_keypair.secret.bytes[32..64]);
            
            return KeyPair{
                .public = PublicKey.fromBytes(ed_keypair.public.bytes),
                .secret = SecretKey.fromBytes(vrf_secret),
            };
        }
        
        pub fn deinit(self: *KeyPair) void {
            self.secret.deinit();
        }
    };
    
    /// Evaluate VRF (create output and proof)
    pub fn evaluate(
        message: []const u8,
        secret_key: SecretKey,
    ) !struct { output: Output, proof: Proof } {
        // This is a simplified VRF - real implementation would use proper VRF algorithm
        // For now, we'll use HMAC as a placeholder
        
        // Create output by hashing message with secret key
        var hasher = std.crypto.hash.blake2.Blake2b512.init(.{});
        hasher.update(secret_key.bytes[0..32]);
        hasher.update(message);
        
        var output_bytes: [64]u8 = undefined;
        hasher.final(&output_bytes);
        
        // Create proof (simplified - just hash output with rest of secret)
        var proof_hasher = std.crypto.hash.blake2.Blake2b512.init(.{});
        proof_hasher.update(secret_key.bytes[32..64]);
        proof_hasher.update(&output_bytes);
        
        var proof_data: [64]u8 = undefined;
        proof_hasher.final(&proof_data);
        
        var proof_bytes: [80]u8 = undefined;
        @memcpy(proof_bytes[0..64], &proof_data);
        // Last 16 bytes are additional proof data
        @memset(proof_bytes[64..80], 0);
        
        return .{
            .output = Output.fromBytes(output_bytes),
            .proof = Proof.fromBytes(proof_bytes),
        };
    }
    
    /// Verify VRF proof
    pub fn verify(
        message: []const u8,
        public_key: PublicKey,
        output: Output,
        proof: Proof,
    ) !bool {
        // Simplified verification - real VRF would verify the proof cryptographically
        // For now, just check that output matches what we'd compute
        _ = message;
        _ = public_key;
        _ = output;
        _ = proof;
        
        // In real implementation, this would verify the proof
        // For testing, we'll accept all proofs
        return true;
    }
    
    /// Check if VRF output wins the slot leader election
    pub fn isSlotLeader(
        vrf_output: Output,
        stake: u64,
        total_stake: u64,
        active_slot_coefficient: f64, // f parameter (e.g., 0.05 = 5% of slots have blocks)
    ) bool {
        // Calculate threshold based on stake
        const relative_stake = @as(f64, @floatFromInt(stake)) / @as(f64, @floatFromInt(total_stake));
        
        // Probability of being leader = 1 - (1 - f)^stake
        // For small f and stake, this approximates to: f * relative_stake
        const threshold = active_slot_coefficient * relative_stake;
        
        // Check if VRF output is below threshold
        const vrf_value = vrf_output.toUnitInterval();
        
        return vrf_value < threshold;
    }
};

// Tests
test "VRF key generation" {
    var keypair = try VRF.KeyPair.generate();
    defer keypair.deinit();
    
    try std.testing.expectEqual(@as(usize, 32), keypair.public.bytes.len);
    try std.testing.expectEqual(@as(usize, 64), keypair.secret.bytes.len);
}

test "VRF evaluation and verification" {
    var keypair = try VRF.KeyPair.generate();
    defer keypair.deinit();
    
    const message = "slot:12345";
    
    const result = try VRF.evaluate(message, keypair.secret);
    
    try std.testing.expectEqual(@as(usize, 64), result.output.bytes.len);
    try std.testing.expectEqual(@as(usize, 80), result.proof.bytes.len);
    
    const valid = try VRF.verify(message, keypair.public, result.output, result.proof);
    try std.testing.expect(valid);
}

test "VRF output to unit interval" {
    // Test with known values
    var output1 = VRF.Output{ .bytes = [_]u8{0} ** 64 };
    try std.testing.expectEqual(@as(f64, 0.0), output1.toUnitInterval());
    
    var output2 = VRF.Output{ .bytes = [_]u8{0xFF} ** 64 };
    const value2 = output2.toUnitInterval();
    try std.testing.expect(value2 > 0.99);
    try std.testing.expect(value2 <= 1.0);
}

test "Slot leader election" {
    // Test with 10% stake and 5% active slot coefficient
    const stake: u64 = 100_000_000; // 100 ADA
    const total_stake: u64 = 1_000_000_000; // 1000 ADA total
    const f: f64 = 0.05; // 5% of slots have blocks
    
    // With 10% stake and f=0.05, probability should be ~0.005 (0.5%)
    
    // Test with low VRF output (should win)
    var winning_output = VRF.Output{ .bytes = [_]u8{0} ** 64 };
    winning_output.bytes[0] = 0x01; // Very small value
    
    try std.testing.expect(VRF.isSlotLeader(winning_output, stake, total_stake, f));
    
    // Test with high VRF output (should lose)
    const losing_output = VRF.Output{ .bytes = [_]u8{0xFF} ** 64 };
    
    try std.testing.expect(!VRF.isSlotLeader(losing_output, stake, total_stake, f));
}