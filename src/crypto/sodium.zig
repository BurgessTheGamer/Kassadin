const std = @import("std");
const c = @cImport({
    @cInclude("sodium.h");
});

/// Error types for libsodium operations
pub const SodiumError = error{
    InitFailed,
    InvalidKey,
    InvalidSignature,
    InvalidSeed,
    InvalidNonce,
    VerificationFailed,
    AllocationFailed,
};

/// Initialize libsodium (must be called before any other operations)
pub fn init() !void {
    if (c.sodium_init() < 0) {
        return SodiumError.InitFailed;
    }
}

/// Ed25519 operations
pub const Ed25519 = struct {
    pub const PUBLIC_KEY_BYTES = c.crypto_sign_ed25519_PUBLICKEYBYTES;
    pub const SECRET_KEY_BYTES = c.crypto_sign_ed25519_SECRETKEYBYTES;
    pub const SIGNATURE_BYTES = c.crypto_sign_ed25519_BYTES;
    pub const SEED_BYTES = c.crypto_sign_ed25519_SEEDBYTES;

    /// Generate a new Ed25519 keypair
    pub fn generateKeypair() !struct { public: [PUBLIC_KEY_BYTES]u8, secret: [SECRET_KEY_BYTES]u8 } {
        var public_key: [PUBLIC_KEY_BYTES]u8 = undefined;
        var secret_key: [SECRET_KEY_BYTES]u8 = undefined;

        if (c.crypto_sign_ed25519_keypair(&public_key, &secret_key) != 0) {
            return SodiumError.InvalidKey;
        }

        return .{ .public = public_key, .secret = secret_key };
    }

    /// Generate keypair from seed
    pub fn keypairFromSeed(seed: [SEED_BYTES]u8) !struct { public: [PUBLIC_KEY_BYTES]u8, secret: [SECRET_KEY_BYTES]u8 } {
        var public_key: [PUBLIC_KEY_BYTES]u8 = undefined;
        var secret_key: [SECRET_KEY_BYTES]u8 = undefined;

        if (c.crypto_sign_ed25519_seed_keypair(&public_key, &secret_key, &seed) != 0) {
            return SodiumError.InvalidSeed;
        }

        return .{ .public = public_key, .secret = secret_key };
    }

    /// Sign a message
    pub fn sign(message: []const u8, secret_key: [SECRET_KEY_BYTES]u8) ![SIGNATURE_BYTES]u8 {
        var signature: [SIGNATURE_BYTES]u8 = undefined;

        // We use detached signatures for Cardano compatibility
        if (c.crypto_sign_ed25519_detached(&signature, null, message.ptr, message.len, &secret_key) != 0) {
            return SodiumError.InvalidKey;
        }

        return signature;
    }

    /// Verify a signature
    pub fn verify(signature: [SIGNATURE_BYTES]u8, message: []const u8, public_key: [PUBLIC_KEY_BYTES]u8) !bool {
        const result = c.crypto_sign_ed25519_verify_detached(&signature, message.ptr, message.len, &public_key);
        return result == 0;
    }

    /// Extract public key from secret key
    pub fn publicKeyFromSecret(secret_key: [SECRET_KEY_BYTES]u8) ![PUBLIC_KEY_BYTES]u8 {
        var public_key: [PUBLIC_KEY_BYTES]u8 = undefined;

        if (c.crypto_sign_ed25519_sk_to_pk(&public_key, &secret_key) != 0) {
            return SodiumError.InvalidKey;
        }

        return public_key;
    }
};

/// Blake2b hashing
pub const Blake2b = struct {
    pub const HASH_256_BYTES = 32;
    pub const HASH_224_BYTES = 28;
    pub const HASH_512_BYTES = 64;

    /// Compute Blake2b-256 hash
    pub fn hash256(data: []const u8) [HASH_256_BYTES]u8 {
        var hash: [HASH_256_BYTES]u8 = undefined;
        _ = c.crypto_generichash_blake2b(&hash, HASH_256_BYTES, data.ptr, data.len, null, 0);
        return hash;
    }

    /// Compute Blake2b-224 hash (used for addresses)
    pub fn hash224(data: []const u8) [HASH_224_BYTES]u8 {
        var hash: [HASH_224_BYTES]u8 = undefined;
        _ = c.crypto_generichash_blake2b(&hash, HASH_224_BYTES, data.ptr, data.len, null, 0);
        return hash;
    }

    /// Compute Blake2b-512 hash
    pub fn hash512(data: []const u8) [HASH_512_BYTES]u8 {
        var hash: [HASH_512_BYTES]u8 = undefined;
        _ = c.crypto_generichash_blake2b(&hash, HASH_512_BYTES, data.ptr, data.len, null, 0);
        return hash;
    }

    /// Compute Blake2b with custom output length
    pub fn hashCustom(data: []const u8, out_len: usize) ![]u8 {
        if (out_len < c.crypto_generichash_blake2b_BYTES_MIN or out_len > c.crypto_generichash_blake2b_BYTES_MAX) {
            return error.InvalidLength;
        }

        const hash = try std.heap.page_allocator.alloc(u8, out_len);
        _ = c.crypto_generichash_blake2b(hash.ptr, out_len, data.ptr, data.len, null, 0);
        return hash;
    }
};

/// VRF (Verifiable Random Function) operations
/// Note: libsodium doesn't have built-in VRF, so we'll need to implement or use another library
pub const VRF = struct {
    pub const PROOF_BYTES = 80; // Cardano VRF proof size
    pub const OUTPUT_BYTES = 64; // VRF output size

    /// Generate VRF proof (placeholder - needs actual implementation)
    pub fn prove(message: []const u8, secret_key: []const u8) ![PROOF_BYTES]u8 {
        _ = message;
        _ = secret_key;
        // TODO: Implement actual VRF using libsodium primitives or external library
        return [_]u8{0} ** PROOF_BYTES;
    }

    /// Verify VRF proof (placeholder - needs actual implementation)
    pub fn verify(proof: [PROOF_BYTES]u8, message: []const u8, public_key: []const u8) !bool {
        _ = proof;
        _ = message;
        _ = public_key;
        // TODO: Implement actual VRF verification
        return true;
    }
};

/// Random number generation
pub const Random = struct {
    /// Generate random bytes
    pub fn bytes(buffer: []u8) void {
        c.randombytes_buf(buffer.ptr, buffer.len);
    }

    /// Generate a random u32
    pub fn randomU32() u32 {
        return c.randombytes_random();
    }

    /// Generate a random u64
    pub fn randomU64() u64 {
        const high = @as(u64, c.randombytes_random());
        const low = @as(u64, c.randombytes_random());
        return (high << 32) | low;
    }
};

/// Generate random bytes (convenience function)
pub fn randomBytes(buffer: []u8) void {
    Random.bytes(buffer);
}

/// Memory utilities
pub const Memory = struct {
    /// Secure memory wipe
    pub fn secureZero(buffer: []u8) void {
        c.sodium_memzero(buffer.ptr, buffer.len);
    }

    /// Constant-time memory comparison
    pub fn compare(a: []const u8, b: []const u8) bool {
        if (a.len != b.len) return false;
        return c.sodium_memcmp(a.ptr, b.ptr, a.len) == 0;
    }
};

// Tests
test "libsodium initialization" {
    try init();
}

test "Ed25519 keypair generation" {
    try init();

    const keypair = try Ed25519.generateKeypair();
    try std.testing.expectEqual(@as(usize, Ed25519.PUBLIC_KEY_BYTES), keypair.public.len);
    try std.testing.expectEqual(@as(usize, Ed25519.SECRET_KEY_BYTES), keypair.secret.len);
}

test "Ed25519 sign and verify" {
    try init();

    const keypair = try Ed25519.generateKeypair();
    const message = "Hello, Cardano!";

    const signature = try Ed25519.sign(message, keypair.secret);
    try std.testing.expectEqual(@as(usize, Ed25519.SIGNATURE_BYTES), signature.len);

    const valid = try Ed25519.verify(signature, message, keypair.public);
    try std.testing.expect(valid);

    // Test invalid signature
    var bad_signature = signature;
    bad_signature[0] ^= 0xFF;
    const invalid = try Ed25519.verify(bad_signature, message, keypair.public);
    try std.testing.expect(!invalid);
}

test "Blake2b hashing" {
    try init();

    const data = "Hello, Cardano!";

    const hash256 = Blake2b.hash256(data);
    try std.testing.expectEqual(@as(usize, 32), hash256.len);

    const hash224 = Blake2b.hash224(data);
    try std.testing.expectEqual(@as(usize, 28), hash224.len);

    // Hashes should be deterministic
    const hash256_2 = Blake2b.hash256(data);
    try std.testing.expectEqualSlices(u8, &hash256, &hash256_2);
}

test "Random number generation" {
    try init();

    var buffer: [32]u8 = undefined;
    Random.bytes(&buffer);

    // Check that we got non-zero bytes (extremely unlikely to be all zeros)
    var all_zero = true;
    for (buffer) |byte| {
        if (byte != 0) {
            all_zero = false;
            break;
        }
    }
    try std.testing.expect(!all_zero);

    // Random u32/u64
    const r1 = Random.randomU32();
    const r2 = Random.randomU32();
    try std.testing.expect(r1 != r2); // Extremely unlikely to be equal
}

test "Memory utilities" {
    try init();

    var secret: [32]u8 = [_]u8{0xFF} ** 32;
    Memory.secureZero(&secret);

    for (secret) |byte| {
        try std.testing.expectEqual(@as(u8, 0), byte);
    }

    // Test comparison
    const a = "Hello";
    const b = "Hello";
    const c_str = "World";

    try std.testing.expect(Memory.compare(a, b));
    try std.testing.expect(!Memory.compare(a, c_str));
}
