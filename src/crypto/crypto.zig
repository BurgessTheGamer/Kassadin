const std = @import("std");
const testing = std.testing;
const sodium = @import("sodium.zig");
const kes_mod = @import("kes.zig");

/// Core cryptographic operations for Cardano
pub const Crypto = struct {
    /// Ed25519 public key (32 bytes)
    pub const PublicKey = struct {
        bytes: [sodium.Ed25519.PUBLIC_KEY_BYTES]u8,

        pub fn fromBytes(bytes: [sodium.Ed25519.PUBLIC_KEY_BYTES]u8) PublicKey {
            return .{ .bytes = bytes };
        }

        pub fn toHex(self: PublicKey, allocator: std.mem.Allocator) ![]u8 {
            const hex = try allocator.alloc(u8, 64);
            _ = try std.fmt.bufPrint(hex, "{x}", .{std.fmt.fmtSliceHexLower(&self.bytes)});
            return hex;
        }

        pub fn toHexBuf(self: PublicKey, buffer: []u8) ![]u8 {
            if (buffer.len < 64) return error.BufferTooSmall;
            _ = try std.fmt.bufPrint(buffer, "{x}", .{std.fmt.fmtSliceHexLower(&self.bytes)});
            return buffer[0..64];
        }

        pub fn eql(self: PublicKey, other: PublicKey) bool {
            return sodium.Memory.compare(&self.bytes, &other.bytes);
        }

        pub fn zero() PublicKey {
            return .{ .bytes = [_]u8{0} ** sodium.Ed25519.PUBLIC_KEY_BYTES };
        }

        pub fn verify(self: PublicKey, message: []const u8, signature: Signature) !void {
            const valid = try sodium.Ed25519.verify(signature.bytes, message, self.bytes);
            if (!valid) {
                return error.InvalidSignature;
            }
        }
    };

    /// Ed25519 secret key (64 bytes)
    pub const SecretKey = struct {
        bytes: [sodium.Ed25519.SECRET_KEY_BYTES]u8,

        pub fn fromBytes(bytes: [sodium.Ed25519.SECRET_KEY_BYTES]u8) SecretKey {
            return .{ .bytes = bytes };
        }

        pub fn deinit(self: *SecretKey) void {
            // Securely wipe secret key from memory
            sodium.Memory.secureZero(&self.bytes);
        }

        pub fn getPublicKey(self: SecretKey) !PublicKey {
            const pub_bytes = try sodium.Ed25519.publicKeyFromSecret(self.bytes);
            return PublicKey.fromBytes(pub_bytes);
        }
    };

    /// Ed25519 signature (64 bytes)
    pub const Signature = struct {
        bytes: [sodium.Ed25519.SIGNATURE_BYTES]u8,

        pub fn fromBytes(bytes: [sodium.Ed25519.SIGNATURE_BYTES]u8) Signature {
            return .{ .bytes = bytes };
        }

        pub fn toHex(self: Signature, allocator: std.mem.Allocator) ![]u8 {
            const hex = try allocator.alloc(u8, 128);
            _ = try std.fmt.bufPrint(hex, "{x}", .{std.fmt.fmtSliceHexLower(&self.bytes)});
            return hex;
        }

        pub fn zero() Signature {
            return .{ .bytes = [_]u8{0} ** sodium.Ed25519.SIGNATURE_BYTES };
        }
    };

    /// Blake2b-256 hash (32 bytes)
    pub const Hash256 = struct {
        bytes: [sodium.Blake2b.HASH_256_BYTES]u8,

        pub fn fromBytes(bytes: [sodium.Blake2b.HASH_256_BYTES]u8) Hash256 {
            return .{ .bytes = bytes };
        }

        pub fn toHex(self: Hash256, allocator: std.mem.Allocator) ![]u8 {
            const hex = try allocator.alloc(u8, 64);
            _ = try std.fmt.bufPrint(hex, "{x}", .{std.fmt.fmtSliceHexLower(&self.bytes)});
            return hex;
        }

        pub fn eql(self: Hash256, other: Hash256) bool {
            return sodium.Memory.compare(&self.bytes, &other.bytes);
        }

        pub fn zero() Hash256 {
            return .{ .bytes = [_]u8{0} ** 32 };
        }
    };

    /// Blake2b-224 hash (28 bytes) - used for addresses
    pub const Hash224 = struct {
        bytes: [sodium.Blake2b.HASH_224_BYTES]u8,

        pub fn fromBytes(bytes: [sodium.Blake2b.HASH_224_BYTES]u8) Hash224 {
            return .{ .bytes = bytes };
        }
    };

    /// Key pair for Ed25519
    pub const KeyPair = struct {
        public: PublicKey,
        secret: SecretKey,

        pub fn generate() !KeyPair {
            const keys = try sodium.Ed25519.generateKeypair();
            return KeyPair{
                .public = PublicKey.fromBytes(keys.public),
                .secret = SecretKey.fromBytes(keys.secret),
            };
        }

        pub fn fromSeed(seed: [sodium.Ed25519.SEED_BYTES]u8) !KeyPair {
            const keys = try sodium.Ed25519.keypairFromSeed(seed);
            return KeyPair{
                .public = PublicKey.fromBytes(keys.public),
                .secret = SecretKey.fromBytes(keys.secret),
            };
        }

        pub fn deinit(self: *KeyPair) void {
            self.secret.deinit();
        }

        pub fn sign(self: KeyPair, message: []const u8) !Signature {
            const sig_bytes = try sodium.Ed25519.sign(message, self.secret.bytes);
            return Signature.fromBytes(sig_bytes);
        }
    };

    /// Initialize the crypto subsystem
    pub fn init() !void {
        try sodium.init();
    }

    /// Sign a message with Ed25519
    pub fn sign(message: []const u8, secret_key: SecretKey) !Signature {
        const sig_bytes = try sodium.Ed25519.sign(message, secret_key.bytes);
        return Signature.fromBytes(sig_bytes);
    }

    /// Verify an Ed25519 signature
    pub fn verifySignature(
        signature: Signature,
        message: []const u8,
        public_key: PublicKey,
    ) !bool {
        return try sodium.Ed25519.verify(signature.bytes, message, public_key.bytes);
    }

    /// Compute Blake2b-256 hash
    pub fn hash256(data: []const u8) Hash256 {
        return Hash256.fromBytes(sodium.Blake2b.hash256(data));
    }

    /// Compute Blake2b-224 hash (for addresses)
    pub fn hash224(data: []const u8) Hash224 {
        return Hash224.fromBytes(sodium.Blake2b.hash224(data));
    }

    /// Generate random bytes
    pub fn randomBytes(buffer: []u8) void {
        sodium.Random.bytes(buffer);
    }

    /// Re-export KES for convenience
    pub const KES = kes_mod.KES;
};

test "Crypto initialization" {
    try Crypto.init();
}

test "PublicKey hex conversion" {
    try Crypto.init();

    const pk = Crypto.PublicKey.fromBytes([_]u8{0xAB} ** 32);
    var hex_buf: [64]u8 = undefined;
    const hex = try pk.toHexBuf(&hex_buf);
    try testing.expectEqualStrings(
        "abababababababababababababababababababababababababababababababab",
        hex,
    );
}

test "KeyPair generation and signing" {
    try Crypto.init();

    // Generate a new keypair
    var keypair = try Crypto.KeyPair.generate();
    defer keypair.deinit();

    // Sign a message
    const message = "Hello, Cardano!";
    const signature = try Crypto.sign(message, keypair.secret);

    // Verify the signature
    const valid = try Crypto.verifySignature(signature, message, keypair.public);
    try testing.expect(valid);

    // Verify with wrong message should fail
    const wrong_message = "Hello, Bitcoin!";
    const invalid = try Crypto.verifySignature(signature, wrong_message, keypair.public);
    try testing.expect(!invalid);
}

test "Hash256 deterministic" {
    try Crypto.init();

    const data = "Hello, Cardano!";
    const hash1 = Crypto.hash256(data);
    const hash2 = Crypto.hash256(data);

    try testing.expect(hash1.eql(hash2));

    // Different data should produce different hash
    const hash3 = Crypto.hash256("Different data");
    try testing.expect(!hash1.eql(hash3));
}

test "KeyPair from seed" {
    try Crypto.init();

    // Use a fixed seed
    const seed = [_]u8{42} ** sodium.Ed25519.SEED_BYTES;

    var kp1 = try Crypto.KeyPair.fromSeed(seed);
    defer kp1.deinit();

    var kp2 = try Crypto.KeyPair.fromSeed(seed);
    defer kp2.deinit();

    // Same seed should produce same keys
    try testing.expect(kp1.public.eql(kp2.public));
}

test "Random bytes generation" {
    try Crypto.init();

    var buf1: [32]u8 = undefined;
    var buf2: [32]u8 = undefined;

    Crypto.randomBytes(&buf1);
    Crypto.randomBytes(&buf2);

    // Random bytes should be different (extremely unlikely to be same)
    try testing.expect(!std.mem.eql(u8, &buf1, &buf2));
}
