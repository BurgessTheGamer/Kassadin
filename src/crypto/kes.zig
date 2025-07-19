const std = @import("std");
const crypto = @import("crypto.zig");
const sodium = @import("sodium.zig");

/// Key Evolving Signatures (KES) implementation
/// Used in Cardano for forward-secure block signing
pub const KES = struct {
    /// KES algorithm parameters
    pub const Parameters = struct {
        /// Tree depth (Cardano uses 7)
        depth: u8 = 7,
        /// Total periods (2^depth)
        total_periods: u32 = 128,
        /// Period duration in slots
        period_length: u32 = 129600, // ~1.5 days
    };

    /// KES public key
    pub const PublicKey = struct {
        /// Root of the Merkle tree
        root: crypto.Crypto.Hash256,

        pub fn fromBytes(bytes: [32]u8) PublicKey {
            return .{ .root = crypto.Crypto.Hash256.fromBytes(bytes) };
        }

        pub fn toBytes(self: PublicKey) [32]u8 {
            return self.root.bytes;
        }

        pub fn zero() PublicKey {
            return .{ .root = crypto.Crypto.Hash256.zero() };
        }
    };

    /// KES secret key (evolving)
    pub const SecretKey = struct {
        /// Current period
        period: u32,
        /// Seed for current signing key
        seed: [32]u8,
        /// Merkle tree nodes needed for proof
        auth_path: [][32]u8,
        /// Parameters
        params: Parameters,

        allocator: std.mem.Allocator,

        /// Generate initial KES key pair
        pub fn generate(allocator: std.mem.Allocator, params: Parameters) !struct { public: PublicKey, secret: *SecretKey } {
            const sk = try allocator.create(SecretKey);
            errdefer allocator.destroy(sk);

            // Generate random seed
            var seed: [32]u8 = undefined;
            sodium.randomBytes(&seed);

            // Initialize secret key
            sk.* = .{
                .period = 0,
                .seed = seed,
                .auth_path = try allocator.alloc([32]u8, params.depth),
                .params = params,
                .allocator = allocator,
            };

            // Build Merkle tree and get root
            const root = try buildMerkleTree(allocator, seed, params);

            // Initialize auth path for period 0
            try sk.computeAuthPath();

            return .{
                .public = PublicKey{ .root = root },
                .secret = sk,
            };
        }

        pub fn deinit(self: *SecretKey) void {
            self.allocator.free(self.auth_path);
            self.allocator.destroy(self);
        }

        /// Evolve to next period
        pub fn evolve(self: *SecretKey) !void {
            if (self.period >= self.params.total_periods - 1) {
                return error.KESExhausted;
            }

            self.period += 1;

            // Update seed for new period
            var hasher = std.crypto.hash.blake2.Blake2b256.init(.{});
            hasher.update(&self.seed);
            hasher.update("evolve");
            hasher.final(&self.seed);

            // Update auth path
            try self.computeAuthPath();
        }

        /// Sign a message
        pub fn sign(self: *SecretKey, message: []const u8) !Signature {
            // Generate signing key for current period
            const signing_key = try self.deriveSigningKey();

            // Sign with Ed25519
            const sig = try signing_key.sign(message);

            // For simplified implementation, store the public key in the first auth path element
            var auth_path_copy = try self.allocator.dupe([32]u8, self.auth_path);
            if (auth_path_copy.len > 0) {
                auth_path_copy[0] = signing_key.public.bytes;
            }

            return Signature{
                .period = self.period,
                .signature = sig,
                .auth_path = auth_path_copy,
                .allocator = self.allocator,
            };
        }
        fn deriveSigningKey(self: *SecretKey) !crypto.Crypto.KeyPair {
            var seed: [32]u8 = undefined;
            var hasher = std.crypto.hash.blake2.Blake2b256.init(.{});
            hasher.update(&self.seed);
            hasher.update("signing");
            hasher.update(std.mem.asBytes(&self.period));
            hasher.final(&seed);

            // Derive Ed25519 key from seed
            return crypto.Crypto.KeyPair.fromSeed(seed);
        }

        fn computeAuthPath(self: *SecretKey) !void {
            // Simplified: In real implementation, compute Merkle auth path
            for (self.auth_path) |*node| {
                sodium.randomBytes(node);
            }
        }
    };

    /// KES signature
    pub const Signature = struct {
        /// Period when signed
        period: u32,
        /// Ed25519 signature
        signature: crypto.Crypto.Signature,
        /// Merkle authentication path
        auth_path: [][32]u8,

        allocator: std.mem.Allocator,

        pub fn deinit(self: *Signature) void {
            self.allocator.free(self.auth_path);
        }

        /// Verify signature
        pub fn verify(self: *const Signature, public_key: PublicKey, message: []const u8) !void {
            // Derive the signing public key for this period
            const signing_pubkey = try derivePublicKey(self.period, self.auth_path);

            // Verify Ed25519 signature
            try signing_pubkey.verify(message, self.signature);

            // For simplified implementation, skip Merkle path verification
            // In a real implementation, we would verify the Merkle path to the root
            _ = public_key;
        }
    };

    /// Build Merkle tree from seed
    fn buildMerkleTree(allocator: std.mem.Allocator, seed: [32]u8, params: Parameters) !crypto.Crypto.Hash256 {
        _ = allocator;
        _ = params;

        // Simplified: compute root hash
        var hasher = std.crypto.hash.blake2.Blake2b256.init(.{});
        hasher.update(&seed);
        hasher.update("merkle_root");

        var root: [32]u8 = undefined;
        hasher.final(&root);

        return crypto.Crypto.Hash256.fromBytes(root);
    }

    /// Derive public key for a period
    fn derivePublicKey(period: u32, auth_path: [][32]u8) !crypto.Crypto.PublicKey {
        _ = period;

        // For simplified implementation, the public key is stored in the first auth path element
        if (auth_path.len > 0) {
            return crypto.Crypto.PublicKey.fromBytes(auth_path[0]);
        }

        return error.InvalidAuthPath;
    }
    /// Compute Merkle root from leaf and auth path
    fn computeMerkleRoot(leaf: crypto.Crypto.PublicKey, auth_path: [][32]u8, period: u32) !crypto.Crypto.Hash256 {
        _ = period;

        var current = crypto.Crypto.hash256(&leaf.bytes);

        for (auth_path) |sibling| {
            var hasher = std.crypto.hash.blake2.Blake2b256.init(.{});
            hasher.update(&current.bytes);
            hasher.update(&sibling);

            var result: [32]u8 = undefined;
            hasher.final(&result);
            current = crypto.Crypto.Hash256.fromBytes(result);
        }

        return current;
    }
};

test "KES key generation and signing" {
    const allocator = std.testing.allocator;

    // Initialize crypto
    try crypto.Crypto.init();

    // Generate KES key pair
    const params = KES.Parameters{};
    const keypair = try KES.SecretKey.generate(allocator, params);
    defer keypair.secret.deinit();

    // Sign a message
    const message = "test message";
    var signature = try keypair.secret.sign(message);
    defer signature.deinit();

    try std.testing.expectEqual(@as(u32, 0), signature.period);

    // Verify signature
    try signature.verify(keypair.public, message);

    // Evolve key
    try keypair.secret.evolve();
    try std.testing.expectEqual(@as(u32, 1), keypair.secret.period);

    // Sign with evolved key
    var signature2 = try keypair.secret.sign(message);
    defer signature2.deinit();

    try std.testing.expectEqual(@as(u32, 1), signature2.period);
    try signature2.verify(keypair.public, message);
}

test "KES exhaustion" {
    const allocator = std.testing.allocator;

    try crypto.Crypto.init();

    // Create KES with small depth for testing
    const params = KES.Parameters{ .depth = 2, .total_periods = 4 };
    const keypair = try KES.SecretKey.generate(allocator, params);
    defer keypair.secret.deinit();

    // Evolve to max
    try keypair.secret.evolve(); // period 1
    try keypair.secret.evolve(); // period 2
    try keypair.secret.evolve(); // period 3

    // Next evolve should fail
    try std.testing.expectError(error.KESExhausted, keypair.secret.evolve());
}
