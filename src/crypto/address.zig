const std = @import("std");
const crypto = @import("crypto.zig");
const bech32 = @import("bech32.zig");

/// Cardano address types
pub const AddressType = enum(u8) {
    // Shelley era addresses
    base_payment_key_stake_key = 0b0000,
    base_payment_script_stake_key = 0b0001,
    base_payment_key_stake_script = 0b0010,
    base_payment_script_stake_script = 0b0011,
    pointer_payment_key = 0b0100,
    pointer_payment_script = 0b0101,
    enterprise_payment_key = 0b0110,
    enterprise_payment_script = 0b0111,
    // Byron era addresses (legacy)
    byron = 0b1000,
    // Reward addresses
    reward_key = 0b1110,
    reward_script = 0b1111,
};

/// Network ID
pub const NetworkId = enum(u8) {
    mainnet = 1,
    testnet = 0,
};

/// Credential type (payment or stake)
pub const Credential = union(enum) {
    key_hash: [28]u8, // Blake2b-224 hash of public key
    script_hash: [28]u8, // Blake2b-224 hash of script
};

/// Shelley address structure
pub const Address = struct {
    network: NetworkId,
    payment: Credential,
    staking: ?Credential,
    
    /// Get the address type based on credentials
    pub fn getType(self: Address) AddressType {
        const has_stake = self.staking != null;
        const payment_is_key = switch (self.payment) {
            .key_hash => true,
            .script_hash => false,
        };
        
        if (!has_stake) {
            return if (payment_is_key) .enterprise_payment_key else .enterprise_payment_script;
        }
        
        const stake_is_key = switch (self.staking.?) {
            .key_hash => true,
            .script_hash => false,
        };
        
        if (payment_is_key and stake_is_key) return .base_payment_key_stake_key;
        if (!payment_is_key and stake_is_key) return .base_payment_script_stake_key;
        if (payment_is_key and !stake_is_key) return .base_payment_key_stake_script;
        return .base_payment_script_stake_script;
    }
    
    /// Encode address to raw bytes
    pub fn toBytes(self: Address, allocator: std.mem.Allocator) ![]u8 {
        const addr_type = self.getType();
        const header = (@intFromEnum(addr_type) << 4) | @intFromEnum(self.network);
        
        var bytes = std.ArrayList(u8).init(allocator);
        defer bytes.deinit();
        
        // Header byte
        try bytes.append(header);
        
        // Payment credential
        switch (self.payment) {
            .key_hash => |hash| try bytes.appendSlice(&hash),
            .script_hash => |hash| try bytes.appendSlice(&hash),
        }
        
        // Staking credential (if present)
        if (self.staking) |stake| {
            switch (stake) {
                .key_hash => |hash| try bytes.appendSlice(&hash),
                .script_hash => |hash| try bytes.appendSlice(&hash),
            }
        }
        
        return bytes.toOwnedSlice();
    }
    
    /// Encode address to Bech32
    pub fn toBech32(self: Address, allocator: std.mem.Allocator) ![]u8 {
        const bytes = try self.toBytes(allocator);
        defer allocator.free(bytes);
        
        const prefix = switch (self.network) {
            .mainnet => "addr",
            .testnet => "addr_test",
        };
        
        return try bech32.encode(allocator, prefix, bytes);
    }
    
    /// Create address from public key hash
    pub fn fromKeyHash(network: NetworkId, payment_key_hash: [28]u8, stake_key_hash: ?[28]u8) Address {
        return Address{
            .network = network,
            .payment = .{ .key_hash = payment_key_hash },
            .staking = if (stake_key_hash) |skh| .{ .key_hash = skh } else null,
        };
    }
    
    /// Create enterprise address (no staking)
    pub fn enterprise(network: NetworkId, payment_key_hash: [28]u8) Address {
        return Address{
            .network = network,
            .payment = .{ .key_hash = payment_key_hash },
            .staking = null,
        };
    }
};

/// Derive payment key hash from public key
pub fn keyHash(public_key: crypto.Crypto.PublicKey) crypto.Crypto.Hash224 {
    return crypto.Crypto.hash224(&public_key.bytes);
}

/// Create a base address from payment and stake public keys
pub fn baseAddress(
    network: NetworkId,
    payment_key: crypto.Crypto.PublicKey,
    stake_key: crypto.Crypto.PublicKey,
) Address {
    const payment_hash = keyHash(payment_key);
    const stake_hash = keyHash(stake_key);
    
    return Address.fromKeyHash(network, payment_hash.bytes, stake_hash.bytes);
}

/// Create an enterprise address from payment public key
pub fn enterpriseAddress(
    network: NetworkId,
    payment_key: crypto.Crypto.PublicKey,
) Address {
    const payment_hash = keyHash(payment_key);
    return Address.enterprise(network, payment_hash.bytes);
}

// Tests
test "address type detection" {
    const addr1 = Address{
        .network = .testnet,
        .payment = .{ .key_hash = [_]u8{0} ** 28 },
        .staking = .{ .key_hash = [_]u8{0} ** 28 },
    };
    try std.testing.expectEqual(AddressType.base_payment_key_stake_key, addr1.getType());
    
    const addr2 = Address{
        .network = .mainnet,
        .payment = .{ .key_hash = [_]u8{0} ** 28 },
        .staking = null,
    };
    try std.testing.expectEqual(AddressType.enterprise_payment_key, addr2.getType());
}

test "address encoding" {
    const addr = Address{
        .network = .testnet,
        .payment = .{ .key_hash = [_]u8{0xAB} ** 28 },
        .staking = null,
    };
    
    const bytes = try addr.toBytes(std.testing.allocator);
    defer std.testing.allocator.free(bytes);
    
    // Check header byte (0x60 = enterprise address on testnet)
    try std.testing.expectEqual(@as(u8, 0x60), bytes[0]);
    try std.testing.expectEqual(@as(usize, 29), bytes.len); // 1 header + 28 payment
}

test "key hash derivation" {
    try crypto.Crypto.init();
    
    var keypair = try crypto.Crypto.KeyPair.generate();
    defer keypair.deinit();
    
    const hash = keyHash(keypair.public);
    try std.testing.expectEqual(@as(usize, 28), hash.bytes.len);
}