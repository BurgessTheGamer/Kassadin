const std = @import("std");
const crypto = @import("../crypto/crypto.zig");
const tx_mod = @import("transaction.zig");
const consensus = @import("../consensus/consensus.zig");
const vrf = @import("../crypto/vrf.zig");

/// Maximum block size (90KB for Cardano)
const MAX_BLOCK_SIZE: u32 = 90_000;

/// Block header - contains metadata and proof of leadership
pub const BlockHeader = struct {
    /// Block number (height)
    block_number: u64,
    
    /// Slot number when block was created
    slot: consensus.Consensus.Slot,
    
    /// Hash of previous block header
    prev_hash: crypto.Crypto.Hash256,
    
    /// Hash of block body
    body_hash: crypto.Crypto.Hash256,
    
    /// Issuer verification key (pool operator)
    issuer_vkey: crypto.Crypto.PublicKey,
    
    /// VRF output proving right to create block
    vrf_output: VrfOutput,
    
    /// Block size in bytes
    block_size: u32,
    
    /// Operational certificate
    operational_cert: OperationalCert,
    
    /// Protocol version
    protocol_version: ProtocolVersion,
    
    /// Calculate header hash
    pub fn hash(self: BlockHeader) crypto.Crypto.Hash256 {
        var hasher = std.crypto.hash.blake2.Blake2b256.init(.{});
        
        hasher.update(std.mem.asBytes(&self.block_number));
        hasher.update(std.mem.asBytes(&self.slot));
        hasher.update(&self.prev_hash.bytes);
        hasher.update(&self.body_hash.bytes);
        hasher.update(&self.issuer_vkey.bytes);
        hasher.update(&self.vrf_output.output);
        hasher.update(std.mem.asBytes(&self.block_size));
        
        var result: [32]u8 = undefined;
        hasher.final(&result);
        return crypto.Crypto.Hash256.fromBytes(result);
    }
};

/// VRF output and proof
pub const VrfOutput = struct {
    output: [64]u8,
    proof: [80]u8,
};

/// Operational certificate for block production
pub const OperationalCert = struct {
    /// Hot key (KES key)
    hot_vkey: [32]u8,
    /// Sequence number (counter)
    sequence_number: u64,
    /// KES period
    kes_period: u32,
    /// Signature by cold key
    sigma: crypto.Crypto.Signature,
};

/// Protocol version
pub const ProtocolVersion = struct {
    major: u32,
    minor: u32,
};

/// Block body - contains transactions
pub const BlockBody = struct {
    /// Transactions in this block
    transactions: []const tx_mod.Transaction,
    
    /// Calculate body hash
    pub fn hash(self: BlockBody) crypto.Crypto.Hash256 {
        var hasher = std.crypto.hash.blake2.Blake2b256.init(.{});
        
        // Hash each transaction ID
        for (self.transactions) |tx| {
            const tx_id = tx.id();
            hasher.update(&tx_id.bytes);
        }
        
        var result: [32]u8 = undefined;
        hasher.final(&result);
        return crypto.Crypto.Hash256.fromBytes(result);
    }
    
    /// Get total fees from all transactions
    pub fn totalFees(self: BlockBody) u64 {
        var total: u64 = 0;
        for (self.transactions) |tx| {
            total += tx.body.fee;
        }
        return total;
    }
    
    /// Get block size in bytes (estimated)
    pub fn estimateSize(self: BlockBody) u32 {
        var size: u32 = 100; // Header overhead
        
        for (self.transactions) |tx| {
            // Rough estimate: 50 bytes per input/output, 100 per witness
            size += @intCast(tx.body.inputs.len * 50);
            size += @intCast(tx.body.outputs.len * 50);
            size += @intCast(tx.witnesses.vkey_witnesses.len * 100);
            size += 50; // Other tx overhead
        }
        
        return size;
    }
};

    /// Complete block
    pub const Block = struct {
        header: BlockHeader,
        body: BlockBody,
        
        /// Validate block structure (not consensus rules)
        pub fn validate(self: Block) !void {
            // Check body hash matches header
            const calculated_body_hash = self.body.hash();
            if (!calculated_body_hash.eql(self.header.body_hash)) {
                return error.InvalidBodyHash;
            }
            
            // Check block size
            const calculated_size = self.body.estimateSize();
            if (calculated_size > MAX_BLOCK_SIZE) {
                return error.BlockTooLarge;
            }
            
            // Validate all transactions
            for (self.body.transactions) |tx| {
                try tx.validate();
            }
        }
        
        /// Get block ID (header hash)
        pub fn id(self: Block) crypto.Crypto.Hash256 {
            return self.header.hash();
        }
        
        /// Check if this block extends from given hash
        pub fn extendsFrom(self: Block, prev: crypto.Crypto.Hash256) bool {
            return self.header.prev_hash.eql(prev);
        }
        
        /// Encode block to bytes (simplified CBOR-like format)
        pub fn encode(self: *const Block, allocator: std.mem.Allocator) ![]u8 {
            var buffer = std.ArrayList(u8).init(allocator);
            errdefer buffer.deinit();
            
            const writer = buffer.writer();
            
            // Write header
            try writer.writeInt(u64, self.header.block_number, .big);
            try writer.writeInt(u64, self.header.slot, .big);
            try writer.writeAll(&self.header.prev_hash.bytes);
            try writer.writeAll(&self.header.body_hash.bytes);
            try writer.writeAll(&self.header.issuer_vkey.bytes);
            try writer.writeAll(&self.header.vrf_output.output);
            try writer.writeAll(&self.header.vrf_output.proof);
            try writer.writeInt(u32, self.header.block_size, .big);
            
            // Write operational cert
            try writer.writeAll(&self.header.operational_cert.hot_vkey);
            try writer.writeInt(u64, self.header.operational_cert.sequence_number, .big);
            try writer.writeInt(u32, self.header.operational_cert.kes_period, .big);
            try writer.writeAll(&self.header.operational_cert.sigma.bytes);
            
            // Write protocol version
            try writer.writeInt(u16, self.header.protocol_version.major, .big);
            try writer.writeInt(u16, self.header.protocol_version.minor, .big);
            
            // Write body (transaction count + tx hashes for now)
            try writer.writeInt(u32, @intCast(self.body.transactions.len), .big);
            for (self.body.transactions) |tx| {
                const tx_id = tx.id();
                try writer.writeAll(&tx_id.bytes);
            }
            
            return buffer.toOwnedSlice();
        }
        
        /// Decode block from bytes
        pub fn decode(allocator: std.mem.Allocator, data: []const u8) !Block {
            _ = allocator;
            var stream = std.io.fixedBufferStream(data);
            const reader = stream.reader();
            
            // Read header
            var header: BlockHeader = undefined;
            header.block_number = try reader.readInt(u64, .big);
            header.slot = try reader.readInt(u64, .big);
            _ = try reader.read(&header.prev_hash.bytes);
            _ = try reader.read(&header.body_hash.bytes);
            _ = try reader.read(&header.issuer_vkey.bytes);
            _ = try reader.read(&header.vrf_output.output);
            _ = try reader.read(&header.vrf_output.proof);
            header.block_size = try reader.readInt(u32, .big);
            
            // Read operational cert
            _ = try reader.read(&header.operational_cert.hot_vkey);
            header.operational_cert.sequence_number = try reader.readInt(u64, .big);
            header.operational_cert.kes_period = try reader.readInt(u32, .big);
            _ = try reader.read(&header.operational_cert.sigma.bytes);
            
            // Read protocol version
            header.protocol_version.major = try reader.readInt(u16, .big);
            header.protocol_version.minor = try reader.readInt(u16, .big);
            
            // Read body (simplified - just tx count)
            const tx_count = try reader.readInt(u32, .big);
            _ = tx_count;
            
            // For now, return block with empty body
            return Block{
                .header = header,
                .body = .{
                    .transactions = &[_]tx_mod.Transaction{},
                },
            };
        }
        
        /// Block doesn't need explicit cleanup
        pub fn deinit(self: *Block, allocator: std.mem.Allocator) void {
            _ = self;
            _ = allocator;
            // In a real implementation, we'd free transaction arrays
        }
    };

/// Block metadata for chain management
pub const BlockMetadata = struct {
    /// Block hash
    hash: crypto.Crypto.Hash256,
    /// Block number
    number: u64,
    /// Slot number
    slot: u64,
    /// Block size
    size: u32,
    /// Number of transactions
    tx_count: u32,
    /// Total fees
    total_fees: u64,
    /// Timestamp (derived from slot)
    timestamp: i64,
    
    pub fn fromBlock(block: Block, slot_to_time: fn (u64) i64) BlockMetadata {
        return BlockMetadata{
            .hash = block.id(),
            .number = block.header.block_number,
            .slot = block.header.slot,
            .size = block.header.block_size,
            .tx_count = @intCast(block.body.transactions.len),
            .total_fees = block.body.totalFees(),
            .timestamp = slot_to_time(block.header.slot),
        };
    }
};

/// Chain tip information
pub const ChainTip = struct {
    /// Current block hash
    hash: crypto.Crypto.Hash256,
    /// Current block number
    block_number: u64,
    /// Current slot
    slot: u64,
    /// Chain density (blocks per slot)
    density: f32,
};

// Tests
test "Block header hashing" {
    const header = BlockHeader{
        .block_number = 12345,
        .slot = 54321,
        .prev_hash = crypto.Crypto.Hash256.fromBytes([_]u8{1} ** 32),
        .body_hash = crypto.Crypto.Hash256.fromBytes([_]u8{2} ** 32),
        .issuer_vkey = crypto.Crypto.PublicKey.fromBytes([_]u8{3} ** 32),
        .vrf_output = VrfOutput{
            .output = [_]u8{4} ** 64,
            .proof = [_]u8{5} ** 80,
        },
        .block_size = 50000,
        .operational_cert = OperationalCert{
            .hot_vkey = [_]u8{6} ** 32,
            .sequence_number = 10,
            .kes_period = 100,
            .sigma = crypto.Crypto.Signature.fromBytes([_]u8{7} ** 64),
        },
        .protocol_version = ProtocolVersion{ .major = 8, .minor = 0 },
    };
    
    const hash1 = header.hash();
    const hash2 = header.hash();
    
    // Hashing should be deterministic
    try std.testing.expect(hash1.eql(hash2));
}

test "Block body operations" {
    try crypto.Crypto.init();
    
    // Create some test transactions
    var transactions = [_]tx_mod.Transaction{
        tx_mod.Transaction{
            .body = tx_mod.TransactionBody{
                .inputs = &.{},
                .outputs = &.{},
                .fee = 100_000,
            },
            .witnesses = tx_mod.TransactionWitnessSet{},
        },
        tx_mod.Transaction{
            .body = tx_mod.TransactionBody{
                .inputs = &.{},
                .outputs = &.{},
                .fee = 200_000,
            },
            .witnesses = tx_mod.TransactionWitnessSet{},
        },
    };
    
    const body = BlockBody{
        .transactions = &transactions,
    };
    
    try std.testing.expectEqual(@as(u64, 300_000), body.totalFees());
    
    const hash1 = body.hash();
    const hash2 = body.hash();
    try std.testing.expect(hash1.eql(hash2));
}

test "Block validation" {
    try crypto.Crypto.init();
    
    const body = BlockBody{
        .transactions = &.{},
    };
    
    const body_hash = body.hash();
    
    const header = BlockHeader{
        .block_number = 1,
        .slot = 100,
        .prev_hash = crypto.Crypto.Hash256.fromBytes([_]u8{0} ** 32),
        .body_hash = body_hash,
        .issuer_vkey = crypto.Crypto.PublicKey.fromBytes([_]u8{1} ** 32),
        .vrf_output = VrfOutput{
            .output = [_]u8{0} ** 64,
            .proof = [_]u8{0} ** 80,
        },
        .block_size = 1000,
        .operational_cert = OperationalCert{
            .hot_vkey = [_]u8{0} ** 32,
            .sequence_number = 0,
            .kes_period = 0,
            .sigma = crypto.Crypto.Signature.fromBytes([_]u8{0} ** 64),
        },
        .protocol_version = ProtocolVersion{ .major = 8, .minor = 0 },
    };
    
    const block = Block{
        .header = header,
        .body = body,
    };
    
    // Should validate successfully
    try block.validate();
    
    // Test with mismatched body hash
    var bad_header = header;
    bad_header.body_hash = crypto.Crypto.Hash256.fromBytes([_]u8{99} ** 32);
    
    const bad_block = Block{
        .header = bad_header,
        .body = body,
    };
    
    try std.testing.expectError(error.InvalidBodyHash, bad_block.validate());
}