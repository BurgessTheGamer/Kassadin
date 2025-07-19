const std = @import("std");
const crypto = @import("../crypto/crypto.zig");
const block = @import("../ledger/block.zig");
const transaction = @import("../ledger/transaction.zig");
const address = @import("../crypto/address.zig");
const ledger = @import("../ledger/ledger.zig");

/// Storage interface for blockchain data persistence
pub const Storage = struct {
    /// Storage backend type
    pub const Backend = enum {
        memory,
        file,
        rocksdb, // Future implementation
    };
    
    /// Storage configuration
    pub const Config = struct {
        backend: Backend = .file,
        data_dir: []const u8 = "./data",
        cache_size_mb: u32 = 100,
        compression: bool = true,
    };
    
    /// Key-value store interface
    pub const Store = struct {
        /// Get value by key
        getFn: *const fn (self: *Store, key: []const u8, allocator: std.mem.Allocator) anyerror!?[]u8,
        /// Put key-value pair
        putFn: *const fn (self: *Store, key: []const u8, value: []const u8) anyerror!void,
        /// Delete key
        deleteFn: *const fn (self: *Store, key: []const u8) anyerror!void,
        /// Check if key exists
        hasFn: *const fn (self: *Store, key: []const u8) anyerror!bool,
        /// Close the store
        closeFn: *const fn (self: *Store) void,
        
        /// Implementation-specific data
        impl: *anyopaque,
        
        pub fn get(self: *Store, key: []const u8, allocator: std.mem.Allocator) !?[]u8 {
            return self.getFn(self, key, allocator);
        }
        
        pub fn put(self: *Store, key: []const u8, value: []const u8) !void {
            return self.putFn(self, key, value);
        }
        
        pub fn delete(self: *Store, key: []const u8) !void {
            return self.deleteFn(self, key);
        }
        
        pub fn has(self: *Store, key: []const u8) !bool {
            return self.hasFn(self, key);
        }
        
        pub fn close(self: *Store) void {
            self.closeFn(self);
        }
    };
    
    /// Block storage
    pub const BlockStore = struct {
        store: *Store,
        allocator: std.mem.Allocator,
        
        const BLOCK_PREFIX = "block:";
        const BLOCK_HEIGHT_PREFIX = "height:";
        const TIP_KEY = "chain:tip";
        
        pub fn init(allocator: std.mem.Allocator, store: *Store) BlockStore {
            return .{
                .store = store,
                .allocator = allocator,
            };
        }
        
        /// Store a block
        pub fn putBlock(self: *BlockStore, blk: *const block.Block) !void {
            // For now, just store the block hash and height mapping
            // Full block serialization would be implemented later
            const hash = blk.header.hash();
            var key_buf: [256]u8 = undefined;
            
            // Store a placeholder for the block data
            const block_key = try std.fmt.bufPrint(&key_buf, "{s}{}", .{ BLOCK_PREFIX, std.fmt.fmtSliceHexLower(&hash.bytes) });
            try self.store.put(block_key, "block_data_placeholder");
            
            // Store height -> hash mapping
            const height_key = try std.fmt.bufPrint(&key_buf, "{s}{}", .{ BLOCK_HEIGHT_PREFIX, blk.header.block_number });
            try self.store.put(height_key, &hash.bytes);
        }
        
        /// Get block by hash
        pub fn getBlock(self: *BlockStore, hash: crypto.Crypto.Hash256) !?block.Block {
            _ = self;
            _ = hash;
            // Full block deserialization would be implemented later
            return null;
        }
        
        /// Get block by height
        pub fn getBlockByHeight(self: *BlockStore, height: u64) !?block.Block {
            var key_buf: [256]u8 = undefined;
            const height_key = try std.fmt.bufPrint(&key_buf, "{s}{}", .{ BLOCK_HEIGHT_PREFIX, height });
            
            const hash_bytes = try self.store.get(height_key, self.allocator) orelse return null;
            defer self.allocator.free(hash_bytes);
            
            if (hash_bytes.len != 32) return error.InvalidHash;
            
            var hash: crypto.Crypto.Hash256 = undefined;
            @memcpy(&hash.bytes, hash_bytes);
            
            return self.getBlock(hash);
        }
        
        /// Store chain tip
        pub fn putTip(self: *BlockStore, tip_hash: crypto.Crypto.Hash256) !void {
            try self.store.put(TIP_KEY, &tip_hash.bytes);
        }
        
        /// Get chain tip
        pub fn getTip(self: *BlockStore) !?crypto.Crypto.Hash256 {
            const data = try self.store.get(TIP_KEY, self.allocator) orelse return null;
            defer self.allocator.free(data);
            
            if (data.len != 32) return error.InvalidHash;
            
            var hash: crypto.Crypto.Hash256 = undefined;
            @memcpy(&hash.bytes, data);
            return hash;
        }
    };
    
    /// UTXO storage
    pub const UtxoStore = struct {
        store: *Store,
        allocator: std.mem.Allocator,
        
        const UTXO_PREFIX = "utxo:";
        
        pub fn init(allocator: std.mem.Allocator, store: *Store) UtxoStore {
            return .{
                .store = store,
                .allocator = allocator,
            };
        }
        
        /// Store UTXO
        pub fn putUtxo(self: *UtxoStore, input: transaction.TransactionInput, output: transaction.TransactionOutput) !void {
            var key_buf: [256]u8 = undefined;
            const key = try std.fmt.bufPrint(&key_buf, "{s}{}:{}", .{
                UTXO_PREFIX,
                std.fmt.fmtSliceHexLower(&input.tx_id.bytes),
                input.index,
            });
            
            // Serialize output (simplified for now)
            var buffer: [1024]u8 = undefined;
            var stream = std.io.fixedBufferStream(&buffer);
            const writer = stream.writer();
            
            // Write address bytes
            const addr_bytes = output.address.toBytes();
            try writer.writeAll(&addr_bytes);
            
            // Write value
            try writer.writeInt(u64, output.value.lovelace, .big);
            
            // Write datum hash flag
            if (output.datum_hash) |hash| {
                try writer.writeByte(1);
                try writer.writeAll(&hash.bytes);
            } else {
                try writer.writeByte(0);
            }
            
            const written = stream.getWritten();
            try self.store.put(key, written);
        }
        
        /// Get UTXO
        pub fn getUtxo(self: *UtxoStore, input: transaction.TransactionInput) !?transaction.TransactionOutput {
            var key_buf: [256]u8 = undefined;
            const key = try std.fmt.bufPrint(&key_buf, "{s}{}:{}", .{
                UTXO_PREFIX,
                std.fmt.fmtSliceHexLower(&input.tx_id.bytes),
                input.index,
            });
            
            const data = try self.store.get(key, self.allocator) orelse return null;
            defer self.allocator.free(data);
            
            // Deserialize output (simplified for now)
            var stream = std.io.fixedBufferStream(data);
            const reader = stream.reader();
            
            // Read address
            var addr_bytes: [57]u8 = undefined;
            _ = try reader.read(&addr_bytes);
            const addr = address.Address.fromBytes(addr_bytes);
            
            // Read value
            const lovelace = try reader.readInt(u64, .big);
            
            // Read datum hash
            const has_datum = try reader.readByte();
            var datum_hash: ?crypto.Crypto.Hash256 = null;
            if (has_datum == 1) {
                datum_hash = crypto.Crypto.Hash256{};
                _ = try reader.read(&datum_hash.?.bytes);
            }
            
            return transaction.TransactionOutput{
                .address = addr,
                .value = .{ .lovelace = lovelace },
                .datum_hash = datum_hash,
            };
        }
        
        /// Delete UTXO (when spent)
        pub fn deleteUtxo(self: *UtxoStore, input: transaction.TransactionInput) !void {
            var key_buf: [256]u8 = undefined;
            const key = try std.fmt.bufPrint(&key_buf, "{s}{}:{}", .{
                UTXO_PREFIX,
                std.fmt.fmtSliceHexLower(&input.tx_id.bytes),
                input.index,
            });
            
            try self.store.delete(key);
        }
    };
};