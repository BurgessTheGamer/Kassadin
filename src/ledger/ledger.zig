const std = @import("std");
const crypto = @import("../crypto/crypto.zig");
const tx_mod = @import("transaction.zig");
const address = @import("../crypto/address.zig");
const logger = @import("../utils/logger.zig");

/// UTXO-based ledger state management
pub const Ledger = struct {
    /// The UTXO set - maps inputs to outputs
    utxos: std.AutoHashMap(tx_mod.TransactionInput, tx_mod.TransactionOutput),
    
    /// Protocol parameters
    protocol_params: ProtocolParameters,
    
    /// Current slot number
    current_slot: u64,
    
    /// Allocator for memory management
    allocator: std.mem.Allocator,
    
    /// Statistics
    stats: LedgerStats,

    /// Ledger statistics
    pub const LedgerStats = struct {
        total_utxos: u64 = 0,
        total_lovelace: u128 = 0,
        transactions_processed: u64 = 0,
        blocks_processed: u64 = 0,
    };

    /// Protocol parameters (simplified)
    pub const ProtocolParameters = struct {
        min_fee_a: u32 = 44,           // Linear fee factor
        min_fee_b: u32 = 155381,       // Constant fee factor
        max_tx_size: u32 = 16384,      // 16KB
        max_block_size: u32 = 90112,   // ~88KB
        key_deposit: u64 = 2_000_000,  // 2 ADA
        pool_deposit: u64 = 500_000_000, // 500 ADA
        min_utxo_value: u64 = 1_000_000, // 1 ADA
        
        /// Calculate minimum fee for a transaction
        pub fn calculateMinFee(self: ProtocolParameters, tx_size: u32) u64 {
            return @as(u64, self.min_fee_a) * @as(u64, tx_size) + @as(u64, self.min_fee_b);
        }
    };

    /// Initialize a new ledger
    pub fn init(allocator: std.mem.Allocator) Ledger {
        return .{
            .utxos = std.AutoHashMap(tx_mod.TransactionInput, tx_mod.TransactionOutput).init(allocator),
            .protocol_params = ProtocolParameters{},
            .current_slot = 0,
            .allocator = allocator,
            .stats = LedgerStats{},
        };
    }

    /// Clean up resources
    pub fn deinit(self: *Ledger) void {
        self.utxos.deinit();
    }

    /// Apply a transaction to the ledger
    pub fn applyTransaction(self: *Ledger, transaction: tx_mod.Transaction) !void {
        // Validate transaction first
        try self.validateTransaction(transaction);
        
        // Remove spent UTXOs
        for (transaction.body.inputs) |input| {
            if (self.utxos.fetchRemove(input)) |kv| {
                self.stats.total_lovelace -= kv.value.value.lovelace;
                self.stats.total_utxos -= 1;
            } else {
                return error.UtxoNotFound;
            }
        }
        
        // Add new UTXOs
        const tx_id = transaction.id();
        for (transaction.body.outputs, 0..) |output, index| {
            const input = tx_mod.TransactionInput{
                .tx_id = tx_id,
                .output_index = @intCast(index),
            };
            try self.utxos.put(input, output);
            self.stats.total_lovelace += output.value.lovelace;
            self.stats.total_utxos += 1;
        }
        
        self.stats.transactions_processed += 1;
        const tx_id_slice = tx_id.bytes[0..8];
        logger.debug("Applied transaction {x}, UTXOs: {}, Total ADA: {}", .{
            std.fmt.fmtSliceHexLower(tx_id_slice),
            self.stats.total_utxos,
            self.stats.total_lovelace / 1_000_000,
        });
    }

    /// Validate a transaction
    pub fn validateTransaction(self: *Ledger, transaction: tx_mod.Transaction) !void {
        // 1. Check transaction size
        const tx_size = self.estimateTransactionSize(transaction);
        if (tx_size > self.protocol_params.max_tx_size) {
            return error.TransactionTooLarge;
        }
        
        // 2. Check all inputs exist
        var total_input = tx_mod.Value{ .lovelace = 0 };
        for (transaction.body.inputs) |input| {
            const utxo = self.utxos.get(input) orelse return error.UtxoNotFound;
            total_input = try total_input.add(utxo.value);
        }
        
        // 3. Check outputs are valid
        var total_output = tx_mod.Value{ .lovelace = 0 };
        for (transaction.body.outputs) |output| {
            if (!output.isValid()) {
                return error.InvalidOutput;
            }
            total_output = try total_output.add(output.value);
        }
        
        // 4. Add fee to total output
        total_output.lovelace += transaction.body.fee;
        
        // 5. Check value preservation (inputs = outputs + fee)
        if (!total_input.eql(total_output)) {
            logger.err("Value not preserved: inputs {} != outputs {} + fee {}", .{
                total_input.lovelace,
                total_output.lovelace - transaction.body.fee,
                transaction.body.fee,
            });
            return error.ValueNotPreserved;
        }
        
        // 6. Check minimum fee
        const min_fee = self.protocol_params.calculateMinFee(tx_size);
        if (transaction.body.fee < min_fee) {
            return error.InsufficientFee;
        }
        
        // 7. Check TTL if present
        if (transaction.body.ttl) |ttl| {
            if (self.current_slot > ttl) {
                return error.TransactionExpired;
            }
        }
        
        // 8. Verify witnesses (simplified - just check count)
        if (transaction.witnesses.vkey_witnesses.len < transaction.body.inputs.len) {
            return error.MissingWitnesses;
        }
        
        // TODO: Actually verify signatures
        // TODO: Check script witnesses
        // TODO: Validate certificates
        // TODO: Check collateral for script transactions
    }

    /// Estimate transaction size in bytes
    fn estimateTransactionSize(self: *Ledger, transaction: tx_mod.Transaction) u32 {
        _ = self;
        // Simplified estimation
        var size: u32 = 0;
        
        // Fixed overhead
        size += 50;
        
        // Inputs (about 40 bytes each)
        size += @intCast(transaction.body.inputs.len * 40);
        
        // Outputs (about 50 bytes each)
        size += @intCast(transaction.body.outputs.len * 50);
        
        // Witnesses (about 100 bytes each)
        size += @intCast(transaction.witnesses.vkey_witnesses.len * 100);
        
        return size;
    }

    /// Get a UTXO
    pub fn getUtxo(self: *Ledger, input: tx_mod.TransactionInput) ?tx_mod.TransactionOutput {
        return self.utxos.get(input);
    }

    /// Get total number of UTXOs
    pub fn getUtxoCount(self: *Ledger) usize {
        return self.utxos.count();
    }

    /// Get total ADA in circulation
    pub fn getTotalLovelace(self: *Ledger) u128 {
        return self.stats.total_lovelace;
    }

    /// Update current slot
    pub fn updateSlot(self: *Ledger, slot: u64) void {
        self.current_slot = slot;
    }

    /// Create a snapshot of the current state
    pub fn createSnapshot(self: *Ledger, allocator: std.mem.Allocator) !LedgerSnapshot {
        var snapshot = LedgerSnapshot{
            .utxos = std.AutoHashMap(tx_mod.TransactionInput, tx_mod.TransactionOutput).init(allocator),
            .slot = self.current_slot,
            .stats = self.stats,
        };
        
        // Copy all UTXOs
        var iter = self.utxos.iterator();
        while (iter.next()) |entry| {
            try snapshot.utxos.put(entry.key_ptr.*, entry.value_ptr.*);
        }
        
        return snapshot;
    }

    /// Restore from a snapshot
    pub fn restoreFromSnapshot(self: *Ledger, snapshot: LedgerSnapshot) !void {
        // Clear current state
        self.utxos.clearAndFree();
        
        // Restore from snapshot
        var iter = snapshot.utxos.iterator();
        while (iter.next()) |entry| {
            try self.utxos.put(entry.key_ptr.*, entry.value_ptr.*);
        }
        
        self.current_slot = snapshot.slot;
        self.stats = snapshot.stats;
    }
};

/// Ledger snapshot for rollback support
pub const LedgerSnapshot = struct {
    utxos: std.AutoHashMap(tx_mod.TransactionInput, tx_mod.TransactionOutput),
    slot: u64,
    stats: Ledger.LedgerStats,
    
    pub fn deinit(self: *LedgerSnapshot) void {
        self.utxos.deinit();
    }
};

