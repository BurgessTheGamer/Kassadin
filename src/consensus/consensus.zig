const std = @import("std");
const crypto = @import("../crypto/crypto.zig");

/// Ouroboros Praos consensus implementation
pub const Consensus = struct {
    /// Slot number (1 second per slot)
    pub const Slot = u64;
    
    /// Epoch number
    pub const Epoch = u32;
    
    /// Number of slots per epoch (5 days)
    pub const SLOTS_PER_EPOCH: u64 = 432000;

    /// Block header
    pub const BlockHeader = struct {
        slot: Slot,
        block_number: u64,
        prev_hash: crypto.Crypto.Hash256,
        issuer_vkey: crypto.Crypto.PublicKey,
        vrf_vkey: [32]u8, // VRF verification key
        block_body_hash: crypto.Crypto.Hash256,
        operational_cert: OperationalCert,
        protocol_version: ProtocolVersion,
    };

    /// Operational certificate
    pub const OperationalCert = struct {
        hot_vkey: crypto.Crypto.PublicKey,
        sequence_number: u64,
        kes_period: u32,
        sigma: crypto.Crypto.Signature,
    };

    /// Protocol version
    pub const ProtocolVersion = struct {
        major: u32,
        minor: u32,
    };

    /// Convert slot to epoch
    pub fn slotToEpoch(slot: Slot) Epoch {
        return @intCast(slot / SLOTS_PER_EPOCH);
    }

    /// Get first slot of an epoch
    pub fn epochFirstSlot(epoch: Epoch) Slot {
        return @as(u64, epoch) * SLOTS_PER_EPOCH;
    }

    /// Check if we're at an epoch boundary
    pub fn isEpochBoundary(slot: Slot) bool {
        return slot % SLOTS_PER_EPOCH == 0;
    }

    /// Verify VRF output for slot leadership
    pub fn verifySlotLeader(
        slot: Slot,
        vrf_output: []const u8,
        stake: u64,
        total_stake: u64,
    ) !bool {
        // TODO: Implement VRF verification
        _ = slot;
        _ = vrf_output;
        _ = stake;
        _ = total_stake;
        return error.NotImplemented;
    }
};

test "slot to epoch conversion" {
    try std.testing.expectEqual(@as(Consensus.Epoch, 0), Consensus.slotToEpoch(0));
    try std.testing.expectEqual(@as(Consensus.Epoch, 0), Consensus.slotToEpoch(431999));
    try std.testing.expectEqual(@as(Consensus.Epoch, 1), Consensus.slotToEpoch(432000));
    try std.testing.expectEqual(@as(Consensus.Epoch, 1), Consensus.slotToEpoch(863999));
    try std.testing.expectEqual(@as(Consensus.Epoch, 2), Consensus.slotToEpoch(864000));
}

test "epoch boundaries" {
    try std.testing.expect(Consensus.isEpochBoundary(0));
    try std.testing.expect(Consensus.isEpochBoundary(432000));
    try std.testing.expect(!Consensus.isEpochBoundary(1));
    try std.testing.expect(!Consensus.isEpochBoundary(431999));
}