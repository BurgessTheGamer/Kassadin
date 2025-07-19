const std = @import("std");
const crypto = @import("../crypto/crypto.zig");
const address = @import("../crypto/address.zig");

/// Transaction input - references a previous output
pub const TransactionInput = struct {
    /// Transaction ID of the output being spent
    tx_id: crypto.Crypto.Hash256,
    /// Index of the output in that transaction
    output_index: u32,

    pub fn eql(self: TransactionInput, other: TransactionInput) bool {
        return self.tx_id.eql(other.tx_id) and self.output_index == other.output_index;
    }

    pub fn hash(self: TransactionInput) u64 {
        var hasher = std.hash.Wyhash.init(0);
        hasher.update(&self.tx_id.bytes);
        hasher.update(std.mem.asBytes(&self.output_index));
        return hasher.final();
    }
};

/// Multi-asset value (supports ADA and native tokens)
pub const Value = struct {
    /// Lovelace amount (1 ADA = 1,000,000 lovelace)
    lovelace: u64,
    /// Native tokens (policy_id -> asset_name -> amount)
    /// For now, we'll just support ADA
    // TODO: Add multi-asset support for Mary era

    pub fn add(self: Value, other: Value) !Value {
        // Check for overflow
        const result = @addWithOverflow(self.lovelace, other.lovelace);
        if (result[1] != 0) return error.ValueOverflow;

        return Value{ .lovelace = result[0] };
    }

    pub fn sub(self: Value, other: Value) !Value {
        if (self.lovelace < other.lovelace) return error.InsufficientValue;
        return Value{ .lovelace = self.lovelace - other.lovelace };
    }

    pub fn eql(self: Value, other: Value) bool {
        return self.lovelace == other.lovelace;
    }

    pub fn isZero(self: Value) bool {
        return self.lovelace == 0;
    }
};

/// Transaction output
pub const TransactionOutput = struct {
    /// Recipient address
    address: address.Address,
    /// Value being sent
    value: Value,
    /// Optional datum hash (for smart contracts)
    datum_hash: ?crypto.Crypto.Hash256 = null,

    /// Minimum ADA requirement (prevents dust)
    pub fn minAdaValue(self: TransactionOutput) u64 {
        _ = self;
        // Simplified calculation - real one is more complex
        return 1_000_000; // 1 ADA minimum
    }

    pub fn isValid(self: TransactionOutput) bool {
        return self.value.lovelace >= self.minAdaValue();
    }
};

/// Witness for spending an input
pub const TransactionWitness = struct {
    /// Verification key witness
    vkey_witness: ?VKeyWitness = null,
    /// Script witness (for script-locked UTXOs)
    script_witness: ?ScriptWitness = null,
    /// Bootstrap witness (for Byron-era addresses)
    bootstrap_witness: ?BootstrapWitness = null,
};

/// Verification key witness (most common)
pub const VKeyWitness = struct {
    /// Public key that can spend the UTXO
    vkey: crypto.Crypto.PublicKey,
    /// Signature of the transaction
    signature: crypto.Crypto.Signature,
};

/// Script witness (placeholder for now)
pub const ScriptWitness = struct {
    script: []const u8,
};

/// Bootstrap witness for Byron addresses (legacy)
pub const BootstrapWitness = struct {
    public_key: crypto.Crypto.PublicKey,
    signature: crypto.Crypto.Signature,
    chain_code: [32]u8,
    attributes: []const u8,
};

/// Complete transaction
pub const Transaction = struct {
    /// Transaction body (the part that gets signed)
    body: TransactionBody,
    /// Witnesses that authorize spending
    witnesses: TransactionWitnessSet,
    /// Is this transaction valid?
    is_valid: bool = true,
    /// Auxiliary data (metadata)
    auxiliary_data: ?AuxiliaryData = null,

    /// Calculate transaction ID (hash of the body)
    pub fn id(self: Transaction) crypto.Crypto.Hash256 {
        // In real implementation, this would CBOR encode the body first
        // For now, we'll create a simple hash
        var hasher = std.crypto.hash.blake2.Blake2b256.init(.{});

        // Hash inputs
        for (self.body.inputs) |input| {
            hasher.update(&input.tx_id.bytes);
            hasher.update(std.mem.asBytes(&input.output_index));
        }

        // Hash outputs
        for (self.body.outputs) |output| {
            hasher.update(std.mem.asBytes(&output.value.lovelace));
        }

        // Hash fee
        hasher.update(std.mem.asBytes(&self.body.fee));

        var result: [32]u8 = undefined;
        hasher.final(&result);
        return crypto.Crypto.Hash256.fromBytes(result);
    }

    /// Get total input value (requires UTXO set)
    pub fn totalInput(self: Transaction, utxo_set: anytype) !Value {
        var total = Value{ .lovelace = 0 };

        for (self.body.inputs) |input| {
            const utxo = utxo_set.get(input) orelse return error.UtxoNotFound;
            total = try total.add(utxo.value);
        }

        return total;
    }

    /// Get total output value (including fee)
    pub fn totalOutput(self: Transaction) !Value {
        var total = Value{ .lovelace = self.body.fee };

        for (self.body.outputs) |output| {
            total = try total.add(output.value);
        }

        return total;
    }

    /// Verify value is preserved (inputs = outputs + fee)
    pub fn verifyValuePreserved(self: Transaction, utxo_set: anytype) !bool {
        const input_value = try self.totalInput(utxo_set);
        const output_value = try self.totalOutput();
        return input_value.eql(output_value);
    }

    /// Validate transaction structure (basic validation without UTXO set)
    pub fn validate(self: Transaction) !void {
        // Check that we have at least one input
        if (self.body.inputs.len == 0) {
            return error.NoInputs;
        }

        // Check that we have at least one output
        if (self.body.outputs.len == 0) {
            return error.NoOutputs;
        }

        // Check that all outputs meet minimum ADA requirement
        for (self.body.outputs) |output| {
            if (!output.isValid()) {
                return error.OutputBelowMinimum;
            }
        }

        // Check fee is not zero
        if (self.body.fee == 0) {
            return error.ZeroFee;
        }

        // If TTL is set, it should be reasonable
        if (self.body.ttl) |ttl| {
            if (ttl == 0) {
                return error.InvalidTTL;
            }
        }

        // Check witness count matches input count (simplified check)
        if (self.witnesses.vkey_witnesses.len == 0 and
            self.witnesses.bootstrap_witnesses.len == 0)
        {
            return error.NoWitnesses;
        }
    }
};

/// Transaction body (the part that gets hashed/signed)
pub const TransactionBody = struct {
    /// Inputs being spent
    inputs: []const TransactionInput,
    /// Outputs being created
    outputs: []const TransactionOutput,
    /// Transaction fee
    fee: u64,
    /// Time to live (slot number after which tx is invalid)
    ttl: ?u64 = null,
    /// Certificates (stake pool registration, delegation, etc.)
    certificates: []const Certificate = &.{},
    /// Withdrawals from reward accounts
    withdrawals: []const Withdrawal = &.{},
    /// Update proposal
    update: ?Update = null,
    /// Auxiliary data hash
    auxiliary_data_hash: ?crypto.Crypto.Hash256 = null,
    /// Validity interval start
    validity_start: ?u64 = null,
    /// Mint field for minting/burning native tokens
    mint: ?Value = null,
    /// Script data hash (for Plutus scripts)
    script_data_hash: ?crypto.Crypto.Hash256 = null,
    /// Collateral inputs (for script transactions)
    collateral: []const TransactionInput = &.{},
    /// Required signers
    required_signers: []const crypto.Crypto.PublicKey = &.{},
    /// Network ID
    network_id: ?address.NetworkId = null,
};

/// Witness set
pub const TransactionWitnessSet = struct {
    /// Verification key witnesses
    vkey_witnesses: []const VKeyWitness = &.{},
    /// Native scripts
    native_scripts: []const NativeScript = &.{},
    /// Bootstrap witnesses (Byron era)
    bootstrap_witnesses: []const BootstrapWitness = &.{},
    /// Plutus scripts v1
    plutus_scripts_v1: []const []const u8 = &.{},
    /// Plutus scripts v2
    plutus_scripts_v2: []const []const u8 = &.{},
    /// Plutus data
    plutus_data: []const []const u8 = &.{},
    /// Redeemers
    redeemers: []const Redeemer = &.{},
};

/// Certificate types (staking related)
pub const Certificate = union(enum) {
    stake_registration: StakeRegistration,
    stake_deregistration: StakeDeregistration,
    stake_delegation: StakeDelegation,
    pool_registration: PoolRegistration,
    pool_retirement: PoolRetirement,
    genesis_key_delegation: GenesisKeyDelegation,
    move_instantaneous_rewards: MoveInstantaneousRewards,
};

/// Stake registration certificate
pub const StakeRegistration = struct {
    stake_credential: address.Credential,
};

/// Stake deregistration certificate
pub const StakeDeregistration = struct {
    stake_credential: address.Credential,
};

/// Stake delegation certificate
pub const StakeDelegation = struct {
    stake_credential: address.Credential,
    pool_keyhash: crypto.Crypto.Hash224,
};

/// Pool registration certificate
pub const PoolRegistration = struct {
    operator: crypto.Crypto.Hash224,
    vrf_keyhash: crypto.Crypto.Hash256,
    pledge: u64,
    cost: u64,
    margin: Rational,
    reward_account: address.Address,
    pool_owners: []const crypto.Crypto.Hash224,
    relays: []const Relay,
    pool_metadata: ?PoolMetadata,
};

/// Pool retirement certificate
pub const PoolRetirement = struct {
    pool_keyhash: crypto.Crypto.Hash224,
    epoch: u32,
};

/// Genesis key delegation
pub const GenesisKeyDelegation = struct {
    genesis_hash: crypto.Crypto.Hash224,
    genesis_delegate_hash: crypto.Crypto.Hash224,
    vrf_keyhash: crypto.Crypto.Hash256,
};

/// Move instantaneous rewards
pub const MoveInstantaneousRewards = struct {
    pot: Pot,
    amounts: []const struct {
        stake_credential: address.Credential,
        amount: u64,
    },
};

/// Reward pot
pub const Pot = enum { reserves, treasury };

/// Rational number for pool margin
pub const Rational = struct {
    numerator: u64,
    denominator: u64,
};

/// Pool relay information
pub const Relay = union(enum) {
    single_host_addr: SingleHostAddr,
    single_host_name: SingleHostName,
    multi_host_name: MultiHostName,
};

pub const SingleHostAddr = struct {
    port: ?u16,
    ipv4: ?[4]u8,
    ipv6: ?[16]u8,
};

pub const SingleHostName = struct {
    port: ?u16,
    dns_name: []const u8,
};

pub const MultiHostName = struct {
    dns_name: []const u8,
};

/// Pool metadata
pub const PoolMetadata = struct {
    url: []const u8,
    metadata_hash: crypto.Crypto.Hash256,
};

/// Withdrawal from rewards
pub const Withdrawal = struct {
    reward_account: address.Address,
    amount: u64,
};

/// Update proposal
pub const Update = struct {
    proposed_protocol_parameter_updates: []const ProposedProtocolParameterUpdate,
    epoch: u32,
};

pub const ProposedProtocolParameterUpdate = struct {
    genesis_delegate_key_hash: crypto.Crypto.Hash224,
    update: ProtocolParameterUpdate,
};

/// Protocol parameter update (simplified)
pub const ProtocolParameterUpdate = struct {
    min_fee_a: ?u32 = null,
    min_fee_b: ?u32 = null,
    max_block_body_size: ?u32 = null,
    max_transaction_size: ?u32 = null,
    max_block_header_size: ?u32 = null,
    key_deposit: ?u64 = null,
    pool_deposit: ?u64 = null,
    // ... many more parameters
};

/// Auxiliary data (metadata)
pub const AuxiliaryData = struct {
    metadata: ?GeneralTransactionMetadata = null,
    native_scripts: []const NativeScript = &.{},
    plutus_scripts_v1: []const []const u8 = &.{},
    plutus_scripts_v2: []const []const u8 = &.{},
};

/// General transaction metadata
pub const GeneralTransactionMetadata = std.AutoHashMap(u64, []const u8);

/// Native script (simple scripts)
pub const NativeScript = union(enum) {
    script_pubkey: ScriptPubkey,
    script_all: ScriptAll,
    script_any: ScriptAny,
    script_n_of_k: ScriptNOfK,
    invalid_after: InvalidAfter,
    invalid_before: InvalidBefore,
};

pub const ScriptPubkey = struct {
    addr_keyhash: crypto.Crypto.Hash224,
};

pub const ScriptAll = struct {
    native_scripts: []const NativeScript,
};

pub const ScriptAny = struct {
    native_scripts: []const NativeScript,
};

pub const ScriptNOfK = struct {
    n: u32,
    native_scripts: []const NativeScript,
};

pub const InvalidAfter = struct {
    after: u64, // slot
};

pub const InvalidBefore = struct {
    before: u64, // slot
};

/// Redeemer for Plutus scripts
pub const Redeemer = struct {
    tag: RedeemerTag,
    index: u32,
    data: []const u8,
    ex_units: ExUnits,
};

pub const RedeemerTag = enum {
    spend,
    mint,
    cert,
    reward,
};

/// Execution units for scripts
pub const ExUnits = struct {
    mem: u64,
    steps: u64,
};

// Tests
test "TransactionInput equality" {
    const tx_id = crypto.Crypto.Hash256.fromBytes([_]u8{1} ** 32);

    const input1 = TransactionInput{ .tx_id = tx_id, .output_index = 0 };
    const input2 = TransactionInput{ .tx_id = tx_id, .output_index = 0 };
    const input3 = TransactionInput{ .tx_id = tx_id, .output_index = 1 };

    try std.testing.expect(input1.eql(input2));
    try std.testing.expect(!input1.eql(input3));
}

test "Value arithmetic" {
    const val1 = Value{ .lovelace = 1_000_000 };
    const val2 = Value{ .lovelace = 2_000_000 };

    const sum = try val1.add(val2);
    try std.testing.expectEqual(@as(u64, 3_000_000), sum.lovelace);

    const diff = try val2.sub(val1);
    try std.testing.expectEqual(@as(u64, 1_000_000), diff.lovelace);

    // Test underflow
    try std.testing.expectError(error.InsufficientValue, val1.sub(val2));
}

test "TransactionOutput validation" {
    const addr = address.Address{
        .network = .testnet,
        .payment = .{ .key_hash = [_]u8{0} ** 28 },
        .staking = null,
    };

    const output1 = TransactionOutput{
        .address = addr,
        .value = Value{ .lovelace = 1_000_000 },
    };
    try std.testing.expect(output1.isValid());

    const output2 = TransactionOutput{
        .address = addr,
        .value = Value{ .lovelace = 500_000 }, // Below minimum
    };
    try std.testing.expect(!output2.isValid());
}
