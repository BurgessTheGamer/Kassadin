const std = @import("std");
const node = @import("node.zig");
const logger = @import("utils/logger.zig");

const VERSION = "0.1.0";

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Parse command line arguments
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    var config = node.Node.Config{};

    // Simple argument parsing
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--network")) {
            i += 1;
            if (i >= args.len) {
                try printUsage();
                return;
            }
            if (std.mem.eql(u8, args[i], "mainnet")) {
                config.network = .mainnet;
            } else if (std.mem.eql(u8, args[i], "testnet")) {
                config.network = .testnet;
            } else if (std.mem.eql(u8, args[i], "preview")) {
                config.network = .preview;
            } else if (std.mem.eql(u8, args[i], "preprod")) {
                config.network = .preprod;
            } else {
                logger.err("Unknown network: {s}", .{args[i]});
                return;
            }
        } else if (std.mem.eql(u8, args[i], "--port")) {
            i += 1;
            if (i >= args.len) {
                try printUsage();
                return;
            }
            config.listen_port = try std.fmt.parseInt(u16, args[i], 10);
        } else if (std.mem.eql(u8, args[i], "--data-dir")) {
            i += 1;
            if (i >= args.len) {
                try printUsage();
                return;
            }
            config.data_dir = args[i];
        } else if (std.mem.eql(u8, args[i], "--log-level")) {
            i += 1;
            if (i >= args.len) {
                try printUsage();
                return;
            }
            if (std.mem.eql(u8, args[i], "debug")) {
                config.log_level = .debug;
            } else if (std.mem.eql(u8, args[i], "info")) {
                config.log_level = .info;
            } else if (std.mem.eql(u8, args[i], "warn")) {
                config.log_level = .warn;
            } else if (std.mem.eql(u8, args[i], "error")) {
                config.log_level = .err;
            }
        } else if (std.mem.eql(u8, args[i], "--help") or std.mem.eql(u8, args[i], "-h")) {
            try printUsage();
            return;
        } else if (std.mem.eql(u8, args[i], "--version") or std.mem.eql(u8, args[i], "-v")) {
            try printVersion();
            return;
        } else {
            logger.err("Unknown argument: {s}", .{args[i]});
            try printUsage();
            return;
        }
    }

    // Print banner
    try printBanner();

    // Initialize and run node
    var kassadin = try node.Node.init(allocator, config);
    defer kassadin.deinit();

    // Set up signal handler for graceful shutdown
    // Note: Signal handling is platform-specific in Zig 0.14
    // For now, we'll rely on the node's internal shutdown mechanism

    // Start the node
    try kassadin.start();
}

fn printBanner() !void {
    const stdout = std.io.getStdOut().writer();
    try stdout.print(
        \\
        \\╔═══════════════════════════════════════╗
        \\║          KASSADIN v{s}           ║
        \\║     Cardano Node Implementation       ║
        \\║           Written in Zig              ║
        \\╚═══════════════════════════════════════╝
        \\
    , .{VERSION});
}

fn printVersion() !void {
    const stdout = std.io.getStdOut().writer();
    try stdout.print("Kassadin v{s}\n", .{VERSION});
}

fn printUsage() !void {
    const stdout = std.io.getStdOut().writer();
    try stdout.print(
        \\Usage: kassadin [options]
        \\
        \\Options:
        \\  --network <name>     Network to connect to (mainnet, testnet, preview, preprod)
        \\  --port <port>        Port to listen on (default: 3001)
        \\  --data-dir <path>    Data directory (default: ./data)
        \\  --log-level <level>  Log level (debug, info, warn, error)
        \\  --help, -h           Show this help message
        \\  --version, -v        Show version information
        \\
        \\Examples:
        \\  kassadin --network testnet
        \\  kassadin --network mainnet --port 3001 --log-level info
        \\
    , .{});
}

// Re-export tests from modules
test {
    _ = @import("crypto/crypto.zig");
    _ = @import("crypto/sodium.zig");
    _ = @import("crypto/address.zig");
    _ = @import("crypto/bech32.zig");
    _ = @import("crypto/vrf.zig");
    _ = @import("crypto/kes.zig");
    _ = @import("ledger/ledger.zig");
    _ = @import("ledger/transaction.zig");
    _ = @import("ledger/block.zig");
    _ = @import("ledger/ledger_test.zig");
    _ = @import("consensus/consensus.zig");
    _ = @import("consensus/praos.zig");
    _ = @import("consensus/chain.zig");
    _ = @import("network/network.zig");
    _ = @import("network/protocol.zig");
    _ = @import("network/peer.zig");
    _ = @import("network/sync.zig");
    _ = @import("network/dns.zig");
    _ = @import("storage/storage.zig");
    _ = @import("storage/file_store.zig");
    _ = @import("utils/logger.zig");
    _ = @import("node.zig");
}
