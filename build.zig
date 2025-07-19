const std = @import("std");

pub fn build(b: *std.Build) void {
    // Standard target options allows the person running `zig build` to choose
    // what target to build for. Here we do not override the defaults, which
    // means any target is allowed, and the default is native.
    const target = b.standardTargetOptions(.{});

    // Standard optimization options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall.
    const optimize = b.standardOptimizeOption(.{});

    // Main executable
    const exe = b.addExecutable(.{
        .name = "kassadin",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Link system libraries
    exe.linkSystemLibrary("sodium");
    // exe.linkSystemLibrary("rocksdb"); // TODO: Add when needed
    
    // Add include paths for macOS (Homebrew)
    if (target.result.os.tag == .macos) {
        exe.addIncludePath(.{ .cwd_relative = "/opt/homebrew/include" });
        exe.addLibraryPath(.{ .cwd_relative = "/opt/homebrew/lib" });
        // Also check x86_64 paths for compatibility
        exe.addIncludePath(.{ .cwd_relative = "/usr/local/include" });
        exe.addLibraryPath(.{ .cwd_relative = "/usr/local/lib" });
    }

    b.installArtifact(exe);

    // Create run command
    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());

    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    // Tests
    const unit_tests = b.addTest(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Link libsodium for tests too
    unit_tests.linkSystemLibrary("sodium");
    if (target.result.os.tag == .macos) {
        unit_tests.addIncludePath(.{ .cwd_relative = "/opt/homebrew/include" });
        unit_tests.addLibraryPath(.{ .cwd_relative = "/opt/homebrew/lib" });
        unit_tests.addIncludePath(.{ .cwd_relative = "/usr/local/include" });
        unit_tests.addLibraryPath(.{ .cwd_relative = "/usr/local/lib" });
    }

    const run_unit_tests = b.addRunArtifact(unit_tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);

    // Format checking
    const fmt_step = b.step("fmt", "Format all source files");
    const fmt = b.addFmt(.{
        .paths = &.{ "src", "tests" },
        .check = false,
    });
    fmt_step.dependOn(&fmt.step);

    const fmt_check_step = b.step("fmt-check", "Check formatting of all source files");
    const fmt_check = b.addFmt(.{
        .paths = &.{ "src", "tests" },
        .check = true,
    });
    fmt_check_step.dependOn(&fmt_check.step);

    // Crypto test executable
    const crypto_test = b.addExecutable(.{
        .name = "crypto_test",
        .root_source_file = b.path("src/crypto_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    crypto_test.linkSystemLibrary("sodium");
    if (target.result.os.tag == .macos) {
        crypto_test.addIncludePath(.{ .cwd_relative = "/opt/homebrew/include" });
        crypto_test.addLibraryPath(.{ .cwd_relative = "/opt/homebrew/lib" });
        crypto_test.addIncludePath(.{ .cwd_relative = "/usr/local/include" });
        crypto_test.addLibraryPath(.{ .cwd_relative = "/usr/local/lib" });
    }
    
    const run_crypto_test = b.addRunArtifact(crypto_test);
    const crypto_test_step = b.step("crypto-test", "Run the crypto test");
    crypto_test_step.dependOn(&run_crypto_test.step);

    // Ledger demo executable
    const ledger_demo = b.addExecutable(.{
        .name = "ledger_demo",
        .root_source_file = b.path("src/ledger_demo.zig"),
        .target = target,
        .optimize = optimize,
    });
    ledger_demo.linkSystemLibrary("sodium");
    if (target.result.os.tag == .macos) {
        ledger_demo.addIncludePath(.{ .cwd_relative = "/opt/homebrew/include" });
        ledger_demo.addLibraryPath(.{ .cwd_relative = "/opt/homebrew/lib" });
        ledger_demo.addIncludePath(.{ .cwd_relative = "/usr/local/include" });
        ledger_demo.addLibraryPath(.{ .cwd_relative = "/usr/local/lib" });
    }
    
    const run_ledger_demo = b.addRunArtifact(ledger_demo);
    const ledger_demo_step = b.step("ledger-demo", "Run the ledger demo");
    ledger_demo_step.dependOn(&run_ledger_demo.step);

    // Consensus demo executable
    const consensus_demo = b.addExecutable(.{
        .name = "consensus_demo",
        .root_source_file = b.path("src/consensus_demo.zig"),
        .target = target,
        .optimize = optimize,
    });
    consensus_demo.linkSystemLibrary("sodium");
    if (target.result.os.tag == .macos) {
        consensus_demo.addIncludePath(.{ .cwd_relative = "/opt/homebrew/include" });
        consensus_demo.addLibraryPath(.{ .cwd_relative = "/opt/homebrew/lib" });
        consensus_demo.addIncludePath(.{ .cwd_relative = "/usr/local/include" });
        consensus_demo.addLibraryPath(.{ .cwd_relative = "/usr/local/lib" });
    }
    
    const run_consensus_demo = b.addRunArtifact(consensus_demo);
    const consensus_demo_step = b.step("consensus-demo", "Run the consensus demo");
    consensus_demo_step.dependOn(&run_consensus_demo.step);

    // Network demo executable
    const network_demo = b.addExecutable(.{
        .name = "network_demo",
        .root_source_file = b.path("src/network_demo.zig"),
        .target = target,
        .optimize = optimize,
    });
    network_demo.linkSystemLibrary("sodium");
    if (target.result.os.tag == .macos) {
        network_demo.addIncludePath(.{ .cwd_relative = "/opt/homebrew/include" });
        network_demo.addLibraryPath(.{ .cwd_relative = "/opt/homebrew/lib" });
        network_demo.addIncludePath(.{ .cwd_relative = "/usr/local/include" });
        network_demo.addLibraryPath(.{ .cwd_relative = "/usr/local/lib" });
    }
    
    const run_network_demo = b.addRunArtifact(network_demo);
    const network_demo_step = b.step("network-demo", "Run the network demo");
    network_demo_step.dependOn(&run_network_demo.step);

    // Integration demo executable
    const integration_demo = b.addExecutable(.{
        .name = "integration_demo",
        .root_source_file = b.path("src/integration_demo.zig"),
        .target = target,
        .optimize = optimize,
    });
    integration_demo.linkSystemLibrary("sodium");
    if (target.result.os.tag == .macos) {
        integration_demo.addIncludePath(.{ .cwd_relative = "/opt/homebrew/include" });
        integration_demo.addLibraryPath(.{ .cwd_relative = "/opt/homebrew/lib" });
        integration_demo.addIncludePath(.{ .cwd_relative = "/usr/local/include" });
        integration_demo.addLibraryPath(.{ .cwd_relative = "/usr/local/lib" });
    }
    
    const run_integration_demo = b.addRunArtifact(integration_demo);
    const integration_demo_step = b.step("integration-demo", "Run the integration demo");
    integration_demo_step.dependOn(&run_integration_demo.step);

    // Storage demo executable
    const storage_demo = b.addExecutable(.{
        .name = "storage_demo",
        .root_source_file = b.path("src/storage_demo.zig"),
        .target = target,
        .optimize = optimize,
    });
    storage_demo.linkSystemLibrary("sodium");
    if (target.result.os.tag == .macos) {
        storage_demo.addIncludePath(.{ .cwd_relative = "/opt/homebrew/include" });
        storage_demo.addLibraryPath(.{ .cwd_relative = "/opt/homebrew/lib" });
        storage_demo.addIncludePath(.{ .cwd_relative = "/usr/local/include" });
        storage_demo.addLibraryPath(.{ .cwd_relative = "/usr/local/lib" });
    }
    
    const run_storage_demo = b.addRunArtifact(storage_demo);
    const storage_demo_step = b.step("storage-demo", "Run the storage demo");
    storage_demo_step.dependOn(&run_storage_demo.step);

    // Testnet demo executable
    const testnet_demo = b.addExecutable(.{
        .name = "testnet_demo",
        .root_source_file = b.path("src/testnet_demo.zig"),
        .target = target,
        .optimize = optimize,
    });
    testnet_demo.linkSystemLibrary("sodium");
    if (target.result.os.tag == .macos) {
        testnet_demo.addIncludePath(.{ .cwd_relative = "/opt/homebrew/include" });
        testnet_demo.addLibraryPath(.{ .cwd_relative = "/opt/homebrew/lib" });
        testnet_demo.addIncludePath(.{ .cwd_relative = "/usr/local/include" });
        testnet_demo.addLibraryPath(.{ .cwd_relative = "/usr/local/lib" });
    }
    
    const run_testnet_demo = b.addRunArtifact(testnet_demo);
    const testnet_demo_step = b.step("testnet-demo", "Run the testnet connection demo");
    testnet_demo_step.dependOn(&run_testnet_demo.step);
}