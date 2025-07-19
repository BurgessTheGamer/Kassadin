const std = @import("std");
const crypto = @import("crypto/crypto.zig");
const ledger = @import("ledger/ledger.zig");
const transaction = @import("ledger/transaction.zig");
const block = @import("ledger/block.zig");
const consensus = @import("consensus/consensus.zig");
const praos = @import("consensus/praos.zig");
const chain = @import("consensus/chain.zig");
const network = @import("network/network.zig");
const peer = @import("network/peer.zig");
const sync = @import("network/sync.zig");
const dns = @import("network/dns.zig");
const logger = @import("utils/logger.zig");

/// Main node manager that coordinates all components
pub const Node = struct {
    /// Node configuration
    pub const Config = struct {
        network: NetworkType = .mainnet,
        data_dir: []const u8 = "./data",
        listen_port: u16 = 3001,
        max_peers: u32 = 50,
        log_level: logger.Level = .info,
    };

    /// Network type
    pub const NetworkType = enum {
        mainnet,
        testnet,
        preview,
        preprod,

        pub fn toNetworkMagic(self: NetworkType) network.Network.NetworkMagic {
            return switch (self) {
                .mainnet => .mainnet,
                .testnet => .testnet,
                .preview => .preview,
                .preprod => .preprod,
            };
        }

        pub fn toString(self: NetworkType) []const u8 {
            return switch (self) {
                .mainnet => "mainnet",
                .testnet => "testnet",
                .preview => "preview",
                .preprod => "preprod",
            };
        }
    };

    /// Node state
    pub const State = enum {
        initializing,
        syncing,
        synchronized,
        shutting_down,
    };

    config: Config,
    state: State,
    allocator: std.mem.Allocator,

    // Core components
    ledger_state: *ledger.Ledger,
    chain_state: *chain.ChainManager,
    consensus_state: *praos.Praos.State,
    peer_manager: *peer.Peer.Manager,
    sync_manager: *sync.ChainSync,

    // Network parameters
    network_params: network.Network.ProtocolParams,

    // Control
    should_stop: std.atomic.Value(bool),
    main_thread: ?std.Thread = null,

    pub fn init(allocator: std.mem.Allocator, config: Config) !*Node {
        logger.setLevel(config.log_level);
        logger.info("Initializing Kassadin node for {s}", .{config.network.toString()});

        // Initialize crypto subsystem
        try crypto.Crypto.init();

        // Create node instance
        const node = try allocator.create(Node);
        errdefer allocator.destroy(node);

        // Initialize components
        const ledger_state = try allocator.create(ledger.Ledger);
        ledger_state.* = ledger.Ledger.init(allocator);
        errdefer ledger_state.deinit();

        const chain_state = try allocator.create(chain.ChainManager);
        chain_state.* = chain.ChainManager.init(allocator, ledger_state, .{});
        errdefer {
            chain_state.deinit();
            allocator.destroy(chain_state);
        }

        const consensus_state = try allocator.create(praos.Praos.State);
        consensus_state.* = praos.Praos.State.init(.{});
        errdefer allocator.destroy(consensus_state);

        const network_params = network.Network.ProtocolParams{
            .network_magic = config.network.toNetworkMagic(),
            .max_transmission_unit = 65536,
            .max_concurrency = config.max_peers,
            .ping_interval_ms = 30000,
            .handshake_timeout_ms = 10000,
        };

        const peer_manager = try allocator.create(peer.Peer.Manager);
        peer_manager.* = peer.Peer.Manager.init(allocator, network_params);
        errdefer peer_manager.deinit();

        const sync_manager = try sync.ChainSync.init(allocator, chain_state, peer_manager);
        errdefer sync_manager.deinit();

        node.* = Node{
            .config = config,
            .state = .initializing,
            .allocator = allocator,
            .ledger_state = ledger_state,
            .chain_state = chain_state,
            .consensus_state = consensus_state,
            .peer_manager = peer_manager,
            .sync_manager = sync_manager,
            .network_params = network_params,
            .should_stop = std.atomic.Value(bool).init(false),
        };

        return node;
    }

    pub fn deinit(self: *Node) void {
        logger.info("Shutting down Kassadin node", .{});

        // Stop main thread if running
        self.stop();
        if (self.main_thread) |thread| {
            thread.join();
        }

        // Stop sync manager first (it uses peer manager)
        self.sync_manager.stop();

        // Disconnect all peers before destroying managers
        self.peer_manager.disconnectAll();

        // Clean up components in reverse order of creation
        self.sync_manager.deinit();
        self.allocator.destroy(self.sync_manager);

        self.peer_manager.deinit();
        self.allocator.destroy(self.peer_manager);

        self.allocator.destroy(self.consensus_state);

        self.chain_state.deinit();
        self.allocator.destroy(self.chain_state);

        self.ledger_state.deinit();
        self.allocator.destroy(self.ledger_state);

        self.allocator.destroy(self);
    }

    /// Start the node
    pub fn start(self: *Node) !void {
        logger.info("Starting Kassadin node", .{});

        // Start in a separate thread
        self.main_thread = try std.Thread.spawn(.{}, runMainLoop, .{self});
    }

    /// Main event loop
    fn runMainLoop(self: *Node) !void {
        logger.info("Node main loop started", .{});

        // Start listening for connections
        const listen_addr = try std.net.Address.parseIp("0.0.0.0", self.config.listen_port);
        var server = try listen_addr.listen(.{
            .reuse_address = true,
        });
        defer server.deinit();

        logger.info("Listening on port {}", .{self.config.listen_port});

        // Connect to bootstrap peers
        try self.connectToBootstrapPeers();

        // Set up message handler for peers
        self.peer_manager.sync_manager = self.sync_manager.sync_manager;

        // Start synchronization
        self.state = .syncing;
        try self.sync_manager.start();

        // Main event loop
        while (!self.should_stop.load(.acquire)) {
            // Accept new connections (with timeout)
            if (server.accept()) |conn| {
                self.handleNewConnection(conn) catch |err| {
                    logger.err("Failed to handle connection: {}", .{err});
                };
            } else |err| switch (err) {
                error.WouldBlock => {},
                else => logger.err("Accept error: {}", .{err}),
            }

            // Check if we're synchronized
            if (self.sync_manager.isSynced() and self.state == .syncing) {
                self.state = .synchronized;
                logger.info("Node synchronized with network", .{});
            }

            // Small delay to prevent busy loop
            std.time.sleep(10 * std.time.ns_per_ms);
        }

        self.state = .shutting_down;
        logger.info("Node main loop stopped", .{});
    }

    /// Handle new incoming connection
    fn handleNewConnection(self: *Node, conn: std.net.Server.Connection) !void {
        const peer_addr = network.Network.PeerAddr{
            .ip = conn.address,
        };

        logger.info("New connection from {}", .{peer_addr});

        // Create peer connection (we are responder since they connected to us)
        const peer_conn = try peer.Peer.Connection.init(self.allocator, conn.stream, peer_addr, false);

        // Perform handshake in background
        // TODO: Spawn thread for peer handling
        peer_conn.handshake(self.network_params) catch |err| {
            logger.err("Handshake failed with {}: {}", .{ peer_addr, err });
            peer_conn.deinit();
            return;
        };

        // Add to peer manager
        self.peer_manager.mutex.lock();
        defer self.peer_manager.mutex.unlock();
        try self.peer_manager.connections.append(peer_conn);
        self.peer_manager.stats.peers_connected += 1;
    }

    /// Connect to bootstrap peers
    fn connectToBootstrapPeers(self: *Node) !void {
        const bootstrap_peers = dns.DNS.BootstrapPeers.getForNetwork(self.network_params.network_magic);

        logger.info("Connecting to {} bootstrap peers", .{bootstrap_peers.len});

        for (bootstrap_peers) |peer_str| {
            // Parse host:port
            const parsed = dns.DNS.parseHostPort(peer_str, 3001) catch |err| {
                logger.err("Failed to parse {s}: {}", .{ peer_str, err });
                continue;
            };

            logger.info("Resolving {s}:{}", .{ parsed.host, parsed.port });

            // Resolve addresses
            const addresses = dns.DNS.resolve(self.allocator, parsed.host, parsed.port) catch |err| {
                logger.err("Failed to resolve {s}: {}", .{ parsed.host, err });
                continue;
            };
            defer self.allocator.free(addresses);

            // Try to connect to resolved addresses
            for (addresses) |addr| {
                logger.info("Connecting to {}", .{addr});

                _ = self.peer_manager.connect(addr) catch |err| {
                    logger.err("Failed to connect to {}: {}", .{ addr, err });
                    continue;
                };

                logger.info("Successfully connected to {}", .{addr});
                break; // Connected to this peer, try next bootstrap peer
            }
        }

        logger.info("Connected to {} peers", .{self.peer_manager.activePeerCount()});
    }

    /// Stop the node
    pub fn stop(self: *Node) void {
        logger.info("Stopping node...", .{});
        self.should_stop.store(true, .release);
    }

    /// Get node status
    pub fn getStatus(self: *Node) Status {
        const sync_progress = self.sync_manager.getSyncProgress();
        const chain_tip = self.chain_state.getTip();

        return .{
            .state = self.state,
            .network = self.config.network,
            .current_slot = chain_tip.header.slot,
            .current_epoch = @intCast(chain_tip.header.slot / 432000), // slots per epoch
            .sync_progress = sync_progress,
            .peer_count = self.peer_manager.activePeerCount(),
            .utxo_count = self.ledger_state.getUtxoCount(),
        };
    }

    /// Node status information
    pub const Status = struct {
        state: State,
        network: NetworkType,
        current_slot: consensus.Consensus.Slot,
        current_epoch: consensus.Consensus.Epoch,
        sync_progress: f32,
        peer_count: usize,
        utxo_count: usize,
    };
};

test "Node initialization" {
    const config = Node.Config{
        .network = .testnet,
        .log_level = .debug,
    };

    const node = try Node.init(std.testing.allocator, config);
    defer node.deinit();

    try std.testing.expectEqual(Node.State.initializing, node.state);

    const status = node.getStatus();
    try std.testing.expectEqual(@as(f32, 0.0), status.sync_progress);
    try std.testing.expectEqual(@as(u32, 0), status.peer_count);
}
