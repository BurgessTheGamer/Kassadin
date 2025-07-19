const std = @import("std");
const network = @import("network.zig");
const protocol = @import("protocol.zig");
const block = @import("../ledger/block.zig");
const transaction = @import("../ledger/transaction.zig");
const handshake_mod = @import("handshake.zig");
const handshake_v2 = @import("handshake_v2.zig");
const cbor = @import("../utils/cbor.zig");
const frame_mod = @import("frame.zig");
const logger = @import("../utils/logger.zig");
const mux = @import("mux.zig");
const MuxConnection = mux.MuxConnection;
const ProtocolId = mux.ProtocolId;

/// Peer connection management
pub const Peer = struct {
    /// Peer capabilities
    pub const Capabilities = struct {
        protocol_version: network.Network.ProtocolVersion,
        services: Services,
    };

    /// Services offered by peer
    pub const Services = struct {
        relay: bool = true,
        full_node: bool = true,
    };

    /// Peer connection state
    pub const Connection = struct {
        const READ_BUFFER_SIZE = 65536;
        const WRITE_BUFFER_SIZE = 65536;

        allocator: std.mem.Allocator,
        stream: std.net.Stream,
        mux_conn: MuxConnection,
        address: network.Network.PeerAddr,
        state: network.Network.ConnectionState,
        capabilities: ?Capabilities,
        their_tip: ?block.ChainTip,
        last_activity: i64,

        // Buffers
        read_buffer: []u8,
        write_buffer: []u8,

        // Statistics
        messages_sent: u64,
        messages_received: u64,
        bytes_sent: u64,
        bytes_received: u64,

        pub fn init(allocator: std.mem.Allocator, stream: std.net.Stream, address: network.Network.PeerAddr, is_initiator: bool) !*Connection {
            const conn = try allocator.create(Connection);
            conn.* = .{
                .allocator = allocator,
                .stream = stream,
                .mux_conn = MuxConnection.init(stream, allocator, is_initiator),
                .address = address,
                .state = .connecting,
                .capabilities = null,
                .their_tip = null,
                .last_activity = std.time.milliTimestamp(),
                .read_buffer = try allocator.alloc(u8, READ_BUFFER_SIZE),
                .write_buffer = try allocator.alloc(u8, WRITE_BUFFER_SIZE),
                .messages_sent = 0,
                .messages_received = 0,
                .bytes_sent = 0,
                .bytes_received = 0,
            };
            return conn;
        }

        pub fn deinit(self: *Connection) void {
            self.stream.close();
            self.allocator.free(self.read_buffer);
            self.allocator.free(self.write_buffer);
            self.allocator.destroy(self);
        }

        /// Send a protocol message
        pub fn sendMessage(self: *Connection, msg: protocol.Protocol.Message) !void {
            const timestamp: u32 = @intCast(@divTrunc(std.time.milliTimestamp(), 1000));

            // Encode message payload
            var payload_buffer = std.ArrayList(u8).init(self.allocator);
            defer payload_buffer.deinit();

            // Encode based on message type
            switch (msg) {
                .msg_propose_versions => |handshake_msg| {
                    const data = try handshake_msg.encode(self.allocator);
                    defer self.allocator.free(data);
                    try payload_buffer.appendSlice(data);
                },
                .msg_keep_alive => {},
                .msg_keep_alive_response => {},
                .msg_request_next => {},
                .msg_await_reply => {},
                .msg_done => {},
                else => return error.NotImplemented,
            }

            // Create header
            const header = protocol.Protocol.MessageHeader{
                .timestamp = timestamp,
                .msg_type = std.meta.activeTag(msg),
                .payload_size = @intCast(payload_buffer.items.len),
            };

            // Write header and payload
            var write_stream = std.io.fixedBufferStream(self.write_buffer);
            try header.encode(write_stream.writer());
            try write_stream.writer().writeAll(payload_buffer.items);

            const total_size = protocol.Protocol.MessageHeader.SIZE + payload_buffer.items.len;
            _ = try self.stream.write(self.write_buffer[0..total_size]);

            self.messages_sent += 1;
            self.bytes_sent += total_size;
            self.last_activity = std.time.milliTimestamp();
        }

        /// Receive a protocol message
        pub fn receiveMessage(self: *Connection) !protocol.Protocol.Message {
            // Read header
            const header_bytes = self.read_buffer[0..protocol.Protocol.MessageHeader.SIZE];
            _ = try self.stream.read(header_bytes);

            var header_stream = std.io.fixedBufferStream(header_bytes);
            const header = try protocol.Protocol.MessageHeader.decode(header_stream.reader());

            // Read payload
            if (header.payload_size > 0) {
                if (header.payload_size > self.read_buffer.len) {
                    return error.MessageTooLarge;
                }
                _ = try self.stream.read(self.read_buffer[0..header.payload_size]);
            }

            self.messages_received += 1;
            self.bytes_received += protocol.Protocol.MessageHeader.SIZE + header.payload_size;
            self.last_activity = std.time.milliTimestamp();

            // Decode message based on type
            switch (header.msg_type) {
                .msg_keep_alive => return .{ .msg_keep_alive = {} },
                .msg_keep_alive_response => return .{ .msg_keep_alive_response = {} },
                else => return error.NotImplemented,
            }
        }

        /// Send raw bytes with framing
        fn sendFramedMessage(self: *Connection, protocol_id: frame_mod.Frame.ProtocolId, data: []const u8) !void {
            const encoder = frame_mod.Frame.Encoder.init(self.allocator);
            const framed = try encoder.encode(protocol_id, data);
            defer self.allocator.free(framed);

            _ = try self.stream.write(framed);
            self.bytes_sent += framed.len;
            self.messages_sent += 1;
            self.last_activity = std.time.milliTimestamp();
        }

        /// Receive framed message
        fn receiveFramedMessage(self: *Connection) !frame_mod.Frame.Message {
            const decoder = frame_mod.Frame.Decoder.init(self.allocator);
            const message = try decoder.decode(self.stream);

            self.bytes_received += frame_mod.Frame.HEADER_SIZE + message.payload.len;
            self.messages_received += 1;
            self.last_activity = std.time.milliTimestamp();

            return message;
        }

        /// Perform protocol handshake
        pub fn handshake(self: *Connection, params: network.Network.ProtocolParams) !void {
            self.state = .handshaking;

            // Use v2 handshake for proper protocol support
            var hs = handshake_v2.HandshakeV2.init(self.allocator, @intFromEnum(params.network_magic));

            // Send propose versions message
            const propose_msg = try hs.createProposeVersions();
            defer self.allocator.free(propose_msg);

            logger.info("Sending handshake propose versions (CBOR: {} bytes) via Mux", .{propose_msg.len});

            // Log the CBOR bytes we're sending
            logger.debug("CBOR bytes: {x}", .{std.fmt.fmtSliceHexLower(propose_msg)});

            // Send via mux layer with handshake protocol ID
            try self.mux_conn.sendFrame(.handshake, propose_msg);
            hs.state = .proposed;

            // Wait for response via mux
            var response_frame = try self.mux_conn.recvFrame();
            defer response_frame.deinit(self.allocator);

            logger.info("Received handshake response (protocol: {}, {} bytes)", .{ response_frame.header.protocol_id, response_frame.payload.len });
            logger.debug("Response bytes: {x}", .{std.fmt.fmtSliceHexLower(response_frame.payload)});

            // Verify it's a handshake protocol message
            if (response_frame.header.protocol_id != @intFromEnum(ProtocolId.handshake)) {
                return error.UnexpectedProtocol;
            }

            try hs.processMessage(response_frame.payload);

            if (hs.state == .confirmed) {
                // We received propose_versions, send accept_version
                const accept_msg = try hs.createAcceptVersion(hs.agreed_version.?);
                defer self.allocator.free(accept_msg);

                logger.info("Sending accept version {} via Mux", .{hs.agreed_version.?});
                try self.mux_conn.sendFrame(.handshake, accept_msg);

                // Now wait for their accept or next message
                var final_frame = try self.mux_conn.recvFrame();
                defer final_frame.deinit(self.allocator);

                logger.info("Received final handshake message (protocol: {}, {} bytes)", .{ final_frame.header.protocol_id, final_frame.payload.len });

                // Process the final message
                try hs.processMessage(final_frame.payload);

                if (hs.state == .done) {
                    self.capabilities = .{
                        .protocol_version = .{ .major = hs.agreed_version.?, .minor = 0 },
                        .services = .{},
                    };
                    logger.info("Handshake completed with version {}", .{hs.agreed_version.?});
                    self.state = .established;
                } else {
                    self.state = .closed;
                    return error.HandshakeFailed;
                }
            } else if (hs.state == .done) {
                // We received accept_version directly
                self.capabilities = .{
                    .protocol_version = .{ .major = hs.agreed_version.?, .minor = 0 },
                    .services = .{},
                };
                logger.info("Handshake completed with version {}", .{hs.agreed_version.?});
                self.state = .established;
            } else if (hs.state == .refused) {
                self.state = .closed;
                return error.HandshakeRefused;
            } else {
                self.state = .closed;
                return error.HandshakeFailed;
            }
        }

        /// Check if connection is alive
        pub fn isAlive(self: *Connection) bool {
            const now = std.time.milliTimestamp();
            const idle_time = now - self.last_activity;
            return self.state == .established and idle_time < 60000; // 60 second timeout
        }

        /// Send a chain-sync message
        pub fn sendChainSyncMessage(self: *Connection, msg: []const u8) !void {
            try self.mux_conn.sendFrame(.chain_sync, msg);
            self.messages_sent += 1;
            self.last_activity = std.time.milliTimestamp();
        }

        /// Receive messages in a loop (for thread)
        pub fn receiveLoop(self: *Connection, handler: anytype) !void {
            while (self.state == .established) {
                var frame = self.mux_conn.recvFrame() catch |err| {
                    if (err == error.ConnectionClosed) {
                        self.state = .closed;
                        break;
                    }
                    return err;
                };
                defer frame.deinit(self.allocator);

                self.messages_received += 1;
                self.bytes_received += frame.payload.len;
                self.last_activity = std.time.milliTimestamp();

                // Dispatch based on protocol ID
                switch (@as(ProtocolId, @enumFromInt(frame.header.protocol_id))) {
                    .chain_sync => try handler.handleChainSync(self, frame.payload),
                    .block_fetch => try handler.handleBlockFetch(self, frame.payload),
                    .keep_alive => {}, // Just update activity timestamp
                    else => logger.warn("Unhandled protocol ID: {}", .{frame.header.protocol_id}),
                }
            }
        }
    };

    /// Peer manager
    pub const Manager = struct {
        allocator: std.mem.Allocator,
        connections: std.ArrayList(*Connection),
        params: network.Network.ProtocolParams,
        stats: network.Network.Stats,
        mutex: std.Thread.Mutex,
        sync_manager: ?*anyopaque = null, // Will be set by node after initialization

        pub fn init(allocator: std.mem.Allocator, params: network.Network.ProtocolParams) Manager {
            return .{
                .allocator = allocator,
                .connections = std.ArrayList(*Connection).init(allocator),
                .params = params,
                .stats = .{},
                .mutex = .{},
                .sync_manager = null,
            };
        }

        pub fn deinit(self: *Manager) void {
            self.mutex.lock();
            defer self.mutex.unlock();

            // Mark all connections as closed first to stop receive loops
            for (self.connections.items) |conn| {
                conn.state = .closed;
            }

            // Give threads more time to exit cleanly
            std.time.sleep(500 * std.time.ns_per_ms);

            // Now clean up connections
            for (self.connections.items) |conn| {
                conn.deinit();
            }
            self.connections.deinit();
        }

        /// Connect to a peer
        pub fn connect(self: *Manager, address: network.Network.PeerAddr) !*Connection {
            const stream = try std.net.tcpConnectToAddress(address.ip);
            const conn = try Connection.init(self.allocator, stream, address, true); // We are the initiator

            // Perform handshake
            conn.handshake(self.params) catch |err| {
                conn.deinit();
                return err;
            };

            self.mutex.lock();
            defer self.mutex.unlock();

            try self.connections.append(conn);
            self.stats.peers_connected += 1;

            // Start receive loop in a separate thread
            const PeerHandler = struct {
                manager: *Manager,

                pub fn runReceiveLoop(handler: *@This(), peer_conn: *Connection) void {
                    peer_conn.receiveLoop(handler) catch |err| {
                        logger.err("Receive loop error for {}: {}", .{ peer_conn.address, err });
                    };
                    // Clean up when done
                    handler.manager.disconnect(peer_conn);
                }

                pub fn handleChainSync(handler: *@This(), peer_conn: *Connection, data: []const u8) !void {
                    logger.debug("Received chain-sync message from {} ({} bytes)", .{ peer_conn.address, data.len });

                    // Forward to sync manager if available
                    if (handler.manager.sync_manager) |sync_mgr| {
                        const sync_manager = @import("sync_manager.zig");
                        const sm = @as(*sync_manager.SyncManager, @ptrCast(@alignCast(sync_mgr)));
                        try sm.processMessage(peer_conn, data);
                    }
                }

                pub fn handleBlockFetch(handler: *@This(), peer_conn: *Connection, data: []const u8) !void {
                    _ = handler;
                    _ = peer_conn;
                    _ = data;
                    // TODO: Implement block fetch handling
                }
            };

            const handler = try self.allocator.create(PeerHandler);
            handler.* = .{ .manager = self };

            // Store handler reference for cleanup
            // TODO: Track thread handle for proper cleanup
            _ = try std.Thread.spawn(.{}, PeerHandler.runReceiveLoop, .{ handler, conn });

            return conn;
        }

        /// Disconnect a peer
        pub fn disconnect(self: *Manager, conn: *Connection) void {
            self.mutex.lock();
            defer self.mutex.unlock();

            // Find and remove connection
            var found = false;
            for (self.connections.items, 0..) |c, i| {
                if (c == conn) {
                    _ = self.connections.swapRemove(i);
                    self.stats.peers_connected -= 1;
                    found = true;
                    break;
                }
            }

            // Only deinit if we found and removed it
            if (found) {
                conn.deinit();
            }
        }

        /// Get active peer count
        pub fn activePeerCount(self: *Manager) u32 {
            self.mutex.lock();
            defer self.mutex.unlock();

            var count: u32 = 0;
            for (self.connections.items) |conn| {
                // Count established connections (not just alive ones)
                if (conn.state == .established) {
                    count += 1;
                }
            }
            return count;
        }

        /// Disconnect all peers
        pub fn disconnectAll(self: *Manager) void {
            self.mutex.lock();
            defer self.mutex.unlock();

            // Disconnect all connections
            for (self.connections.items) |conn| {
                conn.deinit();
            }
            self.connections.clearRetainingCapacity();

            self.stats.peers_connected = 0;
        }
        /// Get all connected peers
        pub fn getConnectedPeers(self: *Manager) []*Connection {
            self.mutex.lock();
            defer self.mutex.unlock();

            // Count established connections
            var count: usize = 0;
            for (self.connections.items) |conn| {
                if (conn.state == .established) {
                    count += 1;
                }
            }

            // Allocate result array
            const result = self.allocator.alloc(*Connection, count) catch return &[_]*Connection{};

            // Fill result array
            var i: usize = 0;
            for (self.connections.items) |conn| {
                if (conn.state == .established) {
                    result[i] = conn;
                    i += 1;
                }
            }

            return result;
        }

        /// Broadcast message to all peers
        pub fn broadcast(self: *Manager, msg: protocol.Protocol.Message) !void {
            self.mutex.lock();
            defer self.mutex.unlock();

            for (self.connections.items) |conn| {
                if (conn.state == .established) {
                    conn.sendMessage(msg) catch |err| {
                        std.log.err("Failed to send to peer {}: {}", .{ conn.address, err });
                    };
                }
            }
        }
    };
};

test "Peer connection lifecycle" {
    // This would require actual network setup, so we'll just test the structures
    const allocator = std.testing.allocator;

    var manager = Peer.Manager.init(allocator, .{
        .network_magic = .mainnet,
    });
    defer manager.deinit();

    try std.testing.expectEqual(@as(u32, 0), manager.activePeerCount());
}
