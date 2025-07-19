const std = @import("std");
const handshake = @import("network/handshake.zig");
const cbor = @import("utils/cbor.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Create handshake for testnet
    var hs = handshake.Handshake.init(allocator, 1097911063); // testnet magic

    // Create propose versions message
    const propose_msg = try hs.createProposeVersions();
    defer allocator.free(propose_msg);

    std.log.info("Handshake propose versions message:", .{});
    std.log.info("  Length: {} bytes", .{propose_msg.len});
    std.log.info("  Hex: {x}", .{std.fmt.fmtSliceHexLower(propose_msg)});

    // Decode it to verify structure
    var decoder = cbor.CBOR.Decoder.init(propose_msg);

    const array_len = try decoder.decodeArrayHeader();
    std.log.info("  Array length: {}", .{array_len});

    const msg_type = try decoder.decodeUint();
    std.log.info("  Message type: {}", .{msg_type});

    const map_len = try decoder.decodeMapHeader();
    std.log.info("  Version map length: {}", .{map_len});

    var i: usize = 0;
    while (i < map_len) : (i += 1) {
        const version = try decoder.decodeUint();
        std.log.info("    Version: {}", .{version});

        const params_len = try decoder.decodeArrayHeader();
        std.log.info("    Params array length: {}", .{params_len});

        const magic = try decoder.decodeUint();
        std.log.info("      Network magic: {} (0x{x})", .{ magic, magic });

        const initiator_only = try decoder.decodeBool();
        std.log.info("      Initiator only: {}", .{initiator_only});
    }
}
