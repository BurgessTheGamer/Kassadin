const std = @import("std");

/// CBOR (Concise Binary Object Representation) encoder/decoder
/// Implements RFC 7049 for Cardano protocol compatibility
pub const CBOR = struct {
    /// Major types in CBOR
    pub const MajorType = enum(u3) {
        unsigned_int = 0,
        negative_int = 1,
        byte_string = 2,
        text_string = 3,
        array = 4,
        map = 5,
        tag = 6,
        simple_float = 7,
    };

    /// CBOR simple values
    pub const SimpleValue = enum(u8) {
        false_val = 20,
        true_val = 21,
        null_val = 22,
        undefined = 23,
    };

    /// CBOR encoder
    pub const Encoder = struct {
        writer: std.ArrayList(u8),
        allocator: std.mem.Allocator,

        pub fn init(allocator: std.mem.Allocator) Encoder {
            return .{
                .writer = std.ArrayList(u8).init(allocator),
                .allocator = allocator,
            };
        }

        pub fn deinit(self: *Encoder) void {
            self.writer.deinit();
        }

        pub fn toBytes(self: *Encoder) []u8 {
            return self.writer.items;
        }

        /// Encode unsigned integer
        pub fn encodeUint(self: *Encoder, value: u64) !void {
            try self.encodeTypeAndValue(.unsigned_int, value);
        }

        /// Encode negative integer
        pub fn encodeNegativeInt(self: *Encoder, value: i64) !void {
            if (value >= 0) return error.InvalidNegativeInt;
            const abs_minus_one = @as(u64, @intCast(-(value + 1)));
            try self.encodeTypeAndValue(.negative_int, abs_minus_one);
        }

        /// Encode byte string
        pub fn encodeBytes(self: *Encoder, bytes: []const u8) !void {
            try self.encodeTypeAndValue(.byte_string, bytes.len);
            try self.writer.appendSlice(bytes);
        }

        /// Encode text string
        pub fn encodeText(self: *Encoder, text: []const u8) !void {
            try self.encodeTypeAndValue(.text_string, text.len);
            try self.writer.appendSlice(text);
        }

        /// Encode array header
        pub fn encodeArrayHeader(self: *Encoder, len: u64) !void {
            try self.encodeTypeAndValue(.array, len);
        }

        /// Encode map header
        pub fn encodeMapHeader(self: *Encoder, len: u64) !void {
            try self.encodeTypeAndValue(.map, len);
        }

        /// Encode tag
        pub fn encodeTag(self: *Encoder, tag: u64) !void {
            try self.encodeTypeAndValue(.tag, tag);
        }

        /// Encode boolean
        pub fn encodeBool(self: *Encoder, value: bool) !void {
            const simple_val: u8 = if (value) @intFromEnum(SimpleValue.true_val) else @intFromEnum(SimpleValue.false_val);
            try self.writer.append(@as(u8, @intFromEnum(MajorType.simple_float)) << 5 | simple_val);
        }

        /// Encode null
        pub fn encodeNull(self: *Encoder) !void {
            try self.writer.append(@as(u8, @intFromEnum(MajorType.simple_float)) << 5 | @intFromEnum(SimpleValue.null_val));
        }

        /// Encode type and value
        fn encodeTypeAndValue(self: *Encoder, major_type: MajorType, value: u64) !void {
            const type_bits = @as(u8, @intFromEnum(major_type)) << 5;

            if (value < 24) {
                try self.writer.append(type_bits | @as(u8, @intCast(value)));
            } else if (value <= 0xFF) {
                try self.writer.append(type_bits | 24);
                try self.writer.append(@as(u8, @intCast(value)));
            } else if (value <= 0xFFFF) {
                try self.writer.append(type_bits | 25);
                const v = @as(u16, @intCast(value));
                try self.writer.append(@intCast(v >> 8));
                try self.writer.append(@intCast(v & 0xFF));
            } else if (value <= 0xFFFFFFFF) {
                try self.writer.append(type_bits | 26);
                const v = @as(u32, @intCast(value));
                try self.writer.append(@intCast(v >> 24));
                try self.writer.append(@intCast((v >> 16) & 0xFF));
                try self.writer.append(@intCast((v >> 8) & 0xFF));
                try self.writer.append(@intCast(v & 0xFF));
            } else {
                try self.writer.append(type_bits | 27);
                try self.writer.append(@intCast(value >> 56));
                try self.writer.append(@intCast((value >> 48) & 0xFF));
                try self.writer.append(@intCast((value >> 40) & 0xFF));
                try self.writer.append(@intCast((value >> 32) & 0xFF));
                try self.writer.append(@intCast((value >> 24) & 0xFF));
                try self.writer.append(@intCast((value >> 16) & 0xFF));
                try self.writer.append(@intCast((value >> 8) & 0xFF));
                try self.writer.append(@intCast(value & 0xFF));
            }
        }
    };

    /// CBOR decoder
    pub const Decoder = struct {
        reader: []const u8,
        pos: usize,

        pub fn init(data: []const u8) Decoder {
            return .{
                .reader = data,
                .pos = 0,
            };
        }

        pub fn peekByte(self: *Decoder) !u8 {
            if (self.pos >= self.reader.len) return error.EndOfStream;
            return self.reader[self.pos];
        }

        pub fn readByte(self: *Decoder) !u8 {
            const byte = try self.peekByte();
            self.pos += 1;
            return byte;
        }

        pub fn readBytes(self: *Decoder, len: usize) ![]const u8 {
            if (self.pos + len > self.reader.len) return error.EndOfStream;
            const bytes = self.reader[self.pos .. self.pos + len];
            self.pos += len;
            return bytes;
        }

        /// Peek at the next major type without consuming it
        pub fn peekType(self: *Decoder) !MajorType {
            if (self.pos >= self.reader.len) return error.EndOfData;
            const byte = self.reader[self.pos];
            const major_type: MajorType = @enumFromInt(byte >> 5);
            return major_type;
        }

        /// Decode major type and additional info
        pub fn decodeMajorType(self: *Decoder) !struct { major_type: MajorType, additional_info: u5 } {
            const byte = try self.readByte();
            return .{
                .major_type = @enumFromInt(byte >> 5),
                .additional_info = @intCast(byte & 0x1F),
            };
        }

        /// Decode unsigned integer
        pub fn decodeUint(self: *Decoder) !u64 {
            const header = try self.decodeMajorType();
            if (header.major_type != .unsigned_int) return error.UnexpectedType;
            return try self.decodeValue(header.additional_info);
        }

        /// Decode byte string
        pub fn decodeBytes(self: *Decoder) ![]const u8 {
            const header = try self.decodeMajorType();
            if (header.major_type != .byte_string) return error.UnexpectedType;
            const len = try self.decodeValue(header.additional_info);
            return try self.readBytes(@intCast(len));
        }

        /// Decode text string
        pub fn decodeText(self: *Decoder) ![]const u8 {
            const header = try self.decodeMajorType();
            if (header.major_type != .text_string) return error.UnexpectedType;
            const len = try self.decodeValue(header.additional_info);
            return try self.readBytes(@intCast(len));
        }

        /// Decode array header
        pub fn decodeArrayHeader(self: *Decoder) !u64 {
            const header = try self.decodeMajorType();
            if (header.major_type != .array) return error.UnexpectedType;
            return try self.decodeValue(header.additional_info);
        }

        /// Decode map header
        pub fn decodeMapHeader(self: *Decoder) !u64 {
            const header = try self.decodeMajorType();
            if (header.major_type != .map) return error.UnexpectedType;
            return try self.decodeValue(header.additional_info);
        }

        /// Decode boolean
        pub fn decodeBool(self: *Decoder) !bool {
            const header = try self.decodeMajorType();
            if (header.major_type != .simple_float) return error.UnexpectedType;

            const value = try self.decodeValue(header.additional_info);
            return switch (value) {
                20 => false,
                21 => true,
                else => error.InvalidBool,
            };
        }

        pub fn decodeTag(self: *Decoder) !u64 {
            const header = try self.decodeMajorType();
            if (header.major_type != .tag) return error.UnexpectedType;
            return try self.decodeValue(header.additional_info);
        }

        /// Decode value based on additional info
        fn decodeValue(self: *Decoder, additional_info: u5) !u64 {
            return switch (additional_info) {
                0...23 => additional_info,
                24 => try self.readByte(),
                25 => blk: {
                    const bytes = try self.readBytes(2);
                    break :blk std.mem.readInt(u16, bytes[0..2], .big);
                },
                26 => blk: {
                    const bytes = try self.readBytes(4);
                    break :blk std.mem.readInt(u32, bytes[0..4], .big);
                },
                27 => blk: {
                    const bytes = try self.readBytes(8);
                    break :blk std.mem.readInt(u64, bytes[0..8], .big);
                },
                else => error.InvalidAdditionalInfo,
            };
        }
    };
};

// Tests
test "CBOR encode/decode unsigned integers" {
    const allocator = std.testing.allocator;

    var encoder = CBOR.Encoder.init(allocator);
    defer encoder.deinit();

    // Test various integer sizes
    try encoder.encodeUint(0);
    try encoder.encodeUint(23);
    try encoder.encodeUint(24);
    try encoder.encodeUint(255);
    try encoder.encodeUint(256);
    try encoder.encodeUint(65535);
    try encoder.encodeUint(65536);

    const bytes = encoder.toBytes();
    var decoder = CBOR.Decoder.init(bytes);

    try std.testing.expectEqual(@as(u64, 0), try decoder.decodeUint());
    try std.testing.expectEqual(@as(u64, 23), try decoder.decodeUint());
    try std.testing.expectEqual(@as(u64, 24), try decoder.decodeUint());
    try std.testing.expectEqual(@as(u64, 255), try decoder.decodeUint());
    try std.testing.expectEqual(@as(u64, 256), try decoder.decodeUint());
    try std.testing.expectEqual(@as(u64, 65535), try decoder.decodeUint());
    try std.testing.expectEqual(@as(u64, 65536), try decoder.decodeUint());
}

test "CBOR encode/decode byte strings" {
    const allocator = std.testing.allocator;

    var encoder = CBOR.Encoder.init(allocator);
    defer encoder.deinit();

    try encoder.encodeBytes("hello");
    try encoder.encodeBytes("");
    try encoder.encodeBytes(&[_]u8{ 0xFF, 0x00, 0xAB });

    const bytes = encoder.toBytes();
    var decoder = CBOR.Decoder.init(bytes);

    const hello = try decoder.decodeBytes();
    try std.testing.expectEqualStrings("hello", hello);

    const empty = try decoder.decodeBytes();
    try std.testing.expectEqual(@as(usize, 0), empty.len);

    const binary = try decoder.decodeBytes();
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xFF, 0x00, 0xAB }, binary);
}

test "CBOR encode/decode arrays" {
    const allocator = std.testing.allocator;

    var encoder = CBOR.Encoder.init(allocator);
    defer encoder.deinit();

    // Encode array [1, 2, 3]
    try encoder.encodeArrayHeader(3);
    try encoder.encodeUint(1);
    try encoder.encodeUint(2);
    try encoder.encodeUint(3);

    const bytes = encoder.toBytes();
    var decoder = CBOR.Decoder.init(bytes);

    const len = try decoder.decodeArrayHeader();
    try std.testing.expectEqual(@as(u64, 3), len);

    try std.testing.expectEqual(@as(u64, 1), try decoder.decodeUint());
    try std.testing.expectEqual(@as(u64, 2), try decoder.decodeUint());
    try std.testing.expectEqual(@as(u64, 3), try decoder.decodeUint());
}

test "CBOR encode/decode maps" {
    const allocator = std.testing.allocator;

    var encoder = CBOR.Encoder.init(allocator);
    defer encoder.deinit();

    // Encode map {"a": 1, "b": 2}
    try encoder.encodeMapHeader(2);
    try encoder.encodeText("a");
    try encoder.encodeUint(1);
    try encoder.encodeText("b");
    try encoder.encodeUint(2);

    const bytes = encoder.toBytes();
    var decoder = CBOR.Decoder.init(bytes);

    const len = try decoder.decodeMapHeader();
    try std.testing.expectEqual(@as(u64, 2), len);

    const key1 = try decoder.decodeText();
    try std.testing.expectEqualStrings("a", key1);
    try std.testing.expectEqual(@as(u64, 1), try decoder.decodeUint());

    const key2 = try decoder.decodeText();
    try std.testing.expectEqualStrings("b", key2);
    try std.testing.expectEqual(@as(u64, 2), try decoder.decodeUint());
}
