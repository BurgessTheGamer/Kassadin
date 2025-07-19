const std = @import("std");

/// Logging levels
pub const Level = enum(u8) {
    debug = 0,
    info = 1,
    warn = 2,
    err = 3,

    pub fn toString(self: Level) []const u8 {
        return switch (self) {
            .debug => "DEBUG",
            .info => "INFO",
            .warn => "WARN",
            .err => "ERROR",
        };
    }

    pub fn color(self: Level) []const u8 {
        return switch (self) {
            .debug => "\x1b[36m", // Cyan
            .info => "\x1b[32m", // Green
            .warn => "\x1b[33m", // Yellow
            .err => "\x1b[31m", // Red
        };
    }
};

/// Global logger configuration
pub const Config = struct {
    level: Level = .info,
    use_color: bool = true,
    include_timestamp: bool = true,
};

var config = Config{};
var mutex = std.Thread.Mutex{};

/// Set the global log level
pub fn setLevel(level: Level) void {
    mutex.lock();
    defer mutex.unlock();
    config.level = level;
}

/// Enable/disable color output
pub fn setColor(use_color: bool) void {
    mutex.lock();
    defer mutex.unlock();
    config.use_color = use_color;
}

/// Log a message at the specified level
pub fn log(
    comptime level: Level,
    comptime format: []const u8,
    args: anytype,
) void {
    mutex.lock();
    defer mutex.unlock();

    if (@intFromEnum(level) < @intFromEnum(config.level)) return;

    const stderr = std.io.getStdErr().writer();

    // Timestamp
    if (config.include_timestamp) {
        const timestamp = std.time.timestamp();
        const epoch_seconds = @as(u64, @intCast(timestamp));
        const hours = @mod(@divFloor(epoch_seconds, 3600), 24);
        const minutes = @mod(@divFloor(epoch_seconds, 60), 60);
        const seconds = @mod(epoch_seconds, 60);

        stderr.print("{d:0>2}:{d:0>2}:{d:0>2} ", .{ hours, minutes, seconds }) catch return;
    }

    // Level with color
    if (config.use_color) {
        stderr.print("{s}{s}\x1b[0m ", .{ level.color(), level.toString() }) catch return;
    } else {
        stderr.print("{s} ", .{level.toString()}) catch return;
    }

    // Message
    stderr.print(format ++ "\n", args) catch return;
}

/// Convenience functions
pub fn debug(comptime format: []const u8, args: anytype) void {
    log(.debug, format, args);
}

pub fn info(comptime format: []const u8, args: anytype) void {
    log(.info, format, args);
}

pub fn warn(comptime format: []const u8, args: anytype) void {
    log(.warn, format, args);
}

pub fn err(comptime format: []const u8, args: anytype) void {
    log(.err, format, args);
}

test "logger levels" {
    // Save original config
    const original_level = config.level;
    const original_color = config.use_color;
    defer {
        config.level = original_level;
        config.use_color = original_color;
    }

    setLevel(.warn);
    setColor(false);

    // These should not print in tests, but we're testing they compile
    debug("This is a debug message: {}", .{42});
    info("This is an info message: {s}", .{"test"});
    warn("This is a warning: {d}", .{100});
    err("This is an error: {x}", .{0xDEADBEEF});
}
