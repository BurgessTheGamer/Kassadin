const std = @import("std");
const storage = @import("storage.zig");

/// File-based key-value store implementation
pub const FileStore = struct {
    allocator: std.mem.Allocator,
    data_dir: []const u8,
    cache: std.StringHashMap([]u8),
    mutex: std.Thread.Mutex,
    
    pub fn init(allocator: std.mem.Allocator, data_dir: []const u8) !*FileStore {
        // Create data directory if it doesn't exist
        std.fs.cwd().makePath(data_dir) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };
        
        const store = try allocator.create(FileStore);
        store.* = .{
            .allocator = allocator,
            .data_dir = try allocator.dupe(u8, data_dir),
            .cache = std.StringHashMap([]u8).init(allocator),
            .mutex = .{},
        };
        
        return store;
    }
    
    pub fn deinit(self: *FileStore) void {
        // Clean up cache
        var iter = self.cache.iterator();
        while (iter.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.cache.deinit();
        
        self.allocator.free(self.data_dir);
        self.allocator.destroy(self);
    }
    
    /// Convert to Store interface
    pub fn toStore(self: *FileStore) storage.Storage.Store {
        return .{
            .getFn = get,
            .putFn = put,
            .deleteFn = delete,
            .hasFn = has,
            .closeFn = close,
            .impl = self,
        };
    }
    
    fn get(store: *storage.Storage.Store, key: []const u8, allocator: std.mem.Allocator) !?[]u8 {
        const self = @as(*FileStore, @ptrCast(@alignCast(store.impl)));
        
        self.mutex.lock();
        defer self.mutex.unlock();
        
        // Check cache first
        if (self.cache.get(key)) |value| {
            return try allocator.dupe(u8, value);
        }
        
        // Read from file
        const file_path = try self.keyToPath(key);
        defer self.allocator.free(file_path);
        
        const file = std.fs.cwd().openFile(file_path, .{}) catch |err| switch (err) {
            error.FileNotFound => return null,
            else => return err,
        };
        defer file.close();
        
        const stat = try file.stat();
        const data = try allocator.alloc(u8, stat.size);
        _ = try file.read(data);
        
        // Update cache
        const cache_key = try self.allocator.dupe(u8, key);
        const cache_value = try self.allocator.dupe(u8, data);
        try self.cache.put(cache_key, cache_value);
        
        return data;
    }
    
    fn put(store: *storage.Storage.Store, key: []const u8, value: []const u8) !void {
        const self = @as(*FileStore, @ptrCast(@alignCast(store.impl)));
        
        self.mutex.lock();
        defer self.mutex.unlock();
        
        // Write to file
        const file_path = try self.keyToPath(key);
        defer self.allocator.free(file_path);
        
        // Ensure directory exists
        if (std.fs.path.dirname(file_path)) |dir| {
            std.fs.cwd().makePath(dir) catch |err| switch (err) {
                error.PathAlreadyExists => {},
                else => return err,
            };
        }
        
        const file = try std.fs.cwd().createFile(file_path, .{});
        defer file.close();
        
        try file.writeAll(value);
        
        // Update cache
        const cache_key = try self.allocator.dupe(u8, key);
        const cache_value = try self.allocator.dupe(u8, value);
        
        // Remove old cache entry if exists
        if (self.cache.fetchRemove(cache_key)) |old| {
            self.allocator.free(old.key);
            self.allocator.free(old.value);
        }
        
        try self.cache.put(cache_key, cache_value);
    }
    
    fn delete(store: *storage.Storage.Store, key: []const u8) !void {
        const self = @as(*FileStore, @ptrCast(@alignCast(store.impl)));
        
        self.mutex.lock();
        defer self.mutex.unlock();
        
        // Delete file
        const file_path = try self.keyToPath(key);
        defer self.allocator.free(file_path);
        
        std.fs.cwd().deleteFile(file_path) catch |err| switch (err) {
            error.FileNotFound => {},
            else => return err,
        };
        
        // Remove from cache
        if (self.cache.fetchRemove(key)) |entry| {
            self.allocator.free(entry.key);
            self.allocator.free(entry.value);
        }
    }
    
    fn has(store: *storage.Storage.Store, key: []const u8) !bool {
        const self = @as(*FileStore, @ptrCast(@alignCast(store.impl)));
        
        self.mutex.lock();
        defer self.mutex.unlock();
        
        // Check cache first
        if (self.cache.contains(key)) {
            return true;
        }
        
        // Check file existence
        const file_path = try self.keyToPath(key);
        defer self.allocator.free(file_path);
        
        const file = std.fs.cwd().openFile(file_path, .{}) catch |err| switch (err) {
            error.FileNotFound => return false,
            else => return err,
        };
        file.close();
        
        return true;
    }
    
    fn close(store: *storage.Storage.Store) void {
        const self = @as(*FileStore, @ptrCast(@alignCast(store.impl)));
        self.deinit();
    }
    
    /// Convert key to file path
    fn keyToPath(self: *FileStore, key: []const u8) ![]u8 {
        // Replace colons with slashes for directory structure
        var path = std.ArrayList(u8).init(self.allocator);
        defer path.deinit();
        
        try path.appendSlice(self.data_dir);
        try path.append('/');
        
        for (key) |c| {
            if (c == ':') {
                try path.append('/');
            } else {
                try path.append(c);
            }
        }
        
        try path.appendSlice(".dat");
        
        return path.toOwnedSlice();
    }
};

test "FileStore basic operations" {
    const allocator = std.testing.allocator;
    
    // Create temporary directory
    const temp_dir = "test_file_store";
    defer std.fs.cwd().deleteTree(temp_dir) catch {};
    
    // Create store
    const file_store = try FileStore.init(allocator, temp_dir);
    var store = file_store.toStore();
    defer store.close();
    
    // Test put and get
    const key = "test:key";
    const value = "test value";
    
    try store.put(key, value);
    
    const retrieved = try store.get(key, allocator);
    defer if (retrieved) |v| allocator.free(v);
    
    try std.testing.expect(retrieved != null);
    try std.testing.expectEqualStrings(value, retrieved.?);
    
    // Test has
    try std.testing.expect(try store.has(key));
    try std.testing.expect(!try store.has("nonexistent"));
    
    // Test delete
    try store.delete(key);
    try std.testing.expect(!try store.has(key));
}