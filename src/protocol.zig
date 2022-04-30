const std = @import("std");

pub const Header = struct {
    pub const PROTOCOL = std.mem.bytesToValue(u64, "TELEPORT");
    pub const BASE_LEN = 8 + 4 + 1;
    pub const IV_LEN = 12;

    action: u8,
    iv: ?[IV_LEN]u8 = null,
    data: ?[]const u8 = null,

    pub fn dataLen(self: *const @This()) u32 {
        return if (self.data) |data| @intCast(u32, data.len) else 0;
    }

    pub fn write(self: *const @This(), writer: anytype) !void {
        try writer.writeIntLittle(u64, PROTOCOL);
        try writer.writeIntLittle(u32, self.dataLen());
        try writer.writeByte(self.action | if (self.iv) |_| ACTION.ENCRYPTED else 0);
        if (self.iv) |*iv|
            try writer.writeAll(iv);
        if (self.data) |data|
            try writer.writeAll(data);
    }

    const Ret = std.meta.Tuple(&.{ @This(), u32 });
    fn readRaw(reader: anytype) !Ret {
        if ((try reader.readIntLittle(u64)) != PROTOCOL)
            return error.BadProtocol;
        const dataLength = try reader.readIntLittle(u32);
        const action = try reader.readByte();
        const iv = if (action & ACTION.ENCRYPTED == ACTION.ENCRYPTED)
            try reader.readBytesNoEof(IV_LEN)
        else
            null;
        const res = @This(){
            .action = action,
            .iv = iv,
            .data = null,
        };
        return Ret{ res, dataLength };
    }

    pub fn readEmpty(reader: anytype) !@This() {
        const raw = try readRaw(reader);
        if (raw.@"1" != 0)
            return error.NotEmpty;
        return raw.@"0";
    }

    pub fn readAlloc(alloc: std.mem.Allocator, reader: anytype) !@This() {
        var raw = try readRaw(reader);
        const new: *@This() = &raw.@"0";
        if (raw.@"1" > 0) {
            var buf = try alloc.alloc(u8, raw.@"1");
            try reader.readNoEof(buf);
            new.data = buf;
        }
        return new.*;
    }

    pub fn serializedSize(self: *const @This()) usize {
        return BASE_LEN + if (self.iv) |_| IV_LEN else 0 + self.dataLen();
    }

    pub fn deinit(self: *@This(), alloc: std.mem.Allocator) void {
        if (self.data) |data|
            alloc.free(data);
        self.* = undefined;
    }
};

pub const Version = struct {
    major: u16,
    minor: u16,
    patch: u16,

    const SIZE: u32 = 3 * 2;

    pub fn write(self: *const @This(), writer: anytype) !void {
        try writer.writeIntLittle(u16, self.major);
        try writer.writeIntLittle(u16, self.minor);
        try writer.writeIntLittle(u16, self.patch);
    }

    pub fn read(reader: anytype) !@This() {
        return @This(){
            .major = try reader.readIntLittle(u16),
            .minor = try reader.readIntLittle(u16),
            .patch = try reader.readIntLittle(u16),
        };
    }

    pub fn isSupported(self: *const @This()) bool {
        return self.major == DEFAULT_VERSION.major and self.minor == DEFAULT_VERSION.minor;
    }
};

pub const DEFAULT_VERSION = Version{ .major = 0, .minor = 9, .patch = 5 };

pub const Init = struct {
    pub const FEATURE = struct {
        pub const NEW_FILE = 0x01;
        pub const DELTA = 0x02;
        pub const OVERWRITE = 0x04;
        pub const BACKUP = 0x08;
        pub const RENAME = 0x10;
    };

    version: Version = DEFAULT_VERSION,
    features: u32,
    permissions: u32,
    filesize: u64,
    filename: []const u8,

    pub fn write(self: *const @This(), writer: anytype) !void {
        try self.version.write(writer);
        try writer.writeIntLittle(u32, self.features);
        try writer.writeIntLittle(u32, self.permissions);
        try writer.writeIntLittle(u64, self.filesize);
        try writer.writeIntLittle(u16, @intCast(u16, self.filename.len));
        try writer.writeAll(self.filename);
    }

    pub fn read(alloc: std.mem.Allocator, reader: anytype) !@This() {
        var res = @This(){
            .version = try Version.read(reader),
            .features = try reader.readIntLittle(u32),
            .permissions = try reader.readIntLittle(u32),
            .filesize = try reader.readIntLittle(u64),
            .filename = undefined,
        };
        res.filename = try reader.readAllAlloc(alloc, res.filesize);
        return res;
    }

    pub fn size(self: *const @This()) u32 {
        return Version.SIZE + 4 + 4 + 8 + 2 + @intCast(u16, self.filename.len);
    }
};

pub fn newFile(name: []const u8, size: u64, permissions: u32) Init {
    return Init{
        .filename = name,
        .filesize = size,
        .permissions = permissions,
    };
}

pub const Delta = struct {
    filesize: u64,
    hash: u64,
    chunk_size: u32,
    chunk_hash: []const u64,
};

pub const InitAck = struct {
    pub const Status = enum {
        proceed,
        no_overwrite,
        no_space,
        no_permission,
        wrong_version,
        encryption_error,
        unknown_action,
    };

    status: Status,
    version: Version,
    features: ?u32,
    delta: ?Delta = null,

    pub fn size(self: *const @This()) u32 {
        return 1 + Version.SIZE + if (self.features) |_| @as(u32, 4) else 0;
    }

    fn read(reader: anytype) !@This() {
        const status = try std.meta.intToEnum(Status, try reader.readByte());
        const version = try Version.read(reader);
        if (!version.isSupported())
            return error.VersionUnsupported;
        const features = try reader.readIntLittle(u32);
        return @This(){
            .status = status,
            .version = version,
            .features = features,
        };
    }
};

pub const Data = struct {
    offset: u64,
    data: []const u8,

    fn size(self: *const @This()) u32 {
        return 8 + 4 + @intCast(u32, self.data.len);
    }

    fn write(self: *const @This(), writer: anytype) !void {
        try writer.writeIntLittle(u64, self.offset);
        try writer.writeIntLittle(u32, @intCast(u32, self.data.len));
        try writer.writeAll(self.data);
    }
};

pub const Packet = union(enum) {
    init: Init,
    init_ack: InitAck,
    data: Data,
    delta,
    ecdh,
    ecdh_ack,

    const Self = @This();

    pub fn action(self: Self, is_encrypted: bool) u8 {
        return switch (self) {
            .init => ACTION.INIT,
            .init_ack => ACTION.INIT_ACK,
            .data => ACTION.DATA,
            .delta => ACTION.DATA,
            .ecdh => ACTION.ECDH,
            .ecdh_ack => ACTION.ECDH_ACK,
        } | if (is_encrypted) ACTION.ENCRYPTED else 0;
    }

    pub fn write(self: Self, writer: anytype) !void {
        const payload_size = switch (self) {
            Self.init => |init| init.size(),
            Self.init_ack => |init_ack| init_ack.size(),
            Self.data => |data| data.size(),
            else => 0,
        };
        try writer.writeIntLittle(u64, Header.PROTOCOL);
        try writer.writeIntLittle(u32, payload_size);
        try writer.writeByte(self.action(false));
        switch (self) {
            Self.init => |init| try init.write(writer),
            //Self.init_ack => |init_ack| try init_ack.write(writer),
            Self.data => |data| try data.write(writer),
            else => return error.UnsupportedAction,
        }
    }

    pub fn read(reader: anytype) !Packet {
        if ((try reader.readIntLittle(u64)) != Header.PROTOCOL)
            return error.BadProtocol;
        const dataLength = try reader.readIntLittle(u32);
        _ = dataLength; // who needs this value?
        const actionKind = try reader.readByte();
        if (actionKind & ACTION.ENCRYPTED == ACTION.ENCRYPTED)
            return error.EncryptionUnsupported;
        switch (actionKind) {
            ACTION.INIT_ACK => return Packet{ .init_ack = try InitAck.read(reader) },
            //ACTION.DATA => return Packet{ .data = try Data.read(reader) },
            else => return error.UnknownAction,
        }

        unreachable;
    }
};

pub const FileOptions = struct {
    features: u32 = Init.FEATURE.NEW_FILE,
    permissions: u32 = 0o644,
};

pub fn initPacket(filename: []const u8, filesize: u64, options: FileOptions) Packet {
    return Packet{
        .init = Init{
            .filename = filename,
            .filesize = filesize,
            .features = options.features,
            .permissions = options.permissions,
        },
    };
}

pub fn dataPacket(data: []const u8, offset: u64) Packet {
    return Packet{
        .data = Data{
            .data = data,
            .offset = offset,
        },
    };
}

pub const ACTION = struct {
    pub const INIT: u8 = 0x01;
    pub const INIT_ACK: u8 = 0x02;
    pub const ECDH: u8 = 0x04;
    pub const ECDH_ACK: u8 = 0x08;
    pub const DATA: u8 = 0x40;
    pub const ENCRYPTED: u8 = 0x80;
};

// comptime known init packet
pub const INIT_PACKET = blk: {
    const hdr = Header{ .action = ACTION.INIT };
    var buffer: [hdr.serializedSize()]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buffer);
    hdr.write(stream.writer()) catch unreachable;
    break :blk stream.getWritten();
};

test "new header" {
    const data: []const u8 = ""; // "this is some data to send";
    const hdr = Header{ .action = ACTION.INIT, .data = data };
    var buffer: [100]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buffer);
    try hdr.write(stream.writer());
    // compare comptime and runtime values
    try std.testing.expectEqualSlices(u8, INIT_PACKET, stream.getWritten());
}

test "parse packet" {
    const alloc = std.testing.allocator;
    var stream = std.io.fixedBufferStream(INIT_PACKET);
    var packet = try Header.readAlloc(alloc, stream.reader());
    defer packet.deinit(alloc);
    try std.testing.expectEqual(packet.action, ACTION.INIT);
    try std.testing.expectEqual(packet.iv, null);
    try std.testing.expectEqual(packet.data, null);
}
