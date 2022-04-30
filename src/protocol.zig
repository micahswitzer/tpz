const std = @import("std");

pub const PROTOCOL = std.mem.bytesToValue(u64, "TELEPORT");
pub const IV_LEN = 12;

pub const Version = struct {
    major: u16,
    minor: u16,
    patch: u16,

    const SIZE: u32 = 3 * 2;

    fn write(self: *const @This(), writer: anytype) !void {
        try writer.writeIntLittle(u16, self.major);
        try writer.writeIntLittle(u16, self.minor);
        try writer.writeIntLittle(u16, self.patch);
    }

    fn read(reader: anytype) !@This() {
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

    fn write(self: *const @This(), writer: anytype) !void {
        try self.version.write(writer);
        try writer.writeIntLittle(u32, self.features);
        try writer.writeIntLittle(u32, self.permissions);
        try writer.writeIntLittle(u64, self.filesize);
        try writer.writeIntLittle(u16, @intCast(u16, self.filename.len));
        try writer.writeAll(self.filename);
    }

    fn read(alloc: std.mem.Allocator, reader: anytype, _: u32) !@This() {
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

    fn read(reader: anytype, available: u32) !@This() {
        const status = try std.meta.intToEnum(Status, try reader.readByte());
        const version = try Version.read(reader);
        if (!version.isSupported())
            return error.VersionUnsupported;
        const features = if (available > 1 + Version.SIZE) try reader.readIntLittle(u32) else null;
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

pub const ACTION = struct {
    pub const INIT: u8 = 0x01;
    pub const INIT_ACK: u8 = 0x02;
    pub const ECDH: u8 = 0x04;
    pub const ECDH_ACK: u8 = 0x08;
    pub const DATA: u8 = 0x40;
    pub const ENCRYPTED: u8 = 0x80;
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
        try writer.writeIntLittle(u64, PROTOCOL);
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
        if ((try reader.readIntLittle(u64)) != PROTOCOL)
            return error.BadProtocol;
        const data_length = try reader.readIntLittle(u32);
        const action_kind = try reader.readByte();
        if (action_kind & ACTION.ENCRYPTED == ACTION.ENCRYPTED)
            return error.EncryptionUnsupported;
        switch (action_kind) {
            ACTION.INIT_ACK => return Packet{ .init_ack = try InitAck.read(reader, data_length) },
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
