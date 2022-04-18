const std = @import("std");

pub const Header = struct {
    const PROTOCOL = std.mem.bytesToValue(u64, "TELEPORT");
    const IV_LEN = 12;

    action: u8,
    iv: ?[IV_LEN]u8 = null,
    data: []const u8 = &[0]u8{},

    pub fn write(self: *const @This(), writer: anytype) !void {
        try writer.writeIntLittle(u64, @This().PROTOCOL);
        try writer.writeIntLittle(u32, @intCast(u32, self.data.len));
        try writer.writeByte(self.action | if (self.iv) |_| ACTION.ENCRYPTED else 0);
        if (self.iv) |*iv|
            try writer.writeAll(iv);
        try writer.writeAll(self.data);
    }

    pub fn readAlloc(alloc: std.mem.Allocator, reader: anytype) !@This() {
        if ((try reader.readIntLittle(u64)) != @This().PROTOCOL)
            return error.BadProtocol;
        const dataLength = try reader.readIntLittle(u32);
        const action = try reader.readByte();
        const iv = blk: {
            if (action & ACTION.ENCRYPTED == ACTION.ENCRYPTED) {
                break :blk try reader.readBytesNoEof(@This().IV_LEN);
            } else {
                break :blk null;
            }
        };
        const data = try reader.readAllAlloc(alloc, dataLength);
        return @This(){
            .action = action,
            .iv = iv,
            .data = data,
        };
    }

    pub fn serializedSize(self: *const @This()) usize {
        return (8 + 4 + 1) + if (self.iv) |_| 12 else 0 + self.data.len;
    }
};

pub const ACTION = struct {
    const INIT: u8 = 0x01;
    const INIT_ACK: u8 = 0x02;
    const ECDH: u8 = 0x04;
    const ECDH_ACK: u8 = 0x08;
    const DATA: u8 = 0x40;
    const ENCRYPTED: u8 = 0x80;
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
    const packet = try Header.readAlloc(alloc, stream.reader());
    defer alloc.free(packet.data);
    try std.testing.expectEqual(packet.action, ACTION.INIT);
    try std.testing.expectEqual(packet.iv, null);
    try std.testing.expectEqual(packet.data.len, 0);
}
