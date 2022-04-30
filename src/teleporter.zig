const std = @import("std");
const proto = @import("protocol.zig");

const LOCALHOST = std.net.Address.parseIp4("127.0.0.1", 9001) catch unreachable;

fn TeleporterClient(comptime buffer_size: usize, comptime StreamType: type) type {
    const ReadBuffer = std.io.BufferedReader(buffer_size, StreamType.Reader);
    const WriteBuffer = std.io.BufferedWriter(buffer_size, StreamType.Writer);
    return struct {
        stream: StreamType,
        buffered_reader: ReadBuffer,
        buffered_writer: WriteBuffer,

        pub fn flush(self: *@This()) !void {
            return self.buffered_writer.flush();
        }

        pub fn reader(self: *@This()) ReadBuffer.Reader {
            return self.buffered_reader.reader();
        }

        pub fn writer(self: *@This()) WriteBuffer.Writer {
            return self.buffered_writer.writer();
        }

        pub fn close(self: *@This()) void {
            // returns void because:
            // * resource deallocation must succeed.
            _ = self.flush() catch void;
            self.stream.close();
        }
    };
}

const BUFFER_SIZE = 256;

fn genericClient(stream: anytype) TeleporterClient(BUFFER_SIZE, @TypeOf(stream)) {
    return .{
        .stream = stream,
        .buffered_writer = .{ .unbuffered_writer = stream.writer() },
        .buffered_reader = .{ .unbuffered_reader = stream.reader() },
    };
}

fn connectedClient(address: std.net.Address) !TeleporterClient(BUFFER_SIZE, std.net.Stream) {
    const stream = try std.net.tcpConnectToAddress(address);
    return genericClient(stream);
}

pub const FileInfo = struct {
    name: []const u8,
    permissions: u32 = 0o644,
    dest: std.net.Address,
};

pub fn sendData(file_info: FileInfo, contents: []const u8) !void {
    // open socket
    var client = try connectedClient(file_info.dest);
    defer client.close();
    const writer = client.writer();
    const reader = client.reader();
    // send init packet
    const initPacket = proto.initPacket(
        file_info.name,
        contents.len,
        .{ .permissions = file_info.permissions },
    );
    try initPacket.write(writer);
    try client.flush();
    // read response
    const initResp = try proto.Packet.read(reader);
    std.log.info("{?}", .{initResp});
    // check response
    switch (initResp) {
        .init_ack => |ack| if (ack.status != .proceed) return error.CantProceed,
        else => return error.UnexpectedResponse,
    }
    const dataPacket = proto.dataPacket(contents, 0);
    try dataPacket.write(writer);
    if (contents.len > 0) {
        const finishPacket = proto.dataPacket(&[0]u8{}, 0);
        try finishPacket.write(writer);
    }
    try client.flush();
}

pub fn main() !void {
    try sendData(.{ .name = "test.txt", .dest = LOCALHOST }, "Hello world!\n");
}
