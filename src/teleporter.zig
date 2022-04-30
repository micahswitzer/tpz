const std = @import("std");
const proto = @import("protocol.zig");

const LOCALHOST = std.net.Address.parseIp4("127.0.0.1", 9001) catch unreachable;

pub fn sendFile(name: []const u8, contents: []const u8) !void {
    // open socket
    const sock = try std.net.tcpConnectToAddress(LOCALHOST);
    defer sock.close();
    var writer_buf = std.io.bufferedWriter(sock.writer());
    var reader_buf = std.io.bufferedReader(sock.reader());
    const writer = writer_buf.writer();
    const reader = reader_buf.reader();
    // send init packet
    const initPacket = proto.initPacket(name, contents.len, .{});
    try initPacket.write(writer);
    try writer_buf.flush();
    // read response
    const initResp = try proto.Packet.read(reader);
    std.log.info("{?}", .{initResp});
    // check response
    switch (initResp) {
        .init_ack => |ack| if (ack.status != .proceed) return error.CantProceed,
        else => return error.UnexpectedResponse,
    }
    const dataPacket = proto.dataPacket(contents, 0);
    std.log.debug("Sending: {?}", .{dataPacket});
    try dataPacket.write(writer);
    if (contents.len > 0) {
        const finishPacket = proto.dataPacket(&[0]u8{}, 0);
        try finishPacket.write(writer);
    }
    try writer_buf.flush();
    std.log.info("File sent", .{});
}

pub fn main() !void {
    try sendFile("test.txt", "Hello world!\n");
}
