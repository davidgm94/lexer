const std = @import("std");
const assert = std.debug.assert;
const Instant = std.time.Instant;
const print = std.debug.print;

const simd = false;

pub fn main() !void {
    const arguments = try std.process.argsAlloc(std.heap.c_allocator);
    if (arguments.len != 2) return error.InvalidInput;
    assert(arguments[1][0] == '0');
    assert(arguments[1][1] == 'x');
    const buffer_len = try std.fmt.parseInt(u64, arguments[1][2..], 16);
    print("Byte count: 0x{x}\n", .{buffer_len});
    const buffer = try generateRandomData(buffer_len);
    if (buffer.len < buffer_len) {
        return error.InputTooLarge;
    }
    assert(buffer.len == buffer_len);
    var token_list = try TokenList.initCapacity(std.heap.page_allocator, buffer.len);

    const time_result = switch (simd) {
        true => lexSimd(buffer, &token_list),
        false => lexScalar(buffer, &token_list),
    };
    switch (Timer.type) {
        .system_precision => {
            const mb_s = @as(f64, @floatFromInt(buffer.len * 1000)) / @as(f64, @floatFromInt(time_result));
            print("Time: {} ns ({d} MB/s)\n", .{ time_result, mb_s });
        },
        .tsc => print("TSC cycles: {}\n", .{time_result}),
    }
}

fn lexScalar(bytes: Slice, list: *TokenList) u64 {
    _ = list;
    const timer = Timer.start();

    var i: usize = 0;
    while (i < bytes.len) : (i += 1) {
        if (bytes[i] == 0) break;
    }
    // while (i < bytes.len) {
    //     const start_character = bytes[i];
    //     switch (start_character) {
    //         space_characters[0],
    //         space_characters[1],
    //         space_characters[2],
    //         space_characters[3],
    //         => i += 1,
    //         alphabet_ranges[0].start...alphabet_ranges[0].end,
    //         alphabet_ranges[1].start...alphabet_ranges[1].end,
    //         => i += 1,
    //         number_range.start...number_range.end => i += 1,
    //         operator_ranges[0].start...operator_ranges[0].end,
    //         operator_ranges[1].start...operator_ranges[1].end,
    //         operator_ranges[2].start...operator_ranges[2].end,
    //         operator_ranges[3].start...operator_ranges[3].end,
    //         => i += 1,
    //         else => |ch| reportError(i, ch),
    //     }
    // }

    return timer.end();
}

fn lexSimd(bytes: Slice, list: *TokenList) u64 {
    _ = list;
    _ = bytes;

    const timer = Timer.start();
    return timer.end();
}

fn reportError(index: usize, character: u8) noreturn {
    @setCold(true);
    std.debug.panic("Unexpected character at {}: {c} (0x{x})", .{ index, character, character });
}

const Timer = struct {
    start: switch (Timer.type) {
        .system_precision => Instant,
        .tsc => u64,
    },

    const @"type" = Type.system_precision;

    const Type = enum {
        system_precision,
        tsc,
    };

    inline fn start() Timer {
        return Timer{
            .start = switch (Timer.type) {
                .system_precision => Instant.now() catch unreachable,
                .tsc => tscInstant(),
            },
        };
    }

    inline fn end(timer: Timer) u64 {
        return switch (Timer.type) {
            .system_precision => Instant.since(Instant.now() catch unreachable, timer.start),
            .tsc => tscInstant() - timer.start,
        };
    }
};

const Token = packed struct(u64) {
    start: u32,
    len: u24,
    id: Id,
    const Id = enum(u8) {};
};

const TokenList = std.ArrayListAligned(Token, 0x1000);

pub const FixedKeyword = enum {
    @"comptime",
    @"const",
    @"var",
    void,
    noreturn,
    function,
    @"while",
    bool,
    true,
    false,
    @"fn",
    @"unreachable",
    @"return",
    ssize,
    usize,
    @"switch",
    @"if",
    @"else",
    @"struct",
    @"enum",
    @"union",
    @"extern",
    u8,
    u16,
    u32,
    u64,
    s8,
    s16,
    s32,
    s64,
    f32,
    f64,
};

const AsciiRange = struct {
    start: u8,
    end: u8,

    fn getRandomCharacter(range: AsciiRange) u8 {
        return random.intRangeAtMost(u8, range.start, range.end);
    }
};

const alphabet_ranges = [2]AsciiRange{
    .{ .start = 'A', .end = 'Z' },
    .{ .start = 'a', .end = 'z' },
};

const number_range = AsciiRange{
    .start = '0',
    .end = '9',
};

const space_characters = [_]u8{ '\n', '\r', '\t', ' ' };

const operator_ranges = [_]AsciiRange{
    .{ .start = 0x21, .end = 0x2f },
    .{ .start = 0x3a, .end = 0x40 },
    .{ .start = 0x5b, .end = 0x60 },
    .{ .start = 0x7b, .end = 0x7e },
};

inline fn tscInstant() u64 {
    var eax: u32 = undefined;
    var edx: u32 = undefined;

    asm volatile (
        \\lfence
        \\rdtsc
        : [eax] "={eax}" (eax),
          [edx] "={edx}" (edx),
        :
        : "memory"
    );

    return @as(u64, edx) << 32 | eax;
}

const writers = [_]Writer{
    writeRandomOperator,
    writeRandomInt,
    writeRandomIdentifier,
    writeRandomKeyword,
};
const Slice = []align(0x1000) u8;

const Stream = std.io.FixedBufferStream(Slice);
const Writer = *const fn (stream: Stream.Writer) void;

fn writeRandomOperator(writer: Stream.Writer) void {
    const choice = random.uintLessThan(u8, @intCast(operator_ranges.len));
    const range = operator_ranges[choice];
    writer.writeByte(range.getRandomCharacter()) catch unreachable;
}

fn writeRandomInt(writer: Stream.Writer) void {
    const IntFormat = enum {
        decimal,
        hexadecimal,
        binary,
        octal,
    };

    const format_choice: IntFormat = @enumFromInt(random.uintLessThan(u8, @typeInfo(IntFormat).Enum.fields.len));
    const integer = random.int(u64);
    switch (format_choice) {
        .decimal => writer.print("{}", .{integer}) catch unreachable,
        .hexadecimal => writer.print("0x{x}", .{integer}) catch unreachable,
        .binary => writer.print("0b{b}", .{integer}) catch unreachable,
        .octal => writer.print("0o{o}", .{integer}) catch unreachable,
    }
}

fn writeRandomIdentifier(writer: Stream.Writer) void {
    const identifier_start = [2]u8{ random.intRangeAtMost(u8, 'a', 'z'), random.intRangeAtMost(u8, 'A', 'Z') };
    const start_choice = random.boolean();
    writer.writeByte(identifier_start[@intFromBool(start_choice)]) catch unreachable;
    var character_count: usize = 1;
    const identifier_max_character_count = 32;
    const this_identifier_character_count = random.intRangeAtMost(u8, 1, identifier_max_character_count);

    while (character_count < this_identifier_character_count) : (character_count += 1) {
        const ranges = [_]AsciiRange{
            alphabet_ranges[0],
            alphabet_ranges[1],
            number_range,
        };
        const choice = random.uintLessThan(u8, ranges.len);
        const range = ranges[choice];
        const random_character = range.getRandomCharacter();
        writer.writeByte(random_character) catch unreachable;
    }
}

fn writeRandomKeyword(writer: Stream.Writer) void {
    const choice = random.uintLessThan(u8, @typeInfo(FixedKeyword).Enum.fields.len);
    const enum_tag = @tagName(@as(FixedKeyword, @enumFromInt(choice)));
    for (enum_tag) |ch| {
        if (ch > 0x7e) unreachable;
    }
    _ = writer.write(enum_tag) catch unreachable;
}

var prng: std.rand.DefaultPrng = undefined;
var random: std.rand.Random = undefined;

fn generateRandomData(size: usize) !Slice {
    prng = std.rand.DefaultPrng.init(blk: {
        var seed: u64 = undefined;
        try std.os.getrandom(std.mem.asBytes(&seed));
        break :blk seed;
    });
    random = prng.random();
    assert(std.mem.isAligned(size, 0x1000));
    const byte_buffer = try std.os.mmap(null, size, std.os.PROT.READ | std.os.PROT.WRITE, std.os.MAP.ANONYMOUS | std.os.MAP.PRIVATE, -1, 0);
    var stream = Stream{
        .buffer = byte_buffer,
        .pos = 0,
    };
    var count: usize = 0;
    const line_approximate_character_count = 150;
    const max_start_line_space_count = 8;
    const writer = stream.writer();

    while (count < byte_buffer.len - 0x200) {
        var line_character_count: usize = 0;

        const line_start_space_count = random.uintAtMost(u8, max_start_line_space_count);
        for (0..line_start_space_count) |_| {
            writer.writeByte(' ') catch unreachable;
        }

        line_character_count += line_start_space_count;

        while (line_character_count < line_approximate_character_count) {
            const token_start = stream.pos;

            const choice = random.uintAtMost(u8, writers.len - 1);
            writers[choice](writer);

            const written_char_count = stream.pos - token_start;
            line_character_count += written_char_count;

            const space = choice == 3 or random.boolean();
            if (space) {
                writer.writeByte(' ') catch unreachable;
                line_character_count += 1;
            }
        }

        writer.writeByte('\n') catch unreachable;
        line_character_count += 1;

        count += line_character_count;
    }

    while (count < byte_buffer.len) : (count += 1) {
        const ranges = [_]AsciiRange{
            alphabet_ranges[0],
            alphabet_ranges[1],
            number_range,
            operator_ranges[0],
            operator_ranges[1],
            operator_ranges[2],
            operator_ranges[3],
        };
        const choice = random.uintLessThan(u8, ranges.len);
        const character = ranges[choice].getRandomCharacter();
        if (character > 0x7e) unreachable;
        writer.writeByte(character) catch unreachable;

        if (byte_buffer.len - count >= 2 and stream.pos % line_approximate_character_count == 0) {
            writer.writeByte('\n') catch unreachable;
            count += 1;
        }
    }

    return byte_buffer;
}
