const std = @import("std");
const assert = std.debug.assert;
const Instant = std.time.Instant;
const print = std.debug.print;

const page_size = std.mem.page_size;

comptime {
    if (@import("builtin").cpu.arch != .x86_64) {
        @compileError("Only x86_64 is supported");
    }

    if (!std.Target.x86.featureSetHas(@import("builtin").cpu.features, std.Target.x86.Feature.avx2)) {
        @compileError("AVX2 is required");
    }

    assert(page_size == 0x1000);
}

pub fn main() !void {
    const arguments = try std.process.argsAlloc(std.heap.page_allocator);

    var arg_simd: ?bool = null;
    var arg_page_size: ?usize = null;
    var argument_i: usize = 1;

    while (argument_i < arguments.len) : (argument_i += 1) {
        const argument = arguments[argument_i];
        const index = argument_i + 1;
        if (std.mem.eql(u8, argument, "-size")) {
            if (index < arguments.len) {
                arg_page_size = if (std.mem.eql(u8, arguments[index][0..2], "0x"))
                    try std.fmt.parseInt(u64, arguments[index][2..], 16)
                else
                    try std.fmt.parseInt(u64, arguments[index], 10);

                if (!std.mem.isAligned(arg_page_size.?, std.mem.page_size)) {
                    return error.InvalidInput;
                }

                argument_i += 1;
            } else return error.InvalidInput;
        } else if (std.mem.eql(u8, argument, "-simd")) {
            if (index < arguments.len) {
                const bool_arg = arguments[index];
                if (std.mem.eql(u8, bool_arg, "true")) {
                    arg_simd = true;
                } else if (std.mem.eql(u8, bool_arg, "false")) {
                    arg_simd = false;
                } else return error.InvalidInput;

                argument_i += 1;
            } else return error.InvalidInput;
        } else return error.InvalidInput;
    }

    const simd = arg_simd orelse true;
    const buffer_len = arg_page_size orelse 0x1000000;

    print("Running in {s} optimization mode. SIMD on: {}. Preparing 0x{x} bytes ", .{ @tagName(@import("builtin").mode), simd, buffer_len });
    if (buffer_len % (1024 * 1024) == 0) {
        print("({} MiB)", .{@divExact(buffer_len, 1024 * 1024)});
    } else if (buffer_len % 1024 == 0) {
        print("({} KiB)", .{@divExact(buffer_len, 1024)});
    }

    print(" worth of data\n", .{});

    const buffer = try generateRandomData(buffer_len);
    assert(buffer.len == buffer_len);
    const token_list_buffer = try mmap(buffer_len, .{});
    var token_list_fba = std.heap.FixedBufferAllocator.init(token_list_buffer);
    var token_list = try TokenList.initCapacity(token_list_fba.allocator(), @divExact(buffer_len, @sizeOf(Token)));

    print("Data prepared. Running benchmark...\n", .{});
    const time_result = switch (simd) {
        true => lexSimd(buffer, &token_list),
        false => lexScalar(buffer, &token_list),
    };
    switch (Timer.type) {
        .system_precision => {
            const mib_s = @as(f64, @floatFromInt(buffer.len * 1000 * 1000 * 1000)) / @as(f64, @floatFromInt(time_result * 1024 * 1024));
            print("{} ns. {d:0.2} MiB/s\n", .{ time_result, mib_s });
            if (token_list.items.len > 0) {
                const ns_per_token = @as(f64, @floatFromInt(time_result)) / @as(f64, @floatFromInt(token_list.items.len));
                print("{} tokens ({d:0.2} ns/token)\n", .{ token_list.items.len, ns_per_token });
            } else {
                print("No token was processed\n", .{});
            }
        },
        .tsc => print("TSC cycles: {}\n", .{time_result}),
    }
}

fn lexScalar(bytes: Slice, list: *TokenList) u64 {
    const timer = Timer.start();
    var i: u32 = 0;

    while (i < bytes.len) {
        const start_i = i;
        const token_id: Token.Id = switch (bytes[start_i]) {
            space_characters[0],
            space_characters[1],
            space_characters[2],
            space_characters[3],
            => {
                i += 1;
                continue;
            },
            alphabet_ranges[0].start...alphabet_ranges[0].end,
            alphabet_ranges[1].start...alphabet_ranges[1].end,
            => blk: {
                while (i < bytes.len) {
                    const ch = bytes[i];
                    const is_identifier_character = alphabet_ranges[0].inRange(ch) or alphabet_ranges[1].inRange(ch) or decimal_range.inRange(ch) or ch == '_';
                    i += @intFromBool(is_identifier_character);
                    if (!is_identifier_character) {
                        break;
                    }
                } else {
                    // TODO
                    unreachable;
                }

                break :blk .identifier;
            },
            decimal_range.start...decimal_range.end => blk: {
                const has_prefix = start_i + 2 <= bytes.len or std.mem.eql(u8, bytes[start_i..][0..2], "0x") or std.mem.eql(u8, bytes[start_i..][0..2], "0b") or std.mem.eql(u8, bytes[start_i..][0..2], "0o");
                i += @as(u2, @intFromBool(has_prefix)) << 1;
                while (i < bytes.len) {
                    const ch = bytes[i];
                    const is_number_character = decimal_range.inRange(ch) or extra_hex_ranges[0].inRange(ch) or extra_hex_ranges[1].inRange(ch);
                    i += @intFromBool(is_number_character);
                    if (!is_number_character) {
                        break;
                    }
                } else {
                    // TODO
                    unreachable;
                }

                break :blk .number;
            },
            operator_ranges[0].start...operator_ranges[0].end,
            operator_ranges[1].start...operator_ranges[1].end,
            operator_ranges[2].start...operator_ranges[2].end,
            operator_ranges[3].start...operator_ranges[3].end,
            operator_ranges[4].start...operator_ranges[4].end,
            operator_ranges[5].start...operator_ranges[5].end,
            => blk: {
                const ch = bytes[i];
                const operator: Token.Id = @enumFromInt(ch);
                i += 1;
                break :blk operator;
            },
            '\'' => blk: {
                i += 1;
                i += @intFromBool(bytes[i] == '\\');
                i += 1;
                if (bytes[i] != '\'') {
                    reportError(i, bytes[i]);
                }
                i += 1;

                break :blk .character_literal;
            },
            '"' => blk: {
                i += 1;
                while (i < bytes.len) {
                    const ch = bytes[i];
                    if (ch == '"' and bytes[i - 1] != '\'') {
                        break;
                    }

                    i += 1;
                } else {
                    // TODO
                    unreachable;
                }

                // TODO: detect valid string
                i += 1;

                break :blk .string_literal;
            },
            else => |ch| reportError(i, ch),
        };

        const len = i - start_i;
        const token = Token{
            .id = token_id,
            .start = start_i,
            .len = @intCast(len),
        };
        list.appendAssumeCapacity(token);
    }

    return timer.end();
}

const Chunk = @Vector(chunk_byte_count, u8);
const Bitmask = u64;
const ChunkBitset = @Vector(64, u1);
const chunk_byte_count = 64;

fn fillMask(ch: u8) Chunk {
    return @splat(ch);
}

fn characterBitset(chunk: Chunk, ch: u8) ChunkBitset {
    const mask: Chunk = @splat(ch);
    return @bitCast(mask == chunk);
}

fn getChunkFromSlice(slice: []const u8, index: usize) Chunk {
    const chunk: Chunk = @bitCast(slice[index..][0..chunk_byte_count].*);
    return chunk;
}

fn isInsideRange(chunk: Chunk, range: AsciiRange) ChunkBitset {
    const is_greater_or_eq_than_start_ch: ChunkBitset = @bitCast(chunk >= fillMask(range.start));
    const is_lower_or_eq_than_end_ch: ChunkBitset = @bitCast(chunk <= fillMask(range.end));
    return is_greater_or_eq_than_start_ch & is_lower_or_eq_than_end_ch;
}

fn isInsideRanges(chunk: Chunk, comptime ranges: []const AsciiRange) ChunkBitset {
    var bitset: ChunkBitset = [1]u8{0} ** 64;
    inline for (ranges) |range| {
        const is_inside_range = isInsideRange(chunk, range);
        bitset |= is_inside_range;
    }

    return bitset;
}

// TODO
fn lexSimd(bytes: Slice, list: *TokenList) u64 {
    _ = list;

    const timer = Timer.start();

    var character_i: usize = 0;
    while (character_i + chunk_byte_count < bytes.len) {
        const chunk = getChunkFromSlice(bytes, character_i);
        const space_bitset = characterBitset(chunk, '\n') | characterBitset(chunk, '\r') | characterBitset(chunk, '\t') | characterBitset(chunk, ' ');
        const space_character_count = @ctz(~@as(u64, @bitCast(space_bitset)));
        character_i += space_character_count;

        const is_alphabet_bitset = isInsideRanges(chunk, &alphabet_ranges);
        const is_decimal_bitset = isInsideRange(chunk, decimal_range);
        const is_underscore_bitset = characterBitset(chunk, '_');
        const identifier_bitset = is_alphabet_bitset | is_decimal_bitset | is_underscore_bitset;
        const is_identifier_mask: ChunkBitset = @splat(is_alphabet_bitset[0]);
        const identifier_character_count = @ctz(~(@as(u64, @bitCast(identifier_bitset)))) & @as(u64, @bitCast(is_identifier_mask));
        character_i += identifier_character_count;

        const is_hex_prefix_chunk: Chunk = [2]u8{ '0', 'x' } ** (chunk_byte_count / 2);
        const is_bin_prefix_chunk: Chunk = [2]u8{ '0', 'b' } ** (chunk_byte_count / 2);
        const is_octal_prefix_chunk: Chunk = [2]u8{ '0', 'o' } ** (chunk_byte_count / 2);

        const is_hex_prefix: ChunkBitset = @bitCast(chunk == is_hex_prefix_chunk);
        const is_bin_prefix: ChunkBitset = @bitCast(chunk == is_bin_prefix_chunk);
        const is_octal_prefix: ChunkBitset = @bitCast(chunk == is_octal_prefix_chunk);
        const is_number_prefix = is_hex_prefix | is_bin_prefix | is_octal_prefix;
        const prefix_character_count = 2 & @as(u64, @bitCast(@as(ChunkBitset, @splat(is_number_prefix[1] & is_number_prefix[0]))));
        character_i += prefix_character_count;

        const is_extra_hex_character = isInsideRanges(chunk, &extra_hex_ranges);
        const is_number_bitset = is_extra_hex_character | is_decimal_bitset;
        const number_literal_character_count = ~@ctz(@as(u64, @bitCast(is_number_bitset)));
        character_i += number_literal_character_count;

        // TODO: extra hardening the code
        // TODO: string literals
        // TODO: character literals
        // TODO: operators
        // TODO: store tokens
    }

    // TODO: loop end

    const time_result = timer.end();

    return time_result;
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
        // clock_gettime, QueryPerformanceCounter
        system_precision,
        // ordered tsc
        tsc,
    };

    inline fn start() Timer {
        return Timer{
            .start = switch (Timer.type) {
                .system_precision => Instant.now() catch unreachable,
                .tsc => blk: {
                    var eax: u32 = undefined;
                    var edx: u32 = undefined;

                    asm volatile (
                        \\lfence
                        \\rdtsc
                        : [eax] "={eax}" (eax),
                          [edx] "={edx}" (edx),
                    );

                    break :blk @as(u64, edx) << 32 | eax;
                },
            },
        };
    }
    inline fn end(timer: Timer) u64 {
        return switch (Timer.type) {
            .system_precision => Instant.since(Instant.now() catch unreachable, timer.start),
            .tsc => (blk: {
                var eax: u32 = undefined;
                var edx: u32 = undefined;

                asm volatile (
                    \\rdtscp
                    \\lfence
                    : [eax] "={eax}" (eax),
                      [edx] "={edx}" (edx),
                );

                break :blk @as(u64, edx) << 32 | eax;
            }) - timer.start,
        };
    }
};

const Token = packed struct(u64) {
    start: u32,
    len: u24,
    id: Id,
    const Id = enum(u8) {
        identifier = 0x00,
        number = 0x01,
        character_literal = 0x02,
        string_literal = 0x03,

        bang = '!', // 0x21
        //double_quote = '\"', // 0x22
        hash = '#', // 0x23
        dollar_sign = '$', // 0x24
        modulus = '%', // 0x25
        ampersand = '&', // 0x26
        //quote = '\'', // 0x27
        left_parenthesis = '(', // 0x28
        right_parenthesis = ')', // 0x29
        asterisk = '*', // 0x2a
        plus = '+', // 0x2b
        comma = ',', // 0x2c
        minus = '-', // 0x2d
        period = '.', // 0x2e
        slash = '/', // 0x2f
        colon = ':', // 0x3a
        semicolon = ';', // 0x3b
        less = '<', // 0x3c
        equal = '=', // 0x3d
        greater = '>', // 0x3e
        question_mark = '?', // 0x3f
        at = '@', // 0x40
        left_bracket = '[', // 0x5b
        backslash = '\\', // 0x5c
        right_bracket = ']', // 0x5d
        caret = '^', // 0x5e
        underscore = '_', // 0x5f
        grave = '`', // 0x60
        left_brace = '{', // 0x7b
        vertical_bar = '|', // 0x7c
        right_brace = '}', // 0x7d
        tilde = '~', // 0x7e
    };
};

const TokenList = std.ArrayListAligned(Token, page_size);

const AsciiRange = struct {
    start: u8,
    end: u8,

    inline fn getRandomCharacter(range: AsciiRange) u8 {
        return random.intRangeAtMost(u8, range.start, range.end);
    }

    inline fn inRange(range: AsciiRange, ch: u8) bool {
        return ch >= range.start and ch <= range.end;
    }
};

const alphabet_ranges = [2]AsciiRange{
    .{ .start = 'A', .end = 'Z' },
    .{ .start = 'a', .end = 'z' },
};

const decimal_range = AsciiRange{
    .start = '0',
    .end = '9',
};

const extra_hex_ranges = [2]AsciiRange{
    .{ .start = 'A', .end = 'f' },
    .{ .start = 'a', .end = 'f' },
};

const space_characters = [_]u8{ '\n', '\r', '\t', ' ' };

const operator_ranges = [_]AsciiRange{
    .{ .start = 0x21, .end = 0x21 },
    .{ .start = 0x23, .end = 0x26 },
    .{ .start = 0x28, .end = 0x2f },
    .{ .start = 0x3a, .end = 0x40 },
    .{ .start = 0x5b, .end = 0x60 },
    .{ .start = 0x7b, .end = 0x7e },
};

pub fn mmap(size: usize, flags: packed struct {
    executable: bool = false,
}) ![]align(page_size) u8 {
    return switch (@import("builtin").os.tag) {
        .windows => blk: {
            const windows = std.os.windows;
            break :blk @as([*]align(page_size) u8, @ptrCast(@alignCast(try windows.VirtualAlloc(null, size, windows.MEM_COMMIT | windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE))))[0..size];
        },
        .linux, .macos => |os_tag| blk: {
            const jit = switch (os_tag) {
                .macos => 0x800,
                .linux => 0,
                else => unreachable,
            };
            const execute_flag: switch (os_tag) {
                .linux => u32,
                .macos => c_int,
                else => unreachable,
            } = if (flags.executable) std.os.PROT.EXEC else 0;
            const protection_flags: u32 = @intCast(std.os.PROT.READ | std.os.PROT.WRITE | execute_flag);
            const mmap_flags = std.os.MAP.ANONYMOUS | std.os.MAP.PRIVATE | jit;

            const result = try std.os.mmap(null, size, protection_flags, mmap_flags, -1, 0);

            break :blk result;
        },
        else => @compileError("OS not supported"),
    };
}

const writers = [_]Writer{
    writeRandomOperator,
    writeRandomInt,
    writeRandomIdentifier,
    writeRandomStringLiteral,
    writeRandomCharacterLiteral,
};
const Slice = []align(page_size) u8;

const Stream = std.io.FixedBufferStream(Slice);
const Writer = *const fn (stream: Stream.Writer) void;

fn writeRandomOperator(writer: Stream.Writer) void {
    const choice = random.uintLessThan(u8, operator_ranges.len);
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
    const identifier_max_character_count = 32;
    const this_identifier_character_count = random.intRangeAtMost(u8, 1, identifier_max_character_count);

    for (1..this_identifier_character_count) |_| {
        const ranges = [_]AsciiRange{
            alphabet_ranges[0],
            alphabet_ranges[1],
            decimal_range,
        };
        const choice = random.uintLessThan(u8, ranges.len);
        const range = ranges[choice];
        const random_character = range.getRandomCharacter();
        writer.writeByte(random_character) catch unreachable;
    }
}

fn writeRandomStringLiteral(writer: Stream.Writer) void {
    const max_string_len = 100;
    const len = random.uintLessThan(u8, max_string_len);

    writer.writeByte('"') catch unreachable;

    for (0..len) |_| {
        const ranges = [_]AsciiRange{
            decimal_range,
            alphabet_ranges[0],
            alphabet_ranges[1],
            operator_ranges[0],
            operator_ranges[1],
            operator_ranges[2],
            operator_ranges[3],
            operator_ranges[4],
            operator_ranges[5],
        };
        const choice = random.uintLessThan(u8, ranges.len);
        const character = ranges[choice].getRandomCharacter();
        writer.writeByte(character) catch unreachable;
    }

    writer.writeByte('"') catch unreachable;
}

fn writeRandomCharacterLiteral(writer: Stream.Writer) void {
    writer.writeByte('\'') catch unreachable;

    while (true) {
        const ranges = [_]AsciiRange{
            decimal_range,
            alphabet_ranges[0],
            alphabet_ranges[1],
            operator_ranges[0],
            operator_ranges[1],
            operator_ranges[2],
            operator_ranges[3],
            operator_ranges[4],
            operator_ranges[5],
        };

        const choice = random.uintLessThan(u8, ranges.len);
        const character = ranges[choice].getRandomCharacter();
        if (character != '\'' and character != '\\') {
            writer.writeByte(character) catch unreachable;
            break;
        }
    }

    writer.writeByte('\'') catch unreachable;
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
    assert(std.mem.isAligned(size, page_size));
    const byte_buffer = try mmap(size, .{});
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

    // Finish the buffer with a string literal
    const len = byte_buffer.len - count - 2;

    writer.writeByte('"') catch unreachable;

    for (0..len) |_| {
        const ranges = [_]AsciiRange{
            decimal_range,
            alphabet_ranges[0],
            alphabet_ranges[1],
            operator_ranges[0],
            operator_ranges[1],
            operator_ranges[2],
            operator_ranges[3],
            operator_ranges[4],
            operator_ranges[5],
        };
        const choice = random.uintLessThan(u8, ranges.len);
        const character = ranges[choice].getRandomCharacter();
        writer.writeByte(character) catch unreachable;
    }

    writer.writeByte('"') catch unreachable;

    return byte_buffer;
}
