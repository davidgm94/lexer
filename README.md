# Lexer SIMD experiments

## Build and run

### Requirements

- To execute the binary: x86\_64 machine with AVX-2 support
- To build the program: Zig compiler from master branch. Can be downloaded from [here](https://ziglang.org/download/).

### Steps

#### To compile:

```
zig build
```

#### To (compile and) install:

```
zig build install
```

After installation, the binary will be placed in `./zig-out/bin`.

#### To (compile, install and) run the binary

The program currently accepts the following arguments, the size of the lexer input data (it can be written in hexadecimal or decimal format), which must be aligned to a page (0x1000).

```
-size {page_size_aligned_bytes}
-simd {false, true}

```

It can be run directly invoking the executable: `./zig-out/bin/lexer -size 0x80000 -simd true`

However, the most convenient way to run the program is using the Zig build system itself. The command written below is equivalent with the one described above, passing the program arguments after the `--` token:

```
zig build run -size 0x80000 -simd true
```

By default, `zig build` compiles the program in Debug mode. Zig offers four optimization modes: `Debug`, `ReleaseSafe`, `ReleaseSmall` and `ReleaseFast`. For each invocation of `zig build`, you can modify the optimization mode by using the `-Doptimize={release mode}` argument. For example:

```
zig build -Doptimize=ReleaseFast
```

Assuming you want to compile, install and run the program in ReleaseFast mode and with a page size of `0x80000`, you would need to type this command:

```
zig build run -Doptimize=ReleaseFast -- -size 0x80000 -simd true
```
