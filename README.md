# rs-shellcode

A shellcode runner write in Rust.

# how to use it

Install [rustup](https://rustup.rs/).

```sh
rustup default
```

Use msfvenom generate shellcode for test.

```sh
msfvenom -p windows/x64/exec CMD=calc.exe  --platform win -f raw -o calc64.raw
```

XOR obfuscated payload.
```sh
msfvenom --platform windows --arch x64  -p windows/x64/exec CMD=calc.exe -f raw --encrypt xor --encrypt-key "\x55"
```

XOR obfuscated payload for linux.
```sh
sfvenom --platform linux --arch x64  -p linux/x64/exec  -f python --encrypt xor --encrypt-key "\x55"
```

Build:

```sh
cargo build --release
```

On linux using [cross](https://github.com/cross-rs/cross):
```sh
cross build -r --target=x86_64-pc-windows-gnu
```

Usage:
```
Usage: rs_shellcode [OPTIONS] --file <file>

Options:
  -f, --file <file>      shellcode path
  -b, --breakpoint       set breakpoint in debugger
  -o, --offset <offset>  shellcode offset
  -x, --xor <xor>        deobfuscate with XOR encoding
  -s, --stealth          removes shell code and itself
  -h, --help             Print help
  -V, --version          Print version
```

Run:

```sh
./target/debug/rs_shellcode.exe -f <SHELLCODE_PATH>
```

When your shellcode not start at offset 0, you can specify the offset use `-o`:

```sh
./target/debug/rs_shellcode.exe -f <SHELLCODE_PATH> -o 0x30
```


Run with breakpoint flag (`-b`):

```sh
./target/debug/rs_shellcode.exe -f <SHELLCODE_PATH> -b
```

use this flag, you can break just before your shellcode in the debugger, which will make your life easier.

![breakpoint in windbg](./breakpoint.png)