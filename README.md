![checksec.rs](./resources/checksec.svg)

[![crates.io](https://img.shields.io/crates/v/checksec.svg)](https://crates.io/crates/checksec) [![docs.rs](https://docs.rs/checksec/badge.svg)](https://docs.rs/checksec) [![github-actions](https://github.com/etke/checksec.rs/workflows/github%20actions/badge.svg?branch=master)](https://github.com/etke/checksec.rs/actions)

Fast multi-platform (ELF/PE/MachO) binary checksec written in Rust.

*cargo crate releases periodically*

Uses [goblin](https://docs.rs/goblin) to for multi-platform binary parsing support and [ignore](https://docs.rs/ignore) for fast recursive path iteration that respects various filters such as globs, file types and `.gitignore` files and [serde](https://docs.rs/serde) for Serializaiton/Deserialization.

### Prior Art

Plenty of prior art exists for this type of tool. Some are standalone command line utilities and some are plugins for frameworks or debuggers, however all are platform specific.

Project | Author | Language | Active
--- | --- |--- | ---
[checksec.sh](http://trapkit.de/tools/checksec.html) *(original)*| Tobias Klein | _bash_ | *Jan 28, 2009 - Nov 17, 2011*
[checksec](https://github.com/kholia/checksec) | Dhiru Kholia | _python_ | *Apr 18, 2013 - Mar 19, 2014*
[checksec.sh](https://github.com/slimm609/checksec.sh) | Brian Davis | _bash_ | *Feb 14, 2014 - current*
[pwntools - checksec](https://github.com/Gallopsled/pwntools/blob/26598f3da61677da6254daf25f699bda6635d803/pwnlib/elf/elf.py#L1734) | Gallopsled | _python_ | *Nov 8, 2014 - current*
[CheckSec.c](https://github.com/hugsy/stuff/blob/master/CheckSec.c)| hugsy | _c_ | *Dec 7, 2015 - Apr 24, 2018*
[checksec](https://github.com/klks/checksec) | klks | _c++_ | *Mar 25, 2017*
[iOS-checksec.py](https://gist.github.com/ChiChou/15f0772db25343be0bb7072f15992a4e) | ChiChou | _python_ | *Apr 6, 2017*
[checksec-win](https://github.com/wmliang/checksec-win) | Lucas Leong | _c++_ | *Aug 21, 2017*
[winchecksec](https://github.com/trailofbits/winchecksec) | Trail Of Bits | _c++_ | *Aug 17, 2018 - current*
[pe_mitigation_check.py](https://gist.github.com/edeca/d123c5eb2ce541f36ab245da544d80cd) | David Cannings | _python_ | *Sep 20, 2018*

*note: not an exhaustive list*

## Build/Install

### git *(HEAD)*

```sh
git clone https://github.com/etke/checksec.rs && cd checksec.rs
cargo build --release
cargo install --path .
```

### cargo

```sh
cargo install checksec
```

### Cross-compilation

For instances where you want to compile for a different target OS or architecture, see [rust-cross](https://github.com/japaric/rust-cross).

## Usage

**Note:** command line args/options have changed as of version `0.1.0`

```sh
$ checksec
Fast multi-platform (ELF/PE/MachO) binary checksec command line utility and library.

Usage: checksec <COMMAND> [OPTIONS]

Commands:
  blob     Scan binaries or compressed archives by path
  process  Scan binaries by process
  help     Print this message or the help of the given subcommand(s)

Options:
      --no-color         Disables color output
      --format <FORMAT>  Output format [default: text] [possible values: text, json, json-pretty]
  -h, --help             Print help information
  -V, --version          Print version information
```

## Subcommands usage

### blob

```sh
$ checksec blob
Scan binaries or compressed archives by path

Usage: checksec blob [OPTIONS] [PATHS]
       command | checksec blob [OPTIONS] --stdin

Arguments:
  [PATHS]...

Options:
  -s, --stdin            Read paths from stdin
      --no-color         Disables color output
      --format <FORMAT>  Output format [default: text] [possible values: text, json, json-pretty]
  -h, --help             Print help information
```

### process

```sh
$ checksec process
Scan binaries by process

Usage: checksec process <command> [OPTIONS]

Commands:
  all   Scan all running processes
  id    Scan processes by PID
  name  Scan processes by name
  help  Print this message or the help of the given subcommand(s)

Options:
      --no-color         Disables color output
      --format <FORMAT>  Output format [default: text] [possible values: text, json, json-pretty]
  -h, --help             Print help information
```

#### process all

```sh
$ checksec process all -h
Scan all running processes

Usage: checksec process all [OPTIONS]

Options:
  -m, --maps             Include process memory maps (linux/windows only)
      --no-color         Disables color output
      --format <FORMAT>  Output format [default: text] [possible values: text, json, json-pretty]
  -h, --help             Print help information
```

#### process id

```sh
$ checksec process id
Scan processes by PID

Usage: checksec process id [OPTIONS] <PIDS>
       command | checksec process id [OPTIONS] --stdin

Arguments:
  [PIDS]...

Options:
  -m, --maps             Include process memory maps (linux/windows only)
  -s, --stdin            Read process ids from stdin
      --no-color         Disables color output
      --format <FORMAT>  Output format [default: text] [possible values: text, json, json-pretty]
  -h, --help             Print help information
```

### Examples

#### standalone checksec

##### individual blob (binary/compressed archive)

```sh
$ checksec blob test/binaries/true-x86_64
ELF64: | Canary: true  CFI: false SafeStack: false Fortify: Partial     Fortified:  2 Fortifiable:  2 NX: true  PIE: None Relro: Partial RPATH: None RUNPATH: None | File: test/binaries/true-x86_64
# or from stdin
$ echo "test/binaries/true-x86_64" | checksec blob --stdin
ELF64: | Canary: true  CFI: false SafeStack: false Fortify: Partial     Fortified:  2 Fortifiable:  2 NX: true  PIE: None Relro: Partial RPATH: None RUNPATH: None | File: test/binaries/true-x86_64
```

##### individual blob (binary/compressed archive) (JSON output)

```sh
$ checksec blob --format json test/binaries/true-x86_64
{"binaries":[{"binarytype":"Elf64","file":"test/binaries/true-x86_64","properties":{"Elf":{"canary":true,"clang_cfi":false,"clang_safestack":false,"fortifiable":2,"fortified":2,"fortify":"Partial","nx":true,"pie":"None","relro":"Partial","rpath":{"paths":["None"]},"runpath":{"paths":["None"]}}}}]}
```

##### multiple blobs via stdin

```sh
# newline delminated
$ dpkg -L dpkg | target/release/checksec blob --stdin 2>/dev/null
ELF64: | Canary: true  CFI: false SafeStack: false Fortify: Partial     Fortified:  9 Fortifiable:  3 NX: true  Pie: Full Relro: Full    RPATH: None RUNPATH: None | File: /sbin/start-stop-daemon
ELF64: | Canary: true  CFI: false SafeStack: false Fortify: Partial     Fortified: 10 Fortifiable:  8 NX: true  Pie: Full Relro: Full    RPATH: None RUNPATH: None | File: /usr/bin/dpkg
ELF64: | Canary: true  CFI: false SafeStack: false Fortify: Partial     Fortified:  9 Fortifiable:  5 NX: true  Pie: Full Relro: Full    RPATH: None RUNPATH: None | File: /usr/bin/dpkg-deb
ELF64: | Canary: true  CFI: false SafeStack: false Fortify: Partial     Fortified:  9 Fortifiable:  6 NX: true  Pie: Full Relro: Full    RPATH: None RUNPATH: None | File: /usr/bin/dpkg-divert
ELF64: | Canary: true  CFI: false SafeStack: false Fortify: Partial     Fortified:  9 Fortifiable:  7 NX: true  Pie: Full Relro: Full    RPATH: None RUNPATH: None | File: /usr/bin/dpkg-query
ELF64: | Canary: true  CFI: false SafeStack: false Fortify: Partial     Fortified:  8 Fortifiable:  5 NX: true  Pie: Full Relro: Full    RPATH: None RUNPATH: None | File: /usr/bin/dpkg-split
ELF64: | Canary: true  CFI: false SafeStack: false Fortify: Partial     Fortified:  8 Fortifiable:  5 NX: true  Pie: Full Relro: Full    RPATH: None RUNPATH: None | File: /usr/bin/dpkg-statoverride
ELF64: | Canary: true  CFI: false SafeStack: false Fortify: Partial     Fortified:  9 Fortifiable:  5 NX: true  Pie: Full Relro: Full    RPATH: None RUNPATH: None | File: /usr/bin/dpkg-trigger
ELF64: | Canary: true  CFI: false SafeStack: false Fortify: Partial     Fortified:  5 Fortifiable:  3 NX: true  Pie: Full Relro: Full    RPATH: None RUNPATH: None | File: /usr/bin/update-alternatives
```

##### running processes

```sh
$ checksec process all
zsh(34)
 ↪ ELF64: | Canary: true  CFI: false SafeStack: false Fortify: Partial     Fortified:  8 Fortifiable: 19 NX: true  PIE: Full Relro: Full    RPATH: None RUNPATH: None | File: /usr/bin/zsh
checksec(216)
↪ ELF64: | Canary: false CFI: false SafeStack: false Fortify: None        Fortified:  0 Fortifiable:  8 NX: true  PIE: Full Relro: Full    RPATH: None RUNPATH: None | File: /home/etke/.cargo/bin/checksec
```

##### running processes (JSON output)

```sh
$ checksec process all --format json
{"processes":[{"binary":[{"binarytype":"Elf64","file":"/bin/zsh","properties":{"Elf":{"canary":true,"clang_cfi":false,"clang_safestack":false,"fortified":8,"fortify":true,"nx":true,"pie":"PIE","relro":"Full","rpath":{"paths":["None"]},"runpath":{"paths":["None"]}}}}],"pid":34},{"binary":[{"binarytype":"Elf64","file":"/init","properties":{"Elf":{"canary":false,"clang_cfi":false,"clang_safestack":false,"fortified":0,"fortify":false,"nx":true,"pie":"None","relro":"Partial","rpath":{"paths":["None"]},"runpath":{"paths":["None"]}}}}],"pid":1},{"binary":[{"binarytype":"Elf64","file":"/home/etke/.cargo/bin/checksec","properties":{"Elf":{"canary":false,"clang_cfi":false,"clang_safestack":false,"fortified":0,"fortify":false,"nx":true,"pie":"PIE","relro":"Full","rpath":{"paths":["None"]},"runpath":{"paths":["None"]}}}}],"pid":232}]}
```

##### running processes with name(s)

```sh
$ checksec process name zsh
zsh(34)
 ↪ ELF64: | Canary: true  CFI: false SafeStack: false Fortify: Partial     Fortified:  8 Fortifiable: 19 NX: true  PIE: Full Relro: Full    RPATH: None RUNPATH: None | File: /usr/bin/zsh
# or from stdin (space delimited)
$ echo "zsh vim" | checksec process name --stdin
# or from stdin (newline delimited)
$ printf "zsh\vim" | checksec process name --stdin
vim(4567)
 ↪ ELF64: | Canary: true  CFI: false SafeStack: false Fortify: Partial     Fortified: 10 Fortifiable: 18 NX: true  Pie: Full Relro: Full    RPATH: None RUNPATH: None | File: /usr/bin/vim
zsh(1234)
 ↪ ELF64: | Canary: true  CFI: false SafeStack: false Fortify: Partial     Fortified:  8 Fortifiable: 19 NX: true  Pie: Full Relro: Full    RPATH: None RUNPATH: None | File: /usr/bin/zsh
```

##### running process by id(s)

```sh
$ checksec process id 1234
zsh(1234)
 ↪ ELF64: | Canary: true  CFI: false SafeStack: false Fortify: Partial     Fortified:  8 Fortifiable: 19 NX: true  Pie: Full Relro: Full    RPATH: None RUNPATH: None | File: /usr/bin/zsh
# or from stdin (space delimited)
$ pidof zsh | checksec process id --stdin
# or from stdin (newline delimited)
$ pgrep zsh | checksec process id --stdin
zsh(4567)
 ↪ ELF64: | Canary: true  CFI: false SafeStack: false Fortify: Partial     Fortified:  8 Fortifiable: 19 NX: true  Pie: Full Relro: Full    RPATH: None RUNPATH: None | File: /usr/bin/zsh
zsh(1234)
 ↪ ELF64: | Canary: true  CFI: false SafeStack: false Fortify: Partial     Fortified:  8 Fortifiable: 19 NX: true  Pie: Full Relro: Full    RPATH: None RUNPATH: None | File: /usr/bin/zsh
```

#### libchecksec

Just add the following to any current project with goblin dependencies to enable checksec trait on `goblin::Object::{Elf, Mach, PE}` objects.

Add `checksec` crate dependency to your project `Cargo.toml`.

```toml
[dependencies]
checksec = { version = "0.0.9", features = ["elf", "macho", "pe", "color"] }
```

Now in your project source, specify dependency on the `checksec` crate and import the required module to access the associated `Properties` trait(s).

```rust
extern crate checksec;
use checksec::elf;
use checksec::macho;
use checksec::pe;
```

You will now have access to all the implemented check functions directly from the `goblin::Object`.

See [examples/](https://github.com/etke/checksec.rs/tree/master/examples) for library usage examples.

## Todo

### libchecksec todos

* Platform specific checks
  * ELF
    * Fortifiable
    * Rpath RW
  * PE
    * Authenticode verification
  * MachO
    * Rpath RW
* Platform independent checks
  * MachO
    * `@rpath` contents into `shared::VecRpath` similar to `DT_RPATH`/`DT_RUNPATH` on ELFs
    * Code signature validation

### checksec todos

* ?

### project todos

* Tests *(cargo test)*

## Contributing

Improvements welcome!

* For ideas, please check the Github Issues page.
  * Want something added? file an issue and tag it with `improvement`
* Found a problem? file an issue including the following information
  * Description of the problem
  * Expected behaviour
  * Attach `bug` tag
* For pull requests to be reviewed;
  * must be formatted with supplied project `rustfmt.toml`
  * must have no Clippy warnings/errors with supplied project `clippy.toml` *(when one exists)*
