![checksec.rs](./resources/checksec.svg)

[![crates.io](https://img.shields.io/badge/crates.io-v0.0.2-orange.svg)](https://crates.io/crates/checksec) [![docs.rs](https://docs.rs/checksec/badge.svg)](https://docs.rs/checksec) [![github-actions](https://github.com/etke/checksec.rs/workflows/github%20actions/badge.svg?branch=master)](https://github.com/etke/checksec.rs/actions)

Fast multi-platform (ELF/PE/MachO) binary checksec written in Rust.

*\*under active development, cargo crate releases periodically*

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

```sh
Usage: checksec <-f|-d> <file|directory> [--json]
```

### Example

#### standalone checksec

```sh
$ checksec -f test/binaries/true-x86_64
ELF32: | Canary: true CFI: false SafeStack: false Fortify: true Fortified: 2 NX: true PIE: None Relro: Partial RPATH: None RUNPATH: None | File:
 test/binaries/true-x86_64
```

json output

```sh
$ checksec -f test/binaries/true-x86_64 --json
{"binaries":[{"binarytype":"Elf64","file":"test/binaries/true-x86_64","properties":{"Elf":{"canary":true,"clang_cfi":false,"clang_safestack":fal
se,"fortified":2,"fortify":true,"nx":true,"pie":"None","relro":"Partial","rpath":{"paths":["None"]},"runpath":{"paths":["None"]}}}}]}
```

#### libchecksec

Just add the following to any current project with goblin dependencies to enable checksec trait on `goblin::Object::{Elf, Mach, PE}` objects.

Add `checksec` crate dependency to your project `Cargo.toml`.

```toml
[dependencies]
checksec = { version = "0.0.2", features = ["elf", "macho", "pe"] }
```

Now in your project source, specify dependency on the `checksec` crate and import the `*Properties` trait(s).
```rust
extern crate checksec;
use checksec::elf::ElfProperties;
use checksec::macho::MachOProperties;
use checksec::pe::PEProperties;
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

* `parse()` to return multiple results in case of multi-arch Fat MachO
* Check running processes

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
