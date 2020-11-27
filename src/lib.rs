//! ![checksec](https://raw.githubusercontent.com/etke/checksec.rs/master/resources/checksec.svg?sanitize=true)
//!
//! Checksec is a standalone command line utility and library that provides
//! binary executable security-oriented property checks for `ELF`, `PE`, and
//! `MachO`executables.
//!
//! **Structures**
//!
//! The full checksec results can be retrieved from the implemented
//! `*CheckSecResult` structures for a given binary by passing a
//! [`goblin::Object`](https://docs.rs/goblin/latest/goblin/enum.Object.html)
//! object to the parse method.
//!
//! * [`checksec::elf::ElfCheckSecResults`](./elf/struct.ElfCheckSecResults.html)
//! * [`checksec::macho::MachOCheckSecResults`](./macho/struct.MachOCheckSecResults.html)
//! * [`checksec::pe::PECheckSecResults`](./pe/struct.PECheckSecResults.html)
//!
//! ```rust
//! use checksec::elf::ElfCheckSecResults;
//! use checksec::macho::MachOCheckSecResults;
//! use checksec::pe::PECheckSecResults;
//! ```
//!
//! **Traits**
//!
//! Add the associated `*Properties` trait to the imports as shown below to
//! have direct access to the security property check functions for a given
//! binary executable format.
//!
//! * [`checksec::elf::ElfProperties`](./elf/trait.ElfProperties.html)
//! * [`checksec::macho::MachOProperties`](./macho/trait.MachOProperties.html)
//! * [`checksec::pe::PEProperties`](./pe/trait.PEProperties.html)
//!
//! ```rust
//! use checksec::elf::ElfProperties;
//! use checksec::macho::MachOProperties;
//! use checksec::pe::PEProperties;
//! ```
//!
//! Refer to the generated docs or the examples directory
//! [examples/](https://github.com/etke/checksec.rs/tree/master/examples)
//! for examples of working with both `*Properties` traits and
//! `*CheckSecResults` structs.
//!
#[cfg(feature = "elf")]
pub mod elf;
#[cfg(feature = "macho")]
pub mod macho;
pub mod macros;
#[cfg(feature = "pe")]
pub mod pe;
#[cfg(feature = "shared")]
#[macro_use]
pub mod shared;
