//! Binary fuse filter implementations for `durable-membership-check`.
//!
//! Linking this crate registers its implementations with the [`dmc_core`]
//! registry, making them reachable by name from the Ruby binding and any other
//! consumer without those consumers naming the types.
//!
//! # Implementations
//!
//! | id | notes |
//! |----|-------|
//! | [`fuse_001`](Fuse001) | Binary fuse filter, built by segmented peeling. |
//!
//! The family alias `fuse` resolves to the highest version linked in.
//!
//! # Fuse versus xor
//!
//! A binary fuse filter needs the same complete-key-set-up-front construction
//! as the classic xor filter (`dmc-xor`), and offers the same fixed false
//! positive rate for the same 8-bit fingerprint width, but packs its table
//! about 8% smaller by drawing a key's three fingerprint slots from
//! overlapping segments instead of three disjoint blocks. See [`Fuse001`]
//! for the construction.
//!
//! # Examples
//!
//! ```
//! use dmc_fuse::Fuse001;
//! use dmc_core::{Filter, Params};
//!
//! let keys: Vec<&[u8]> = vec![b"alice", b"bob"];
//! let filter = Fuse001::build(&keys, &Params::default())?;
//!
//! assert!(filter.contains(b"alice"));
//! # Ok::<(), dmc_core::Error>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::pedantic)]

pub mod fuse_001;

pub use fuse_001::Fuse001;
