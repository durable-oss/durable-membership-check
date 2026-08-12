//! Xor filter implementations for `durable-membership-check`.
//!
//! Linking this crate registers its implementations with the [`dmc_core`]
//! registry, making them reachable by name from the Ruby binding and any other
//! consumer without those consumers naming the types.
//!
//! # Implementations
//!
//! | id | notes |
//! |----|-------|
//! | [`xor_001`](Xor001) | Classic three-hash xor filter, built by peeling. |
//!
//! The family alias `xor` resolves to the highest version linked in.
//!
//! # Xor versus Bloom
//!
//! A xor filter needs the complete distinct key set up front and costs more
//! to build, in exchange for a smaller table and a faster, branch-light query
//! than a Bloom filter at a comparable false positive rate. Its rate is fixed
//! by the fingerprint width rather than tunable; see [`Xor001`] for the
//! figure an 8-bit fingerprint gives.
//!
//! # Examples
//!
//! ```
//! use dmc_xor::Xor001;
//! use dmc_core::{Filter, Params};
//!
//! let keys: Vec<&[u8]> = vec![b"alice", b"bob"];
//! let filter = Xor001::build(&keys, &Params::default())?;
//!
//! assert!(filter.contains(b"alice"));
//! # Ok::<(), dmc_core::Error>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::pedantic)]

pub mod xor_001;

pub use xor_001::Xor001;
