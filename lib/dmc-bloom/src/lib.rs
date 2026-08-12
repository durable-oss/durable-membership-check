//! Bloom filter implementations for `durable-membership-check`.
//!
//! Linking this crate registers its implementations with the [`dmc_core`]
//! registry, making them reachable by name from the Ruby binding and any other
//! consumer without those consumers naming the types.
//!
//! # Implementations
//!
//! | id | notes |
//! |----|-------|
//! | [`bloom_001`](Bloom001) | Classic Bloom filter, Kirsch-Mitzenmacher double hashing. |
//!
//! The family alias `bloom` resolves to the highest version linked in.
//!
//! # Set operations
//!
//! Bloom filters of the same shape combine bitwise: [`ops`] adds union,
//! intersection, cardinality estimation, and Jaccard and containment
//! similarity on top of [`Bloom001`]. Union is exact; intersection is
//! approximate in a way worth reading about before relying on it.
//!
//! # Examples
//!
//! ```
//! use dmc_bloom::Bloom001;
//! use dmc_core::{Filter, Params};
//!
//! let keys: Vec<&[u8]> = vec![b"alice", b"bob"];
//! let filter = Bloom001::build(&keys, &Params::new(2, 0.01))?;
//!
//! assert!(filter.contains(b"alice"));
//! # Ok::<(), dmc_core::Error>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::pedantic)]

pub mod bloom_001;
pub mod ops;

pub use bloom_001::Bloom001;
