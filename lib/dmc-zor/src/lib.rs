//! Zor filter implementations for `durable-membership-check`.
//!
//! Linking this crate registers its implementations with the [`dmc_core`]
//! registry, making them reachable by name from the Ruby binding and any other
//! consumer without those consumers naming the types.
//!
//! # Implementations
//!
//! | id | notes |
//! |----|-------|
//! | [`zor_001`](Zor001) | Fuse-shaped filter with deterministic peeling, backed by a fuse auxiliary for abandoned keys. |
//!
//! The family alias `zor` resolves to the highest version linked in.
//!
//! # Zor versus fuse
//!
//! A binary fuse filter's peeling construction can get stuck: every remaining
//! key sits on a table slot with two or more other keys, and no further slot
//! can be resolved. The standard fix is a full restart under a fresh seed,
//! which succeeds with high but not certain probability per attempt.
//!
//! A zor filter never restarts. When peeling would otherwise get stuck, it
//! deterministically abandons all but one of the keys crowding the
//! lowest-degree slot and continues. The abandoned keys — typically a small
//! fraction of the input — go into an auxiliary [`Fuse001`](dmc_fuse::Fuse001)
//! built over that remainder, restoring the same false-positive-only
//! semantics as fuse at a smaller total table size: the main structure needs
//! less slack than fuse's because it never has to survive a full restart, and
//! the auxiliary holds only the keys that were abandoned.
//!
//! # Examples
//!
//! ```
//! use dmc_zor::Zor001;
//! use dmc_core::{Filter, Params};
//!
//! let keys: Vec<&[u8]> = vec![b"alice", b"bob"];
//! let filter = Zor001::build(&keys, &Params::default())?;
//!
//! assert!(filter.contains(b"alice"));
//! # Ok::<(), dmc_core::Error>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::pedantic)]

pub mod zor_001;

pub use zor_001::Zor001;
