//! Core traits and plugin registry for `durable-membership-check`.
//!
//! This crate defines [`Filter`], the object-safe trait every membership
//! filter implements, and the [`registry`] that lets callers reach any linked
//! implementation by name. It contains no filter implementations itself.
//!
//! # Naming
//!
//! Implementations register under a versioned id such as `bloom_001`. That id
//! names a frozen implementation: once published, which keys it accepts and
//! rejects never changes. The bare family name `bloom` is an alias resolving
//! to the highest registered version, so linking a newer implementation
//! upgrades every caller that asked for the family without any code edits.
//!
//! Ask for a family name when you want the current best implementation; ask
//! for an exact id when you need bit-identical results over time.
//!
//! # Using this crate
//!
//! This crate holds no filter implementations, so on its own its registry is
//! empty. Most callers want the [`dmc`](https://docs.rs/dmc) facade, which
//! links the implementations and re-exports everything here.
//!
//! Depend on `dmc-core` directly when you are *writing* a filter: implement
//! [`Filter`] and register it with
//! [`register_filter!`](crate::register_filter), and every `dmc` consumer can
//! reach it by name without editing their code.

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::pedantic)]

pub mod capabilities;
pub mod crc32c;
pub mod error;
pub mod family;
pub mod filter;
pub mod hash;
pub mod header;
pub mod registry;

pub use capabilities::Capabilities;
pub use error::{Error, Result};
pub use filter::{Filter, Params};
pub use header::Header;
pub use registry::{build, decode, find, registrations, resolve_alias};

/// Re-exported so that [`register_filter!`](crate::register_filter) works in
/// crates that do not depend on `inventory` directly.
#[doc(hidden)]
pub use inventory;
