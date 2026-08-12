//! Command-line access to `durable-membership-check` filters.
//!
//! The binary exists so that a test harness written in another language can
//! drive every registered filter without linking Rust. The correctness suite
//! under `correctness-testing/` is written in Ruby and talks to this.
//!
//! # Two modes, one vocabulary
//!
//! `serve` reads newline-delimited JSON commands on stdin and writes one JSON
//! reply per line on stdout. Filters persist across commands under integer
//! handles, so a client builds once and probes a million times in a single
//! process.
//!
//! The one-shot subcommands (`list`, `describe`, `build`, `query`, `info`)
//! assemble the same [`Request`](wire::Request) from arguments and print the
//! same [`Response`](wire::Response). They exist for interactive use and for
//! tests that would rather not manage a subprocess.
//!
//! Both paths run through [`Session::handle`](session::Session::handle), so
//! neither can accept a command the other rejects.
//!
//! # Errors are replies
//!
//! Every failure — an unknown filter name, malformed hex, an out-of-range
//! parameter, a corrupt encoding — comes back as a JSON object with `ok: false`
//! and a machine-readable `kind`. Nothing panics and nothing exits mid-command,
//! because a correctness suite drives the error paths on purpose and has to
//! read the result.

//! # Linking the implementations
//!
//! Filters register themselves through `inventory`, which works by placing
//! entries in a linker section. A dependency that is never referenced can be
//! dropped before those sections are collected, leaving a binary whose registry
//! is empty — every command then reports `unknown_filter` for a filter that is
//! nominally compiled in.
//!
//! [`linked_filter_count`] exists to prevent that: it calls into `dmc`, which
//! keeps the crate and its registrations alive. Removing it makes this binary
//! silently useless, which is why it has a test rather than an `#[allow]`.

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::pedantic)]

pub mod hex;
pub mod session;
pub mod wire;

pub use session::Session;

/// Returns how many filter implementations are linked into this binary.
///
/// The call into `dmc` is load-bearing: it is the reference that stops the
/// linker discarding the implementation crates along with their `inventory`
/// registrations. See the note on linking in the module docs.
///
/// # Examples
///
/// ```
/// // The `bloom` feature is on by default, so at least one filter is linked.
/// assert!(dmc_cli::linked_filter_count() > 0);
/// ```
#[must_use]
pub fn linked_filter_count() -> usize {
    dmc::filter_ids().len()
}

#[cfg(test)]
mod tests {
    #[test]
    fn implementations_survive_linking() {
        // A zero here means the registry is empty and every command in this
        // binary would report `unknown_filter`. That has happened; see the
        // module docs.
        assert!(
            super::linked_filter_count() > 0,
            "no filters linked: inventory registrations were discarded"
        );
    }
}
