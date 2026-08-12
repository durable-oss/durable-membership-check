//! Fast, low-dependency membership and approximate membership filters.
//!
//! `dmc` is the front door: it links the filter implementations and re-exports
//! the core API, so depending on this one crate gives you every filter by name.
//!
//! # Choosing a filter
//!
//! - **Bloom** (`bloom`) — the general default. Tunable false positive rate,
//!   builds incrementally in one pass, tolerates duplicate keys.
//! - **Xor** and **binary fuse** — smaller than Bloom at the same false
//!   positive rate, and faster to query, but require the complete distinct key
//!   set up front and cost more to build.
//! - **Zor** (`zor`) — smaller still than binary fuse, by deterministic
//!   peeling that abandons a small fraction of keys to an auxiliary filter
//!   instead of restarting construction. Costs more to build than either.
//!
//! # Naming
//!
//! Ask for a family (`"bloom"`) to get the newest implementation linked in.
//! Ask for an exact id (`"bloom_001"`) when you need results that stay
//! bit-identical as the library evolves. Published implementations are frozen:
//! `bloom_001` will always accept and reject exactly the keys it does today.
//!
//! # Examples
//!
//! ```
//! use dmc::{build, Filter, Params};
//!
//! let keys: Vec<&[u8]> = vec![b"alice", b"bob", b"carol"];
//! let filter = build("bloom", &keys, &Params::new(3, 0.01))?;
//!
//! assert!(filter.contains(b"alice"));
//! assert!(!filter.contains(b"mallory"));
//! # Ok::<(), dmc::Error>(())
//! ```
//!
//! Filters round-trip through bytes, routed back to the implementation that
//! wrote them:
//!
//! ```
//! use dmc::{build, decode, Filter, Params};
//!
//! let keys: Vec<&[u8]> = vec![b"alice"];
//! let filter = build("bloom", &keys, &Params::new(1, 0.01))?;
//!
//! let mut bytes = Vec::new();
//! filter.encode(&mut bytes)?;
//!
//! let restored = decode(&bytes)?;
//! assert!(restored.contains(b"alice"));
//! # Ok::<(), dmc::Error>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::pedantic)]

pub use dmc_core::{
    Error, Filter, Header, Params, Result, build, decode, family, registrations, resolve_alias,
};

#[cfg(feature = "bloom")]
#[doc(inline)]
pub use dmc_bloom as bloom;

#[cfg(feature = "xor")]
#[doc(inline)]
pub use dmc_xor as xor;

#[cfg(feature = "fuse")]
#[doc(inline)]
pub use dmc_fuse as fuse;

#[cfg(feature = "zor")]
#[doc(inline)]
pub use dmc_zor as zor;

/// Returns the ids of every filter implementation linked into this binary.
///
/// # Examples
///
/// ```
/// let names = dmc::filter_ids();
/// assert!(names.contains(&"bloom_001"));
/// ```
#[must_use]
pub fn filter_ids() -> Vec<&'static str> {
    registrations().map(|reg| reg.id).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bloom_is_reachable_through_the_registry() {
        let keys: Vec<&[u8]> = vec![b"alice", b"bob"];
        let filter = build("bloom", &keys, &Params::new(2, 0.01)).unwrap();

        assert!(filter.contains(b"alice"));
        assert!(filter.contains(b"bob"));
    }

    #[test]
    fn family_alias_resolves_to_the_highest_version() {
        assert_eq!(resolve_alias("bloom"), Some("bloom_001"));
    }

    #[test]
    fn exact_id_is_not_a_family_alias() {
        assert_eq!(resolve_alias("bloom_001"), None);
    }

    #[test]
    fn exact_id_and_family_build_the_same_filter_today() {
        let keys: Vec<&[u8]> = vec![b"alice"];
        let params = Params::new(1, 0.01);

        let by_family = build("bloom", &keys, &params).unwrap();
        let by_id = build("bloom_001", &keys, &params).unwrap();

        assert_eq!(by_family.id(), by_id.id());
    }

    #[test]
    fn unknown_name_is_reported_not_defaulted() {
        let err = build("no-such-filter", &[], &Params::default()).unwrap_err();
        assert!(matches!(err, Error::UnknownFilter { .. }));
    }

    #[test]
    fn encoded_filter_routes_back_to_its_implementation() {
        let keys: Vec<&[u8]> = vec![b"alice", b"bob"];
        let filter = build("bloom_001", &keys, &Params::new(2, 0.01)).unwrap();

        let mut bytes = Vec::new();
        filter.encode(&mut bytes).unwrap();

        let restored = decode(&bytes).unwrap();
        assert_eq!(restored.id(), "bloom_001");
        assert!(restored.contains(b"alice"));
        assert!(restored.contains(b"bob"));
    }

    #[test]
    fn decoding_an_unlinked_version_names_the_family() {
        // A bloom version this binary does not link. The family is known, so
        // the error can still render the id an operator would recognize.
        let mut bytes = Vec::new();
        Header::new(family::code_for("bloom").unwrap(), 999, 1, 0, 0, 64).encode(&mut bytes);
        // Checksummed like any real encoding, so the decode reaches routing
        // rather than stopping at the integrity check.
        Header::finalize(&mut bytes, 0);

        let err = decode(&bytes).unwrap_err();
        assert!(
            matches!(
                err,
                Error::UnknownEncoding {
                    family: Some("bloom"),
                    version: 999,
                    ..
                }
            ),
            "got {err:?}"
        );
        assert!(err.to_string().contains("bloom_999"), "got {err}");
    }

    #[test]
    fn decoding_an_unknown_family_reports_the_code() {
        // A private-use code names nothing this build can resolve, so the
        // message has only numbers to work with.
        let mut bytes = Vec::new();
        Header::new(family::PRIVATE_USE_START, 1, 1, 0, 0, 64).encode(&mut bytes);
        Header::finalize(&mut bytes, 0);

        let err = decode(&bytes).unwrap_err();
        assert!(
            matches!(err, Error::UnknownEncoding { family: None, .. }),
            "got {err:?}"
        );
        assert!(err.to_string().contains("1000"), "got {err}");
    }

    #[test]
    fn decoding_garbage_is_an_error_not_a_panic() {
        assert!(decode(&[]).is_err());
        assert!(decode(b"too-short-to-be-a-header").is_err());
        // A zeroed buffer of the right length: the reserved-zero fields are
        // what stop this parsing as a valid header.
        assert!(decode(&[0u8; Header::SIZE]).is_err());
    }

    #[test]
    fn registry_lists_linked_implementations() {
        let ids = filter_ids();
        assert!(ids.contains(&"bloom_001"), "got {ids:?}");
    }
}
