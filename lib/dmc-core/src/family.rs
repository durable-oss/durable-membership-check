//! Numeric family codes carried in the encoded header.
//!
//! An encoded filter names the implementation that can decode it. That name is
//! a `(family_code, version)` pair rather than a string, so the header stays
//! fixed-width and a decoder can route without parsing.
//!
//! # The code space
//!
//! | Range | Owner |
//! |---|---|
//! | `0` | Invalid. A zeroed header fails validation rather than resolving. |
//! | `1..=999` | Assigned here, in [`KNOWN`]. |
//! | `1000..` | Caller-assigned, for families that live outside this project. |
//!
//! Families in the assigned range get their code from [`code_for`] at compile
//! time, so [`register_filter!`](crate::register_filter) never needs a
//! `family_code` clause for them. A crate registering a family this table does
//! not know supplies its own code above `PRIVATE_USE_START` and is responsible
//! for not colliding with other out-of-tree filters.
//!
//! Codes are permanent. Reusing a retired code would make old encodings decode
//! as the wrong filter, which is the one failure the pair is meant to prevent.

/// First code that this table does not assign.
///
/// Codes at or above this are for families outside this project. Nothing here
/// validates them beyond requiring they not be zero, because nothing here can.
pub const PRIVATE_USE_START: u32 = 1000;

/// Every family code assigned by this project, paired with its name.
///
/// Order is by code so that a reader can see the next free one. Entries are
/// never removed or renumbered; see the module docs.
pub const KNOWN: &[(u32, &str)] = &[
    (1, "bloom"),
    // Reserved for the implementations in PLANS; assigning the codes now keeps
    // them stable whether or not those land in this order.
    (2, "xor"),
    (3, "fuse"),
    (4, "ribbon"),
    (5, "quotient"),
    (6, "cuckoo"),
    (7, "zor"),
];

/// Returns the assigned code for `family`, or `None` if this table has none.
///
/// `const` because [`register_filter!`](crate::register_filter) resolves the
/// code at compile time, where iteration over a slice is available but string
/// comparison operators are not.
///
/// # Examples
///
/// ```
/// use dmc_core::family::code_for;
///
/// assert_eq!(code_for("bloom"), Some(1));
/// assert_eq!(code_for("not-a-family"), None);
/// ```
#[must_use]
pub const fn code_for(family: &str) -> Option<u32> {
    let needle = family.as_bytes();

    let mut i = 0;
    while i < KNOWN.len() {
        let (code, name) = KNOWN[i];
        if str_eq(name.as_bytes(), needle) {
            return Some(code);
        }
        i += 1;
    }

    None
}

/// Returns the family name for `code`, or `None` if this table has none.
///
/// This is what lets [`Error::UnknownEncoding`](crate::Error::UnknownEncoding)
/// report `bloom_007` for a filter this binary cannot decode: the code resolves
/// to a name even when no implementation with that version is linked.
///
/// # Examples
///
/// ```
/// use dmc_core::family::name_for;
///
/// assert_eq!(name_for(1), Some("bloom"));
/// assert_eq!(name_for(1042), None);
/// ```
#[must_use]
pub const fn name_for(code: u32) -> Option<&'static str> {
    let mut i = 0;
    while i < KNOWN.len() {
        let (assigned, name) = KNOWN[i];
        if assigned == code {
            return Some(name);
        }
        i += 1;
    }

    None
}

/// Byte-compares two strings in a `const` context.
///
/// `==` on `&str` is not `const`, and neither is `slice::eq`, so the comparison
/// is written out. Only used by [`code_for`] and only at compile time.
const fn str_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }

    true
}

/// Resolves a family name to its code, panicking at compile time if unknown.
///
/// Used by [`register_filter!`](crate::register_filter) when the registration
/// supplies no explicit `family_code`. The panic is a compile error at the
/// registration site, which is where the fix belongs: either add the family to
/// [`KNOWN`] or declare a private-use code.
///
/// # Panics
///
/// Panics at compile time if `family` is not in [`KNOWN`].
#[must_use]
pub const fn require_code_for(family: &str) -> u32 {
    match code_for(family) {
        Some(code) => code,
        None => panic!(
            "unknown filter family: add it to dmc_core::family::KNOWN, \
             or give register_filter! an explicit `family_code:` at or above \
             dmc_core::family::PRIVATE_USE_START"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn codes_are_unique() {
        let codes: HashSet<u32> = KNOWN.iter().map(|&(code, _)| code).collect();
        assert_eq!(codes.len(), KNOWN.len(), "a family code is assigned twice");
    }

    #[test]
    fn names_are_unique() {
        let names: HashSet<&str> = KNOWN.iter().map(|&(_, name)| name).collect();
        assert_eq!(names.len(), KNOWN.len(), "a family name is assigned twice");
    }

    #[test]
    fn zero_is_not_assigned() {
        // A zeroed header must fail validation rather than resolving to a real
        // family, so nothing may claim code 0.
        assert!(name_for(0).is_none());
    }

    #[test]
    fn assigned_codes_stay_below_the_private_use_range() {
        for &(code, name) in KNOWN {
            assert!(
                code < PRIVATE_USE_START,
                "{name} is assigned {code}, inside the private-use range"
            );
        }
    }

    #[test]
    fn lookup_round_trips_in_both_directions() {
        for &(code, name) in KNOWN {
            assert_eq!(code_for(name), Some(code));
            assert_eq!(name_for(code), Some(name));
        }
    }

    #[test]
    fn unknown_lookups_report_nothing() {
        assert_eq!(code_for(""), None);
        assert_eq!(code_for("bloo"), None);
        assert_eq!(code_for("bloomm"), None);
        assert_eq!(name_for(PRIVATE_USE_START), None);
    }
}
