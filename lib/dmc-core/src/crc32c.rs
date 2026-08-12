//! CRC-32C, the integrity check over an encoded filter.
//!
//! Encoded filters cross trust boundaries: a file, a network, a language
//! binding. Structural validation catches a truncated or nonsensical header,
//! but it cannot catch a header that is structurally perfect and semantically
//! wrong — a flipped bit in the seed decodes into a filter that answers
//! differently from the one that was written, including `false` for keys that
//! were inserted.
//!
//! This closes that gap. [`Header::decode`](crate::header::Header::decode)
//! refuses an encoding whose checksum does not match, so a corrupted filter
//! fails to load rather than quietly returning wrong answers.
//!
//! # Why CRC-32C rather than a hash
//!
//! The errors worth catching here are bit flips and short bursts — storage rot,
//! a truncated write, a mangled transfer. A CRC is a linear code with *proven*
//! Hamming-distance guarantees over a bounded length, so for those patterns it
//! does not merely probably detect the error, it certainly does. Castagnoli's
//! polynomial gives HD=6 out to about 5.2 KB and HD=4 well past any filter this
//! library will encode, meaning every 3-bit error in a small filter is caught
//! with certainty.
//!
//! A general-purpose hash such as xxHash gives a probabilistic bound with no
//! guarantee for any specific error pattern. Faster in throughput terms, but
//! strictly weaker on exactly the failure mode this exists for. It is also a
//! moving target across versions, which a frozen encoding cannot afford.
//!
//! # What it cannot do
//!
//! It detects that the bytes changed. It cannot make a corrupted filter sound.
//!
//! Clearing a set bit in a Bloom filter's bit array produces a perfectly valid
//! encoding of a smaller key set — the bytes *are* the data, so no checksum
//! recovers what was lost. What this buys is that such an encoding refuses to
//! load rather than silently answering `false` for a key that was inserted. A
//! filter that fails loudly is recoverable; one that quietly lies is not.
//!
//! # This is not a security check
//!
//! CRC-32C is trivial to forge. An attacker who can rewrite an encoded filter
//! can recompute its checksum. This detects accidents, not tampering. A filter
//! read from an untrusted source needs a MAC, which is a different problem with
//! a different answer.

/// Castagnoli's polynomial, in reversed (least-significant-bit-first) form.
///
/// The normal form is `0x1EDC6F41`; reversing it lets the update loop shift
/// right, which is how the table-driven implementation below works.
const POLYNOMIAL: u32 = 0x82F6_3B78;

/// Lookup table over every byte value, built once at compile time.
///
/// Eight bits of the polynomial division per table entry, so the update loop
/// handles a whole byte per step instead of one bit. The table costs 1 KiB of
/// read-only data and buys roughly an eightfold speedup over the bitwise form.
const TABLE: [u32; 256] = build_table();

/// Computes the lookup table.
const fn build_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut byte = 0usize;

    while byte < 256 {
        // Not a truncating cast: the loop bound keeps `byte` under 256.
        #[allow(clippy::cast_possible_truncation)]
        let mut crc = byte as u32;

        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ POLYNOMIAL
            } else {
                crc >> 1
            };
            bit += 1;
        }

        table[byte] = crc;
        byte += 1;
    }

    table
}

/// Returns the CRC-32C of `bytes`.
///
/// # Examples
///
/// The check values from RFC 3720 appendix B, which any CRC-32C implementation
/// must reproduce:
///
/// ```
/// use dmc_core::crc32c::checksum;
///
/// assert_eq!(checksum(b""), 0x0000_0000);
/// assert_eq!(checksum(b"123456789"), 0xE306_9283);
/// assert_eq!(checksum(&[0u8; 32]), 0x8A91_36AA);
/// assert_eq!(checksum(&[0xFFu8; 32]), 0x62A8_AB43);
/// ```
///
/// Distinct inputs almost always differ, and a single flipped bit always does:
///
/// ```
/// use dmc_core::crc32c::checksum;
///
/// let original = b"the quick brown fox";
/// let mut flipped = *original;
/// flipped[0] ^= 0x01;
///
/// assert_ne!(checksum(original), checksum(&flipped));
/// ```
#[must_use]
pub fn checksum(bytes: &[u8]) -> u32 {
    update(0, bytes)
}

/// Continues a running CRC-32C over another slice.
///
/// Lets a caller checksum a header and a body without concatenating them into
/// one buffer first, which for a gigabyte-scale filter matters.
///
/// Pass `0` as the initial `crc`. The pre- and post-inversion that the standard
/// requires happen inside this function, so chaining calls gives the same
/// result as one call over the concatenation.
///
/// # Examples
///
/// ```
/// use dmc_core::crc32c::{checksum, update};
///
/// let whole = checksum(b"header+body");
/// let piecewise = update(update(0, b"header+"), b"body");
///
/// assert_eq!(whole, piecewise);
/// ```
#[must_use]
pub fn update(crc: u32, bytes: &[u8]) -> u32 {
    // The standard specifies a starting register of all ones and a final
    // inversion. Storing the inverted form between calls is what makes
    // chaining work without the caller knowing about either step.
    let mut register = !crc;

    for &byte in bytes {
        // The XOR result is masked to 8 bits, so this cannot index past 256.
        let index = ((register ^ u32::from(byte)) & 0xFF) as usize;
        register = (register >> 8) ^ TABLE[index];
    }

    !register
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_the_rfc_3720_check_values() {
        // Appendix B of RFC 3720. An implementation that fails these is not
        // CRC-32C, whatever else it may be.
        assert_eq!(checksum(b""), 0x0000_0000);
        assert_eq!(checksum(b"123456789"), 0xE306_9283);
        assert_eq!(checksum(&[0u8; 32]), 0x8A91_36AA);
        assert_eq!(checksum(&[0xFFu8; 32]), 0x62A8_AB43);
    }

    #[test]
    fn detects_every_single_bit_flip_in_a_header_sized_message() {
        // The guarantee this was chosen for. At 81 bytes a CRC-32C has
        // Hamming distance 6, so no single-bit error can go undetected.
        let original = [0xA5u8; 81];
        let baseline = checksum(&original);

        for byte in 0..original.len() {
            for bit in 0..8 {
                let mut corrupted = original;
                corrupted[byte] ^= 1 << bit;

                assert_ne!(
                    checksum(&corrupted),
                    baseline,
                    "flipping bit {bit} of byte {byte} went undetected"
                );
            }
        }
    }

    #[test]
    fn detects_every_two_bit_flip_in_a_short_message() {
        // HD=6 also covers every 2- and 3-bit error at this length. Checked at
        // 16 bytes rather than 81 to keep the pair count reasonable.
        let original = [0x5Au8; 16];
        let baseline = checksum(&original);
        let bits = original.len() * 8;

        for first in 0..bits {
            for second in (first + 1)..bits {
                let mut corrupted = original;
                corrupted[first / 8] ^= 1 << (first % 8);
                corrupted[second / 8] ^= 1 << (second % 8);

                assert_ne!(
                    checksum(&corrupted),
                    baseline,
                    "flipping bits {first} and {second} went undetected"
                );
            }
        }
    }

    #[test]
    fn detects_truncation_and_extension() {
        let original = b"a filter's worth of bytes";

        assert_ne!(
            checksum(original),
            checksum(&original[..original.len() - 1])
        );
        assert_ne!(checksum(original), checksum(b"a filter's worth of bytes\0"));
    }

    #[test]
    fn detects_a_transposition() {
        // Swapped bytes are a classic case a simple sum would miss entirely.
        assert_ne!(checksum(b"ab"), checksum(b"ba"));
        assert_ne!(checksum(b"0123456789"), checksum(b"0123465789"));
    }

    #[test]
    fn chaining_matches_one_pass() {
        let whole: Vec<u8> = (0u8..=255).collect();

        for split in [0, 1, 17, 128, 255, 256] {
            let (head, tail) = whole.split_at(split);
            assert_eq!(
                checksum(&whole),
                update(update(0, head), tail),
                "chaining disagreed at a {split}-byte split"
            );
        }
    }

    #[test]
    fn leading_zeros_are_not_absorbed() {
        // A CRC that skipped its pre-inversion would give the same value for
        // these, which is the classic way to get a subtly wrong implementation.
        assert_ne!(checksum(b"\x00\x00data"), checksum(b"data"));
        assert_ne!(checksum(&[0u8; 1]), checksum(&[0u8; 2]));
    }

    #[test]
    fn is_deterministic_across_calls() {
        let bytes = b"determinism is the whole point";
        assert_eq!(checksum(bytes), checksum(bytes));
    }
}
