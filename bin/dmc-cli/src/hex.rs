//! Hex encoding for keys and encoded filters.
//!
//! Keys are arbitrary bytes and JSON strings are Unicode, so every key crosses
//! the boundary as hex. Hand-written rather than pulled from a crate: it is
//! twenty lines, and the correctness suite deliberately sends malformed hex to
//! check the error path, so the rejection rules should be visible here rather
//! than inherited from a dependency.

/// Renders bytes as lowercase hex.
///
/// # Examples
///
/// ```
/// # use dmc_cli::hex::encode;
/// assert_eq!(encode(b"\x00\xff"), "00ff");
/// assert_eq!(encode(b""), "");
/// ```
#[must_use]
pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        // `write!` to a String cannot fail, but returns a Result; pushing the
        // two nibbles directly avoids having to justify an unwrap.
        out.push(nibble(byte >> 4));
        out.push(nibble(byte & 0x0f));
    }
    out
}

/// Maps a 0..=15 value to its lowercase hex digit.
fn nibble(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        // Bounded by the caller, which masks to four bits.
        _ => (b'a' + value - 10) as char,
    }
}

/// Parses lowercase or uppercase hex into bytes.
///
/// # Errors
///
/// Returns a message naming the problem if the input has an odd length or
/// contains a non-hex character. Both are client mistakes rather than filter
/// failures, and the suite asserts they are reported as such.
///
/// # Examples
///
/// ```
/// # use dmc_cli::hex::decode;
/// assert_eq!(decode("00FF").unwrap(), vec![0x00, 0xff]);
/// assert!(decode("abc").is_err(), "odd length");
/// assert!(decode("zz").is_err(), "not hex");
/// ```
pub fn decode(text: &str) -> Result<Vec<u8>, String> {
    let bytes = text.as_bytes();

    if bytes.len() % 2 != 0 {
        return Err(format!(
            "hex string has odd length {}; every byte needs two digits",
            bytes.len()
        ));
    }

    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let hi = digit(pair[0])?;
        let lo = digit(pair[1])?;
        out.push((hi << 4) | lo);
    }

    Ok(out)
}

/// Parses one hex digit.
fn digit(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(format!(
            "`{}` is not a hex digit",
            char::from(byte).escape_default()
        )),
    }
}

/// Decodes a list of hex strings, naming the index of the first bad one.
///
/// # Errors
///
/// Returns a message identifying which key failed, since a client sending ten
/// thousand keys needs to know which one it got wrong.
pub fn decode_all(items: &[String]) -> Result<Vec<Vec<u8>>, String> {
    items
        .iter()
        .enumerate()
        .map(|(i, text)| decode(text).map_err(|why| format!("key {i}: {why}")))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_arbitrary_bytes() {
        let original: Vec<u8> = (0..=255).collect();
        assert_eq!(decode(&encode(&original)).unwrap(), original);
    }

    #[test]
    fn empty_input_round_trips() {
        assert_eq!(encode(&[]), "");
        assert_eq!(decode("").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn encoding_is_lowercase() {
        assert_eq!(encode(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
    }

    #[test]
    fn decoding_accepts_uppercase() {
        assert_eq!(decode("DEADBEEF").unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn odd_length_is_rejected() {
        let err = decode("abc").unwrap_err();
        assert!(err.contains("odd length"), "got {err}");
    }

    #[test]
    fn non_hex_character_is_rejected() {
        let err = decode("zz").unwrap_err();
        assert!(err.contains("not a hex digit"), "got {err}");
    }

    #[test]
    fn decode_all_names_the_offending_index() {
        let items = vec!["00".to_string(), "zz".to_string()];
        let err = decode_all(&items).unwrap_err();
        assert!(err.starts_with("key 1:"), "got {err}");
    }

    #[test]
    fn keys_with_embedded_nul_survive() {
        // The encoding format uses NUL to terminate the implementation id, so
        // a key containing one is worth carrying through explicitly.
        let key = b"key\x00with\x00nuls";
        assert_eq!(decode(&encode(key)).unwrap(), key);
    }
}
