//! Base64 (RFC 4648, standard alphabet, padded).
//!
//! Spec S8.3 fixes base64 as the punt frame encoding and spec S2 closes the
//! dependency list, so this is ~40 lines of table lookup rather than a crate.

/// The standard alphabet.
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encode `bytes`.
///
/// Cost: O(n), one allocation of the exact output size.
#[must_use]
pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = u32::from_be_bytes([0, b[0], b[1], b[2]]);
        let digits = [n >> 18, (n >> 12) & 63, (n >> 6) & 63, n & 63];
        for (i, d) in digits.into_iter().enumerate() {
            // Two output digits per input byte, rounded up; the rest is padding.
            out.push(if i <= chunk.len() {
                ALPHABET[d as usize] as char
            } else {
                '='
            });
        }
    }
    out
}

/// Decode `text`, or `None` if it is not valid padded base64.
#[must_use]
pub fn decode(text: &str) -> Option<Vec<u8>> {
    let text = text.as_bytes();
    if !text.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    for chunk in text.chunks(4) {
        let mut n = 0u32;
        let mut bytes = 3;
        for (i, c) in chunk.iter().enumerate() {
            let value = match c {
                b'=' if i >= 2 => {
                    bytes = bytes.min(i - 1);
                    0
                }
                _ => ALPHABET.iter().position(|a| a == c)? as u32,
            };
            n = (n << 6) | value;
        }
        out.extend_from_slice(&n.to_be_bytes()[1..=bytes]);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The RFC 4648 section 10 test vectors.
    #[test]
    fn rfc_vectors_round_trip() {
        for (plain, encoded) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(encode(plain.as_bytes()), encoded, "encoding {plain:?}");
            assert_eq!(
                decode(encoded).as_deref(),
                Some(plain.as_bytes()),
                "decoding {encoded:?}"
            );
        }
    }

    #[test]
    fn arbitrary_bytes_round_trip() {
        let mut state = 0x2545_f491u32;
        for len in 0..300usize {
            let bytes: Vec<u8> = (0..len)
                .map(|_| {
                    state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                    (state >> 24) as u8
                })
                .collect();
            assert_eq!(
                decode(&encode(&bytes)).as_deref(),
                Some(bytes.as_slice()),
                "len {len}"
            );
        }
    }

    #[test]
    fn malformed_input_is_rejected_not_guessed() {
        assert_eq!(decode("Zg="), None, "length must be a multiple of four");
        assert_eq!(decode("Z!=="), None, "alphabet is exact");
    }
}
