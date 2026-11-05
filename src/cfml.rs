//! Recovery of legacy ColdFusion encrypted templates (`cfencode`/CFCRYPT).
//!
//! These files are not ordinary compressed CFM: the fixed Allaire header is
//! followed by DES-ECB blocks derived from ColdFusion's historical
//! `DES_string_to_key` convention. Decode only the recognized template header
//! and validate the plaintext as CFML before returning it to string extraction.

use des::Des;
use des::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};

const HEADER: &[u8] = b"Allaire Cold Fusion Template\nHeader Size: ";
const NEW_VERSION: &[u8] = b"New Version";
const NEW_HEADER_SIZE: usize = 69;
const KEY: &[u8] = b"Error: cannot open template file--\"%s\". Please, try again!\n\n";
const MAX_TEMPLATE_SIZE: usize = 64 * 1024 * 1024;

/// Decode a legacy encrypted ColdFusion template to CFML source.
///
/// The result is present only when the fixed header, encrypted block layout,
/// delimiter (for New Version files), and recovered source all look valid.
pub(crate) fn decode(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < NEW_HEADER_SIZE || data.len() > MAX_TEMPLATE_SIZE || !data.starts_with(HEADER) {
        return None;
    }

    let (header_size, skip_delimiter) = if data.get(HEADER.len()..HEADER.len() + 11)? == NEW_VERSION
    {
        (NEW_HEADER_SIZE, true)
    } else {
        let digits = data
            .get(HEADER.len()..)?
            .iter()
            .take_while(|b| b.is_ascii_digit());
        let number: Vec<u8> = digits.copied().collect();
        if number.is_empty() {
            return None;
        }
        let size = std::str::from_utf8(&number).ok()?.parse::<usize>().ok()?;
        if size < HEADER.len() + number.len() || size > data.len() {
            return None;
        }
        (size, false)
    };

    let ciphertext = data.get(header_size..)?;
    if ciphertext.len() < 8 {
        return None;
    }

    let key = des_string_to_key(KEY)?;
    let cipher = Des::new_from_slice(&key).ok()?;
    let (chunks, remainder) = ciphertext.as_chunks::<8>();
    let mut plaintext = Vec::with_capacity(ciphertext.len());
    for chunk in chunks {
        let mut block = (*chunk).into();
        cipher.decrypt_block(&mut block);
        plaintext.extend_from_slice(&block);
    }

    // The historical reference decoder handles a final partial block with a
    // byte-position XOR after DES processing. Preserve that behavior.
    let full_len = chunks.len() * 8;
    for (index, byte) in remainder.iter().enumerate() {
        let pos_byte = u8::try_from(full_len.wrapping_add(index) & 0xff).unwrap_or(0);
        plaintext.push(byte ^ pos_byte);
    }

    if skip_delimiter {
        let delimiter = plaintext.iter().position(|byte| *byte == 0x1a)?;
        plaintext.drain(..=delimiter);
    }

    // The encrypted format has no authenticated integrity check. Reject bad
    // keys, truncated data, and coincidental magic by requiring a readable
    // body with recognizable CFML syntax.
    while plaintext
        .last()
        .is_some_and(|b| b.is_ascii_whitespace() || *b == 0)
    {
        plaintext.pop();
    }
    let printable = plaintext
        .iter()
        .filter(|b| b.is_ascii_graphic() || b.is_ascii_whitespace())
        .count();
    if plaintext.len() < 64 || printable * 100 / plaintext.len() < 90 {
        return None;
    }
    if !crate::bytes::contains_ignore_ascii_case(&plaintext, b"<cf") || !plaintext.contains(&b'>') {
        return None;
    }

    Some(plaintext)
}

/// OpenSSL-compatible MIT DES string-to-key derivation used by cfdecrypt.
fn des_string_to_key(input: &[u8]) -> Option<[u8; 8]> {
    let mut key = [0u8; 8];
    for (index, byte) in input.iter().copied().enumerate() {
        if index % 16 < 8 {
            key[index % 8] ^= byte.wrapping_shl(1);
        } else {
            key[7 - (index % 8)] ^= byte.reverse_bits();
        }
    }
    set_odd_parity(&mut key);

    let cipher = Des::new_from_slice(&key).ok()?;
    let mut iv = key;
    for chunk in input.chunks(8) {
        let mut block = [0u8; 8];
        block[..chunk.len()].copy_from_slice(chunk);
        for (byte, previous) in block.iter_mut().zip(iv) {
            *byte ^= previous;
        }
        let mut block = block.into();
        cipher.encrypt_block(&mut block);
        iv.copy_from_slice(&block);
    }
    set_odd_parity(&mut iv);
    Some(iv)
}

fn set_odd_parity(key: &mut [u8; 8]) {
    for byte in key {
        let upper = *byte & 0xfe;
        *byte = upper | u8::from(upper.count_ones() % 2 == 0);
    }
}

#[cfg(test)]
mod tests {
    use super::{KEY, decode, des_string_to_key};

    /// A template encrypted with the `des` 0.8 implementation this decoder
    /// was first validated against; it pins the key derivation and the
    /// block layout across cipher-crate upgrades.
    const TEMPLATE: &str = "416c6c6169726520436f6c6420467573696f6e2054656d706c6174650a486561646572\
        2053697a653a203434a666546d117b24358acad825bdd6b1ad4f2b8bf8db3d0202e589996069745e5e18\
        bfb953bc15e8a65594a30f40d435c4ce0cf4b9c4ff5686b981e83d801355e3591f87f11cf647da2fede6\
        3bdbeeaecc5bb501118dbb9aa5879cb065257ae786";

    #[test]
    fn derives_the_historical_key() {
        assert_eq!(
            des_string_to_key(KEY),
            Some([0x62, 0x31, 0xef, 0xba, 0x16, 0x31, 0xe0, 0x15])
        );
    }

    #[test]
    fn decrypts_a_known_template() {
        let file = crate::bytes::from_hex(TEMPLATE.as_bytes()).unwrap();
        let source = decode(&file).unwrap();
        assert_eq!(
            String::from_utf8(source).unwrap(),
            "<cfset secret = \"http://c2.example/drop\">\n<cfoutput>#secret#</cfoutput>\n<!-- padding padding -->"
        );
    }

    #[test]
    fn refuses_a_template_with_a_damaged_block() {
        let mut file = crate::bytes::from_hex(TEMPLATE.as_bytes()).unwrap();
        file[44] ^= 0xff; // the first ciphertext block
        assert!(decode(&file).is_none_or(|s| !s.starts_with(b"<cfset secret")));
    }
}
