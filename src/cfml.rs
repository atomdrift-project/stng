//! Recovery of legacy ColdFusion encrypted templates (`cfencode`/CFCRYPT).
//!
//! These files are not ordinary compressed CFM: the fixed Allaire header is
//! followed by DES-ECB blocks derived from ColdFusion's historical
//! `DES_string_to_key` convention. Decode only the recognized template header
//! and validate the plaintext as CFML before returning it to string extraction.

use des::Des;
use des::cipher::{BlockDecrypt, BlockEncrypt, KeyInit, generic_array::GenericArray};

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
    let full_len = ciphertext.len() / 8 * 8;
    let mut plaintext = Vec::with_capacity(ciphertext.len());
    for chunk in ciphertext[..full_len].chunks_exact(8) {
        let mut block = GenericArray::clone_from_slice(chunk);
        cipher.decrypt_block(&mut block);
        plaintext.extend_from_slice(&block);
    }

    // The historical reference decoder handles a final partial block with a
    // byte-position XOR after DES processing. Preserve that behavior.
    let remainder = &ciphertext[full_len..];
    for (index, byte) in remainder.iter().enumerate() {
        plaintext.push(byte ^ (full_len.wrapping_add(index) as u8));
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
    let lower = String::from_utf8_lossy(&plaintext).to_ascii_lowercase();
    if !lower.contains("<cf") || !lower.contains('>') {
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
        let mut block = GenericArray::clone_from_slice(&block);
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
