//! Garble transformation operators.
//!
//! Garble's "simple" transformation uses one of three byte-wise operations
//! to encrypt strings. This module provides the operator enum and application.

/// Operators used by garble's simple transformation.
///
/// Garble encrypts strings using one of three reversible byte-wise operations:
/// - XOR: self-inverse, decrypt with XOR
/// - ADD: decrypt with SUB (wrapping)
/// - SUB: decrypt with ADD (wrapping)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GarbleOp {
    /// XOR operation (self-inverse)
    Xor = 0,
    /// Subtraction to reverse ADD encryption: plaintext = ciphertext - key
    Sub = 1,
    /// Addition to reverse SUB encryption: plaintext = ciphertext + key
    Add = 2,
}

impl GarbleOp {
    /// Apply this operator to decode a byte pair.
    #[inline]
    pub fn apply(self, ciphertext: u8, key: u8) -> u8 {
        match self {
            Self::Xor => ciphertext ^ key,
            Self::Sub => ciphertext.wrapping_sub(key),
            Self::Add => ciphertext.wrapping_add(key),
        }
    }

    /// All available operators for iteration.
    pub const ALL: [Self; 3] = [Self::Xor, Self::Sub, Self::Add];
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xor_is_self_inverse() {
        let plaintext = b"hello";
        let key = b"world";

        // Encrypt
        let encrypted: Vec<u8> = plaintext
            .iter()
            .zip(key.iter())
            .map(|(&p, &k)| GarbleOp::Xor.apply(p, k))
            .collect();

        // Decrypt (XOR again)
        let decrypted: Vec<u8> = encrypted
            .iter()
            .zip(key.iter())
            .map(|(&c, &k)| GarbleOp::Xor.apply(c, k))
            .collect();

        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_add_sub_inverse() {
        let plaintext = b"test";
        let key = b"key!";

        // Encrypt with ADD
        let encrypted: Vec<u8> = plaintext
            .iter()
            .zip(key.iter())
            .map(|(&p, &k)| p.wrapping_add(k))
            .collect();

        // Decrypt with SUB
        let decrypted: Vec<u8> = encrypted
            .iter()
            .zip(key.iter())
            .map(|(&c, &k)| GarbleOp::Sub.apply(c, k))
            .collect();

        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_sub_add_inverse() {
        let plaintext = b"data";
        let key = b"abcd";

        // Encrypt with SUB
        let encrypted: Vec<u8> = plaintext
            .iter()
            .zip(key.iter())
            .map(|(&p, &k)| p.wrapping_sub(k))
            .collect();

        // Decrypt with ADD
        let decrypted: Vec<u8> = encrypted
            .iter()
            .zip(key.iter())
            .map(|(&c, &k)| GarbleOp::Add.apply(c, k))
            .collect();

        assert_eq!(&decrypted, plaintext);
    }
}
