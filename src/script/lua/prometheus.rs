//! Public Prometheus EncryptStrings arithmetic, parameterised by source facts.
//! Algorithm constants are fixed; keys, seeds and multipliers are never fixed.
use super::whole;
use std::collections::BTreeSet;
pub(super) const MOD45: f64 = 35184372088832.;
#[derive(Clone, Copy, Debug)]
pub(super) struct Cipher {
    pub mul45: f64,
    pub add45: f64,
    pub mul8: f64,
    pub key: u8,
}
#[derive(Default, Debug)]
pub(super) struct Discovery {
    lcg45: BTreeSet<(i64, i64)>,
    lcg8: BTreeSet<u16>,
    keys: BTreeSet<u8>,
    mod32: bool,
    mod_word: bool,
    mod_byte: bool,
    variable_shift: bool,
}
impl Discovery {
    pub(super) fn operation(
        &mut self,
        op: &str,
        a: Option<f64>,
        b: Option<f64>,
        symbolic_right: bool,
    ) {
        self.mod32 |= op == "%" && b == Some(32.);
        self.mod_word |= op == "%" && b == Some(4294967296.);
        self.mod_byte |= op == "%" && b == Some(256.);
        self.variable_shift |= op == "^" && a == Some(2.) && symbolic_right;
    }
    pub(super) fn lcg45(&mut self, mul: f64, add: f64) {
        if let (Some(m), Some(a)) = (whole(mul), whole(add))
            && (1..256).contains(&m)
            && m % 4 == 1
            && (0. ..MOD45).contains(&add)
            && a % 2 == 1
        {
            self.lcg45.insert((m, a));
        }
    }
    pub(super) fn lcg8(&mut self, mul: f64) {
        if let Some(m) = whole(mul).and_then(|m| u16::try_from(m).ok())
            && (2..257).contains(&m)
        {
            self.lcg8.insert(m);
        }
    }
    pub(super) fn key(&mut self, key: u8) {
        self.keys.insert(key);
    }
    pub(super) fn cipher(&self) -> Option<Cipher> {
        if self.lcg45.len() != 1
            || self.lcg8.len() != 1
            || self.keys.len() != 1
            || !self.mod32
            || !self.mod_word
            || !self.mod_byte
            || !self.variable_shift
        {
            return None;
        }
        let (m, a) = *self.lcg45.first()?;
        Some(Cipher {
            mul45: m as f64,
            add45: a as f64,
            mul8: f64::from(*self.lcg8.first()?),
            key: *self.keys.first()?,
        })
    }
}
fn modulo(a: f64, b: f64) -> f64 {
    a - (a / b).floor() * b
}
impl Cipher {
    fn stream(self, seed: f64, len: usize) -> Vec<u8> {
        let mut s45 = modulo(seed, MOD45);
        let mut s8 = modulo(seed, 255.) + 2.;
        let mut out = Vec::with_capacity(len);
        while out.len() < len {
            let product = s45 * self.mul45;
            s45 = modulo(product + self.add45, MOD45);
            let mut found = false;
            for _ in 0..256 {
                s8 = modulo(s8 * self.mul8, 257.);
                if s8 != 1. {
                    found = true;
                    break;
                }
            }
            if !found {
                return Vec::new();
            }
            let r = modulo(s8, 32.);
            let tmp = (s45 / 2f64.powf(13. - (s8 - r) / 32.)).floor();
            let n = modulo(tmp, 4294967296.) / 2f64.powf(r);
            let rnd = (modulo(n, 1.) * 4294967296.).floor() + n.floor();
            let low = modulo(rnd, 65536.);
            let high = (rnd - low) / 65536.;
            #[expect(
                clippy::cast_possible_truncation,
                clippy::cast_sign_loss,
                reason = "modulo keeps each value in [0, 256); `as` floors it like the reference"
            )]
            let bytes = [
                modulo(high / 256., 256.) as u8,
                modulo(high, 256.) as u8,
                modulo(low / 256., 256.) as u8,
                modulo(low, 256.) as u8,
            ];
            out.extend(bytes.into_iter().take(len - out.len()));
        }
        out
    }
    pub(super) fn decrypt(self, input: &[u8], seed: f64) -> Vec<u8> {
        let stream = self.stream(seed, input.len());
        if stream.len() != input.len() {
            return Vec::new();
        }
        let mut prev = self.key;
        input
            .iter()
            .zip(stream)
            .map(|(a, b)| {
                prev = a.wrapping_add(b).wrapping_add(prev);
                prev
            })
            .collect()
    }
    #[cfg(test)]
    pub(super) fn encrypt(self, input: &[u8], seed: f64) -> Vec<u8> {
        let stream = self.stream(seed, input.len());
        let mut prev = self.key;
        input
            .iter()
            .zip(stream)
            .map(|(a, b)| {
                let v = a.wrapping_sub(b).wrapping_sub(prev);
                prev = *a;
                v
            })
            .collect()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn byte_order_and_feedback_known_vector() {
        let c = Cipher {
            mul45: 5.,
            add45: 12345678901.,
            mul8: 3.,
            key: 73,
        };
        let plaintext = b"static arithmetic, no interpreter";
        let ciphertext = [
            207, 1, 176, 65, 76, 100, 142, 45, 107, 21, 178, 164, 124, 209, 27, 48, 49, 28, 43, 23,
            8, 210, 60, 73, 211, 188, 149, 108, 103, 141, 181, 129, 78,
        ];
        assert_eq!(c.encrypt(plaintext, 817263541209.), ciphertext);
        assert_eq!(c.decrypt(&ciphertext, 817263541209.), plaintext);
        assert_ne!(
            Cipher { key: 74, ..c }.decrypt(&ciphertext, 817263541209.),
            plaintext
        );
    }
    #[test]
    fn ambiguous_parameter_sets_are_rejected() {
        let mut d = Discovery::default();
        d.operation("%", None, Some(32.), false);
        d.operation("%", None, Some(4294967296.), false);
        d.operation("%", None, Some(256.), false);
        d.operation("^", Some(2.), None, true);
        d.lcg45(5., 12345678901.);
        d.lcg8(3.);
        d.key(73);
        assert!(d.cipher().is_some());
        d.lcg45(9., 98765432101.);
        assert!(d.cipher().is_none());
    }
}
