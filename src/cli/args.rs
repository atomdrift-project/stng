//! Parsers for command-line values clap cannot parse on its own.

use std::ops::Range;

/// A `--xor` key.
#[derive(Debug, Clone)]
pub(crate) struct XorKey(pub(crate) Vec<u8>);

/// `0x`/`0X`/`hex:` then hex digit pairs, otherwise the text's bytes.
pub(crate) fn parse_xor_key(input: &str) -> Result<XorKey, String> {
    let hex = ["0x", "0X", "hex:"]
        .iter()
        .find_map(|prefix| input.strip_prefix(prefix));
    let Some(hex) = hex else {
        return if input.is_empty() {
            Err("the key is empty".to_string())
        } else {
            Ok(XorKey(input.as_bytes().to_vec()))
        };
    };
    if hex.is_empty() || !hex.len().is_multiple_of(2) || !hex.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(format!(
            "'{input}': a hex key needs a non-empty, even number of hex digits"
        ));
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect::<Result<_, _>>()
        .map(XorKey)
}

/// An `--xor-lcg` keystream and the file range it decodes.
#[derive(Debug, Clone)]
pub(crate) struct LcgRange(pub(crate) stng::Lcg, pub(crate) Range<usize>);

/// `seed,multiplier,modulus,mask,offset,length`, each decimal or `0x` hex.
pub(crate) fn parse_lcg(input: &str) -> Result<LcgRange, String> {
    let integer = |field: &str| -> Result<u64, String> {
        let parsed = match field
            .strip_prefix("0x")
            .or_else(|| field.strip_prefix("0X"))
        {
            Some(hex) => u64::from_str_radix(hex, 16),
            None => field.parse(),
        };
        parsed.map_err(|e| format!("'{field}': {e}"))
    };
    let fields: Vec<&str> = input.split(',').map(str::trim).collect();
    let [seed, multiplier, modulus, mask, offset, length] = fields[..] else {
        return Err("expected seed,multiplier,modulus,mask,offset,length".to_string());
    };
    let lcg = stng::Lcg {
        seed: integer(seed)?,
        multiplier: integer(multiplier)?,
        modulus: integer(modulus)?,
        mask: u8::try_from(integer(mask)?)
            .map_err(|e| format!("the mask must fit in a byte: {e}"))?,
    };
    let offset = usize::try_from(integer(offset)?).map_err(|e| e.to_string())?;
    let length = usize::try_from(integer(length)?).map_err(|e| e.to_string())?;
    if lcg.multiplier == 0 || lcg.modulus == 0 || length == 0 {
        return Err("the multiplier, modulus and length must be nonzero".to_string());
    }
    let end = offset
        .checked_add(length)
        .ok_or("offset + length overflows")?;
    Ok(LcgRange(lcg, offset..end))
}

#[cfg(test)]
mod tests;
