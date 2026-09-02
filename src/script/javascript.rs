//! JavaScript script deobfuscation patterns.
//!
//! Detects and decodes common JavaScript/Node.js obfuscation recipes:
//! - `eval(atob("..."))`
//! - `eval(Buffer.from("...", "base64").toString())`
//! - `eval(String.fromCharCode(...))`
//! - `eval("...".split("").reverse().join(""))`
//! - `eval(rot([...].map(c => String.fromCharCode(c)).join(""), n))`

use regex::Regex;
use std::sync::LazyLock;

use super::DeobfuscationResult;
use super::decode_chain::DecodeStep;

/// eval(atob("..."))
#[allow(clippy::expect_used)]
static EVAL_ATOB_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"eval\s*\(\s*atob\s*\(\s*['"]([A-Za-z0-9+/=\s]+)['"]\s*\)"#).expect("static regex")
});

/// eval(Buffer.from("...", "base64").toString())
#[allow(clippy::expect_used)]
static EVAL_BUFFER_B64_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"eval\s*\(\s*Buffer\.from\s*\(\s*['"]([A-Za-z0-9+/=\s]+)['"]\s*,\s*['"]base64['"]\s*\)\.toString\s*\(\s*\)"#)
        .expect("static regex")
});

/// eval(String.fromCharCode(...)) or Function(String.fromCharCode(...))()
#[allow(clippy::expect_used)]
static EVAL_CHARCODE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?:eval|Function)\s*\(\s*String\.fromCharCode\s*\(([0-9xXa-fA-F,\s]+)\)"#)
        .expect("static regex")
});

/// `[104,105,...].map(function(c){return String.fromCharCode(c)}).join("")`
///
/// The array spelling of the charcode recipe. `EVAL_CHARCODE_RE` above only
/// sees the direct `eval(String.fromCharCode(1,2,3))` call, so a packer that
/// builds the same string by mapping over an array — and then hands it to a
/// rotation function rather than straight to `eval` — passes through it
/// untouched. That is the shape the npm install-hook droppers use.
///
/// The digit run is required to be long because a short `[1,2,3].map(...)` is
/// ordinary application code; a packed payload is thousands of codes.
#[allow(clippy::expect_used)]
static CHARCODE_ARRAY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\[([0-9][0-9,\s]{200,})\]\s*\.\s*map\s*\(").expect("static regex")
});

/// eval("...".split("").reverse().join(""))
#[allow(clippy::expect_used)]
static EVAL_REVERSE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"eval\s*\(\s*['"]([^'"]+)['"]\s*\.split\s*\(\s*['"]['"]?\s*\)\s*\.reverse\s*\(\s*\)\s*\.join\s*\(\s*['"]['"]?\s*\)"#)
        .expect("static regex")
});

/// Extract all obfuscated payloads from a JavaScript source.
pub(super) fn extract_obfuscated_payloads(source: &str) -> Vec<DeobfuscationResult> {
    let mut results = Vec::new();

    results.extend(try_eval_atob(source));
    results.extend(try_eval_buffer_b64(source));
    results.extend(try_eval_charcode(source));
    results.extend(try_charcode_array(source));
    results.extend(try_eval_reverse(source));

    results
}

fn try_eval_atob(source: &str) -> Vec<DeobfuscationResult> {
    EVAL_ATOB_RE
        .captures_iter(source)
        .filter_map(|cap| {
            let blob = cap.get(1)?.as_str().replace(char::is_whitespace, "");
            let offset = cap.get(0)?.start();
            let steps = vec![DecodeStep::Base64];
            let result = super::decode_chain::apply_chain(blob.as_bytes(), &steps)?;
            Some(DeobfuscationResult {
                decoded: result.payload,
                offset,
                chain_description: format!("javascript:{}", result.chain_description),
                language: "javascript",
            })
        })
        .collect()
}

fn try_eval_buffer_b64(source: &str) -> Vec<DeobfuscationResult> {
    EVAL_BUFFER_B64_RE
        .captures_iter(source)
        .filter_map(|cap| {
            let blob = cap.get(1)?.as_str().replace(char::is_whitespace, "");
            let offset = cap.get(0)?.start();
            let steps = vec![DecodeStep::Base64];
            let result = super::decode_chain::apply_chain(blob.as_bytes(), &steps)?;
            Some(DeobfuscationResult {
                decoded: result.payload,
                offset,
                chain_description: format!("javascript:{}", result.chain_description),
                language: "javascript",
            })
        })
        .collect()
}

fn try_eval_charcode(source: &str) -> Vec<DeobfuscationResult> {
    EVAL_CHARCODE_RE
        .captures_iter(source)
        .filter_map(|cap| {
            let nums_str = cap.get(1)?.as_str();
            let offset = cap.get(0)?.start();
            let bytes: Vec<u8> = nums_str
                .split(',')
                .filter_map(|n| {
                    let n = n.trim();
                    if let Some(hex) = n.strip_prefix("0x").or_else(|| n.strip_prefix("0X")) {
                        u32::from_str_radix(hex, 16).ok()
                    } else {
                        n.parse::<u32>().ok()
                    }
                })
                .filter(|&n| n <= 0x10FFFF)
                .filter_map(char::from_u32)
                .collect::<String>()
                .into_bytes();
            if bytes.is_empty() {
                return None;
            }
            let payload = String::from_utf8(bytes).ok()?;
            Some(DeobfuscationResult {
                decoded: payload,
                offset,
                chain_description: "javascript:charcodes".to_string(),
                language: "javascript",
            })
        })
        .collect()
}

/// How much a decoded candidate reads like JavaScript source.
///
/// Used to pick the right Caesar shift out of 25 candidates. Counts keywords
/// that are common in real code and rare as coincidence, so the correct
/// rotation wins by a wide margin and a wrong one scores near zero.
fn javascript_likeness(text: &str) -> usize {
    const MARKERS: [&str; 10] = [
        "function", "return", "const ", "require(", "=>", "await ", "import ", "var ", "typeof",
        "process.",
    ];
    MARKERS.iter().map(|m| text.matches(m).count()).sum()
}

/// Decode `[...codes].map(...fromCharCode...).join("")`, recovering a Caesar
/// shift when the packer applied one.
///
/// Two layers, because they travel together. The array yields a string that is
/// itself rotated — the sample this was written for wraps the join in a
/// `replace(/[a-zA-Z]/g, ...)` that shifts by 6 before evaluating — so decoding
/// the codes alone produces plausible-looking mojibake and nothing matches it.
///
/// The shift is recovered rather than assumed: ROT13 is the one people try, so
/// packers pick something else. Scoring all 25 rotations for JavaScript-likeness
/// costs a linear pass each over a bounded prefix and needs no knowledge of
/// which shift was used.
fn try_charcode_array(source: &str) -> Vec<DeobfuscationResult> {
    /// Scoring window. The correct rotation is obvious within a few hundred
    /// bytes, and payloads here run to megabytes.
    const SCORE_WINDOW: usize = 4096;
    /// Below this the "winner" is noise rather than recovered source.
    const MIN_SCORE: usize = 4;

    CHARCODE_ARRAY_RE
        .captures_iter(source)
        .filter_map(|cap| {
            let whole = cap.get(0)?;
            // The regex stops at `.map(`; require the callback to actually be
            // the charcode conversion, within a short window after it.
            let tail_end = source.len().min(whole.end() + 160);
            if !source
                .get(whole.end()..tail_end)?
                .contains("fromCharCode")
            {
                return None;
            }
            let decoded: String = cap
                .get(1)?
                .as_str()
                .split(',')
                .filter_map(|n| n.trim().parse::<u32>().ok())
                .filter_map(char::from_u32)
                .collect();
            if decoded.is_empty() {
                return None;
            }

            let window: String = decoded.chars().take(SCORE_WINDOW).collect();
            let plain = javascript_likeness(&window);
            // Already readable: the packer used no rotation.
            let (payload, steps) = if plain >= MIN_SCORE {
                (decoded, vec![DecodeStep::CharCodes(Vec::new())])
            } else {
                let (shift, score) = (1u8..26)
                    .map(|n| (n, javascript_likeness(&rot(&window, n))))
                    .max_by_key(|&(_, score)| score)?;
                if score < MIN_SCORE {
                    return None;
                }
                (rot(&decoded, shift), vec![DecodeStep::Rot(shift)])
            };

            let chain = steps
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("+");
            Some(DeobfuscationResult {
                decoded: payload,
                offset: whole.start(),
                chain_description: format!("javascript:charcode-array+{chain}"),
                language: "javascript",
            })
        })
        .collect()
}

/// Caesar-shift ASCII letters, leaving everything else alone.
fn rot(text: &str, n: u8) -> String {
    let n = n % 26;
    text.chars()
        .map(|c| match c {
            'a'..='z' => char::from(((c as u8) - b'a' + n) % 26 + b'a'),
            'A'..='Z' => char::from(((c as u8) - b'A' + n) % 26 + b'A'),
            other => other,
        })
        .collect()
}

fn try_eval_reverse(source: &str) -> Vec<DeobfuscationResult> {
    EVAL_REVERSE_RE
        .captures_iter(source)
        .filter_map(|cap| {
            let reversed = cap.get(1)?.as_str();
            let offset = cap.get(0)?.start();
            let steps = vec![DecodeStep::Reverse];
            let result = super::decode_chain::apply_chain(reversed.as_bytes(), &steps)?;
            Some(DeobfuscationResult {
                decoded: result.payload,
                offset,
                chain_description: format!("javascript:{}", result.chain_description),
                language: "javascript",
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn charcode_array_with_rotation_is_recovered() {
        // The npm install-hook packer: codes -> string -> Caesar shift -> eval.
        // Written here as the encoder so the test states the recipe rather than
        // a magic blob.
        let plain = "const x = require(\"node:crypto\"); function go(){ return process.env; }";
        let rotated = super::rot(plain, 26 - 6); // encode with the inverse of ROT6
        let codes: Vec<String> = rotated.chars().map(|c| (c as u32).to_string()).collect();
        // Pad past the regex's minimum digit-run length with harmless codes.
        let mut all = codes.join(",");
        while all.len() < 260 {
            all.push_str(",32");
        }
        let src = format!(
            "eval(f([{all}].map(function(c){{return String.fromCharCode(c)}}).join(\"\"),6))"
        );
        let results = extract_obfuscated_payloads(&src);
        let hit = results
            .iter()
            .find(|r| r.chain_description.contains("charcode-array"))
            .expect("charcode array payload recovered");
        assert!(hit.decoded.contains("require(\"node:crypto\")"), "{}", hit.decoded);
        assert!(hit.chain_description.contains("rot6"), "{}", hit.chain_description);
    }

    #[test]
    fn charcode_array_without_rotation_is_recovered() {
        let plain = "const a = require(\"fs\"); function run(){ return typeof process; }";
        let mut all: String = plain
            .chars()
            .map(|c| (c as u32).to_string())
            .collect::<Vec<_>>()
            .join(",");
        while all.len() < 260 {
            all.push_str(",32");
        }
        let src = format!("([{all}].map(c=>String.fromCharCode(c)).join(\"\"))");
        let results = extract_obfuscated_payloads(&src);
        let hit = results
            .iter()
            .find(|r| r.chain_description.contains("charcode-array"))
            .expect("unrotated payload recovered");
        assert!(hit.decoded.contains("require(\"fs\")"), "{}", hit.decoded);
    }

    #[test]
    fn charcode_array_ignores_short_and_non_charcode_arrays() {
        // Too short to be a payload.
        assert!(extract_obfuscated_payloads("[1,2,3].map(c=>c*2).join(\"\")").is_empty());
        // Long numeric array, but the callback is not a charcode conversion.
        let long = (0..200).map(|_| "65").collect::<Vec<_>>().join(",");
        let src = format!("[{long}].map(function(v){{return v+1}}).join(\",\")");
        assert!(
            !extract_obfuscated_payloads(&src)
                .iter()
                .any(|r| r.chain_description.contains("charcode-array"))
        );
    }

    #[test]
    fn test_eval_atob() {
        let src = r#"eval(atob("YWxlcnQoMSk="))"#; // alert(1)
        let results = extract_obfuscated_payloads(src);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].decoded, "alert(1)");
        assert!(results[0].chain_description.contains("javascript"));
    }

    #[test]
    fn test_eval_atob_single_quotes() {
        let src = r#"eval(atob('YWxlcnQoMSk='))"#;
        let results = extract_obfuscated_payloads(src);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].decoded, "alert(1)");
    }

    #[test]
    fn test_eval_buffer_from() {
        let src = r#"eval(Buffer.from("YWxlcnQoMSk=", "base64").toString())"#;
        let results = extract_obfuscated_payloads(src);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].decoded, "alert(1)");
    }

    #[test]
    fn test_eval_charcode_decimal() {
        // "alert(1)" as char codes
        let src = r#"eval(String.fromCharCode(97, 108, 101, 114, 116, 40, 49, 41))"#;
        let results = extract_obfuscated_payloads(src);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].decoded, "alert(1)");
    }

    #[test]
    fn test_eval_charcode_hex() {
        let src = r#"eval(String.fromCharCode(0x61, 0x6c, 0x65, 0x72, 0x74, 0x28, 0x31, 0x29))"#;
        let results = extract_obfuscated_payloads(src);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].decoded, "alert(1)");
    }

    #[test]
    fn test_eval_reverse() {
        let src = r#"eval(")1(trela".split("").reverse().join(""))"#;
        let results = extract_obfuscated_payloads(src);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].decoded, "alert(1)");
    }

    #[test]
    fn test_no_false_positive_on_atob_in_variable() {
        // atob not inside eval should not trigger
        let src = r#"var data = atob("YWxlcnQoMSk=");"#;
        let results = extract_obfuscated_payloads(src);
        assert!(results.is_empty());
    }
}
