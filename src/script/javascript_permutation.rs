//! Static recovery of JSO character-permutation and word-dictionary layers.
//! Only recognized pure codec bodies are evaluated, never JavaScript. Names,
//! arithmetic seeds and permutation constants are recovered from source.
use super::DeobfuscationResult;
use super::decode_chain::{MAX_DECODED_SIZE, spend_expansion};
use crate::script::detect::ScriptLanguage;
use regex::Regex;
use std::{cell::LazyCell, collections::HashMap, sync::LazyLock};

const SHUFFLE: &str = "b var t=2319581;var l=b.length;var d=[];for(var k=0;k<l;k++){d[k]=b.charAt(k)};for(var k=0;k<l;k++){var g=t*(k+143)+(t%34562);var j=t*(k+599)+(t%19024);var o=g%l;var h=j%l;var q=d[o];d[o]=d[h];d[h]=q;t=(g+j)%3591111;};return d.join('')";
const TABLE: &str = "h,x var k=h.length;var c=[];for(var u=0;u<k;u++){c[u]=h.charAt(u)};for(var u=0;u<k;u++){var f=x*(u+106)+(x%49301);var n=x*(u+87)+(x%15685);var m=f%k;var a=n%k;var y=c[m];c[m]=c[a];c[a]=y;x=(f+n)%5618418};var d=String.fromCharCode(127);var s='';var v='%';var g='#1';var o='%';var q='#0';var j='#';return c.join(s).split(v).join(d).split(g).join(o).split(q).join(j).split(d)";
const DICT: &str = r#"var h=18,w=30,l=11;var e="abcdefghijklmnopqrstuvwxyz";var j=[70,87,76,71,75,60,81,80,94,88,74,72,66,89,82,90,86,79,65,85];var n=[];for(var p=0;p<j.length;p++)n[j[p]]=p+1;var b=[];h+=15;w+=63;l+=85;for(var q=0;q<arguments.length;q++){var c=arguments[q].split(" ");for(var i=c.length-1;i>=0;i--){var s=null;var d=c[i];var r=null;var m=0;var x=d.length;var y;for(var f=0;f<x;f++){var z=d.charCodeAt(f);var o=n[z];if(o){s=(o-1)*w+d.charCodeAt(f+1)-h;y=f;f++;}else if(z==l){s=w*(j.length-h+d.charCodeAt(f+1))+d.charCodeAt(f+2)-h;y=f;f+=2;}else{continue;}if(r==null)r=[];if(y>m)r.push(d.substring(m,y));r.push(c[s+1]);m=f+1;}if(r!=null){if(m<x)r.push(d.substring(m));c[i]=r.join("");}}b.push(c[0]);}var k=b.join("");var u=[42,96,92,10,39,32].concat(j);var v=String.fromCharCode(46);for(var p=0;p<u.length;p++)k=k.split(v+e.charAt(p)).join(String.fromCharCode(u[p]));return k.split(v+"!").join(v);"#;
#[allow(clippy::expect_used)]
static TOKENS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"[A-Za-z_$][\w$]*|\d+|"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|[^\s]"#)
        .expect("codec tokens")
});
#[allow(clippy::expect_used)]
static FUNCTIONS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"function\s*([A-Za-z_$][\w$]*)?\s*\(([^()]{0,100})\)\s*\{")
        .expect("codec functions")
});
#[allow(clippy::expect_used)]
static STRINGS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#""(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'"#).expect("js strings"));
/// `name(arg)` where the argument is one string literal or identifier.
#[allow(clippy::expect_used)]
static CALLS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"([A-Za-z_$][\w$]*)\s*\(\s*("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|[A-Za-z_$][\w$]*)\s*\)"#,
    )
    .expect("codec calls")
});
/// `name = "literal"`.
#[allow(clippy::expect_used)]
static ASSIGNMENTS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\b([A-Za-z_$][\w$]*)\s*=\s*("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')"#)
        .expect("string assignments")
});
/// The `, seed);` that closes a string-table codec call.
#[allow(clippy::expect_used)]
static TABLE_CALL_END: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s*,\s*\d+\s*\)\s*;?").expect("table call end"));
static SHUFFLE_FINGERPRINT: LazyLock<Option<(String, Vec<u64>)>> =
    LazyLock::new(|| fingerprint(SHUFFLE));
static TABLE_FINGERPRINT: LazyLock<Option<(String, Vec<u64>)>> =
    LazyLock::new(|| fingerprint(TABLE));
static DICT_FINGERPRINT: LazyLock<Option<(String, Vec<u64>)>> = LazyLock::new(|| fingerprint(DICT));

// Preserve member names, keywords, literal values and the identity relationships
// between all local variables. Ignore only whitespace, optional semicolons and
// numeric values (which are separately returned and range-checked).
fn fingerprint(s: &str) -> Option<(String, Vec<u64>)> {
    let mut names = HashMap::new();
    let mut nums = Vec::new();
    let mut out = String::new();
    let mut member = false;
    for m in TOKENS.find_iter(s) {
        let t = m.as_str();
        if t == ";" {
            continue;
        }
        if t.as_bytes()[0].is_ascii_digit() {
            nums.push(t.parse().ok()?);
            out.push('#');
        } else if t.starts_with(['\'', '"']) {
            out.push_str(&serde_json::to_string(&unquote(t)?).ok()?);
        } else if t.as_bytes()[0].is_ascii_alphabetic() || t.starts_with(['_', '$']) {
            if member
                || matches!(
                    t,
                    "var"
                        | "for"
                        | "return"
                        | "if"
                        | "else"
                        | "continue"
                        | "null"
                        | "String"
                        | "arguments"
                )
            {
                out.push_str(t);
            } else {
                let next = names.len();
                let n = *names.entry(t).or_insert(next);
                out.push_str(&format!("v{n}"));
            }
        } else {
            out.push_str(t);
        }
        out.push(' ');
        member = t == ".";
    }
    Some((out, nums))
}
fn unquote(s: &str) -> Option<String> {
    let body = s.get(1..s.len().checked_sub(1)?)?;
    let mut out = String::new();
    let mut cs = body.chars().peekable();
    while let Some(c) = cs.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        let c = cs.next()?;
        match c {
            '0' if !cs.peek().is_some_and(char::is_ascii_digit) => out.push('\0'),
            '0'..='9' => return None,
            'n' => out.push('\n'),
            'r' => out.push('\r'),
            't' => out.push('\t'),
            'b' => out.push('\x08'),
            'f' => out.push('\x0c'),
            'x' | 'u' => {
                let n = if c == 'x' { 2 } else { 4 };
                let digits: String = cs.by_ref().take(n).collect();
                if digits.len() != n {
                    return None;
                }
                out.push(char::from_u32(u32::from_str_radix(&digits, 16).ok()?)?);
            }
            '\n' | '\r' => {}
            c => out.push(c),
        }
    }
    Some(out)
}
fn body_end(s: &str, start: usize) -> Option<usize> {
    let b = s.as_bytes();
    let mut i = start;
    let mut depth = 1;
    while i < b.len() && i - start < 8192 {
        match b[i] {
            b'\'' | b'"' => {
                let q = b[i];
                i += 1;
                while i < b.len() && b[i] != q {
                    if b[i] == b'\\' {
                        i += 1;
                    }
                    i += 1;
                }
            }
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}
fn permute(s: &str, seed: u64, c: &[u64]) -> Option<String> {
    if c.len() != 5 || s.len() > MAX_DECODED_SIZE || c[1] == 0 || c[3] == 0 || c[4] == 0 {
        return None;
    }
    let mut data: Vec<u16> = s.encode_utf16().collect();
    let len = data.len();
    if len == 0 {
        return None;
    }
    let mut state = seed;
    for i in 0..len {
        let r = state
            .checked_mul((i as u64).checked_add(c[0])?)?
            .checked_add(state % c[1])?;
        let t = state
            .checked_mul((i as u64).checked_add(c[2])?)?
            .checked_add(state % c[3])?;
        // JavaScript integers beyond 2^53 cannot be reproduced by integer arithmetic.
        if r > 9_007_199_254_740_991 || t > 9_007_199_254_740_991 {
            return None;
        }
        data.swap(
            usize::try_from(r % len as u64).ok()?,
            usize::try_from(t % len as u64).ok()?,
        );
        let next = r.checked_add(t)?;
        if next > 9_007_199_254_740_991 {
            return None;
        }
        state = next % c[4];
    }
    String::from_utf16(&data).ok()
}
fn dictionary(codec: &str, blob: &str) -> Option<String> {
    let (fp, n) = fingerprint(codec)?;
    let (dict_fp, expected) = DICT_FINGERPRINT.as_ref()?;
    if fp != *dict_fp || n.len() != 49 {
        return None;
    }
    for i in 23..n.len() {
        if !(25..=27).contains(&i) && !(41..47).contains(&i) && n[i] != expected[i] {
            return None;
        }
    }
    // The codec has 20 dictionary tag bytes; recover all numeric parameters,
    // rather than hard-code the alphabet or expansion constants.
    let h = n[0].checked_add(n[25])?;
    if h > 65535 {
        return None;
    }
    let h = h as i64;
    let w = n[1].checked_add(n[26])?;
    if w == 0 || w > 65535 {
        return None;
    }
    let w = w as i64;
    let special = n[2].checked_add(n[27])?;
    let tags = &n[3..23];
    if tags.iter().any(|v| *v > 127) || tags.iter().enumerate().any(|(i, v)| tags[..i].contains(v))
    {
        return None;
    }
    let mut words: Vec<String> = blob.split(' ').map(str::to_string).collect();
    let mut work = 0usize;
    for i in (0..words.len()).rev() {
        let d: Vec<char> = words[i].chars().collect();
        let mut out = String::new();
        let (mut f, mut m) = (0, 0);
        let mut changed = false;
        while f < d.len() {
            let z = d[f] as u64;
            let y = f;
            let idx;
            if let Some(p) = tags.iter().position(|v| *v == z) {
                idx = p as i64 * w + *d.get(f + 1)? as i64 - h;
                f += 1;
            } else if z == special {
                idx =
                    w * (tags.len() as i64 - h + *d.get(f + 1)? as i64) + *d.get(f + 2)? as i64 - h;
                f += 2;
            } else {
                f += 1;
                continue;
            }
            if idx < 0 {
                return None;
            }
            out.extend(d[m..y].iter());
            out.push_str(words.get(usize::try_from(idx).ok()?.checked_add(1)?)?);
            if out.len() > MAX_DECODED_SIZE {
                return None;
            }
            m = f + 1;
            f += 1;
            changed = true;
        }
        if changed {
            out.extend(d[m..].iter());
            if out.len() > MAX_DECODED_SIZE {
                return None;
            }
            work = work.checked_add(out.len())?;
            if work > 4 * MAX_DECODED_SIZE {
                return None;
            }
            words[i] = out;
        }
    }
    let mut out = words.first()?.clone();
    let alpha = "abcdefghijklmnopqrstuvwxyz";
    // The fixed escape grammar and code list are validated by fingerprint;
    // values are the codec's data, not attacker/payload identity.
    let mut escapes = n[41..47].to_vec();
    escapes.extend_from_slice(tags);
    for (p, v) in escapes.iter().enumerate() {
        out = out.replace(
            &format!(".{}", alpha.chars().nth(p)?),
            &char::from_u32((*v).try_into().ok()?)?.to_string(),
        );
    }
    Some(out.replace(".!", "."))
}
fn expand_table(source: &str) -> Option<String> {
    let table_fp = &TABLE_FINGERPRINT.as_ref()?.0;
    for cap in FUNCTIONS.captures_iter(source).take(32) {
        if cap.get(1).is_some() {
            continue;
        }
        let start = cap.get(0)?.end();
        let end = body_end(source, start)?;
        let (fp, n) = fingerprint(&format!("{} {}", &cap[2], &source[start..end]))?;
        if fp != *table_fp || n.len() != 8 || n[0] != 0 || n[1] != 0 || n[7] != 127 {
            continue;
        }
        let tail = source.get(end + 1..)?;
        let open = tail.find('(')?;
        let sm = STRINGS.find(tail.get(open + 1..)?)?;
        if sm.start() != 0 {
            continue;
        }
        let value = unquote(sm.as_str())?;
        let after = tail.get(open + 1 + sm.end()..)?.trim_start();
        let after = after.strip_prefix(',')?.trim_start();
        let seed: u64 = after
            .split(|c: char| !c.is_ascii_digit())
            .next()?
            .parse()
            .ok()?;
        let decoded = permute(&value, seed, &n[2..7])?;
        let table: Vec<&str> = decoded.split('%').collect();
        let prefix = &source[..cap.get(0)?.start()];
        let name = prefix
            .trim_end()
            .strip_suffix('(')?
            .trim_end()
            .strip_suffix('=')?
            .trim_end()
            .rsplit(|c: char| !c.is_ascii_alphanumeric() && c != '_' && c != '$')
            .next()?;
        if name.is_empty() {
            continue;
        }
        let re = Regex::new(&format!(
            r"{}\s*\[\s*(0x[\da-fA-F]+|\d+)\s*\]",
            regex::escape(name)
        ))
        .ok()?;
        let rest = &source[end + 1 + open + 1 + sm.end()..];
        let Some(close) = TABLE_CALL_END.find(rest) else {
            continue;
        };
        let mut valid = true;
        let out = re.replace_all(&rest[close.end()..], |c: &regex::Captures<'_>| {
            let idx = if let Some(n) = c[1].strip_prefix("0x") {
                usize::from_str_radix(n, 16).ok()
            } else {
                c[1].parse().ok()
            };
            idx.and_then(|idx| table.get(idx))
                .and_then(|v| serde_json::to_string(&v.replace("#1", "%").replace("#0", "#")).ok())
                .unwrap_or_else(|| {
                    valid = false;
                    c[0].to_string()
                })
        });
        if valid {
            return Some(format!(
                "var {name} = {};\n{out}",
                serde_json::to_string(&table).ok()?
            ));
        }
    }
    None
}
pub(super) fn extract(source: &str) -> Vec<DeobfuscationResult> {
    if source.len() > MAX_DECODED_SIZE || !source.contains(".charAt(") {
        return Vec::new();
    }
    let mut out = Vec::new();
    let (Some((shuffle_fingerprint, _)), Some((dict_fingerprint, _))) =
        (SHUFFLE_FINGERPRINT.as_ref(), DICT_FINGERPRINT.as_ref())
    else {
        return out;
    };
    // Every `name(arg)` call, at most 64 per name, and the first string
    // literal assigned to each name: one pass each over the source.
    let calls = LazyCell::new(|| {
        let mut calls: HashMap<&str, Vec<&str>> = HashMap::new();
        for cap in CALLS.captures_iter(source) {
            let (Some(name), Some(arg)) = (cap.get(1), cap.get(2)) else {
                continue;
            };
            let args = calls.entry(name.as_str()).or_default();
            if args.len() < 64 {
                args.push(arg.as_str());
            }
        }
        calls
    });
    let literals = LazyCell::new(|| {
        let mut literals: HashMap<&str, &str> = HashMap::new();
        for cap in ASSIGNMENTS.captures_iter(source) {
            if let (Some(name), Some(value)) = (cap.get(1), cap.get(2)) {
                literals.entry(name.as_str()).or_insert(value.as_str());
            }
        }
        literals
    });
    for cap in FUNCTIONS.captures_iter(source).take(64) {
        let Some(whole) = cap.get(0) else {
            continue;
        };
        let Some(name) = cap.get(1) else { continue };
        let Some(end) = body_end(source, whole.end()) else {
            continue;
        };
        let start = whole.end();
        let Some((fp, n)) = fingerprint(&format!("{} {}", &cap[2], &source[start..end])) else {
            continue;
        };
        if fp != *shuffle_fingerprint || n.len() != 8 || n[1] != 0 || n[2] != 0 {
            continue;
        }
        let mut decoded = Vec::new();
        for &arg in calls.get(name.as_str()).into_iter().flatten() {
            let value = if arg.starts_with(['\'', '"']) {
                unquote(arg)
            } else {
                literals.get(arg).and_then(|literal| unquote(literal))
            };
            let Some(value) = value else { continue };
            if let Some(value) = permute(&value, n[0], &n[3..8]) {
                decoded.push(value);
            }
        }
        for codec in &decoded {
            if fingerprint(codec).is_none_or(|(fp, _)| fp != *dict_fingerprint) {
                continue;
            }
            for blob in &decoded {
                let Some(payload) = dictionary(codec, blob) else {
                    continue;
                };
                // `blob` has already passed through the character shuffle.
                // An identity dictionary layer must not discard that recovered
                // source: it can be executable text without dictionary codes.
                if payload.len() < 100 {
                    continue;
                }
                let (payload, chain) = match expand_table(&payload) {
                    Some(value) => (value, "javascript:permutation+dictionary+string-table"),
                    None => (payload, "javascript:permutation+dictionary"),
                };
                if !spend_expansion(payload.len()) {
                    continue;
                }
                out.push(DeobfuscationResult {
                    decoded: payload,
                    offset: whole.start(),
                    chain_description: chain.into(),
                    language: ScriptLanguage::JavaScript,
                });
            }
        }
    }
    out
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn codec_fingerprint_ignores_names_and_spacing() {
        assert_eq!(
            fingerprint(SHUFFLE).unwrap().0,
            fingerprint(
                &SHUFFLE
                    .replace("2319581", "19")
                    .replace("143", "7")
                    .replace("var t=", "var seed=")
                    .replace("t*", "seed*")
                    .replace("t%", "seed%")
                    .replace("t=", "seed=")
            )
            .unwrap()
            .0
        );
    }
    #[test]
    fn rejects_changed_semantics() {
        assert_ne!(
            fingerprint(SHUFFLE).unwrap().0,
            fingerprint(&SHUFFLE.replace("d[o]=d[h]", "d[o]=d[o]"))
                .unwrap()
                .0
        );
    }
    #[test]
    fn inspect_constants() {
        assert_eq!(fingerprint(SHUFFLE).unwrap().1.len(), 8);
        assert_eq!(fingerprint(TABLE).unwrap().1.len(), 8);
        assert_eq!(fingerprint(DICT).unwrap().1.len(), 49);
    }
    /// The malicious script, read at run time so no binary embeds it.
    fn sample() -> &'static str {
        std::str::from_utf8(crate::test_fixture("testdata/script/jso-permutation.js"))
            .expect("UTF-8 script")
    }
    #[test]
    fn refuses_invalid_permutation_arithmetic() {
        assert!(permute("abcd", 1, &[1, 0, 1, 1, 1]).is_none());
        assert!(permute("abcd", u64::MAX, &[1, 2, 1, 2, 3]).is_none());
    }
    #[test]
    fn renamed_and_reformatted_codec_recovers() {
        let s = sample()
            .replace("ype", "decodeText")
            .replace("}; for", "};\nfor");
        let r = extract(&s);
        assert_eq!(r.len(), 1);
        assert!(r[0].decoded.contains("eth_getTransactionByHash"));
    }
    #[test]
    fn changed_loop_is_not_evaluated() {
        let s = sample().replace("d[o] = d[h]", "d[o] = d[o]");
        assert!(extract(&s).is_empty());
    }
    #[test]
    fn identity_dictionary_preserves_permutation_recovered_constant_function() {
        let source = include_str!("../../testdata/script/jso-inert-permutation.js");
        let results = extract(source);
        assert_eq!(results.len(), 1);
        let recovered = &results[0];
        assert_eq!(
            recovered.chain_description,
            "javascript:permutation+dictionary"
        );
        assert!(source[recovered.offset..].starts_with("function ype"));
        let padding = recovered
            .decoded
            .strip_prefix("return/**/2;/*")
            .and_then(|body| body.strip_suffix("*/"))
            .expect("constant-return function body");
        assert_eq!(padding.len(), 4000);
        assert!(padding.bytes().all(|byte| byte == b'a'));
    }

    #[test]
    fn qa4_recovers_source_without_executing() {
        let s = sample();
        let r = extract(s);
        assert_eq!(r.len(), 1);
        assert!(r[0].decoded.contains("eth_getTransactionByHash"));
        assert!(r[0].decoded.contains("child_process"));
        assert!(r[0].decoded.contains("eval("));
        assert!(r[0].decoded.contains("(async function"));
        assert!(!r[0].decoded.contains("_$_2ee9["));
    }
}
