//! Lua constant and public string-cipher recovery. This never runs Lua code.
mod constants;
mod prometheus;
use super::DeobfuscationResult;
const MAX_SOURCE: usize = 1024 * 1024;
/// `n` as an integer when it is whole and every integer up to it is exactly
/// representable (|n| <= 2^53). NaN, infinities and fractions give `None`, so
/// numbers from untrusted source never saturate into valid-looking values.
#[expect(
    clippy::cast_possible_truncation,
    reason = "checked whole and within +/-2^53"
)]
fn whole(n: f64) -> Option<i64> {
    const EXACT: f64 = 9_007_199_254_740_992.;
    if n.fract() == 0. && n.abs() <= EXACT {
        Some(n as i64)
    } else {
        None
    }
}
fn parse(source: &str) -> Option<tree_sitter::Tree> {
    if source.len() > MAX_SOURCE {
        return None;
    }
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_lua::LANGUAGE.into())
        .ok()?;
    let mut polls = 0usize;
    let mut progress = |_: &tree_sitter::ParseState| {
        polls += 1;
        if polls > 100_000 {
            std::ops::ControlFlow::Break(())
        } else {
            std::ops::ControlFlow::Continue(())
        }
    };
    let mut input =
        |offset: usize, _: tree_sitter::Point| source.as_bytes().get(offset..).unwrap_or(&[]);
    let tree = parser.parse_with_options(
        &mut input,
        None,
        Some(tree_sitter::ParseOptions::default().progress_callback(&mut progress)),
    )?;
    (!tree.root_node().has_error()).then_some(tree)
}
pub(super) fn extract_obfuscated_payloads(source: &str) -> Vec<DeobfuscationResult> {
    let Some(tree) = parse(source) else {
        return Vec::new();
    };
    let folded = constants::recover(&tree, source, None);
    let Some(cipher) = folded.discovery.cipher() else {
        return Vec::new();
    };
    let Some(tree) = parse(&folded.source) else {
        return Vec::new();
    };
    let recovered = constants::recover(&tree, &folded.source, Some(cipher));
    // Parameter extraction is corroborated by several decoded cache lookups,
    // not by a malware keyword, filename, network address or campaign key.
    if recovered.decoded_strings < 4
        || recovered.decoded_bytes < 64
        || recovered.printable_bytes * 100 < recovered.decoded_bytes * 90
        || recovered.source == source
    {
        return Vec::new();
    }
    vec![DeobfuscationResult {
        decoded: recovered.source,
        offset: 0,
        chain_description: "lua:static-constants+prometheus-strings".to_string(),
        language: "lua",
    }]
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn permutations_are_data_only() {
        let source = r#"local pack=function(t) local out="" for i=1,#t/2,1 do out=out..t[#t/2+t[i]] end return out end local message=pack({2,1,"world","hello "})"#;
        let t = parse(source).unwrap();
        let out = constants::recover(&t, source, None);
        assert!(
            out.source.contains(r#"local message="hello world""#),
            "{}",
            out.source
        );
    }
    #[test]
    fn unknown_calls_and_shadowed_helpers_are_not_folded() {
        let source = r#"local pack=function(t) local out="" for i=1,#t/2 do out=out..t[#t/2+t[i]] end return out end local function inner(pack) return pack({1,"unchanged"}) end os.execute("never run")"#;
        let t = parse(source).unwrap();
        let out = constants::recover(&t, source, None);
        assert!(out.source.contains(r#"return pack({1,"unchanged"})"#));
        assert!(out.source.contains(r#"os.execute("never run")"#));
    }
    #[test]
    fn arithmetic_parameter_discovery_does_not_depend_on_names() {
        for (m, a, k, key) in [
            (5, 12345678901u64, 3, 73),
            (17, 876543210123u64, 7, 147),
            (253, 1234567890123u64, 11, 199),
        ] {
            let source = format!(
                "local function next45() local m={m} local a={a} return (state*m+a)%(2^45) end local function next8() return (small*{k})%257 end local function recipe() local rotation=small%32 local shifted=2^(13-rotation) return (state%4294967296)%256 end local function init(seed) local r=seed%(2^45) local t=seed%255+2 local previous={key} return r,t,previous end"
            );
            let t = parse(&source).unwrap();
            assert!(
                constants::recover(&t, &source, None)
                    .discovery
                    .cipher()
                    .is_some(),
                "{source}"
            );
        }
    }
    #[test]
    fn table_bootstrap_tracks_aliases_scopes_and_zero_truthiness() {
        let source = r#"local t={"first","second","third"} local alias=t
            for _,range in ipairs({{1,3}}) do while range[1]<range[2] do
                t[range[1]],t[range[2]],range[1],range[2]=t[range[2]],t[range[1]],range[1]+1,range[2]-1
            end end
            do local alias="shadow" local insert=table.insert local target=t
                for t=1,#target do local pieces={} local zero=0
                    if zero then insert(pieces,target[t]); insert(pieces,"!") end
                    target[t]=table.concat(pieces)
                end
            end
            local result=alias[1]..t[3]"#;
        let out = constants::recover(&parse(source).unwrap(), source, None);
        assert!(
            out.source.contains(r#"local result="third!first!""#),
            "{}",
            out.source
        );
    }
    #[test]
    fn captured_mutation_and_missing_parameters_are_not_folded() {
        let source = r#"local value="outside" local t={"old"}
            local function mutate() value="new" return value end
            local function parameter(value) return value end
            local a=mutate() local b=parameter() unknown(t) local c=t[1].."!""#;
        let out = constants::recover(&parse(source).unwrap(), source, None);
        assert!(out.source.contains("local a=mutate()"));
        assert!(out.source.contains("local b=parameter()"));
        assert!(out.source.contains("local c=t[1].."));
    }
    #[test]
    fn full_recovery_handles_independent_keys_and_names() {
        for (m, a, k, key) in [
            (5., 12345678901., 3., 73),
            (17., 876543210123., 7., 147),
            (253., 1234567890123., 11., 199),
        ] {
            let cipher = prometheus::Cipher {
                mul45: m,
                add45: a,
                mul8: k,
                key,
            };
            let mut source = format!(
                "local function evolve() return (state*{m}+{a})%(2^45) end local function smallstep() return (small*{k})%257 end local function recipe() local r=small%32 local shift=2^(13-r) return (state%4294967296)%256 end local function init(seed) local a=seed%(2^45) local b=seed%255+2 local feedback={key} return a,b,feedback end "
            );
            for (i, plain) in [
                "alpha independent constant",
                "beta independent constant",
                "gamma independent constant",
                "delta independent constant",
            ]
            .iter()
            .enumerate()
            {
                let seed = 817263541209. + i as f64 * 111.;
                let bytes = cipher.encrypt(plain.as_bytes(), seed);
                let escaped: String = bytes.iter().map(|b| format!("\\{b:03}")).collect();
                source.push_str(&format!(
                    "local result{i}=cache[renamed(\"{escaped}\",{seed})] "
                ));
            }
            source = source
                .replace("state", &format!("state_{key}"))
                .replace("small", &format!("small_{key}"))
                .replace("seed", &format!("seed_{key}"))
                .replace("cache", &format!("cache_{key}"))
                .replace("renamed", &format!("decode_{key}"));
            let decoded = extract_obfuscated_payloads(&source);
            assert_eq!(decoded.len(), 1, "{source}");
            assert!(decoded[0].decoded.contains("gamma independent constant"));
            let missing = source.replace(&format!("small_{key}%32"), &format!("small_{key}%31"));
            assert!(extract_obfuscated_payloads(&missing).is_empty());
        }
    }
    #[test]
    fn unbounded_loops_and_input_sizes_fail_closed() {
        let source = "local t={1} while true do t[1]=t[1]+1 end local output=t[1]+2";
        let out = constants::recover(&parse(source).unwrap(), source, None);
        assert!(!out.source.contains("local output=(10003)"));
        assert!(parse(&" ".repeat(MAX_SOURCE + 1)).is_none());
    }

    #[test]
    fn captures_survive_parameter_shadowing_and_track_table_mutations() {
        let source = r#"local t={"one","two"} local function reader(i) return t[i] end
            for _,range in ipairs({{1,2}}) do while range[1]<range[2] do
                t[range[1]],t[range[2]],range[1],range[2]=t[range[2]],t[range[1]],range[1]+1,range[2]-1 end end
            local function other(t) return reader(1).."!" end"#;
        let out = constants::recover(&parse(source).unwrap(), source, None);
        assert!(out.source.contains(r#"return "two!""#), "{}", out.source);
        let source = r#"local t={"old"} local function mutate() t[1]="new" return t[1] end
            mutate() local function reader(i) return t[i] end local output=reader(1).."!""#;
        let out = constants::recover(&parse(source).unwrap(), source, None);
        assert!(
            out.source.contains("local output=reader(1).."),
            "{}",
            out.source
        );
    }
    #[test]
    fn loop_handles_large_data_and_stops_on_break() {
        let source = format!(
            "local input=\"{}\" local count=0 for i=1,#input do count=count+1 end local output=count+1",
            "a".repeat(11000)
        );
        let out = constants::recover(&parse(&source).unwrap(), &source, None);
        assert!(out.source.contains("local output=(11001)"));
        let source = "local count=0 while true do count=count+1 if count==3 then break end end local output=count+1";
        let out = constants::recover(&parse(source).unwrap(), source, None);
        assert!(out.source.contains("local output=(4)"));
    }
    #[test]
    fn embedded_lua_example_does_not_hide_javascript_decoder() {
        let source =
            br#"const example="local x=function() end return x";eval(atob("YWxlcnQoMSk="));"#;
        assert_eq!(
            super::super::detect::detect_script_language(source),
            Some(super::super::detect::ScriptLanguage::JavaScript)
        );
        let decoded = super::super::deobfuscate_script(source);
        assert!(decoded.iter().any(|r| r.decoded == "alert(1)"));
    }
    #[test]
    fn overwritten_standard_library_helpers_are_not_folded() {
        let source = r#"local chars=string.char string.char=untrusted local result=chars(65).."!""#;
        let out = constants::recover(&parse(source).unwrap(), source, None);
        assert!(
            out.source.contains("local result=chars(65).."),
            "{}",
            out.source
        );
    }
    #[test]
    fn passing_nested_tables_invalidates_captured_aliases() {
        let source = r#"local t={"original"} local wrapper={t} local function reader() return wrapper[1][1] end unknown({t}) local result=reader().."!""#;
        let out = constants::recover(&parse(source).unwrap(), source, None);
        assert!(
            out.source.contains("local result=reader().."),
            "{}",
            out.source
        );
    }
}
