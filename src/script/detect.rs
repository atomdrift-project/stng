//! Script language detection heuristics.
//!
//! Identifies Python, JavaScript, PHP, PowerShell and Lua scripts from text content.
//! Only called after `is_text_file()` returns true.

/// A scripting language stng deobfuscates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ScriptLanguage {
    /// Lua.
    Lua,
    /// Python.
    Python,
    /// JavaScript.
    JavaScript,
    /// PHP.
    Php,
    /// PowerShell.
    PowerShell,
    /// Windows batch (cmd.exe).
    Batch,
    /// VBScript, including VBScript.Encode.
    VbScript,
}

impl ScriptLanguage {
    /// The language's lowercase name, such as `"python"` or `"vbscript"`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Lua => "lua",
            Self::Python => "python",
            Self::JavaScript => "javascript",
            Self::Php => "php",
            Self::PowerShell => "powershell",
            Self::Batch => "batch",
            Self::VbScript => "vbscript",
        }
    }
}

impl std::fmt::Display for ScriptLanguage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Detect what scripting language a text file is written in, if any.
///
/// Examines the first ~8KB for language-specific markers. Returns `None`
/// for plain text, config files, data files, etc.
#[must_use]
pub fn detect_script_language(data: &[u8]) -> Option<ScriptLanguage> {
    let sample = &data[..data.len().min(8192)];
    // The cut can split a character; judge the text before it rather than
    // give up, which let one multibyte character at byte 8191 hide a script.
    let text = match std::str::from_utf8(sample) {
        Ok(text) => text,
        Err(e) if e.error_len().is_none() => {
            std::str::from_utf8(&sample[..e.valid_up_to()]).ok()?
        }
        Err(_) => return None,
    };

    // PHP is very distinctive — check first
    if text.contains("<?php") || text.contains("<?=") {
        return Some(ScriptLanguage::Php);
    }

    if (text.trim_start().starts_with("local ")
        || text.trim_start().starts_with("return(function")
        || text.trim_start().starts_with("--"))
        && text.contains("local ")
        && text.contains("function")
        && (text.contains(" end") || text.contains("end return"))
    {
        return Some(ScriptLanguage::Lua);
    }

    // A Lua declaration may start with an arbitrarily large string table.
    // Requiring a function/end inside the 8 KiB probe then hides the language
    // and prevents its bounded AST-based decoder from even being attempted.
    // A local identifier initialized with a table is already Lua syntax;
    // recognizing it does not assert obfuscation or execute the initializer.
    let mut lua_head = text.trim_start();
    // Ordinary header comments must not change whether a leading table is
    // recognized. Keep this prefix probe bounded by the existing 8 KiB slice.
    while lua_head.starts_with("--") && !lua_head.starts_with("--[") {
        let Some((_, rest)) = lua_head.split_once('\n') else {
            break;
        };
        lua_head = rest.trim_start();
    }
    if lua_head.strip_prefix("local").is_some_and(|tail| {
        tail.starts_with(char::is_whitespace)
            && tail.split_once('=').is_some_and(|(name, rhs)| {
                let name = name.trim();
                !name.is_empty()
                    && (name.as_bytes()[0].is_ascii_alphabetic() || name.as_bytes()[0] == b'_')
                    && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
                    && rhs.trim_start().starts_with('{')
            })
    }) {
        return Some(ScriptLanguage::Lua);
    }

    // PowerShell has distinctive markers
    if is_powershell(text) {
        return Some(ScriptLanguage::PowerShell);
    }

    // Python vs JavaScript — both can have similar patterns, use scoring
    let py_score = python_score(text);
    let js_score = javascript_score(text);

    if py_score >= 2 && py_score > js_score {
        return Some(ScriptLanguage::Python);
    }
    if js_score >= 2 && js_score > py_score {
        return Some(ScriptLanguage::JavaScript);
    }

    // Lower threshold if obfuscation indicators are present
    if py_score >= 1 && has_python_obfuscation(text) {
        return Some(ScriptLanguage::Python);
    }
    if js_score >= 1
        && (text.contains("eval(") || text.contains("Function("))
        && (text.contains("atob(") || text.contains("Buffer.from") || text.contains("fromCharCode"))
    {
        return Some(ScriptLanguage::JavaScript);
    }

    None
}

fn is_powershell(text: &str) -> bool {
    let lower = text.to_lowercase();

    // Strong PowerShell indicators
    let strong = [
        "invoke-expression",
        "-encodedcommand",
        "new-object",
        "convertto-securestring",
        "convertfrom-securestring",
        "[system.text.encoding]",
        "[convert]::",
        "get-process",
        "set-executionpolicy",
        "write-host",
        "param(",
    ];

    let strong_count = strong.iter().filter(|s| lower.contains(*s)).count();
    if strong_count >= 1 {
        return true;
    }

    // Moderate indicators — need at least 2
    let moderate = [
        "powershell",
        "-enc ",
        "iex(",
        "iex (",
        "$env:",
        "[char]",
        "[char[]]",
        "-join",
        "| iex",
        "|iex",
        "downloadstring",
        "webclient",
    ];

    let moderate_count = moderate.iter().filter(|s| lower.contains(*s)).count();
    moderate_count >= 2
}

/// How Python-like a whole file is. The classifier's
/// [`is_python_code`](crate::classifier) asks the same of one short string,
/// with its own keywords and threshold: a file and a string carry different
/// evidence, so the two lists are kept apart on purpose.
fn python_score(text: &str) -> u32 {
    let mut score = 0u32;

    // Java/Kotlin/Android declarations: if present, it is not Python. Python
    // has no statement starting `package` or `private`, so one at the start of
    // a line decides, while a comment saying "private key" does not.
    let declares = |keyword: &str| {
        text.lines().any(|line| {
            line.trim_start()
                .strip_prefix(keyword)
                .is_some_and(|rest| rest.starts_with(' '))
        })
    };
    if declares("package")
        || declares("private")
        || text.contains("public class ")
        || text.contains("public enum ")
        || text.contains("android.os.")
        || text.contains("java.util.")
    {
        return 0;
    }

    // Strong indicators
    if text.contains("import ") || text.contains("from ") {
        // Python imports don't end with semicolon
        if !text.contains("import ") || !text.contains(';') {
            score += 1;
        }
    }
    if text.contains("def ") || text.contains("class ") {
        // 'class ' can be in Java too, but 'def ' is very Python
        if text.contains("def ") {
            score += 1;
        } else if text.contains("class ") && !text.contains("public ") && !text.contains("private ")
        {
            // Python classes are just 'class Name:', not 'public class Name'
            score += 1;
        }
    }
    if text.contains("__import__") {
        score += 2;
    }
    if text.contains("exec(") || text.contains("compile(") {
        score += 1;
    }
    if text.contains("# -*- coding:") || has_shebang(text, &["python", "python2", "python3"]) {
        score += 2;
    }
    if text.contains("print(") {
        score += 1;
    }
    if text.contains("if __name__") {
        score += 2;
    }

    score
}

fn javascript_score(text: &str) -> u32 {
    let mut score = 0u32;

    if text.contains("require(") || text.contains("module.exports") {
        score += 2;
    }
    if text.contains("function ") || text.contains("=>") {
        score += 1;
    }
    if text.contains("const ") || text.contains("let ") || text.contains("var ") {
        score += 1;
    }
    if text.contains("eval(") {
        score += 1;
    }
    if text.contains("document.") || text.contains("window.") {
        score += 1;
    }
    if text.contains("console.log") {
        score += 1;
    }
    if has_shebang(text, &["node"]) {
        score += 2;
    }

    score
}

fn has_python_obfuscation(text: &str) -> bool {
    // Signs of Python obfuscation that boost confidence
    (text.contains("exec(") || text.contains("compile("))
        && (text.contains("base64")
            || text.contains("b64decode")
            || text.contains("fromhex")
            || text.contains("codecs")
            || text.contains("marshal")
            || text.contains("zlib"))
}

fn has_shebang(text: &str, interpreters: &[&str]) -> bool {
    let Some(first_line) = text.lines().next() else {
        return false;
    };

    let first_line = first_line.trim_start_matches('\u{feff}').trim();
    if !first_line.starts_with("#!") {
        return false;
    }

    let mut parts = first_line[2..].split_whitespace();
    let Some(command) = parts.next() else {
        return false;
    };

    if command == "/usr/bin/env" {
        return parts
            .next()
            .is_some_and(|name| interpreters.contains(&name));
    }

    command
        .rsplit('/')
        .next()
        .is_some_and(|name| interpreters.contains(&name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_lua_after_a_large_escaped_constant_table() {
        let prefix = format!("local n={{{}}}", r#""\084","#.repeat(2000));
        let program = format!(
            "{prefix} local function f() return string.sub(table.concat(n), math.floor(1)) end"
        );
        assert_eq!(
            detect_script_language(program.as_bytes()),
            Some(ScriptLanguage::Lua)
        );
        let spaced = program.replacen("local n={", "local n = { ", 1);
        assert_eq!(
            detect_script_language(spaced.as_bytes()),
            Some(ScriptLanguage::Lua)
        );
        assert_eq!(
            detect_script_language(prefix.as_bytes()),
            Some(ScriptLanguage::Lua)
        );
    }

    #[test]
    fn detects_python_imports() {
        let src = "import os\nimport sys\ndef main():\n    print('hello')\n";
        assert_eq!(
            detect_script_language(src.as_bytes()),
            Some(ScriptLanguage::Python)
        );
    }

    #[test]
    fn detects_obfuscated_python() {
        let src = "# -*- coding: utf-8 -*-\naqg = __import__('base64')\nexec(compile(aqg.b64decode('abc'), '<>', 'exec'))\n";
        assert_eq!(
            detect_script_language(src.as_bytes()),
            Some(ScriptLanguage::Python)
        );
    }

    #[test]
    fn detects_javascript_require() {
        let src =
            "const http = require('http');\nfunction handler(req, res) {\n  res.end('ok');\n}\n";
        assert_eq!(
            detect_script_language(src.as_bytes()),
            Some(ScriptLanguage::JavaScript)
        );
    }

    #[test]
    fn detects_javascript_eval_atob() {
        let src = "var x = 1;\neval(atob('YWxlcnQoMSk='));\n";
        assert_eq!(
            detect_script_language(src.as_bytes()),
            Some(ScriptLanguage::JavaScript)
        );
    }

    #[test]
    fn detects_php_open_tag() {
        let src = "<?php\neval(base64_decode('aW1wb3J0IG9z'));\n?>\n";
        assert_eq!(
            detect_script_language(src.as_bytes()),
            Some(ScriptLanguage::Php)
        );
    }

    #[test]
    fn detects_powershell_encoded_command() {
        let src = "powershell -EncodedCommand ZAByAGkAdABlAC0AaABvAHMAdAA=\n";
        assert_eq!(
            detect_script_language(src.as_bytes()),
            Some(ScriptLanguage::PowerShell)
        );
    }

    #[test]
    fn detects_powershell_convert_and_iex() {
        let src = "$data = [Convert]::FromBase64String('abc')\nInvoke-Expression $decoded\n";
        assert_eq!(
            detect_script_language(src.as_bytes()),
            Some(ScriptLanguage::PowerShell)
        );
    }

    #[test]
    fn plain_text_is_not_script() {
        let src = "Hello, this is a plain text file with no code.\n";
        assert_eq!(detect_script_language(src.as_bytes()), None);
    }

    #[test]
    fn csv_is_not_script() {
        let src = "name,age,city\nAlice,30,NYC\nBob,25,LA\n";
        assert_eq!(detect_script_language(src.as_bytes()), None);
    }

    #[test]
    fn json_is_not_script() {
        let src = r#"{"name": "test", "version": "1.0", "description": "a package"}"#;
        assert_eq!(detect_script_language(src.as_bytes()), None);
    }

    #[test]
    fn python_shebang_must_be_first_line() {
        let src = "#!/bin/sh\nprintf '%s\n' '#!/usr/bin/env python3'\n";
        assert_eq!(detect_script_language(src.as_bytes()), None);
    }

    #[test]
    fn detects_python3_shebang() {
        let src = "#!/usr/bin/env python3\nprint('hello')\n";
        assert_eq!(
            detect_script_language(src.as_bytes()),
            Some(ScriptLanguage::Python)
        );
    }

    #[test]
    fn detects_node_shebang() {
        let src = "#!/usr/bin/node\nconsole.log('hello')\n";
        assert_eq!(
            detect_script_language(src.as_bytes()),
            Some(ScriptLanguage::JavaScript)
        );
    }

    #[test]
    fn java_is_not_python() {
        let src = "package com.example;\nimport java.util.List;\npublic class MyClass {\n    private List<String> items;\n}\n";
        assert_ne!(
            detect_script_language(src.as_bytes()),
            Some(ScriptLanguage::Python)
        );

        let lottie = "package com.airbnb.lottie;\nimport android.os.Build;\npublic enum LottieFeatureFlag {\n    MergePathsApi19(Build.VERSION_CODES.KITKAT);\n}\n";
        assert_ne!(
            detect_script_language(lottie.as_bytes()),
            Some(ScriptLanguage::Python)
        );
    }
}

#[cfg(test)]
mod lua_leading_table_boundary_tests {
    use super::*;
    #[test]
    fn lua_table_before_language_probe_boundary() {
        let source = format!(
            "local constants = {{\"{}\"}} local function later() return constants end",
            "x".repeat(9000)
        );
        assert_eq!(
            detect_script_language(source.as_bytes()),
            Some(ScriptLanguage::Lua)
        );
        assert_eq!(
            detect_script_language(b"local \t renamed_2 = {answer=42} return renamed_2"),
            Some(ScriptLanguage::Lua)
        );
        assert_eq!(
            detect_script_language(b"-- header\nlocal _renamed = {answer=42} return _renamed"),
            Some(ScriptLanguage::Lua)
        );
        assert_ne!(
            detect_script_language(b"local 9invalid = {answer=42}"),
            Some(ScriptLanguage::Lua)
        );
        assert_ne!(
            detect_script_language(b"const constants={answer:42};"),
            Some(ScriptLanguage::Lua)
        );
        assert_ne!(
            detect_script_language(b"local words merely discuss = { data"),
            Some(ScriptLanguage::Lua)
        );
    }
}

#[cfg(test)]
mod declaration_tests {
    use super::{ScriptLanguage, detect_script_language};

    #[test]
    fn a_comment_mentioning_private_or_package_stays_python() {
        let src = "#!/usr/bin/env python3\n# decrypt the private key, then install this package\nimport os\nimport sys\ndef main():\n    os.system(sys.argv[1])\n";
        assert_eq!(
            detect_script_language(src.as_bytes()),
            Some(ScriptLanguage::Python)
        );
    }

    #[test]
    fn java_and_kotlin_declarations_are_not_python() {
        for src in [
            "package com.example;\nimport java.io.File;\nprivate static int x;\n",
            "package com.example\nimport kotlin.io\nprivate val x = 1\n",
        ] {
            assert_ne!(
                detect_script_language(src.as_bytes()),
                Some(ScriptLanguage::Python),
                "{src}"
            );
        }
    }
}
