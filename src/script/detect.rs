//! Script language detection heuristics.
//!
//! Identifies Python, JavaScript, PHP, and PowerShell scripts from text content.
//! Only called after `is_text_file()` returns true.

/// Detected script language.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScriptLanguage {
    Python,
    JavaScript,
    Php,
    PowerShell,
}

impl ScriptLanguage {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Python => "python",
            Self::JavaScript => "javascript",
            Self::Php => "php",
            Self::PowerShell => "powershell",
        }
    }
}

/// Detect what scripting language a text file is written in, if any.
///
/// Examines the first ~8KB for language-specific markers. Returns `None`
/// for plain text, config files, data files, etc.
pub fn detect_script_language(data: &[u8]) -> Option<ScriptLanguage> {
    let sample_size = data.len().min(8192);
    let text = std::str::from_utf8(&data[..sample_size]).ok()?;

    // PHP is very distinctive — check first
    if is_php(text) {
        return Some(ScriptLanguage::Php);
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
    if js_score >= 1 && has_javascript_obfuscation(text) {
        return Some(ScriptLanguage::JavaScript);
    }

    None
}

fn is_php(text: &str) -> bool {
    text.contains("<?php") || text.contains("<?=")
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

fn python_score(text: &str) -> u32 {
    let mut score = 0u32;

    // Strong indicators
    if text.contains("import ") || text.contains("from ") {
        score += 1;
    }
    if text.contains("def ") || text.contains("class ") {
        score += 1;
    }
    if text.contains("__import__") {
        score += 2;
    }
    if text.contains("exec(") || text.contains("compile(") {
        score += 1;
    }
    if text.contains("# -*- coding:")
        || text.contains("#!/usr/bin/env python")
        || text.contains("#!/usr/bin/python")
    {
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
    if text.contains("#!/usr/bin/env node") {
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

fn has_javascript_obfuscation(text: &str) -> bool {
    (text.contains("eval(") || text.contains("Function("))
        && (text.contains("atob(") || text.contains("Buffer.from") || text.contains("fromCharCode"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_python() {
        let src = "import os\nimport sys\ndef main():\n    print('hello')\n";
        assert_eq!(
            detect_script_language(src.as_bytes()),
            Some(ScriptLanguage::Python)
        );
    }

    #[test]
    fn test_detect_python_obfuscated() {
        let src = "# -*- coding: utf-8 -*-\naqg = __import__('base64')\nexec(compile(aqg.b64decode('abc'), '<>', 'exec'))\n";
        assert_eq!(
            detect_script_language(src.as_bytes()),
            Some(ScriptLanguage::Python)
        );
    }

    #[test]
    fn test_detect_javascript() {
        let src =
            "const http = require('http');\nfunction handler(req, res) {\n  res.end('ok');\n}\n";
        assert_eq!(
            detect_script_language(src.as_bytes()),
            Some(ScriptLanguage::JavaScript)
        );
    }

    #[test]
    fn test_detect_javascript_eval() {
        let src = "var x = 1;\neval(atob('YWxlcnQoMSk='));\n";
        assert_eq!(
            detect_script_language(src.as_bytes()),
            Some(ScriptLanguage::JavaScript)
        );
    }

    #[test]
    fn test_detect_php() {
        let src = "<?php\neval(base64_decode('aW1wb3J0IG9z'));\n?>\n";
        assert_eq!(
            detect_script_language(src.as_bytes()),
            Some(ScriptLanguage::Php)
        );
    }

    #[test]
    fn test_detect_powershell_encoded() {
        let src = "powershell -EncodedCommand ZAByAGkAdABlAC0AaABvAHMAdAA=\n";
        assert_eq!(
            detect_script_language(src.as_bytes()),
            Some(ScriptLanguage::PowerShell)
        );
    }

    #[test]
    fn test_detect_powershell_iex() {
        let src = "$data = [Convert]::FromBase64String('abc')\nInvoke-Expression $decoded\n";
        assert_eq!(
            detect_script_language(src.as_bytes()),
            Some(ScriptLanguage::PowerShell)
        );
    }

    #[test]
    fn test_detect_plain_text() {
        let src = "Hello, this is a plain text file with no code.\n";
        assert_eq!(detect_script_language(src.as_bytes()), None);
    }

    #[test]
    fn test_detect_csv() {
        let src = "name,age,city\nAlice,30,NYC\nBob,25,LA\n";
        assert_eq!(detect_script_language(src.as_bytes()), None);
    }

    #[test]
    fn test_detect_json() {
        let src = r#"{"name": "test", "version": "1.0", "description": "a package"}"#;
        assert_eq!(detect_script_language(src.as_bytes()), None);
    }
}
