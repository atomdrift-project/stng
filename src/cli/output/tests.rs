use super::*;

#[test]
fn test_wrap_string_lines_no_wrap_needed() {
    let text = "Short string";
    let result = wrap_string_lines(text, 0, 100);
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].0, 0);
    assert_eq!(result[0].1, text);
}

#[test]
fn test_wrap_string_lines_exact_width() {
    let text = "Exactly10!";
    let result = wrap_string_lines(text, 0, 10);
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].0, 0);
    assert_eq!(result[0].1, text);
}

#[test]
fn test_wrap_string_lines_basic_wrap() {
    let text = "This is a longer string that needs wrapping";
    let result = wrap_string_lines(text, 0, 20);

    // Should be wrapped into multiple lines
    assert!(result.len() > 1, "String should be wrapped");

    // First line should start at offset 0
    assert_eq!(result[0].0, 0);

    // Second line should start after first line
    let first_line_len = result[0].1.len();
    assert_eq!(result[1].0, first_line_len as u64);

    // Verify all content is preserved
    let rejoined: String = result.iter().map(|(_, text)| text.as_str()).collect();
    assert_eq!(rejoined, text);
}

#[test]
fn test_wrap_string_lines_offset_tracking() {
    let text = "AAAABBBBCCCCDDDD";
    let result = wrap_string_lines(text, 100, 4);

    // Should be split into 4 parts: AAAA, BBBB, CCCC, DDDD
    assert_eq!(result.len(), 4);

    // Check offsets
    assert_eq!(result[0].0, 100); // AAAA at offset 100
    assert_eq!(result[1].0, 104); // BBBB at offset 104 (100 + 4)
    assert_eq!(result[2].0, 108); // CCCC at offset 108 (104 + 4)
    assert_eq!(result[3].0, 112); // DDDD at offset 112 (108 + 4)

    // Check content
    assert_eq!(result[0].1, "AAAA");
    assert_eq!(result[1].1, "BBBB");
    assert_eq!(result[2].1, "CCCC");
    assert_eq!(result[3].1, "DDDD");
}

#[test]
fn test_wrap_string_lines_utf8() {
    // Each emoji is 4 bytes
    let text = "🔥🔥🔥🔥";
    let result = wrap_string_lines(text, 0, 2);

    // Should wrap into 2 lines of 2 emojis each
    assert_eq!(result.len(), 2);

    // First line: 2 emojis = 8 bytes
    assert_eq!(result[0].0, 0);
    assert_eq!(result[0].1, "🔥🔥");

    // Second line: starts at byte 8
    assert_eq!(result[1].0, 8);
    assert_eq!(result[1].1, "🔥🔥");
}

#[test]
fn test_wrap_string_lines_mixed_width_chars() {
    // Mix of ASCII and multi-byte UTF-8
    let text = "Hi🔥there";
    let result = wrap_string_lines(text, 0, 4);

    // Should wrap properly: "Hi🔥t" (2 + 4 + 1 = 7 bytes), "here" (4 bytes)
    assert_eq!(result.len(), 2);
    assert_eq!(result[0].0, 0);
    assert_eq!(result[0].1, "Hi🔥t");
    assert_eq!(result[1].0, 7);
    assert_eq!(result[1].1, "here");
}

#[test]
fn test_wrap_string_lines_empty() {
    let text = "";
    let result = wrap_string_lines(text, 42, 100);
    assert_eq!(result.len(), 0);
}

#[test]
fn test_wrap_string_lines_zero_width() {
    let text = "Some text";
    let result = wrap_string_lines(text, 0, 0);

    // Zero width should return the whole string as-is
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].1, text);
}

#[test]
fn test_wrap_string_lines_preserves_content() {
    let text = "abcdefghijklmnopqrstuvwxyz0123456789";
    let result = wrap_string_lines(text, 0, 10);

    // Reconstruct the string
    let reconstructed: String = result.iter().map(|(_, s)| s.as_str()).collect();
    assert_eq!(reconstructed, text, "Wrapping should preserve all content");
}

#[test]
fn test_wrap_string_lines_single_char_width() {
    let text = "ABCDEF";
    let result = wrap_string_lines(text, 0, 1);

    // Should wrap into 6 lines, one char each
    assert_eq!(result.len(), 6);
    assert_eq!(result[0].1, "A");
    assert_eq!(result[1].1, "B");
    assert_eq!(result[2].1, "C");
    assert_eq!(result[3].1, "D");
    assert_eq!(result[4].1, "E");
    assert_eq!(result[5].1, "F");

    // Check offsets increment by 1 each time
    for (i, item) in result.iter().enumerate().take(6) {
        assert_eq!(item.0, i as u64);
    }
}

#[test]
fn test_terminal_safe_escapes_control_sequences() {
    // OSC 52 (clipboard write), CSI conceal, CR overwrite, and a
    // right-to-left override: all shown, none acted on.
    assert_eq!(
        terminal_safe("a\x1b]52;c;Zm9v\x07b"),
        "a\\u{1b}]52;c;Zm9v\\u{7}b"
    );
    assert_eq!(terminal_safe("x\x1b[8my"), "x\\u{1b}[8my");
    assert_eq!(terminal_safe("good\rbad"), "good\\rbad");
    assert_eq!(terminal_safe("one\ntwo"), "one\\ntwo");
    assert_eq!(terminal_safe("abc\u{202e}gpj.exe"), "abc\\u{202e}gpj.exe");
    assert_eq!(terminal_safe("c1\u{9b}31m"), "c1\\u{9b}31m");
}

#[test]
fn colorize_xml_line_colors_key_and_string() {
    assert_eq!(
        colorize_xml_line("<key>a</key><string>b</string>"),
        format!("<key>{RED}a{RESET}</key><string>{CYAN}b{RESET}</string>")
    );
}

#[test]
fn colorize_xml_line_tolerates_misordered_tags() {
    // Closing tags before opening ones come from hostile signatures.
    for line in ["</key><key>", "</string><string>", "<key>", "</string>"] {
        assert_eq!(colorize_xml_line(line), line);
    }
    assert_eq!(
        colorize_xml_line("</key><key>x</key>"),
        format!("</key><key>{RED}x{RESET}</key>")
    );
}

#[test]
fn test_terminal_safe_borrows_clean_text() {
    for text in ["plain", "tab\tseparated", "ünïcødé 🔥", ""] {
        assert!(matches!(terminal_safe(text), Cow::Borrowed(t) if t == text));
    }
}

#[test]
fn test_wrap_string_lines_long_input_is_linear() {
    // Quadratic wrapping took minutes on a string this size.
    let text = "a".repeat(4 * 1024 * 1024);
    let result = wrap_string_lines(&text, 0, 80);
    assert_eq!(result.len(), text.len().div_ceil(80));
    assert_eq!(result.last().map(|(o, _)| *o), Some(4 * 1024 * 1024 - 64));
}
