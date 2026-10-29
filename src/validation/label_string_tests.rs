use super::is_garbage;

/// Field-name labels ending in a colon must survive extraction.
///
/// `TracerPid:` is the literal an anti-debug check compares against when
/// parsing /proc/<pid>/status, so dropping it makes that behaviour
/// invisible in compiled binaries. It was observed missing from a real ELF
/// while its immediate neighbours (`/proc/self/status`, and a 5-character
/// `aeiou`) were both extracted, so neither length nor position explains
/// the loss — the trailing colon does, by adding one character-class run.
#[test]
fn colon_terminated_labels_are_not_garbage() {
    for s in [
        "TracerPid:",
        "Content-Length:",
        "Name:",
        "SigBlkd:",
        "VmRSS:",
        "Uid:",
    ] {
        assert!(!is_garbage(s), "label dropped: {s:?}");
    }
}
