//! Each test gets a private cache root; none touches the user's cache.

use super::*;

/// A cache root unique to this test, removed when dropped.
struct Root(PathBuf);

impl Root {
    fn new(name: &str) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        Self(std::env::temp_dir().join(format!(
            "stng-cache-test-{name}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )))
    }

    fn entry(&self, data: &[u8]) -> Entry {
        Entry::at(&self.0, data, Path::new("/nonexistent/rizin")).unwrap()
    }
}

impl Drop for Root {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn command_file_names_are_filesystem_safe() {
    assert_eq!(file_name("isj"), "isj");
    assert_eq!(file_name("aaa; e scr.color=0"), "aaa__e_scr.color_0");
    assert_eq!(file_name("pdf @ entry0"), "pdf___entry0");
    let long = file_name(&"aoj 1 @ 0x1000; ".repeat(10));
    assert!(long.starts_with("cmd_") && long.len() == 4 + 64, "{long}");
}

#[test]
fn outputs_round_trip_and_persist() {
    let root = Root::new("round-trip");
    let commands = ["isj", "izzj", "aaa; /at xor; p8 1 @ 0; /at lea", ""];
    let large = "[".to_string() + &r#"{"name":"f"},"#.repeat(1000) + "]";
    let outputs = [r#"[{"name":"main"}]"#, "", "0x1000 xor\n", large.as_str()];
    let entry = root.entry(b"binary");
    for (command, output) in commands.iter().zip(outputs) {
        assert_eq!(entry.get(command), None);
        entry.set(command, output).unwrap();
    }
    let reopened = root.entry(b"binary");
    for (command, output) in commands.iter().zip(outputs) {
        assert_eq!(reopened.get(command).as_deref(), Some(output), "{command}");
    }
}

#[test]
fn other_content_or_tool_misses() {
    let root = Root::new("keys");
    root.entry(b"binary").set("isj", "[]").unwrap();
    assert_eq!(root.entry(b"binary!").get("isj"), None);
    let other_tool = Entry::at(&root.0, b"binary", Path::new("/nonexistent/r2")).unwrap();
    assert_eq!(other_tool.get("isj"), None);
}

#[test]
fn clear_removes_only_that_input() {
    let root = Root::new("clear");
    let (a, b) = (root.entry(b"a"), root.entry(b"b"));
    a.set("isj", "[]").unwrap();
    a.set("izzj", "[]").unwrap();
    b.set("isj", "[]").unwrap();
    a.clear().unwrap();
    assert_eq!(a.get("isj"), None);
    assert_eq!(a.get("izzj"), None);
    assert!(b.get("isj").is_some());
    a.clear().unwrap();
}

#[test]
#[cfg(unix)]
fn entries_are_private() {
    use std::os::unix::fs::PermissionsExt;
    let root = Root::new("private");
    let entry = root.entry(b"binary");
    entry.set("isj", "[]").unwrap();
    for dir in [&root.0, &entry.dir] {
        assert_eq!(
            fs::metadata(dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }
}

#[test]
#[cfg(unix)]
fn prune_drops_the_stale_then_the_oldest() {
    let root = Root::new("prune");
    let now = SystemTime::now();
    let ages = [
        ("stale", MAX_AGE + Duration::from_secs(60)),
        ("oldest", Duration::from_secs(300)),
        ("older", Duration::from_secs(200)),
        ("newest", Duration::from_secs(100)),
    ];
    for (name, age) in ages {
        let dir = root.0.join(name);
        create_private_dir(&dir).unwrap();
        fs::File::open(&dir)
            .unwrap()
            .set_modified(now - age)
            .unwrap();
    }
    let kept = || {
        let mut names: Vec<String> = fs::read_dir(&root.0)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    };
    prune(&root.0, 10);
    assert_eq!(kept(), ["newest", "older", "oldest"]);
    prune(&root.0, 2);
    assert_eq!(kept(), ["newest", "older"]);
}
