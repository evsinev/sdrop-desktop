//! SPEC 4, 12.1: the logic never prints or logs (a secret could end up in a terminal or a log
//! file). Test code is allowed to.

#[test]
fn core_sources_do_not_print_or_log() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut checked = 0;
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if !name.ends_with(".rs") || name.ends_with("_tests.rs") || name == "fake.rs" {
            continue;
        }
        let src = std::fs::read_to_string(&path).unwrap();
        // Unit tests at the end of a file are allowed to print.
        let code = src.split("#[cfg(test)]").next().unwrap();
        for bad in [
            "println!",
            "eprintln!",
            "print!(",
            "eprint!(",
            "dbg!",
            "log::",
            "tracing::",
        ] {
            assert!(!code.contains(bad), "{name} uses {bad}");
        }
        checked += 1;
    }
    assert!(checked >= 8, "the check must see the sources ({checked})");
}
