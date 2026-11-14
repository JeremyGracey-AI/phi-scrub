//! CLI behavior: text on stdin, redacted text on stdout.

use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn default_mode_redacts_stdin() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_phi-scrub"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"SSN 123-45-6789")
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    assert_eq!(String::from_utf8(output.stdout).unwrap(), "SSN [SSN]");
}
