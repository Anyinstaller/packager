use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn help_lists_the_build_command() {
    Command::cargo_bin("packager")
        .unwrap()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("build"));
}

#[test]
fn missing_build_directory_fails_without_creating_output() {
    let dir = tempfile::tempdir().unwrap();
    let output = dir.path().join("foo.exe");
    Command::cargo_bin("packager")
        .unwrap()
        .arg("build")
        .arg("--unsigned")
        .arg("--build-dir")
        .arg(dir.path().join("missing"))
        .arg("--output")
        .arg(&output)
        .assert()
        .failure();
    assert!(!output.exists());
}
