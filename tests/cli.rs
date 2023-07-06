extern crate assert_cmd;
extern crate assert_fs;
extern crate predicates;

use assert_cmd::prelude::*;
use assert_fs::prelude::*;
use predicates::prelude::*;
use std::path::Path;
use std::process::Command;

#[test]
fn rules_file_doesnt_exist() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("nazar")?;

    cmd.arg("--rules").arg("rules.toml");
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("No rules file"));

    Ok(())
}

#[test]
fn invalid_rules_file_ext() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("nazar")?;

    cmd.arg("--rules").arg("file/doesnt/exist.txt");
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("rules file must be a .toml file"));

    Ok(())
}

#[test]
fn simple_rules_file() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::cargo_bin("nazar")?;
    let file = assert_fs::NamedTempFile::new("rules.toml")?;
    file.write_str("[whitelist]\n127.0.0.1\n192.168.23.1\n192.168.23.4")?;

    let fp = file.path();
    cmd.arg("--rules").arg(fp);
    cmd.assert()
        .failure()
        .stdout(predicate::str::contains(format!(
            "Reading rules from `{}`",
            fp.display()
        )));
    Ok(())
}
