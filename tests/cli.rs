extern crate anyhow;
extern crate assert_cmd;
extern crate assert_fs;
extern crate predicates;

use anyhow::Result;
use assert_cmd::prelude::*;
use assert_fs::prelude::*;
use predicates::prelude::*;
use std::process::Command;

mod utils;

#[test]
fn rules_file_doesnt_exist() -> Result<()> {
    let mut cmd = Command::cargo_bin("nazar")?;
    cmd.arg("--rules").arg("rules.json");
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("No rules file"));
    Ok(())
}

#[test]
fn invalid_rules_file_ext() -> Result<()> {
    let mut cmd = Command::cargo_bin("nazar")?;
    let invalid_file = assert_fs::NamedTempFile::new("invalidext.txt")?;

    cmd.arg("--rules").arg(invalid_file.path());
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("rules file must be a .json file"));

    Ok(())
}

#[ignore]
#[test]
fn simple_rules_file() -> Result<()> {
    let mut cmd = Command::cargo_bin("nazar")?;
    let file = assert_fs::NamedTempFile::new("rules.json")?;
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
