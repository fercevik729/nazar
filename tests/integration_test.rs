extern crate anyhow;
extern crate assert_fs;
extern crate predicates;

use anyhow::Result;
use assert_fs::prelude::*;
use nazar::{parse_rules, rule_parser::rules::Rules};

#[test]
fn test_parse_rules() -> Result<()> {
    let file = assert_fs::NamedTempFile::new("rules.json")?;
    file.write_str(
        "{
  \"src_ip_list\": {
    \"WhiteList\": [
      {
        \"begin\": \"2001:db8::1\",
        \"end\": \"2001:db8::10\"
      },
      {
        \"begin\": \"fe80::1\",
        \"end\": \"fe80::ff:feff:1\"
      }
    ]
  }
}
",
    )?;

    let rules: Rules = parse_rules(file.path())?;

    Ok(())
}
