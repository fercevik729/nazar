use anyhow::Result;
use assert_fs::prelude::*;
use nazar::{
    parse_rules,
    rule_config::{
        structs::{BWList, IpRange, PortRange, Protocol},
        RuleConfig,
    },
};
use std::net::{IpAddr, Ipv6Addr};
use std::path::PathBuf;

// Currently only supports json
#[test]
fn test_parse_rules_0() -> Result<()> {
    // Test for incorrect config file ext
    let invalid_ext = PathBuf::from(r"invalid.txt");
    let result = parse_rules(invalid_ext);
    assert!(result.is_err());

    // Test for missing config
    let missing_fp = PathBuf::from(r"missing.json");
    let result = parse_rules(missing_fp);
    assert!(result.is_err());

    Ok(())
}

#[test]
fn test_parse_rules_1() -> Result<()> {
    let file = assert_fs::NamedTempFile::new("rules.json")?;
    file.write_str(
        r#"
{
  "ip_list": {
    "WhiteList": [
      {
        "begin": "2001:db8::1",
        "end": "2001:db8::10"
      },
      {
        "begin": "fe80::1",
        "end": "fe80::ff:feff:1"
      }
    ]
  }
}"#,
    )?;

    let expect_config = RuleConfig {
        ip_list: Some(BWList::WhiteList(vec![
            IpRange::new(
                IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>()?),
                Some(IpAddr::V6("2001:db8::10".parse::<Ipv6Addr>()?)),
            )?,
            IpRange::new(
                IpAddr::V6("fe80::1".parse::<Ipv6Addr>()?),
                Some(IpAddr::V6("fe80::ff:feff:1".parse::<Ipv6Addr>()?)),
            )?,
        ])),
        port_list: None,
        protocol_list: None,
        rules: None,
    };

    let config: RuleConfig = *parse_rules(file.to_path_buf())?;
    assert!(expect_config.ip_list == config.ip_list);

    Ok(())
}

#[test]
fn test_parse_rules_2() -> Result<()> {
    let file = assert_fs::NamedTempFile::new("rules.json")?;
    file.write_str(
        r#"
{
  "ip_list": {
    "WhiteList": [
      {
        "begin": "2001:db8::1",
        "end": "2001:db8::10"
      },
      {
        "begin": "fe80::1",
        "end": "fe80::ff:feff:1"
      }
    ]
  },
  "protocol_list": {
    "BlackList": ["Udp", "Icmp"] 
  }
}"#,
    )?;

    let expect_config = RuleConfig {
        ip_list: Some(BWList::WhiteList(vec![
            IpRange::new(
                IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>()?),
                Some(IpAddr::V6("2001:db8::10".parse::<Ipv6Addr>()?)),
            )?,
            IpRange::new(
                IpAddr::V6("fe80::1".parse::<Ipv6Addr>()?),
                Some(IpAddr::V6("fe80::ff:feff:1".parse::<Ipv6Addr>()?)),
            )?,
        ])),
        port_list: None,
        protocol_list: Some(BWList::BlackList(vec![Protocol::Udp, Protocol::Icmp])),
        rules: None,
    };

    let config: RuleConfig = *parse_rules(file.to_path_buf())?;
    assert!(
        config.ip_list == expect_config.ip_list
            && config.protocol_list == expect_config.protocol_list
    );

    Ok(())
}

#[test]
fn test_parse_rules_3() -> Result<()> {
    let file = assert_fs::NamedTempFile::new("rules.json")?;
    file.write_str(
        r#"
{
  "ip_list": {
    "WhiteList": [
      {
        "begin": "2001:db8::1",
        "end": "2001:db8::10"
      },
      {
        "begin": "fe80::1",
        "end": "fe80::ff:feff:1"
      }
    ]
  },
  "protocol_list": {
    "BlackList": ["Udp", "Icmp"] 
  },
  "port_list": {
    "WhiteList": [
      {
        "begin": 20,
        "end": 22
      },
      {
        "begin": 80,
        "end": 84
      }
    ]
  }
}
    "#,
    )?;

    let expect_config = RuleConfig {
        ip_list: Some(BWList::WhiteList(vec![
            IpRange::new(
                IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>()?),
                Some(IpAddr::V6("2001:db8::10".parse::<Ipv6Addr>()?)),
            )?,
            IpRange::new(
                IpAddr::V6("fe80::1".parse::<Ipv6Addr>()?),
                Some(IpAddr::V6("fe80::ff:feff:1".parse::<Ipv6Addr>()?)),
            )?,
        ])),
        port_list: Some(BWList::WhiteList(vec![
            PortRange::new(20, Some(22)).unwrap(),
            PortRange::new(80, Some(84)).unwrap(),
        ])),
        protocol_list: Some(BWList::BlackList(vec![Protocol::Udp, Protocol::Icmp])),
        rules: None,
    };

    let config: RuleConfig = *parse_rules(file.to_path_buf())?;
    assert!(
        config.ip_list == expect_config.ip_list
            && config.protocol_list == expect_config.protocol_list
            && config.port_list == expect_config.port_list
    );

    Ok(())
}
