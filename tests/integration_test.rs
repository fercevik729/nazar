use anyhow::Result;
use assert_fs::prelude::*;
use nazar::{
    parse_rules,
    rule_parser::{rules::RuleConfig, BWList, IpRange, PortRange, Protocol},
};
use std::net::{IpAddr, Ipv6Addr};

// Currently only supports json
#[test]
fn test_parse_rules_1() -> Result<()> {
    let file = assert_fs::NamedTempFile::new("rules.json")?;
    file.write_str(
        r#"
{
  "src_ip_list": {
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
        src_ip_list: Some(BWList::WhiteList(vec![
            IpRange::new(
                IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>()?),
                Some(IpAddr::V6("2001:db8::10".parse::<Ipv6Addr>()?)),
            )?,
            IpRange::new(
                IpAddr::V6("fe80::1".parse::<Ipv6Addr>()?),
                Some(IpAddr::V6("fe80::ff:feff:1".parse::<Ipv6Addr>()?)),
            )?,
        ])),
        dest_ip_list: None,
        port_list: None,
        protoc_list: None,
        rules: None,
    };

    let config: RuleConfig = *parse_rules(file.path())?;
    assert!(expect_config.src_ip_list == config.src_ip_list);

    Ok(())
}

#[test]
fn test_parse_rules_2() -> Result<()> {
    let file = assert_fs::NamedTempFile::new("rules.json")?;
    file.write_str(
        r#"
{
  "src_ip_list": {
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
  "protoc_list": {
    "BlackList": ["Udp", "Icmp"] 
  }
}"#,
    )?;

    let expect_config = RuleConfig {
        src_ip_list: Some(BWList::WhiteList(vec![
            IpRange::new(
                IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>()?),
                Some(IpAddr::V6("2001:db8::10".parse::<Ipv6Addr>()?)),
            )?,
            IpRange::new(
                IpAddr::V6("fe80::1".parse::<Ipv6Addr>()?),
                Some(IpAddr::V6("fe80::ff:feff:1".parse::<Ipv6Addr>()?)),
            )?,
        ])),
        dest_ip_list: None,
        port_list: None,
        protoc_list: Some(BWList::BlackList(vec![Protocol::Udp, Protocol::Icmp])),
        rules: None,
    };

    let config: RuleConfig = *parse_rules(file.path())?;
    assert!(
        config.src_ip_list == expect_config.src_ip_list
            && config.protoc_list == expect_config.protoc_list
    );

    Ok(())
}

#[test]
fn test_parse_rules_3() -> Result<()> {
    let file = assert_fs::NamedTempFile::new("rules.json")?;
    file.write_str(
        r#"
{
  "src_ip_list": {
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
  "protoc_list": {
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
        src_ip_list: Some(BWList::WhiteList(vec![
            IpRange::new(
                IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>()?),
                Some(IpAddr::V6("2001:db8::10".parse::<Ipv6Addr>()?)),
            )?,
            IpRange::new(
                IpAddr::V6("fe80::1".parse::<Ipv6Addr>()?),
                Some(IpAddr::V6("fe80::ff:feff:1".parse::<Ipv6Addr>()?)),
            )?,
        ])),
        dest_ip_list: None,
        port_list: Some(BWList::WhiteList(vec![
            PortRange::new(20, Some(22))?,
            PortRange::new(80, Some(84))?,
        ])),
        protoc_list: Some(BWList::BlackList(vec![Protocol::Udp, Protocol::Icmp])),
        rules: None,
    };

    let config: RuleConfig = *parse_rules(file.path())?;
    assert!(
        config.src_ip_list == expect_config.src_ip_list
            && config.protoc_list == expect_config.protoc_list
            && config.port_list == expect_config.port_list
    );

    Ok(())
}
