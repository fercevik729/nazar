extern crate anyhow;
extern crate pnet;
extern crate serde;
extern crate toml;

use std::net::{IpAddr, Ipv6Addr};

use serde::Deserialize;

use anyhow::{anyhow, Result};

trait Validate {
    type Item: Copy;

    fn is_valid(&self, other: Self::Item) -> bool;
}

// A struct to handle inclusive IP address ranges
#[derive(Deserialize, PartialEq, Debug)]
struct IpRange {
    begin: Ipv6Addr,
    end: Option<Ipv6Addr>,
}

impl IpRange {
    // Creates an IpRange struct of the `begin` and `end` parameters
    fn new(begin: IpAddr, end: Option<IpAddr>) -> Result<Self> {
        // Match statements to ensure IpAddresses are converted to v6
        let begin_ip = match begin {
            IpAddr::V4(ip) => ip.to_ipv6_mapped(),
            IpAddr::V6(ip) => ip,
        };

        let end_ip = match end {
            Some(ip) => match ip {
                IpAddr::V4(i) => Some(i.to_ipv6_mapped()),
                IpAddr::V6(i) => Some(i),
            },
            None => None,
        };

        // Bounds check
        if let Some(e) = end_ip {
            if e < begin_ip {
                return Err(anyhow!(
                    "end_ip {} must be greater than or equal to begin_ip {}",
                    e,
                    begin_ip
                ));
            }
        }

        Ok(Self {
            begin: begin_ip,
            end: end_ip,
        })
    }
}

impl Validate for IpRange {
    type Item = IpAddr;
    // Checks if an ip address `ip` is in the range of the IpRange
    fn is_valid(&self, other: Self::Item) -> bool {
        // Convert `ip` parameter if it is v4
        let new_ip = match other {
            IpAddr::V6(i) => i,
            IpAddr::V4(i) => i.to_ipv6_mapped(),
        };

        // Final range check
        match self.end {
            Some(e) => new_ip >= self.begin && new_ip <= e,
            None => new_ip == self.begin,
        }
    }
}

// IpRange unit tests
#[cfg(test)]
mod iprange_tests {
    use super::*;
    use crate::test_macros::*;

    use std::{
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
        str::FromStr,
    };

    #[test]
    fn new_two_endpoints() {
        let b = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let e = Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3)));

        let exp = IpRange {
            begin: Ipv4Addr::new(127, 0, 0, 1).to_ipv6_mapped(),
            end: Some(Ipv4Addr::new(127, 0, 0, 3).to_ipv6_mapped()),
        };

        assert_ok!(IpRange::new(b, e), exp)
    }

    #[test]
    fn new_one_endpoint() {
        let b = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let e = None;

        let exp = IpRange {
            begin: Ipv4Addr::new(127, 0, 0, 1).to_ipv6_mapped(),
            end: None,
        };

        assert_ok!(IpRange::new(b, e), exp)
    }

    #[test]
    fn new_invalid_range() {
        let b = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3));
        let e_val = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let e = Some(e_val);

        let b_v6 = Ipv4Addr::new(127, 0, 0, 3).to_ipv6_mapped();
        let e_v6 = Ipv4Addr::new(127, 0, 0, 1).to_ipv6_mapped();

        let exp = format!(
            "end_ip {} must be greater than or equal to begin_ip {}",
            e_v6, b_v6
        );
        assert_err!(IpRange::new(b, e), exp);
    }
}

#[derive(Deserialize)]
struct PortRange {
    begin: i32,
    end: Option<i32>,
}

impl PortRange {
    fn new(begin: i32, end: Option<i32>) -> Result<Self> {
        // Validate the port numbers are within the 0 to 65536 range
        let valid_ports = 0..65536;
        if !(valid_ports).contains(&begin) {
            return Err(anyhow!(
                "begin port {} must be in the range 0 to 65536",
                begin
            ));
        }
        match end {
            Some(e) if !(valid_ports).contains(&e) => {
                return Err(anyhow!("end port {} must be in the range 0 to 65536", e));
            }
            Some(e) if e < begin => {
                return Err(anyhow!(
                    "end port {} must be greater than or equal to begin port {}",
                    e,
                    begin,
                ))
            }
            _ => Ok(Self { begin, end }),
        }
    }
}

impl Validate for PortRange {
    type Item = i32;

    fn is_valid(&self, other: Self::Item) -> bool {
        if let Some(e) = self.end {
            other >= self.begin && other <= e
        } else {
            other == self.begin
        }
    }
}

// Enum to represent blacklist and whitelist
// for src/dest IP addresses
// for ports
// for protocols
#[derive(Deserialize)]
enum BWList<T: Validate> {
    WhiteList(Vec<T>),
    BlackList(Vec<T>),
}

impl<T: Validate + PartialEq> BWList<T> {
    fn is_valid_item(&self, target: T::Item) -> bool {
        match self {
            BWList::WhiteList(v) => return v.iter().find(|item| item.is_valid(target)) != None,
            BWList::BlackList(v) => return v.iter().find(|item| item.is_valid(target)) == None,
        }
    }
}

#[cfg(test)]
mod bwlist_tests {

    use anyhow::Result;

    use super::*;
    use crate::test_macros::*;

    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn whitelist_ip_tests() -> Result<()> {
        let wl = BWList::WhiteList(vec![
            IpRange::new(
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 5)),
                Some(IpAddr::V4(Ipv4Addr::new(147, 168, 0, 3))),
            )?,
            IpRange::new(
                IpAddr::V4(Ipv4Addr::new(150, 0, 0, 5)),
                Some(IpAddr::V4(Ipv4Addr::new(162, 168, 0, 3))),
            )?,
            IpRange::new(
                IpAddr::V4(Ipv4Addr::new(170, 0, 0, 5)),
                Some(IpAddr::V4(Ipv4Addr::new(192, 128, 0, 1))),
            )?,
            IpRange::new(IpAddr::V4(Ipv4Addr::new(192, 132, 0, 1)), None)?,
        ]);

        assert!(wl.is_valid_item(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 5))));
        assert!(!wl.is_valid_item(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 4))));
        assert!(wl.is_valid_item(IpAddr::V4(Ipv4Addr::new(161, 0, 0, 4))));
        assert!(!wl.is_valid_item(IpAddr::V4(Ipv4Addr::new(200, 0, 0, 4))));
        assert!(wl.is_valid_item(IpAddr::V4(Ipv4Addr::new(181, 0, 0, 4))));
        assert!(!wl.is_valid_item(IpAddr::V4(Ipv4Addr::new(192, 132, 0, 4))));

        Ok(())
    }

    #[test]
    fn blacklist_ip_tests() -> Result<()> {
        let bl = BWList::BlackList(vec![
            IpRange::new(
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 5)),
                Some(IpAddr::V4(Ipv4Addr::new(147, 168, 0, 3))),
            )?,
            IpRange::new(
                IpAddr::V4(Ipv4Addr::new(150, 0, 0, 5)),
                Some(IpAddr::V4(Ipv4Addr::new(162, 168, 0, 3))),
            )?,
            IpRange::new(
                IpAddr::V4(Ipv4Addr::new(170, 0, 0, 5)),
                Some(IpAddr::V4(Ipv4Addr::new(192, 128, 0, 1))),
            )?,
            IpRange::new(IpAddr::V4(Ipv4Addr::new(192, 132, 0, 1)), None)?,
        ]);

        assert!(!bl.is_valid_item(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 5))));
        assert!(bl.is_valid_item(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 4))));
        assert!(!bl.is_valid_item(IpAddr::V4(Ipv4Addr::new(161, 0, 0, 4))));
        assert!(bl.is_valid_item(IpAddr::V4(Ipv4Addr::new(200, 0, 0, 4))));
        assert!(!bl.is_valid_item(IpAddr::V4(Ipv4Addr::new(181, 0, 0, 4))));
        assert!(bl.is_valid_item(IpAddr::V4(Ipv4Addr::new(192, 132, 0, 4))));

        Ok(())
    }

    #[test]
    fn whitelist_port_tests() -> Result<()> {
        let wl = BWList::WhiteList(vec![
            PortRange::new(80, Some(82)),
            PortRange::new(90, Some(95)),
            PortRange::new(103, Some(195)),
            PortRange::new(202, Some(195)),
        ]);

        Ok(())
    }
}

#[derive(Deserialize)]
struct Rules {
    ip_list: Option<BWList<IpRange>>,
}
