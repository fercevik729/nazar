use std::net::{IpAddr, Ipv6Addr};

use serde::Deserialize;

use anyhow::{anyhow, Result};

pub mod rules;

pub trait Validate {
    type Item: Copy;

    // A function to check if an item `other` is considered valid
    // for a given trait object
    fn is_valid(&self, other: Self::Item) -> bool;
}

// A struct to handle inclusive IP address ranges
#[derive(Deserialize, PartialEq, Eq, Debug)]
pub struct IpRange {
    begin: Ipv6Addr,
    end: Option<Ipv6Addr>,
}
impl IpRange {
    // Creates an IpRange struct of the `begin` and `end` parameters
    pub fn new(begin: IpAddr, end: Option<IpAddr>) -> Result<Self> {
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

    use crate::{assert_err, assert_ok};

    use std::net::{IpAddr, Ipv4Addr};

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

    #[test]
    fn is_valid_ip() -> Result<()> {
        let b1 = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let ipr1 = IpRange::new(b1, None)?;

        assert!(ipr1.is_valid(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        assert!(!ipr1.is_valid(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3))));

        let b2 = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 5));
        let e2 = Some(IpAddr::V4(Ipv4Addr::new(127, 1, 2, 19)));
        let ipr2 = IpRange::new(b2, e2)?;

        assert!(!ipr2.is_valid(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        assert!(!ipr2.is_valid(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 4))));
        assert!(ipr2.is_valid(IpAddr::V4(Ipv4Addr::new(127, 1, 0, 4))));
        assert!(!ipr2.is_valid(IpAddr::V4(Ipv4Addr::new(127, 1, 2, 20))));

        Ok(())
    }
}

// A struct to represent Port Ranges
// To be used with the BWList struct
// to specify which ports are allowed/forbidden
// to be crossed during a connection
#[derive(Deserialize, Debug, PartialEq, Eq)]
pub struct PortRange {
    begin: i32,
    end: Option<i32>,
}

impl PortRange {
    pub fn new(begin: i32, end: Option<i32>) -> Result<Self> {
        // Validate the port numbers are within the 0 to 65536 range
        let valid_ports = 0..=65536;
        if !(valid_ports).contains(&begin) {
            return Err(anyhow!(
                "begin port {} must be in the range 0 to 65536",
                begin
            ));
        }
        match end {
            Some(e) if !(valid_ports).contains(&e) => {
                Err(anyhow!("end port {} must be in the range 0 to 65536", e))
            }
            Some(e) if e < begin => Err(anyhow!(
                "end port {} must be greater than or equal to begin port {}",
                e,
                begin,
            )),
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

#[cfg(test)]
mod portrange_tests {
    use super::*;

    use crate::{assert_err, assert_ok};

    #[test]
    fn new_two_endpoints() {
        let b = 127;
        let e = Some(198);

        let exp = PortRange {
            begin: 127,
            end: Some(198),
        };

        assert_ok!(PortRange::new(b, e), exp)
    }

    #[test]
    fn new_one_endpoint() {
        let b = 127;
        let e: Option<i32> = None;

        let exp = PortRange {
            begin: 127,
            end: None,
        };

        assert_ok!(PortRange::new(b, e), exp)
    }

    #[test]
    fn new_invalid_range() {
        let b = 127;
        let e = 101;

        let exp = format!(
            "end port {} must be greater than or equal to begin port {}",
            e, b
        );
        assert_err!(PortRange::new(b, Some(e)), exp);

        let b2 = 65538;
        let exp2 = format!("begin port {} must be in the range 0 to 65536", b2);
        assert_err!(PortRange::new(b2, None), exp2);

        let b3 = 1;
        let e3 = 65538;
        let exp3 = format!("end port {} must be in the range 0 to 65536", e3);
        assert_err!(PortRange::new(b3, Some(e3)), exp3);
    }

    #[test]
    fn is_valid_port() -> Result<()> {
        let b1 = 127;
        let pr1 = PortRange::new(b1, None)?;

        assert!(pr1.is_valid(127));
        assert!(!pr1.is_valid(128));

        let b2 = 80;
        let e2 = Some(86);
        let pr2 = PortRange::new(b2, e2)?;

        assert!(!pr2.is_valid(87));
        assert!(!pr2.is_valid(79));
        assert!(pr2.is_valid(83));
        assert!(!pr2.is_valid(127));

        Ok(())
    }
}

// Enum to represent Transport layer protocols
#[derive(Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Icmpv6,
}

impl Validate for Protocol {
    type Item = Protocol;

    fn is_valid(&self, other: Self::Item) -> bool {
        matches!(
            (self, other),
            (Self::Tcp, Self::Tcp) | (Self::Udp, Self::Udp) | (Self::Icmp, Self::Icmp)
        )
    }
}

#[cfg(test)]
mod protocol_tests {

    use super::*;

    #[test]
    fn test_validate_1() {
        let prot = Protocol::Tcp;

        assert!(prot.is_valid(Protocol::Tcp));
        assert!(!prot.is_valid(Protocol::Udp));
        assert!(!prot.is_valid(Protocol::Icmp));
    }

    #[test]
    fn test_validate_2() {
        let prot = Protocol::Udp;

        assert!(!prot.is_valid(Protocol::Tcp));
        assert!(prot.is_valid(Protocol::Udp));
        assert!(!prot.is_valid(Protocol::Icmp));
    }

    #[test]
    fn test_validate_3() {
        let prot = Protocol::Icmp;

        assert!(!prot.is_valid(Protocol::Tcp));
        assert!(!prot.is_valid(Protocol::Udp));
        assert!(prot.is_valid(Protocol::Icmp));
    }
}

// Enum to represent blacklist and whitelist
// for src/dest IP addresses
// for ports
// for protocols
#[derive(Deserialize, Debug, PartialEq, Eq)]
pub enum BWList<T: Validate + PartialEq> {
    WhiteList(Vec<T>),
    BlackList(Vec<T>),
}

impl<T: Validate + PartialEq> BWList<T> {
    fn is_valid_item(&self, target: T::Item) -> bool {
        match self {
            BWList::WhiteList(v) => return v.iter().any(|item| item.is_valid(target)),
            BWList::BlackList(v) => return !v.iter().any(|item| item.is_valid(target)),
        }
    }
}

#[cfg(test)]
mod bwlist_tests {

    use anyhow::Result;

    use super::*;

    use std::net::{IpAddr, Ipv4Addr};

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
            PortRange::new(80, Some(82))?,
            PortRange::new(90, Some(95))?,
            PortRange::new(103, Some(195))?,
            PortRange::new(202, Some(212))?,
        ]);

        assert!(wl.is_valid_item(81));
        assert!(!wl.is_valid_item(79));
        assert!(wl.is_valid_item(94));
        assert!(!wl.is_valid_item(100));
        assert!(!wl.is_valid_item(196));
        assert!(wl.is_valid_item(211));

        Ok(())
    }
}
