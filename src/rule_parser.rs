extern crate anyhow;
extern crate pnet;
extern crate serde;
extern crate toml;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::Deserialize;

use anyhow::{anyhow, Result};

// A struct to handle IP address ranges
#[derive(Deserialize, PartialEq, Copy, Clone)]
struct IpRange {
    begin: IpAddr,
    end: Option<IpAddr>,
}

// TODO: add IpRange tests

impl IpRange {
    // Creates an IpRange struct only if the `begin` and `end` parameters
    // are of the same IPAddr type
    fn new(begin: IpAddr, end: Option<IpAddr>) -> Result<Self> {
        // Guard clauses to ensure no mix-matched IP address types and
        // that begin IPAddr < end IPAddr
        if begin.is_ipv4() {
            match end {
                Some(e) => {
                    if e.is_ipv6() {
                        return Err(anyhow!("can not mix-match IP protocols in IP ranges."));
                    } else if e > begin {
                        return Err(anyhow!(
                            "`end` IP address must be strictly greater than `begin` IP address."
                        ));
                    }
                }
                _ => {}
            }
        }

        if begin.is_ipv6() {
            match end {
                Some(e) => {
                    if e.is_ipv4() {
                        return Err(anyhow!("can not mix-match IP protocols in IP ranges."));
                    } else if e > begin {
                        return Err(anyhow!(
                            "`end` IP address must be strictly greater than `begin` IP address."
                        ));
                    }
                }
                _ => {}
            }
        }

        Ok(Self { begin, end })
    }

    // Creates a new IpRange of the V6 protocol
    // If the range endpoints used IPV4 it converts to IPV6
    fn convert_to_ipv6(mut self) -> Self {
        match self.begin {
            IpAddr::V4(b) => match self.end {
                None => Self {
                    begin: IpAddr::V6(b.to_ipv6_mapped()),
                    end: self.end,
                },
                Some(ip) => Self {
                    begin: IpAddr::V6(b.to_ipv6_mapped()),
                    end: match ip {
                        IpAddr::V4(e) => Some(IpAddr::V6(e.to_ipv6_mapped())),
                        IpAddr::V6(e) => self.end,
                    },
                },
            },
            _ => self,
        }
    }

    // Checks if an ip address is in the range of the IpRange
    fn in_range(&self, ip: IpAddr) -> bool {
        match ip {
            // Guard clauses to check for mix-matched IP protocols
            IpAddr::V6(addr) if self.begin.is_ipv4() => self.convert_to_ipv6().in_range(ip),
            IpAddr::V4(addr) if self.begin.is_ipv6() => {
                self.in_range(IpAddr::V6(addr.to_ipv6_mapped()))
            }

            // Range check
            _ => match self.end {
                Some(e) => ip >= self.begin && ip <= e,
                None => self.begin == ip,
            },
        }
    }
}

// Enum to represent ip blacklist and whitelist
#[derive(Deserialize)]
enum BWList {
    WhiteList(Vec<IpRange>),
    BlackList(Vec<IpRange>),
}

impl BWList {
    fn valid_ip(&self, ip: IpAddr) -> bool {
        match self {
            BWList::WhiteList(v) => return v.iter().find(|ipr| ipr.in_range(ip)) != None,
            BWList::BlackList(v) => return v.iter().find(|ipr| ipr.in_range(ip)) == None,
        }
    }
}

#[derive(Deserialize)]
struct Rules {
    list: BWList,
}
