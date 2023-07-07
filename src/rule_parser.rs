extern crate anyhow;
extern crate pnet;
extern crate serde;
extern crate toml;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::Deserialize;

use anyhow::{anyhow, Result};

// A struct to handle IP address ranges
#[derive(Deserialize)]
struct IpRange {
    begin: IpAddr,
    end: Option<IpAddr>,
}

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
}

// Enum to represent ip blacklist and whitelist
#[derive(Deserialize)]
enum BWList {
    WhiteList(Vec<IpRange>),
    BlackList(Vec<IpRange>),
}

#[derive(Deserialize)]
struct Rules {
    list: BWList,
}
