use super::{pnet::packet::Packet, BWList, Deserialize, IpRange, PortRange, Protocol, Result};

#[macro_use]
use crate::hashmap;

use anyhow::anyhow;
use httparse::Status;
use std::{collections::HashMap, fmt, net::IpAddr};

#[derive(Deserialize)]
struct Rules {
    src_ip_list: Option<BWList<IpRange>>,
    dest_ip_list: Option<BWList<IpRange>>,
    port_list: Option<BWList<PortRange>>,
    protoc_list: Option<BWList<Protocol>>,
}

// Enum used to represent intrusion detection system
// actions
// TODO: implement Action-specific packet processing functions
pub enum IdsAction {
    Alert,
    Log,
    Block,
    Terminate,
    Whitelist,
    Blacklist,
}

struct Rule {
    src_ip: Option<IpAddr>,
    src_port: Option<i32>,
    dest_ip: Option<IpAddr>,
    dest_port: Option<i32>,
    prot_rule: ProtocolRule,
    action: IdsAction,
}

enum ProtocolRule {
    Transport(TransportProtocolRule),
    Appllication(ApplicationProtocolRule),
}

// Enum type to represent transport layer
// protocol rules
enum TransportProtocolRule {
    Icmp,
    Icmpv6,
    Tcp,
    Udp,
}

// Enum type to represent HTTP Methods
#[derive(Deserialize, Debug)]
pub enum HttpMethod {
    Get,
    Head,
    Post,
    Put,
    Patch,
    Delete,
    Connection,
    Options,
    Trace,
}

impl fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Get => write!(f, "GET"),
            Self::Head => write!(f, "HEAD"),
            Self::Post => write!(f, "POST"),
            Self::Put => write!(f, "PUT"),
            Self::Patch => write!(f, "PATCH"),
            Self::Delete => write!(f, "DELETE"),
            Self::Connection => write!(f, "CONNECTION"),
            Self::Options => write!(f, "OPTIONS"),
            Self::Trace => write!(f, "TRACE"),
        }
    }
}

trait ApplicationProtocol {
    fn process_packet<'a>(&self, body: &[u8]) -> Result<bool>;
}

#[derive(Deserialize)]
struct HttpRule {
    method: Option<HttpMethod>,
    headers_contain: Option<HashMap<String, String>>,
    path_contains: Option<Patterns>,
    body_contains: Option<Patterns>,
}

#[derive(Deserialize)]
struct Patterns(Vec<String>);

impl Patterns {
    fn match_exists(&self, target: &[u8]) -> bool {
        for p in &self.0 {
            if target.windows(p.len()).any(|window| window == p.as_bytes()) {
                return true;
            }
        }
        false
    }
}

impl HttpRule {
    // Constructor for HTTP Rule
    fn new(
        method: Option<HttpMethod>,
        headers_contain: Option<HashMap<String, String>>,
        path_patterns: Option<Vec<String>>,
        body_patterns: Option<Vec<String>>,
    ) -> Self {
        Self {
            method,
            headers_contain,
            path_contains: match path_patterns {
                Some(p) => Some(Patterns { 0: p }),
                None => None,
            },
            body_contains: match body_patterns {
                Some(bp) => Some(Patterns { 0: bp }),
                None => None,
            },
        }
    }
}

impl ApplicationProtocol for HttpRule {
    // Assumes that packet is some kind of HTTP Packet on port 80 or 8080
    // though not necessarily a valid one.
    //
    // The function parses the byte slice into a Request struct using the httparse
    // library. It returns an error if something went wrong parsing the required
    // fields of the HTTP request
    //
    // All parameters in the Rule struct are optional, and if not provided explicitly
    // this function will not check the request for those parameters.
    //
    // For a request to return 'true' indicating that it matches the Rule struct provided
    // it must match all the fields and *at least one* of their subfields as well as needed.
    fn process_packet<'a>(&self, body: &[u8]) -> Result<bool> {
        // Parse request
        let mut headers = [httparse::EMPTY_HEADER; 16];
        let mut req = httparse::Request::new(&mut headers);
        let res = req.parse(body)?;

        let mut conds = [true; 4];

        // Check the request method
        match req.method {
            Some(m) => {
                if let Some(rm) = &self.method {
                    conds[0] = m == rm.to_string();
                }
            }
            None => {
                return Err(anyhow!(
                    "Malformed HTTP Request, no method field could be parsed"
                ))
            }
        };
        // Check the request path
        // Must match at least one of the patterns in the path_contains field
        match req.path {
            Some(p) => {
                if let Some(rp) = &self.path_contains {
                    conds[1] = rp.match_exists(p.as_bytes());
                }
            }
            None => {
                return Err(anyhow!(
                    "Malformed HTTP request, no path field could be parsed"
                ))
            }
        };

        // Check the headers and make sure at least one of the header values is
        // in the request. Quit early once this header is found
        if let Some(map) = &self.headers_contain {
            for (header, target) in map.iter() {
                let value = req.headers.iter().find(|&x| x.name == header);
                if let Some(found) = value {
                    conds[2] = found
                        .value
                        .windows(target.len())
                        .any(|window| window == target.as_bytes());
                    // Break after the first match
                    if conds[2] {
                        break;
                    }
                }
            }
        }

        // Check the request body for the pattern
        // Must contain at least one match
        // If the body is empty/nonexistent but there
        // are patterns in the rule the function should
        // return false
        if let Status::Complete(ofs) = res {
            match &self.body_contains {
                Some(bp) => {
                    conds[3] = bp.match_exists(&body[ofs..]);
                }
                _ => {}
            }
        } else if let Some(bp) = &self.body_contains {
            conds[3] = false;
        }

        // Final check to see if all the sub-conditions are true
        // Indicating that the HTTP request matches the rule struct

        Ok(conds.iter().all(|&x| x))
    }
}

#[cfg(test)]
mod http_tests {
    use crate::hashmap;

    use super::{ApplicationProtocol, HashMap, HttpMethod, HttpRule, Result};

    #[test]
    fn test_http_process_packet_1() -> Result<()> {
        let req = b"POST nazar.com/api/user HTTP/1.1\r\n\
                        Host: example.com\r\n\
                        Content-Type: application/json\r\n\
                        Content-Length: 25\r\n\
                        \r\n\
                        {\"username\":\"john\",\"password\":\"secret\"}";

        let rule = HttpRule::new(Some(HttpMethod::Post), None, None, None);
        assert!(rule.process_packet(req)?);

        let rule_2 = HttpRule::new(
            Some(HttpMethod::Post),
            None,
            None,
            Some(vec![String::from("secret"), String::from("missing")]),
        );
        assert!(rule_2.process_packet(req)?);

        Ok(())
    }

    #[test]
    fn test_http_process_packet_2() -> Result<()> {
        let req = b"POST /api/user HTTP/1.1\r\n\
                        Host: example.com\r\n\
                        Content-Type: application/json\r\n\
                        Content-Length: 25\r\n\
                        \r\n\
                        {\"username\":\"john\",\"password\":\"secret\"}";
        let rule = HttpRule::new(
            Some(HttpMethod::Post),
            Some(hashmap! {
                String::from("Host") => String::from("example.com"),
                String::from("Content-Type") => String::from("text/html")
            }),
            Some(vec![String::from("/api"), String::from("/usr")]),
            Some(vec![String::from("secret"), String::from("jenn")]),
        );
        assert!(rule.process_packet(req)?);

        let rule2 = HttpRule::new(
            Some(HttpMethod::Post),
            None,
            Some(vec![String::from("/secrete")]),
            None,
        );

        assert!(!rule2.process_packet(req)?);

        Ok(())
    }

    #[test]
    fn test_http_process_packet_3() -> Result<()> {
        let req = b"GET /virus/download.php HTTP/1.1\r\n\
                    Host: sussy.com\r\n";

        let rule = HttpRule::new(
            Some(HttpMethod::Get),
            Some(hashmap! {
                String::from("Host") => String::from("sussy.com"),
                String::from("Non-existent-Header") => String::from("malicious-value")
            }),
            Some(vec![String::from("/virus"), String::from("php")]),
            None,
        );

        assert!(rule.process_packet(req)?);

        let rule_2 = HttpRule::new(
            Some(HttpMethod::Get),
            Some(hashmap! {
                String::from("Host") => String::from("sussy.com")
            }),
            None,
            Some(vec![String::from("Non existent body Value")]),
        );

        assert!(!rule_2.process_packet(req)?);

        Ok(())
    }
}
// Enum type to represent application layer
// protocol rules
// TODO: add more application layer protocols later
enum ApplicationProtocolRule {
    Http(HttpRule),
    Dhcp,
    Dns,
}
