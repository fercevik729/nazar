use super::{pnet::packet::Packet, BWList, Deserialize, IpRange, PortRange, Protocol, Result};
use anyhow::anyhow;
use pnet::packet::tcp::TcpPacket;
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
    type PacketType<'a>;

    fn process_packet<'a>(&self, packet: Self::PacketType<'a>) -> Result<bool>;
}

#[derive(Deserialize, Debug)]
struct HttpRule {
    method: Option<HttpMethod>,
    headers_contain: Option<HashMap<String, String>>,
    path_contains: Option<String>,
}

impl HttpRule {
    // Constructor for HTTP Rule
    fn new(method: HttpMethod, headers: HashMap<String, String>, pattern: String) -> Self {
        Self {
            method: Some(method),
            headers_contain: Some(headers),
            path_contains: Some(pattern),
        }
    }
}

impl ApplicationProtocol for HttpRule {
    type PacketType<'a> = TcpPacket<'a>;

    // Assumes that packet is an HTTP packet on port 80 or 8080
    // Parse it using the httparse library
    fn process_packet<'a>(&self, packet: Self::PacketType<'a>) -> Result<bool> {
        // Parse request
        let body = packet.payload();
        let mut headers = [httparse::EMPTY_HEADER; 16];
        let mut req = httparse::Request::new(&mut headers);
        req.parse(body)?;

        let mut conds = [true; 3];

        // Check the request method
        match req.method {
            Some(m) => {
                if let Some(rm) = &self.method {
                    if m != rm.to_string() {
                        conds[0] = false;
                    }
                }
            }
            None => {
                return Err(anyhow!(
                    "Malformed HTTP Request, no method field could be parsed"
                ))
            }
        };
        // Check the request body
        match req.path {
            Some(p) => {
                if let Some(rp) = &self.path_contains {
                    if p != rp {
                        conds[1] = false;
                    }
                }
            }
            None => {
                return Err(anyhow!(
                    "Malformed HTTP request, no path field could be parsed"
                ))
            }
        };

        // Check the headers
        if let Some(map) = &self.headers_contain {
            for (header, target) in map.iter() {
                let value = req.headers.iter().find(|&x| x.name == header);
                if let Some(found) = value {
                    conds[2] = found
                        .value
                        .windows(target.len())
                        .any(|window| window == target.as_bytes());
                    if conds[2] {
                        break;
                    }
                }
            }
        }

        Ok(conds.iter().all(|&c| c))
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
