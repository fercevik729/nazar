use std::{collections::HashMap, net::IpAddr, vec};

use super::{BWList, Deserialize, IpRange, PortRange, Protocol};

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
    IcmpRule,
    Icmpv6Rule,
    TcpRule,
    UdpRule,
}

// Enum type to represent HTTP Methods
enum HttpMethod {
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

// Enum type to represent application layer
// protocol rules
enum ApplicationProtocolRule {
    HttpRule {
        method: HttpMethod,
        header_contains: HashMap<String, String>,
        body_contains: Vec<String>,
    },
    DhcpRule,
    DnsRule,
    FtpRule,
    SmtpRule,
}
