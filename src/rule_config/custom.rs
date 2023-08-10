use self::dns_rule::DnsRule;
use self::http_rule::HttpRule;
use self::icmp_rule::{IcmpRule, Icmpv6Rule};
use self::tcp_rule::TcpRule;
use self::udp_rule::UdpRule;

use super::{Deserialize, IdsAction, Ipv4Packet, Ipv6Packet};

use pnet::packet::{Packet, PacketSize};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

mod dns_rule;
mod http_rule;
mod icmp_rule;
mod tcp_rule;
mod udp_rule;

#[derive(Deserialize, Debug)]
pub struct CustomRule {
    src_ip: Option<IpAddr>,
    dest_ip: Option<IpAddr>,
    prot_rule: ProtocolRule,
    action: IdsAction,
}

impl CustomRule {
    fn match_ipv6(exp_ip: Option<IpAddr>, actual: Ipv6Addr) -> bool {
        // Checks if an optional IpAddr matches an Ipv6Addr
        match exp_ip {
            Some(IpAddr::V4(ip)) if ip.to_ipv6_mapped() != actual => false,
            Some(IpAddr::V6(ip)) if ip != actual => false,
            _ => true,
        }
    }

    fn match_ipv4(exp_ip: Option<IpAddr>, actual: Ipv4Addr) -> bool {
        // Checks if an optional IpAddr matches an Ipv4Addr
        match exp_ip {
            Some(IpAddr::V4(ip)) if ip != actual => false,
            Some(IpAddr::V6(_)) => false,
            _ => true,
        }
    }

    pub fn process_ipv6_packet(&self, ipv6_packet: &Ipv6Packet) -> IdsAction {
        // Processes the Ipv6 packet based on the CustomRule specifications
        // If it matches the rule, the user-defined IdsAction is returned
        // If it doesn't match the rule, IdsAction::Log is returned (default Action)
        // If the packet's protocol didn't match the ProtocolRule and therefore couldn't
        // be parsed, IdsAction::Nop is returned (do nothing)

        // Check the IpAddrs
        if !CustomRule::match_ipv6(self.src_ip, ipv6_packet.get_source()) {
            return IdsAction::Nop;
        }
        if !CustomRule::match_ipv6(self.dest_ip, ipv6_packet.get_destination()) {
            return IdsAction::Nop;
        }

        // Get the result of processing the protocol rule
        match self.prot_rule.process(ipv6_packet.packet()) {
            Some(true) => self.action,
            _ => IdsAction::Nop,
        }
    }

    pub fn process_ipv4_packet(&self, ipv4_packet: &Ipv4Packet) -> IdsAction {
        // Processes the Ipv4 packet based on the CustomRule specifications
        // If it matches the rule, the user-defined IdsAction is returned
        // If it doesn't match the rule, IdsAction::Log is returned (default Action)
        // If the packet's protocol didn't match the ProtocolRule and therefore couldn't
        // be parsed, IdsAction::Nop is returned (do nothing)

        // Check the IpAddrs
        if !CustomRule::match_ipv4(self.src_ip, ipv4_packet.get_source()) {
            return IdsAction::Nop;
        }
        if !CustomRule::match_ipv4(self.dest_ip, ipv4_packet.get_destination()) {
            return IdsAction::Nop;
        }

        // Get the result of processing the protocol rule
        match self.prot_rule.process(ipv4_packet.packet()) {
            Some(true) => self.action,
            _ => IdsAction::Nop,
        }
    }
}

// Enum representing custom transport layer
// and application layer protocols
#[derive(Deserialize, Debug)]
pub enum ProtocolRule {
    // Transport Protocols
    Icmp(IcmpRule),
    Icmpv6(Icmpv6Rule),
    Tcp(TcpRule),
    Udp(UdpRule),
    // Application Protocols
    Http(HttpRule),
    Dns(DnsRule),
}

impl ProcessPacket for ProtocolRule {
    fn process(&self, body: &[u8]) -> Option<bool> {
        match self {
            Self::Icmp(rule) => rule.process(body),
            Self::Icmpv6(rule) => rule.process(body),
            Self::Tcp(rule) => rule.process(body),
            Self::Udp(rule) => rule.process(body),
            Self::Http(rule) => rule.process(body),
            Self::Dns(rule) => rule.process(body),
        }
    }
}

// Struct that represents a vector of string patterns
#[derive(Deserialize, Debug)]
struct Patterns(Vec<String>);

impl Patterns {
    fn match_exists(&self, target: &[u8]) -> bool {
        // Function that returns true if at least of one the string patterns are
        // contained by `target`
        for p in &self.0 {
            if target.windows(p.len()).any(|window| window == p.as_bytes()) {
                return true;
            }
        }
        false
    }
}

// A trait indicating that the type which implements is capable of processing request packets
trait ProcessPacket {
    fn process(&self, body: &[u8]) -> Option<bool>;
}
