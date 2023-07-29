use super::*;

// Enum representing the different kinds of ICMPv6 Requests
#[derive(Deserialize, Debug)]
enum Icmpv6Type {
    DestinationUnreachable,
    PacketTooBig,
    TimeExceeded,
    ParameterProblem,
    EchoRequest,
    EchoReply,
    Unknown,
}

// Struct representing a rule to match against ICMPv6 packets
#[derive(Deserialize, Debug)]
pub struct Icmpv6Rule {
    icmpv6_types: Option<Vec<Icmpv6Type>>,
    icmpv6_codes: Option<Vec<u8>>,
}

impl Icmpv6Rule {
    fn new(icmpv6_types: Option<Vec<Icmpv6Type>>, icmpv6_codes: Option<Vec<u8>>) -> Self {
        Self {
            icmpv6_types,
            icmpv6_codes,
        }
    }
}

fn match_icmpv6_types(curr: &Icmpv6Type, target: &etherparse::Icmpv6Type) -> bool {
    // Helper function to match the ICMPv6 type of the packet with that of the rules
    match curr {
        Icmpv6Type::ParameterProblem => {
            matches!(target, etherparse::Icmpv6Type::ParameterProblem(_))
        }
        Icmpv6Type::TimeExceeded => matches!(target, etherparse::Icmpv6Type::TimeExceeded(_)),
        Icmpv6Type::DestinationUnreachable => {
            matches!(target, etherparse::Icmpv6Type::DestinationUnreachable(_))
        }
        Icmpv6Type::EchoReply => matches!(target, etherparse::Icmpv6Type::EchoReply(_)),
        Icmpv6Type::EchoRequest => matches!(target, etherparse::Icmpv6Type::EchoRequest(_)),
        Icmpv6Type::PacketTooBig => matches!(target, etherparse::Icmpv6Type::PacketTooBig { .. }),
        Icmpv6Type::Unknown => matches!(target, etherparse::Icmpv6Type::Unknown { .. }),
    }
}

impl ProcessPacket for Icmpv6Rule {
    fn process(&self, body: &[u8]) -> Option<bool> {
        // Assumes that the packet is some kind of ICMPv6 Packet though not necessarily a valid one
        // The function parses the byte slice into a etherparse::Icmpv6Slice struct using the
        // etherparse library. It returns an error if something went wrong during parsing
        //
        // All parameters in the Rule struct are optional, and if not explicitly provided,
        // this function will skip those parameters
        //
        // For a request to return 'true' indicating that it matches the Rule struct provided,
        // it must match all the fields and *at least one* of any subfields.
        //
        // Parse request
        let icmp_packet = etherparse::Icmpv6Slice::from_slice(body).ok();
        if let Some(packet) = icmp_packet {
            // Check the ICMPv6 headers
            if let Some(headers) = &self.icmpv6_types {
                let target = packet.header();
                if !headers
                    .iter()
                    .any(|header| match_icmpv6_types(header, &target.icmp_type))
                {
                    return Some(false);
                }
            }

            // Check the ICMPv6 codes
            if let Some(codes) = &self.icmpv6_codes {
                let target = &packet.code_u8();
                if !codes.iter().any(|c| c == target) {
                    return Some(false);
                }
            }
            return Some(true);
        }

        None
    }
}

// Enum representing the different kinds of ICMPv4 Requests
#[derive(Deserialize, Debug)]
enum IcmpType {
    EchoReply,
    EchoRequest,
    DestinationUnreachable,
    Redirect,
    TimeExceeded,
    ParameterProblem,
    TimestampRequest,
    TimestampReply,
    Unknown,
}

// Struct representing a rule to match against ICMPv4 packets
#[derive(Deserialize, Debug)]
pub struct IcmpRule {
    // Option-al vector of ICMPv4 Types that correspond to the different possible
    // ICMPv4 headers this rule should match
    icmp_types: Option<Vec<IcmpType>>,
    // Option-al vector of ICMPv4 codes that correspond to the different possible
    // ICMPv4 codes in headers this rule should match
    icmp_codes: Option<Vec<u8>>,
}

impl IcmpRule {
    fn new(icmp_types: Option<Vec<IcmpType>>, icmp_codes: Option<Vec<u8>>) -> Self {
        Self {
            icmp_types,
            icmp_codes,
        }
    }
}

fn match_icmpv4_types(curr: &IcmpType, target: &Icmpv4Type) -> bool {
    // Helper function to match the ICMPv4 type of the packet with that of the rules
    match curr {
        IcmpType::EchoReply => matches!(target, Icmpv4Type::EchoReply(_)),
        IcmpType::EchoRequest => matches!(target, Icmpv4Type::EchoRequest(_)),
        IcmpType::DestinationUnreachable => matches!(target, Icmpv4Type::DestinationUnreachable(_)),
        IcmpType::Redirect => matches!(target, Icmpv4Type::Redirect(_)),
        IcmpType::TimeExceeded => matches!(target, Icmpv4Type::TimeExceeded(_)),
        IcmpType::TimestampReply => matches!(target, Icmpv4Type::TimestampReply(_)),
        IcmpType::TimestampRequest => matches!(target, Icmpv4Type::TimestampRequest(_)),
        IcmpType::ParameterProblem => matches!(target, Icmpv4Type::ParameterProblem(_)),
        IcmpType::Unknown => matches!(target, Icmpv4Type::Unknown { .. }),
    }
}

impl ProcessPacket for IcmpRule {
    fn process(&self, body: &[u8]) -> Option<bool> {
        // Assumes that the packet is some kind of ICMPv4 Packet though not necessarily a valid one
        // The function parses the byte slice into a etherparse::Icmpv4Slice struct using the
        // etherparse library. It returns an error if something went wrong during parsing
        //
        // All parameters in the Rule struct are optional, and if not explicitly provided,
        // this function will skip those parameters
        //
        // For a request to return 'true' indicating that it matches the Rule struct provided,
        // it must match all the fields and *at least one* of any subfields.
        //
        // Parse request
        let icmp_packet = etherparse::Icmpv4Slice::from_slice(body).ok();

        if let Some(packet) = icmp_packet {
            // Check the ICMPv4 headers
            if let Some(headers) = &self.icmp_types {
                let target = packet.header();
                if !headers
                    .iter()
                    .any(|header| match_icmpv4_types(header, &target.icmp_type))
                {
                    return Some(false);
                }
            }

            // Check the ICMPv4 codes
            if let Some(codes) = &self.icmp_codes {
                let target = &packet.code_u8();
                if !codes.iter().any(|c| c == target) {
                    return Some(false);
                }
            }
            return Some(true);
        }

        None
    }
}

#[cfg(test)]
mod tests {

    use super::IcmpType;
    use super::*;
    use pnet::{
        packet::Packet,
        packet::{
            icmp::{echo_request, time_exceeded, IcmpType as pnetIcmpType},
            icmpv6::{Icmpv6Types, MutableIcmpv6Packet},
        },
    };

    #[test]
    fn test_icmpv4_1() {
        let mut buffer = [0u8; 64];
        let mut icmp_packet = echo_request::MutableEchoRequestPacket::new(&mut buffer).unwrap();
        icmp_packet.set_icmp_type(pnetIcmpType(8));

        let binding = icmp_packet.to_immutable();
        let icmp_bytes = binding.packet();
        let icmpv4_rule =
            IcmpRule::new(Some(vec![IcmpType::EchoRequest, IcmpType::EchoReply]), None);
        assert!(icmpv4_rule.process(icmp_bytes).unwrap());
    }

    #[test]
    fn test_icmpv4_2() {
        let mut buffer = [0u8; 64];
        let mut icmp_packet = echo_request::MutableEchoRequestPacket::new(&mut buffer).unwrap();
        icmp_packet.set_icmp_type(pnetIcmpType(8));

        let binding = icmp_packet.to_immutable();
        let icmp_bytes = binding.packet();
        let icmpv4_rule = IcmpRule::new(
            Some(vec![IcmpType::TimeExceeded, IcmpType::EchoReply]),
            None,
        );
        assert!(!icmpv4_rule.process(icmp_bytes).unwrap());
    }

    #[test]
    fn test_icmpv4_3() {
        let mut buffer = [0u8; 64];
        let mut icmp_packet = time_exceeded::MutableTimeExceededPacket::new(&mut buffer).unwrap();
        icmp_packet.set_icmp_type(pnetIcmpType(0));

        let binding = icmp_packet.to_immutable();
        let icmp_bytes = binding.packet();
        let icmpv4_rule = IcmpRule::new(
            Some(vec![IcmpType::TimeExceeded, IcmpType::EchoReply]),
            None,
        );
        assert!(icmpv4_rule.process(icmp_bytes).unwrap());
    }

    #[test]
    fn test_icmpv6_1() {
        let mut buffer = [0u8; 64];
        let mut icmpv6_packet = MutableIcmpv6Packet::new(&mut buffer).unwrap();
        icmpv6_packet.set_icmpv6_type(Icmpv6Types::PacketTooBig);

        let binding = icmpv6_packet.to_immutable();
        let icmpv6_bytes = binding.packet();
        let icmpv6_rule = Icmpv6Rule::new(
            Some(vec![Icmpv6Type::PacketTooBig, Icmpv6Type::TimeExceeded]),
            None,
        );

        assert!(icmpv6_rule.process(icmpv6_bytes).unwrap());
    }

    #[test]
    fn test_icmpv6_2() {
        let mut buffer = [0u8; 64];
        let mut icmpv6_packet = MutableIcmpv6Packet::new(&mut buffer).unwrap();
        icmpv6_packet.set_icmpv6_type(Icmpv6Types::NeighborSolicit);

        let binding = icmpv6_packet.to_immutable();
        let icmpv6_bytes = binding.packet();
        let icmpv6_rule = Icmpv6Rule::new(
            Some(vec![Icmpv6Type::PacketTooBig, Icmpv6Type::TimeExceeded]),
            None,
        );

        assert!(!icmpv6_rule.process(icmpv6_bytes).unwrap());
    }

    #[test]
    fn test_icmpv6_3() {
        let mut buffer = [0u8; 64];
        let mut icmpv6_packet = MutableIcmpv6Packet::new(&mut buffer).unwrap();
        icmpv6_packet.set_icmpv6_type(Icmpv6Types::PacketTooBig);

        let binding = icmpv6_packet.to_immutable();
        let icmpv6_bytes = binding.packet();
        let icmpv6_rule = Icmpv6Rule::new(
            Some(vec![Icmpv6Type::PacketTooBig, Icmpv6Type::TimeExceeded]),
            Some(vec![1, 2, 55]),
        );

        assert!(!icmpv6_rule.process(icmpv6_bytes).unwrap());
    }

    #[test]
    fn test_icmpv6_4() {
        // First packet
        let mut buffer_1 = [0u8; 64];
        let mut icmpv6_packet_1 = MutableIcmpv6Packet::new(&mut buffer_1).unwrap();
        icmpv6_packet_1.set_icmpv6_type(Icmpv6Types::TimeExceeded);
        let binding_1 = icmpv6_packet_1.to_immutable();
        let icmpv6_bytes_1 = binding_1.packet();

        // Second packet
        let mut buffer_2 = [0u8; 64];
        let mut icmpv6_packet_2 = MutableIcmpv6Packet::new(&mut buffer_2).unwrap();
        icmpv6_packet_2.set_icmpv6_type(Icmpv6Types::EchoRequest);
        let binding_2 = icmpv6_packet_2.to_immutable();
        let icmpv6_bytes_2 = binding_2.packet();

        let icmpv6_rule = Icmpv6Rule::new(
            Some(vec![Icmpv6Type::PacketTooBig, Icmpv6Type::TimeExceeded]),
            Some(vec![0, 1, 2, 55]),
        );

        assert!(icmpv6_rule.process(icmpv6_bytes_1).unwrap());
        assert!(!icmpv6_rule.process(icmpv6_bytes_2).unwrap());
    }
}
