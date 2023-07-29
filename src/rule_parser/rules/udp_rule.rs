use super::*;

use pnet::packet::udp::UdpPacket;

// Enum representing next level protocols on top of UDP
// DNS is excluded because it has its own separate rule
// implementation
#[derive(Deserialize, Debug)]
enum UdpNextLevel {
    // Domain Name System
    Dns,
    // Dynamic Host Configuration Protocol
    Dhcp,
    // Simple Network Management Protocol
    Snmp,
    // Sessions Initiation Protocol
    Sip,
    // Real-Time Transport Protocol
    Rtp,
}

// Struct representing a UDP rule
#[derive(Deserialize, Debug)]
pub struct UdpRule {
    next_protocol: Option<UdpNextLevel>,
    max_packet_size: Option<usize>,
    src_port: Option<u16>,
    dest_port: Option<u16>,
}

impl UdpRule {
    fn new(
        next_protocol: Option<UdpNextLevel>,
        max_packet_size: Option<usize>,
        src_port: Option<u16>,
        dest_port: Option<u16>,
    ) -> Self {
        Self {
            next_protocol,
            max_packet_size,
            src_port,
            dest_port,
        }
    }
}

// A function to determine if a UDP Packet is a DNS Packet
pub fn is_dns(payload: &[u8]) -> bool {
    if payload.len() < 12 {
        return false;
    }

    let dns_header = &payload[..12];
    dns_header
        == [
            0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]
}

// DHCP Constants
const DHCP_MAGIC_COOKIE: u32 = 0x63825363;
const DHCP_OPTION_MSG_TYPE: u8 = 53;

const DHCP_DISCOVER: u8 = 1;
const DHCP_OFFER: u8 = 2;
const DHCP_REQUEST: u8 = 3;
const DHCP_ACK: u8 = 5;

// A function to determine if a byte slice is a DHCP Packet
pub fn is_dhcp(payload: &[u8]) -> bool {
    // Check if it is long enough
    if payload.len() < 240 {
        return false;
    }

    // Not a valid DHCP Packet if it doesn't contain the magic cookie
    let magic_cookie = u32::from_be_bytes([payload[236], payload[237], payload[238], payload[239]]);
    if magic_cookie != DHCP_MAGIC_COOKIE {
        return false;
    }

    let mut idx = 240;
    while idx + 1 < payload.len() {
        let opt_code = payload[idx];
        if opt_code == DHCP_OPTION_MSG_TYPE {
            // Found a DHCP Option
            let opt_len = payload[idx + 1];
            if idx + 1 + (opt_len as usize) < payload.len() {
                // Match agains the option in the payload
                match payload[idx + 2] {
                    // Only valid DHCP Packet Types are recognized
                    DHCP_DISCOVER | DHCP_ACK | DHCP_OFFER | DHCP_REQUEST => return true,
                    // Anything else returns false
                    _ => return false,
                }
            }
        }

        idx += 2 + (payload[idx + 1] as usize)
    }

    false
}

// SNMP Constants
const SNMP_VERSION_1: u8 = 0;
const SNMP_VERSION_2C: u8 = 1;
const SNMP_VERSION_3: u8 = 3;

const SNMP_GET_REQUEST: u8 = 0xA0;
const SNMP_GET_NEXT_REQUEST: u8 = 0xA1;
const SNMP_GET_RESPONSE: u8 = 0xA2;
const SNMP_SET_REQUEST: u8 = 0xA3;

// Function to determine if a UDP Packet is a SNMP Packet
pub fn is_snmp(payload: &[u8]) -> bool {
    // Check payload size
    if payload.len() < 6 {
        return false;
    }

    // Check version
    let snmp_vers = payload[0];
    match snmp_vers {
        SNMP_VERSION_1 | SNMP_VERSION_2C | SNMP_VERSION_3 => {
            // Check the message type
            let message_type = payload[1];
            match message_type {
                SNMP_GET_REQUEST | SNMP_SET_REQUEST | SNMP_GET_RESPONSE | SNMP_GET_NEXT_REQUEST => {
                    true
                }
                // Unsupported message type
                _ => false,
            }
        }
        _ => false,
    }
}

// Function to determine if a UDP packet is a SIP Packet
pub fn is_sip(payload: &[u8]) -> bool {
    // Check payload size
    if payload.len() < 3 {
        return false;
    }

    // Check if the packet starts with the expected header:
    // INV or SIP in binary
    matches!(&payload[..3], b"INV" | b"SIP")
}

// Function to determine if a UDP packet is a RTP PacketSize
fn is_rtp(payload: &[u8]) -> bool {
    // Check the payload size
    if payload.len() < 12 {
        return false;
    }

    // Check the version number by determining if the two MSB's == 2
    (payload[0] >> 6) == 2
}

impl ProcessPacket for UdpRule {
    fn process(&self, body: &[u8]) -> Option<bool> {
        if let Some(udp_packet) = UdpPacket::new(body) {
            // Check the next level protocols using the previously defined helper functions
            if let Some(next_protocol) = &self.next_protocol {
                let payload = udp_packet.payload();
                match next_protocol {
                    UdpNextLevel::Dns => {
                        if !is_dns(payload) {
                            return Some(false);
                        }
                    }
                    UdpNextLevel::Dhcp => {
                        if !is_dhcp(payload) {
                            return Some(false);
                        }
                    }
                    UdpNextLevel::Rtp => {
                        if !is_rtp(payload) {
                            return Some(false);
                        }
                    }
                    UdpNextLevel::Sip => {
                        if !is_sip(payload) {
                            return Some(false);
                        }
                    }
                    UdpNextLevel::Snmp => {
                        if !is_snmp(payload) {
                            return Some(false);
                        }
                    }
                }
            }

            if let Some(max_packet_size) = self.max_packet_size {
                // Check the packet size
                // Return false if the size of the udp packet is less than then
                // maximum packet size
                if max_packet_size < udp_packet.packet_size() {
                    return Some(false);
                }
            }

            // Check source and destination ports
            if let Some(src_port) = self.src_port {
                if udp_packet.get_source() != src_port {
                    return Some(false);
                }
            }

            if let Some(dest_port) = self.dest_port {
                if udp_packet.get_destination() != dest_port {
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

    use pnet::packet::{udp::MutableUdpPacket, Packet};

    use super::*;

    #[test]
    fn test_is_dns() {
        // Test the is_dns helper function
        //
        // Check the length
        let short_payload = &[0u8; 11];
        assert!(!is_dns(short_payload));

        // Check the header
        let bad_header_payload = &[0u8; 12];
        assert!(!is_dns(bad_header_payload));

        let valid_payload = &[
            0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert!(is_dns(valid_payload));
    }

    #[test]
    fn test_is_dhcp() {
        // Test the is_dhcp helper function
        //
        // Check the length
        let short = [0u8; 239];
        assert!(!is_dhcp(&short));

        // Check the cookie
        let bad_header = [0u8; 241];
        assert!(!is_dhcp(&bad_header));

        // Check the options
        let mut vec1 = vec![0u8; 236];
        let vec2: Vec<u8> = vec![
            // Magic Cookie: 0x63825363
            0x63, 0x82, 0x53, 0x63, // DHCP Option: DHCP Message Type (53)
            0x35, 0x01, 0x04, // Invalid option
            // End Option (255)
            0xFF,
        ];
        vec1.extend(vec2);

        let invalid_opt: [u8; 244] = {
            let mut array_data: [u8; 244] = [0u8; 244];
            let len = vec1.len();
            array_data[..len].copy_from_slice(&vec1);
            array_data
        };

        assert!(!is_dhcp(&invalid_opt));

        // Valid payload
        let mut vec_valid = vec![0u8; 236];
        let vec2_valid: Vec<u8> = vec![
            // Magic Cookie: 0x63825363
            0x63, 0x82, 0x53, 0x63, // DHCP Option: DHCP Message Type (53)
            0x35, 0x01, 0x01, // DHCP Message Type: Discover (1)
            // End Option (255)
            0xFF,
        ];
        vec_valid.extend(vec2_valid);
        let valid_payload: [u8; 244] = {
            let mut array_data: [u8; 244] = [0u8; 244];
            let len = vec_valid.len();
            array_data[..len].copy_from_slice(&vec_valid);
            array_data
        };
        assert!(is_dhcp(&valid_payload))
    }

    #[test]
    fn test_is_snmp() {
        // Test the is_snmp helper function
        //
        // Test length
        let short = [0u8; 5];
        assert!(!is_snmp(&short));

        // Test version number
        let invalid_version = [0x05, 0xA0, 0x00, 0x00, 0x00, 0x00];
        assert!(!is_snmp(&invalid_version));

        // Test invalid type
        let invalid_type = [0x00, 0xA4, 0x00, 0x00, 0x00, 0x00];
        assert!(!is_snmp(&invalid_type));

        // Valid
        let valid = [0x00, 0xA0, 0x00, 0x00, 0x00, 0x00];
        assert!(is_snmp(&valid))
    }

    #[test]
    fn test_is_sip() {
        // Test the is_sip helper function
        //
        // Test length
        let short = [0u8];
        assert!(!is_sip(&short));

        // Test header
        let invalid_header = b"SJP";
        assert!(!is_sip(invalid_header));

        let invalid_header_2 = b"INW";
        assert!(!is_sip(invalid_header_2));

        let valid_1 = b"SIP";
        assert!(is_sip(valid_1));

        let valid_2 = b"INV";
        assert!(is_sip(valid_2));
    }

    #[test]
    fn test_is_rtp() {
        // Test the is_rtp helper function
        //
        // Test length
        let short = [0u8; 11];
        assert!(!is_rtp(&short));

        let invalid_header = [0u8; 12];
        assert!(!is_rtp(&invalid_header));

        let mut valid = [0u8; 15];
        valid[0] = 0x80;
        assert!(is_rtp(&valid));
    }

    // Test process function for udp packets
    #[test]
    fn test_udp_packet_1() {
        // Test DNS packet
        let mut body = [0u8; 50];
        let mut udp_packet = MutableUdpPacket::new(&mut body).unwrap();
        let dns_payload = [
            0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        udp_packet.set_length(130);
        udp_packet.set_payload(&dns_payload);

        let rule = UdpRule::new(Some(UdpNextLevel::Dns), Some(128), None, None);
        assert!(rule.process(udp_packet.packet()).unwrap());
    }

    #[test]
    fn test_udp_packet_2() {
        // Test Next Level Protocol
        let mut body = [0u8; 50];
        let mut udp_packet = MutableUdpPacket::new(&mut body).unwrap();
        let sip_payload = b"SIP";
        udp_packet.set_payload(sip_payload);

        let rule = UdpRule::new(Some(UdpNextLevel::Dhcp), None, None, None);
        assert!(!rule.process(udp_packet.packet()).unwrap());
    }

    #[test]
    fn test_udp_packet_3() {
        // Test Packet Size
        let mut body = [0u8; 50];
        let mut udp_packet = MutableUdpPacket::new(&mut body).unwrap();
        let sip_payload = b"SIP";
        udp_packet.set_payload(sip_payload);

        let rule = UdpRule::new(Some(UdpNextLevel::Sip), Some(6), None, None);
        assert!(!rule.process(udp_packet.packet()).unwrap());
    }

    #[test]
    fn test_udp_packet_4() {
        // Test DHCP packet with packet size and next level protocols
        let mut body = [0u8; 300];
        let mut udp_packet = MutableUdpPacket::new(&mut body).unwrap();

        // DHCP payload
        let mut vec1 = vec![0u8; 236];
        let vec2: Vec<u8> = vec![
            // Magic Cookie: 0x63825363
            0x63, 0x82, 0x53, 0x63, // DHCP Option: DHCP Message Type (53)
            0x35, 0x01, 0x01, // DHCP Message Type: Discover (1)
            // End Option (255)
            0xFF,
        ];
        vec1.extend(vec2);
        let dhcp_payload: [u8; 244] = {
            let mut array_data: [u8; 244] = [0u8; 244];
            let len = vec1.len();
            array_data[..len].copy_from_slice(&vec1);
            array_data
        };
        udp_packet.set_length(300);
        udp_packet.set_payload(&dhcp_payload);

        let rule = UdpRule::new(Some(UdpNextLevel::Dhcp), Some(100), None, None);
        assert!(rule.process(udp_packet.packet()).unwrap());
    }

    #[test]
    fn test_udp_packet_5() {
        // Check source and destination ports
        let rule = UdpRule::new(Some(UdpNextLevel::Sip), Some(100), Some(5060), Some(5060));

        let mut body = [0u8; 50];
        let mut udp_packet = MutableUdpPacket::new(&mut body).unwrap();
        let sip_payload = b"SIP";
        udp_packet.set_payload(sip_payload);
        udp_packet.set_source(5060);
        udp_packet.set_destination(5060);

        assert!(rule.process(udp_packet.packet()).unwrap());

        let mut body2 = [0u8; 50];
        let mut udp_packet2 = MutableUdpPacket::new(&mut body2).unwrap();
        let payload2 = b"SIP";
        udp_packet2.set_payload(payload2);
        udp_packet2.set_source(5049);
        udp_packet2.set_destination(5060);
        assert!(!rule.process(udp_packet2.packet()).unwrap());

        let mut body3 = [0u8; 50];
        let mut udp_packet3 = MutableUdpPacket::new(&mut body3).unwrap();
        let payload3 = b"SIP";
        udp_packet3.set_payload(payload3);
        udp_packet3.set_source(5060);
        udp_packet3.set_destination(5049);
        assert!(!rule.process(udp_packet3.packet()).unwrap());

        let mut body4 = [0u8; 50];
        let mut udp_packet4 = MutableUdpPacket::new(&mut body4).unwrap();
        let payload4 = b"SIP";
        udp_packet4.set_payload(payload4);
        udp_packet4.set_source(5049);
        udp_packet4.set_destination(5049);
        assert!(!rule.process(udp_packet4.packet()).unwrap());
    }
}
