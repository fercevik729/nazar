use super::*;

// Enum representing TCP Options
#[derive(Deserialize, Debug)]
enum TcpOption {
    /// Maximum segment size
    Mss,
    /// Window scale
    Wscale,
    /// Selective acknowledgment
    Sack,
    /// End of Options list
    Eol,
    /// Timestamps
    Timestamps,
    /// No operation
    Nop,
}

#[derive(Deserialize, Debug)]
pub struct TcpRule {
    options: Option<Vec<TcpOption>>,
    flags: Option<u8>,
    max_window_size: Option<u16>,
    max_payload_size: Option<usize>,
    src_port: Option<u16>,
    dest_port: Option<u16>,
}

impl TcpRule {
    fn new(
        options: Option<Vec<TcpOption>>,
        flags: Option<u8>,
        max_window_size: Option<u16>,
        max_payload_size: Option<usize>,
        src_port: Option<u16>,
        dest_port: Option<u16>,
    ) -> Self {
        // Constructor for TcpRule
        // Returns None if either the src or dest port was out
        // of the range of ports from 1 .. 65535 inclusive
        Self {
            options,
            flags,
            max_window_size,
            max_payload_size,
            src_port,
            dest_port,
        }
    }
    fn match_opts(&self, x: tcp::TcpOptionPacket) -> bool {
        // If tcp options are specified in the rule, this function will return true
        // if at least one of the options are contained in the packet, otherwise it will
        // return false
        // If no tcp options are specified in the rule, this function will also return true
        // since in this case any TCP option is valid
        if let Some(rule_options) = &self.options {
            return rule_options.iter().any(|ro| match ro {
                TcpOption::Mss => x.get_number() == tcp::TcpOptionNumbers::MSS,
                TcpOption::Eol => x.get_number() == tcp::TcpOptionNumbers::EOL,
                TcpOption::Nop => x.get_number() == tcp::TcpOptionNumbers::NOP,
                TcpOption::Sack => x.get_number() == tcp::TcpOptionNumbers::SACK,
                TcpOption::Wscale => x.get_number() == tcp::TcpOptionNumbers::WSCALE,
                TcpOption::Timestamps => x.get_number() == tcp::TcpOptionNumbers::TIMESTAMPS,
            });
        }

        true
    }
}

impl ProcessPacket for TcpRule {
    fn process(&self, body: &[u8]) -> Option<bool> {
        // Assumes that the packet is some kind of TCP Packet though not necessarily a valid one
        // The function parses the byte slice into a TcpPacket struct using the
        // pnet library. It returns an error if something went wrong during parsing
        //
        // All parameters in the Rule struct are optional, and if not explicitly provided,
        // this function will skip those parameters
        //
        // For a request to return 'true' indicating that it matches the Rule struct provided,
        // it must match all the fields and *at least one* of any subfields.
        // Try to make a TCP Packet
        if let Some(tcp_packet) = TcpPacket::new(body) {
            // Check the options
            if !tcp_packet.get_options_iter().any(|x| self.match_opts(x)) {
                return Some(false);
            }

            // Check the window size
            if let Some(max_window_size) = self.max_window_size {
                if max_window_size < tcp_packet.get_window() {
                    return Some(false);
                }
            }

            // Check the flags
            if let Some(flags) = self.flags {
                if flags & tcp_packet.get_flags() == 0 {
                    return Some(false);
                }
            }

            // Check the payload size
            if let Some(max_payload_size) = self.max_payload_size {
                if max_payload_size < tcp_packet.packet_size() {
                    return Some(false);
                }
            }

            // Check the src and dest ports
            if let Some(src_port) = self.src_port {
                if src_port != tcp_packet.get_source() {
                    return Some(false);
                }
            }
            if let Some(dest_port) = self.dest_port {
                if dest_port != tcp_packet.get_destination() {
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
    use pnet::packet::{tcp::MutableTcpPacket, Packet};

    use super::*;

    const TCP_PACKET_LEN: usize = 30;
    const TCP_PACKET_OFS: u8 = 10;

    #[test]
    fn test_tcp_process_packet_1() {
        // Tests for TCP options in particular
        // 1 option - matches
        let rule = TcpRule::new(Some(vec![TcpOption::Nop]), None, None, None, None, None);
        let buff = vec![0u8; TCP_PACKET_LEN];
        let mut tcp_packet = MutableTcpPacket::owned(buff).unwrap();
        tcp_packet.set_data_offset(TCP_PACKET_OFS); // TCP header data offset
        tcp_packet.set_flags(tcp::TcpFlags::SYN); // TCP header flags
        tcp_packet.set_options(&[tcp::TcpOption::nop()]);

        assert!(rule.process(tcp_packet.packet()).unwrap());

        // 2 options - at least 1 matches
        let buff_2 = vec![0u8; TCP_PACKET_LEN];
        let mut tcp_packet_2 = MutableTcpPacket::owned(buff_2).unwrap();
        tcp_packet_2.set_data_offset(TCP_PACKET_OFS); // TCP header data offset
        tcp_packet_2.set_flags(tcp::TcpFlags::SYN); // TCP header flags
        tcp_packet_2.set_options(&[tcp::TcpOption::nop(), tcp::TcpOption::sack_perm()]);

        assert!(rule.process(tcp_packet_2.packet()).unwrap());

        // 2 options - don't match
        let buff_3 = vec![0u8; TCP_PACKET_LEN];
        let mut tcp_packet_3 = MutableTcpPacket::owned(buff_3).unwrap();
        tcp_packet_3.set_data_offset(TCP_PACKET_OFS); // TCP header data offset
        tcp_packet_3.set_flags(tcp::TcpFlags::SYN); // TCP header flags
        tcp_packet_3.set_options(&[tcp::TcpOption::mss(3), tcp::TcpOption::sack_perm()]);

        assert!(!rule.process(tcp_packet_3.packet()).unwrap());
    }

    #[test]
    fn test_tcp_process_packet_2() {
        // Tests for TCP Flags in particular
        // 1 flag - matches
        let rule = TcpRule::new(
            Some(vec![TcpOption::Mss]),
            Some(0x02),
            None,
            None,
            None,
            None,
        );
        let buff = vec![0u8; TCP_PACKET_LEN];
        let mut tcp_packet = MutableTcpPacket::owned(buff).unwrap();
        tcp_packet.set_data_offset(TCP_PACKET_OFS);
        tcp_packet.set_flags(tcp::TcpFlags::SYN);
        tcp_packet.set_options(&[tcp::TcpOption::mss(10)]);

        assert!(rule.process(tcp_packet.packet()).unwrap());

        // 1 flag - doesn't match
        let buff_2 = vec![0u8; TCP_PACKET_LEN];
        let mut tcp_packet_2 = MutableTcpPacket::owned(buff_2).unwrap();
        tcp_packet_2.set_data_offset(TCP_PACKET_OFS);
        tcp_packet_2.set_flags(tcp::TcpFlags::ACK);
        tcp_packet_2.set_options(&[tcp::TcpOption::mss(10)]);

        assert!(!rule.process(tcp_packet_2.packet()).unwrap());

        // 3 flags - at least 1 match
        let buff_3 = vec![0u8; TCP_PACKET_LEN];
        let mut tcp_packet_3 = MutableTcpPacket::owned(buff_3).unwrap();
        tcp_packet_3.set_data_offset(TCP_PACKET_OFS);
        tcp_packet_3.set_flags(tcp::TcpFlags::ACK | tcp::TcpFlags::SYN | tcp::TcpFlags::URG);
        tcp_packet_3.set_options(&[tcp::TcpOption::mss(10)]);

        assert!(rule.process(tcp_packet_3.packet()).unwrap());

        // 3 flags - none match
        let buff_4 = vec![0u8; TCP_PACKET_LEN];
        let mut tcp_packet_4 = MutableTcpPacket::owned(buff_4).unwrap();
        tcp_packet_4.set_data_offset(TCP_PACKET_OFS);
        tcp_packet_4.set_flags(tcp::TcpFlags::ACK | tcp::TcpFlags::ECE | tcp::TcpFlags::URG);
        tcp_packet_4.set_options(&[tcp::TcpOption::mss(10)]);

        assert!(!rule.process(tcp_packet_4.packet()).unwrap());
    }

    #[test]
    fn test_tcp_process_packet_3() {
        // Test for maximum window packet_size
        // Should pass: < 1024
        let rule = TcpRule::new(
            Some(vec![TcpOption::Sack]),
            Some(0x02),
            Some(1024),
            None,
            None,
            None,
        );
        let buff = vec![0u8; TCP_PACKET_LEN];
        let acks = [0u32; 1];
        let mut tcp_packet = MutableTcpPacket::owned(buff).unwrap();
        tcp_packet.set_data_offset(TCP_PACKET_OFS);
        tcp_packet.set_flags(tcp::TcpFlags::SYN);
        tcp_packet.set_options(&[
            tcp::TcpOption::sack_perm(),
            tcp::TcpOption::selective_ack(&acks),
        ]);
        tcp_packet.set_window(512);

        assert!(rule.process(tcp_packet.packet()).unwrap());

        // Should fail: > 1024
        let buff_2 = vec![0u8; TCP_PACKET_LEN];
        let mut tcp_packet_2 = MutableTcpPacket::owned(buff_2).unwrap();
        tcp_packet_2.set_data_offset(TCP_PACKET_OFS);
        tcp_packet_2.set_flags(tcp::TcpFlags::SYN);
        tcp_packet_2.set_options(&[
            tcp::TcpOption::sack_perm(),
            tcp::TcpOption::selective_ack(&acks),
        ]);
        tcp_packet_2.set_window(2048);

        assert!(!rule.process(tcp_packet_2.packet()).unwrap());

        // Should pass: == 1024
        let buff_3 = vec![0u8; TCP_PACKET_LEN];
        let mut tcp_packet_3 = MutableTcpPacket::owned(buff_3).unwrap();
        tcp_packet_3.set_data_offset(TCP_PACKET_OFS);
        tcp_packet_3.set_flags(tcp::TcpFlags::SYN);
        tcp_packet_3.set_options(&[
            tcp::TcpOption::sack_perm(),
            tcp::TcpOption::selective_ack(&acks),
        ]);
        tcp_packet_3.set_window(1024);

        assert!(rule.process(tcp_packet_3.packet()).unwrap());
    }

    #[test]
    fn test_tcp_process_packet_4() {
        // Test for maximum payload size
        // Should pass: <= 35
        let rule = TcpRule::new(
            Some(vec![TcpOption::Wscale]),
            Some(0x02),
            Some(1024),
            Some(40),
            None,
            None,
        );
        let buff = vec![0u8; TCP_PACKET_LEN];
        let mut tcp_packet = MutableTcpPacket::owned(buff).unwrap();
        tcp_packet.set_data_offset(TCP_PACKET_OFS);
        tcp_packet.set_flags(tcp::TcpFlags::SYN);
        tcp_packet.set_options(&[tcp::TcpOption::wscale(1)]);
        tcp_packet.set_window(512);

        assert!(rule.process(tcp_packet.packet()).unwrap());

        // Should fail: > 35
        let buff2 = vec![0u8; TCP_PACKET_LEN];
        let mut tcp_packet2 = MutableTcpPacket::owned(buff2).unwrap();
        tcp_packet2.set_data_offset(TCP_PACKET_OFS + 5);
        tcp_packet2.set_flags(tcp::TcpFlags::SYN);
        tcp_packet2.set_options(&[tcp::TcpOption::wscale(1)]);
        tcp_packet2.set_window(512);

        assert!(!rule.process(tcp_packet2.packet()).unwrap());
    }

    #[test]
    fn test_tcp_process_packet_5() {
        // Test source and destination ports
        let rule = TcpRule::new(
            Some(vec![TcpOption::Wscale]),
            Some(0x02),
            None,
            Some(50),
            Some(80),
            Some(80),
        );

        let buff = vec![0u8; TCP_PACKET_LEN];
        let mut tcp_packet = MutableTcpPacket::owned(buff).unwrap();
        tcp_packet.set_data_offset(TCP_PACKET_OFS);
        tcp_packet.set_flags(tcp::TcpFlags::SYN);
        tcp_packet.set_options(&[tcp::TcpOption::wscale(1)]);
        tcp_packet.set_source(80);
        tcp_packet.set_destination(80);

        // Both match
        assert!(rule.process(tcp_packet.packet()).unwrap());

        let buff2 = vec![0u8; TCP_PACKET_LEN];
        let mut tcp_packet2 = MutableTcpPacket::owned(buff2).unwrap();
        tcp_packet2.set_data_offset(TCP_PACKET_OFS);
        tcp_packet2.set_flags(tcp::TcpFlags::SYN);
        tcp_packet2.set_options(&[tcp::TcpOption::wscale(1)]);
        tcp_packet2.set_source(81);
        tcp_packet2.set_destination(80);
        // Only one matches
        assert!(!rule.process(tcp_packet2.packet()).unwrap());

        let buff3 = vec![0u8; TCP_PACKET_LEN];
        let mut tcp_packet3 = MutableTcpPacket::owned(buff3).unwrap();
        tcp_packet3.set_data_offset(TCP_PACKET_OFS);
        tcp_packet3.set_flags(tcp::TcpFlags::SYN);
        tcp_packet3.set_options(&[tcp::TcpOption::wscale(1)]);
        tcp_packet3.set_source(80);
        tcp_packet3.set_destination(81);
        // Only one matches
        assert!(!rule.process(tcp_packet3.packet()).unwrap());

        let buff4 = vec![0u8; TCP_PACKET_LEN];
        let mut tcp_packet4 = MutableTcpPacket::owned(buff4).unwrap();
        tcp_packet4.set_data_offset(TCP_PACKET_OFS);
        tcp_packet4.set_flags(tcp::TcpFlags::SYN);
        tcp_packet4.set_options(&[tcp::TcpOption::wscale(1)]);
        tcp_packet4.set_source(81);
        tcp_packet4.set_destination(81);
        // Neither matches
        assert!(!rule.process(tcp_packet4.packet()).unwrap());
    }
}
