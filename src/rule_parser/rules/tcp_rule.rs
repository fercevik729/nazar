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
}

impl TcpRule {
    fn new(
        options: Option<Vec<TcpOption>>,
        flags: Option<u8>,
        max_window_size: Option<u16>,
        max_payload_size: Option<usize>,
    ) -> Self {
        Self {
            options,
            flags,
            max_window_size,
            max_payload_size,
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
    fn process(&self, body: &[u8]) -> Result<bool> {
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
                return Ok(false);
            }

            // Check the window size
            if let Some(max_window_size) = self.max_window_size {
                if max_window_size < tcp_packet.get_window() {
                    return Ok(false);
                }
            }

            // Check the flags
            if let Some(flags) = self.flags {
                return Ok((flags & tcp_packet.get_flags()) > 0);
            }

            // Check the payload size
            if let Some(max_payload_size) = self.max_payload_size {
                if max_payload_size < tcp_packet.packet_size() {
                    return Ok(false);
                }
            }

            Ok(true)
        } else {
            Err(anyhow!("Unable to parse TCP Packet"))
        }
    }
}

#[cfg(test)]
mod tests {
    use pnet::packet::{tcp::MutableTcpPacket, Packet};

    use super::*;

    const TCP_PACKET_LEN: usize = 30;
    const TCP_PACKET_OFS: u8 = 10;

    #[test]
    fn test_tcp_process_packet_1() -> Result<()> {
        // Tests for TCP options in particular
        // 1 option - matches
        let rule = TcpRule::new(Some(vec![TcpOption::Nop]), None, None, None);
        let buff = vec![0u8; TCP_PACKET_LEN];
        let mut tcp_packet = MutableTcpPacket::owned(buff).unwrap();
        tcp_packet.set_data_offset(TCP_PACKET_OFS); // TCP header data offset
        tcp_packet.set_flags(tcp::TcpFlags::SYN); // TCP header flags
        tcp_packet.set_options(&[tcp::TcpOption::nop()]);

        assert!(rule.process(tcp_packet.packet())?);

        // 2 options - at least 1 matches
        let buff_2 = vec![0u8; TCP_PACKET_LEN];
        let mut tcp_packet_2 = MutableTcpPacket::owned(buff_2).unwrap();
        tcp_packet_2.set_data_offset(TCP_PACKET_OFS); // TCP header data offset
        tcp_packet_2.set_flags(tcp::TcpFlags::SYN); // TCP header flags
        tcp_packet_2.set_options(&[tcp::TcpOption::nop(), tcp::TcpOption::sack_perm()]);

        assert!(rule.process(tcp_packet_2.packet())?);

        // 2 options - don't match
        let buff_3 = vec![0u8; TCP_PACKET_LEN];
        let mut tcp_packet_3 = MutableTcpPacket::owned(buff_3).unwrap();
        tcp_packet_3.set_data_offset(TCP_PACKET_OFS); // TCP header data offset
        tcp_packet_3.set_flags(tcp::TcpFlags::SYN); // TCP header flags
        tcp_packet_3.set_options(&[tcp::TcpOption::mss(3), tcp::TcpOption::sack_perm()]);

        assert!(!rule.process(tcp_packet_3.packet())?);
        Ok(())
    }

    #[test]
    fn test_tcp_process_packet_2() -> Result<()> {
        // Tests for TCP Flags in particular
        // 1 flag - matches
        let rule = TcpRule::new(Some(vec![TcpOption::Mss]), Some(0x02), None, None);
        let buff = vec![0u8; TCP_PACKET_LEN];
        let mut tcp_packet = MutableTcpPacket::owned(buff).unwrap();
        tcp_packet.set_data_offset(TCP_PACKET_OFS);
        tcp_packet.set_flags(tcp::TcpFlags::SYN);
        tcp_packet.set_options(&[tcp::TcpOption::mss(10)]);

        assert!(rule.process(tcp_packet.packet())?);

        // 1 flag - doesn't match
        let buff_2 = vec![0u8; TCP_PACKET_LEN];
        let mut tcp_packet_2 = MutableTcpPacket::owned(buff_2).unwrap();
        tcp_packet_2.set_data_offset(TCP_PACKET_OFS);
        tcp_packet_2.set_flags(tcp::TcpFlags::ACK);
        tcp_packet_2.set_options(&[tcp::TcpOption::mss(10)]);

        assert!(!rule.process(tcp_packet_2.packet())?);

        // 3 flags - at least 1 match
        let buff_3 = vec![0u8; TCP_PACKET_LEN];
        let mut tcp_packet_3 = MutableTcpPacket::owned(buff_3).unwrap();
        tcp_packet_3.set_data_offset(TCP_PACKET_OFS);
        tcp_packet_3.set_flags(tcp::TcpFlags::ACK | tcp::TcpFlags::SYN | tcp::TcpFlags::URG);
        tcp_packet_3.set_options(&[tcp::TcpOption::mss(10)]);

        assert!(rule.process(tcp_packet_3.packet())?);

        // 3 flags - none match
        let buff_4 = vec![0u8; TCP_PACKET_LEN];
        let mut tcp_packet_4 = MutableTcpPacket::owned(buff_4).unwrap();
        tcp_packet_4.set_data_offset(TCP_PACKET_OFS);
        tcp_packet_4.set_flags(tcp::TcpFlags::ACK | tcp::TcpFlags::ECE | tcp::TcpFlags::URG);
        tcp_packet_4.set_options(&[tcp::TcpOption::mss(10)]);

        assert!(!rule.process(tcp_packet_4.packet())?);

        Ok(())
    }

    #[test]
    fn test_tcp_process_packet_3() -> Result<()> {
        // Test for maximum window packet_size
        // Should pass: < 1024
        let rule = TcpRule::new(Some(vec![TcpOption::Sack]), Some(0x02), Some(1024), None);
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

        assert!(rule.process(tcp_packet.packet())?);

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

        assert!(!rule.process(tcp_packet_2.packet())?);

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

        assert!(rule.process(tcp_packet_3.packet())?);
        Ok(())
    }

    #[test]
    fn test_tcp_process_packet_4() -> Result<()> {
        // Test for maximum payload size
        // Should pass: <= 30
        let rule = TcpRule::new(
            Some(vec![TcpOption::Wscale]),
            Some(0x02),
            Some(1024),
            Some(30),
        );
        let buff = vec![0u8; TCP_PACKET_LEN];
        let mut tcp_packet = MutableTcpPacket::owned(buff).unwrap();
        tcp_packet.set_data_offset(TCP_PACKET_OFS);
        tcp_packet.set_flags(tcp::TcpFlags::SYN);
        tcp_packet.set_options(&[tcp::TcpOption::wscale(1)]);
        tcp_packet.set_window(512);

        assert!(rule.process(tcp_packet.packet())?);
        Ok(())
    }
}
