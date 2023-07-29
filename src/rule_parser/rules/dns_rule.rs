use super::*;

// Enum representing the different types of DNS packets
#[derive(Deserialize, Debug)]
enum DnsType {
    A,
    Ns,
    Mx,
    Cname,
    Soa,
    Wks,
    Ptr,
    Minfo,
    Aaaa,
    Srv,
    Axfr,
    All,
}

// Struct to represent a DNS Rule
#[derive(Deserialize, Debug)]
pub struct DnsRule {
    // Option-al Patterns struct of DNS query_names
    // If it is None, then any DNS query name is matched
    // Otherwise, if specified only requests that contain
    // at least one of the patterns will match the rule
    query_names: Option<Patterns>,
    // Option-al vector of DNS Types to represent Query types
    // If None, then any query type is matched
    // Otherwise, the request must match at least one
    // of the query types
    query_types: Option<Vec<DnsType>>,
    // Option-al vector of DNS Types to represent Record types
    // If None, then any resource type is matched
    // Otherwise, the request must match at least one of the query
    // types
    record_types: Option<Vec<DnsType>>,
}

impl DnsRule {
    fn new(
        query_names: Option<Vec<String>>,
        query_types: Option<Vec<DnsType>>,
        record_types: Option<Vec<DnsType>>,
    ) -> Self {
        // Constructor of a DNS Rule
        // Takes in all Option-al parameters and returns a new DnsRule struct
        Self {
            query_names: query_names.map(Patterns),
            query_types,
            record_types,
        }
    }

    fn qtype_matches(&self, target_query_type: dns_parser::QueryType) -> bool {
        // A helper method that iterates over all the query types in the rule
        // and sees if any match the target_query_type, if so it returns true
        // otherwise false. If query_types is None it returns true
        if let Some(query_types) = &self.query_types {
            return query_types.iter().any(|q| match q {
                DnsType::A => target_query_type == dns_parser::QueryType::A,
                DnsType::Ns => target_query_type == dns_parser::QueryType::NS,
                DnsType::Mx => target_query_type == dns_parser::QueryType::MX,
                DnsType::Cname => target_query_type == dns_parser::QueryType::CNAME,
                DnsType::Soa => target_query_type == dns_parser::QueryType::SOA,
                DnsType::Wks => target_query_type == dns_parser::QueryType::WKS,
                DnsType::Ptr => target_query_type == dns_parser::QueryType::PTR,
                DnsType::Minfo => target_query_type == dns_parser::QueryType::MINFO,
                DnsType::Aaaa => target_query_type == dns_parser::QueryType::AAAA,
                DnsType::Srv => target_query_type == dns_parser::QueryType::SRV,
                DnsType::Axfr => target_query_type == dns_parser::QueryType::AXFR,
                DnsType::All => target_query_type == dns_parser::QueryType::All,
            });
        }

        // Return true if no query types are specified
        true
    }

    fn rtype_matches(&self, target_resource_type: &dns_parser::RData) -> bool {
        // A helper method that iterates over all the record data types in the rule
        // and sees if any match the target_resource_type. If so it returns true
        // otherwise false.
        //
        // If no resource types are specified it returns true
        if let Some(r_types) = &self.record_types {
            return r_types.iter().any(|r| match r {
                DnsType::A => matches!(target_resource_type, dns_parser::RData::A(_)),
                DnsType::Ns => matches!(target_resource_type, dns_parser::RData::NS(_)),
                DnsType::Mx => matches!(target_resource_type, dns_parser::RData::MX(_)),
                DnsType::Cname => matches!(target_resource_type, dns_parser::RData::CNAME(_)),
                DnsType::Soa => matches!(target_resource_type, dns_parser::RData::SOA(_)),
                DnsType::Ptr => matches!(target_resource_type, dns_parser::RData::PTR(_)),
                DnsType::Aaaa => matches!(target_resource_type, dns_parser::RData::AAAA(_)),
                DnsType::Srv => matches!(target_resource_type, dns_parser::RData::SRV(_)),
                _ => false,
            });
        }

        // Return true if no record types are specified
        true
    }
}

impl ProcessPacket for DnsRule {
    fn process(&self, body: &[u8]) -> Option<bool> {
        // Assumes that the packet is some kind of DNS Packet over UDP/53 or TCP/53
        // though not necessarily a valid one
        //
        // The function parses the byte slice into a dns_parser::Packet struct using the
        // dns_parser library. It returns None if something went wrong during parsing
        //
        // All parameters in the Rule struct are optional, and if not explicitly provided,
        // this function will skip those parameters
        //
        // For a request to return 'true' indicating that it matches the Rule struct provided,
        // it must match all the fields and *at least one* of any subfields.
        //
        // Parse request
        if let Some(dns_request) = dns_parser::Packet::parse(body).ok() {
            // Iterate over all the questions in the DNS packet and see if any match
            // the patterns specified in the DNS rule
            let questions = dns_request.questions;
            if let Some(q_patterns) = &self.query_names {
                if !questions
                    .iter()
                    .any(|q| q_patterns.match_exists(q.qname.to_string().as_bytes()))
                {
                    return Some(false);
                }
            }
            // Iterate over all the questions in the DNS packet and see if any match
            // one of the query types specified in the DNS Rule
            if self.query_types.is_some() && !questions.iter().any(|q| self.qtype_matches(q.qtype))
            {
                return Some(false);
            }

            // Iterate over all the answer records in the DNS packet and see if any match
            // one of the record types specified in the DNS Rule
            if self.record_types.is_some()
                && !dns_request
                    .answers
                    .iter()
                    .any(|a| self.rtype_matches(&a.data))
            {
                return Some(false);
            }

            return Some(true);
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_qtype_matches() {
        // No query types so treat the rule as a wildcard
        let rule_1 = DnsRule::new(None, None, None);
        assert!(rule_1.qtype_matches(dns_parser::QueryType::NS));

        let rule_2 = DnsRule::new(None, Some(vec![DnsType::Mx]), None);
        assert!(rule_2.qtype_matches(dns_parser::QueryType::MX));
    }

    #[test]
    fn test_dns_process_packet_1() {
        let rule = DnsRule::new(
            Some(vec![String::from("malicious.com")]),
            Some(vec![DnsType::A]),
            None,
        );
        let mut builder = dns_parser::Builder::new_query(1, false);
        builder.add_question(
            "malicious.com",
            false,
            dns_parser::QueryType::A,
            dns_parser::QueryClass::IN,
        );
        let dns_packet = builder.build().unwrap_or_else(|x| x);
        assert!(rule.process(&dns_packet).unwrap());

        let mut builder2 = dns_parser::Builder::new_query(2, false);
        builder2.add_question(
            "malicious.com",
            false,
            dns_parser::QueryType::AAAA,
            dns_parser::QueryClass::IN,
        );
        let dns_packet2 = builder2.build().unwrap_or_else(|x| x);
        assert!(!rule.process(&dns_packet2).unwrap());
    }

    #[test]
    fn test_dns_process_packet_2() {
        let rule = DnsRule::new(
            Some(vec![
                String::from("suspicious.com"),
                String::from("evil.com"),
            ]),
            Some(vec![DnsType::Aaaa, DnsType::Soa]),
            None,
        );
        let mut builder = dns_parser::Builder::new_query(1, false);
        builder.add_question(
            "evil.com",
            false,
            dns_parser::QueryType::SOA,
            dns_parser::QueryClass::IN,
        );
        let dns_packet = builder.build().unwrap_or_else(|x| x);
        assert!(rule.process(&dns_packet).unwrap());

        let mut builder2 = dns_parser::Builder::new_query(1, false);
        builder2.add_question(
            "malicious.com",
            false,
            dns_parser::QueryType::A,
            dns_parser::QueryClass::IN,
        );
        let dns_packet2 = builder2.build().unwrap_or_else(|x| x);

        assert!(!rule.process(&dns_packet2).unwrap());
    }

    #[test]
    fn test_dns_process_packet_3() {
        let rule = DnsRule::new(
            Some(vec![
                String::from("suspicious.com"),
                String::from("malicious.net"),
            ]),
            Some(vec![DnsType::A, DnsType::Aaaa]),
            Some(vec![DnsType::A]),
        );

        let mut builder = dns_parser::Builder::new_query(1, false);
        builder.add_question(
            "malicious.net",
            false,
            dns_parser::QueryType::A,
            dns_parser::QueryClass::IN,
        );
        let dns_packet = builder.build().unwrap_or_else(|x| x);
        assert!(!rule.process(&dns_packet).unwrap());

        let mut builder2 = dns_parser::Builder::new_query(1, false);
        builder2.add_question(
            "malicious.com",
            false,
            dns_parser::QueryType::A,
            dns_parser::QueryClass::IN,
        );
        let dns_packet2 = builder2.build().unwrap_or_else(|x| x);

        assert!(!rule.process(&dns_packet2).unwrap());
    }
}
