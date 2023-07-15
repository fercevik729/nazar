use super::{BWList, Deserialize, IpRange, PortRange, Protocol, Result};

use anyhow::anyhow;
use httparse::Status;
use std::{collections::HashMap, fmt, net::IpAddr};

#[derive(Deserialize, Debug)]
pub struct RuleConfig {
    pub src_ip_list: Option<BWList<IpRange>>,
    pub dest_ip_list: Option<BWList<IpRange>>,
    pub port_list: Option<BWList<PortRange>>,
    pub protoc_list: Option<BWList<Protocol>>,
    pub rules: Option<Vec<Rule>>,
}

// Enum used to represent intrusion detection system
// actions
// TODO: implement Action-specific packet processing functions
#[derive(Deserialize, Debug)]
pub enum IdsAction {
    Alert,
    Log,
    Block,
    Terminate,
    Whitelist,
    Blacklist,
}

#[derive(Deserialize, Debug)]
pub struct Rule {
    src_ip: Option<IpAddr>,
    src_port: Option<i32>,
    dest_ip: Option<IpAddr>,
    dest_port: Option<i32>,
    prot_rule: ProtocolRule,
    action: IdsAction,
}

#[derive(Deserialize, Debug)]
pub enum ProtocolRule {
    Transport(TransportProtocolRule),
    Application(ApplicationProtocolRule),
}

// Enum to represent transport layer
// protocol rules
#[derive(Deserialize, Debug)]
pub enum TransportProtocolRule {
    Icmp,
    Icmpv6,
    Tcp,
    Udp,
}

// Enum type to represent application layer
// protocol rules
#[derive(Deserialize, Debug)]
pub enum ApplicationProtocolRule {
    Http(HttpRule),
    Dhcp,
    Dns,
}

// Represents a vector of string patterns
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

// Enum to represent HTTP Methods
#[derive(Deserialize, Debug)]
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
    fn process_packet(&self, body: &[u8]) -> Result<bool>;
}

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

impl ApplicationProtocol for DnsRule {
    fn process_packet(&self, body: &[u8]) -> Result<bool> {
        // Assumes that the packet is some kind of DNS Packet over UDP/53 or TCP/53
        // though not necessarily a valid one
        //
        // The function parses the byte slice into a dns_parser::Packet struct using the
        // dns_parser library. It returns an error if something went wrong during parsing
        //
        // All parameters in the Rule struct are optional, and if not explicitly provided,
        // this function will skip those parameters
        //
        // For a request to return 'true' indicating that it matches the Rule struct provided,
        // it must match all the fields and *at least one* of any subfields.
        //
        // Parse request
        let dns_request = dns_parser::Packet::parse(body)?;
        // Iterate over all the questions in the DNS packet and see if any match
        // the patterns specified in the DNS rule
        let questions = dns_request.questions;
        if let Some(q_patterns) = &self.query_names {
            if !questions
                .iter()
                .any(|q| q_patterns.match_exists(q.qname.to_string().as_bytes()))
            {
                return Ok(false);
            }
        }
        // Iterate over all the questions in the DNS packet and see if any match
        // one of the query types specified in the DNS Rule
        if self.query_types.is_some() && !questions.iter().any(|q| self.qtype_matches(q.qtype)) {
            return Ok(false);
        }

        // Iterate over all the answer records in the DNS packet and see if any match
        // one of the record types specified in the DNS Rule
        if self.record_types.is_some()
            && !dns_request
                .answers
                .iter()
                .any(|a| self.rtype_matches(&a.data))
        {
            return Ok(false);
        }

        Ok(true)
    }
}

#[cfg(test)]
mod dns_tests {
    use super::*;

    #[test]
    fn test_dns_process_packet_1() -> Result<()> {
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
        assert!(rule.process_packet(&dns_packet)?);

        let mut builder2 = dns_parser::Builder::new_query(2, false);
        builder2.add_question(
            "malicious.com",
            false,
            dns_parser::QueryType::AAAA,
            dns_parser::QueryClass::IN,
        );
        let dns_packet2 = builder2.build().unwrap_or_else(|x| x);
        assert!(!rule.process_packet(&dns_packet2)?);

        Ok(())
    }

    #[test]
    fn test_dns_process_packet_2() -> Result<()> {
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
        assert!(rule.process_packet(&dns_packet)?);

        let mut builder2 = dns_parser::Builder::new_query(1, false);
        builder2.add_question(
            "malicious.com",
            false,
            dns_parser::QueryType::A,
            dns_parser::QueryClass::IN,
        );
        let dns_packet2 = builder2.build().unwrap_or_else(|x| x);

        assert!(!rule.process_packet(&dns_packet2)?);

        Ok(())
    }

    #[test]
    fn test_dns_process_packet_3() -> Result<()> {
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
        assert!(!rule.process_packet(&dns_packet)?);

        let mut builder2 = dns_parser::Builder::new_query(1, false);
        builder2.add_question(
            "malicious.com",
            false,
            dns_parser::QueryType::A,
            dns_parser::QueryClass::IN,
        );
        let dns_packet2 = builder2.build().unwrap_or_else(|x| x);

        assert!(!rule.process_packet(&dns_packet2)?);
        Ok(())
    }
}

// Struct to represent an HTTP rule
#[derive(Deserialize, Debug)]
pub struct HttpRule {
    // Option-al HTTP method.
    // If it is None then any HTTP method is allowed
    // Otherwise, if it is specified only requests with
    // that particular method match the rule
    method: Option<HttpMethod>,
    // Option-al HashMap of HTTP Headers and suspicious
    // Header values. If it is None then any HTTP header
    // matches the rule
    headers_contain: Option<HashMap<String, String>>,
    // Option-al Patterns struct that contains suspicious
    // patterns that might exist in the URI path
    path_contains: Option<Patterns>,
    // Option-al Patterns struct that contains suspicious
    // patterns that might exist in the Request body
    body_contains: Option<Patterns>,
}

impl HttpRule {
    fn new(
        // Constructor for HTTP Rule
        // Takes in all Option-al parameters and returns a new
        // HttpRule struct
        method: Option<HttpMethod>,
        headers_contain: Option<HashMap<String, String>>,
        path_patterns: Option<Vec<String>>,
        body_patterns: Option<Vec<String>>,
    ) -> Self {
        Self {
            method,
            headers_contain,
            path_contains: path_patterns.map(Patterns),
            body_contains: body_patterns.map(Patterns),
        }
    }
}

impl ApplicationProtocol for HttpRule {
    fn process_packet(&self, body: &[u8]) -> Result<bool> {
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
        // For a request to return 'true' indicating that it matches the Rule struct provided,
        // it must match all the fields and *at least one* of their subfields as well as needed.
        //
        // Parse request
        let mut headers = [httparse::EMPTY_HEADER; 16];
        let mut req = httparse::Request::new(&mut headers);
        let res = req.parse(body)?;

        // Check the request method and see if it matches if one was provided in the Rules struct
        match req.method {
            Some(m) => {
                if let Some(rm) = &self.method {
                    if m != rm.to_string() {
                        return Ok(false);
                    }
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
                    if !rp.match_exists(p.as_bytes()) {
                        return Ok(false);
                    }
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
            let mut found = false;
            for (header, target) in map.iter() {
                // Find a header with a matching name in the request
                let value = req.headers.iter().find(|&x| x.name == header);
                if let Some(fnd) = value {
                    found = fnd
                        .value
                        .windows(target.len())
                        .any(|window| window == target.as_bytes());
                    // Break after the first match
                    if found {
                        break;
                    }
                }
            }

            // If no headers with matching values could be found in the
            // request, return false
            if !found {
                return Ok(false);
            }
        }

        // Check the request body for the pattern
        // Must contain at least one match
        // If the body is empty/nonexistent but there
        // are patterns in the rule the function should
        // return false
        if let Status::Complete(ofs) = res {
            if let Some(bp) = &self.body_contains {
                return Ok(bp.match_exists(&body[ofs..]));
            }
        } else if self.body_contains.is_some() {
            return Ok(false);
        }

        Ok(true)
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
