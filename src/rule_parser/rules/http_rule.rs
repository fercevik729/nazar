use super::*;

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

    fn match_method(expected: &HttpMethod, actual: &str) -> bool {
        // Matches an HTTP Method in a rule to an actual parse HTTP Method
        // Returns true if they match, false otherwise
        match expected {
            HttpMethod::Get => actual == "GET",
            HttpMethod::Put => actual == "PUT",
            HttpMethod::Post => actual == "POST",
            HttpMethod::Head => actual == "HEAD",
            HttpMethod::Patch => actual == "PATCH",
            HttpMethod::Trace => actual == "TRACE",
            HttpMethod::Delete => actual == "DELETE",
            HttpMethod::Options => actual == "OPTIONS",
            HttpMethod::Connection => actual == "CONNECTION",
        }
    }
}

impl ProcessPacket for HttpRule {
    fn process(&self, body: &[u8]) -> Result<bool> {
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

        match req.method {
            Some(m) => {
                if let Some(rm) = &self.method {
                    if !HttpRule::match_method(rm, m) {
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
mod tests {
    use super::*;
    use crate::hashmap;

    #[test]
    fn test_http_process_packet_0() -> Result<()> {
        let req = b"POST nazar.com/api/user HTTP/1.1\r\n\
                        Host: example.com\r\n\
                        Content-Type: application/json\r\n\
                        Content-Length: 25\r\n\
                        \r\n\
                        {\"username\":\"john\",\"password\":\"secret\"}";
        let rule = HttpRule::new(Some(HttpMethod::Get), None, None, None);
        assert!(!rule.process(req)?);
        Ok(())
    }

    #[test]
    fn test_http_process_packet_1() -> Result<()> {
        let req = b"POST nazar.com/api/user HTTP/1.1\r\n\
                        Host: example.com\r\n\
                        Content-Type: application/json\r\n\
                        Content-Length: 25\r\n\
                        \r\n\
                        {\"username\":\"john\",\"password\":\"secret\"}";

        let rule = HttpRule::new(Some(HttpMethod::Post), None, None, None);
        assert!(rule.process(req)?);

        let rule_2 = HttpRule::new(
            Some(HttpMethod::Post),
            None,
            None,
            Some(vec![String::from("secret"), String::from("missing")]),
        );
        assert!(rule_2.process(req)?);

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
        assert!(rule.process(req)?);

        let rule2 = HttpRule::new(
            Some(HttpMethod::Post),
            None,
            Some(vec![String::from("/secrete")]),
            None,
        );

        assert!(!rule2.process(req)?);

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

        assert!(rule.process(req)?);

        let rule_2 = HttpRule::new(
            Some(HttpMethod::Get),
            Some(hashmap! {
                String::from("Host") => String::from("sussy.com")
            }),
            None,
            Some(vec![String::from("Non existent body Value")]),
        );

        assert!(!rule_2.process(req)?);

        Ok(())
    }
}
