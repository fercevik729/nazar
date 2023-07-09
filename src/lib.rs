extern crate pnet;

use std::ffi::OsStr;
use std::path::Path;

use pnet::datalink::{interfaces, NetworkInterface};

// Gets the network interface with the corresponding name or returns a default
// value
pub fn get_iface(iface: Option<String>) -> Option<NetworkInterface> {
    // Gather the network interfaces into an iterator
    let mut ifaces = interfaces().into_iter();

    // If an interface name was provided
    if let Some(iface_name) = iface {
        ifaces.find(|x| x.name == iface_name)

    // Try to find a suitable default interface
    } else {
        ifaces.find(|iface| iface.is_up() && !iface.is_loopback() && !iface.ips.is_empty())
    }
}

// Validates a file's extension against the provided `ext` parameter
pub fn validate_file_ext(filepath: &Path, ext: &str) -> bool {
    filepath.extension() == Some(OsStr::new(ext))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::validate_file_ext;

    #[test]
    fn test_validate_file_ext() {
        let fp = PathBuf::from(r"/etc/config.toml");

        assert_eq!(true, validate_file_ext(&fp, "toml"));
        assert_eq!(false, validate_file_ext(&fp, "csv"));
        assert_eq!(false, validate_file_ext(&fp, "exe"));
        assert_eq!(false, validate_file_ext(&fp, "tom"));

        let fp2 = PathBuf::from(r"/etc/config");
        assert_eq!(false, validate_file_ext(&fp2, "toml"));
        assert_eq!(false, validate_file_ext(&fp2, "csv"));
        assert_eq!(false, validate_file_ext(&fp2, "exe"));
        assert_eq!(false, validate_file_ext(&fp2, "tom"));
    }
}
