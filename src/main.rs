use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;

use clap::Parser;

use anyhow::{anyhow, Context, Result};

pub mod rule_parser;
pub mod utils;

#[derive(Parser, Debug)]
#[command(name = "nazar")]
#[command(author = "Furkan E. <f.ercevik21@gmail.com>")]
#[command(version = "0.1.0")]
#[command(about = "A simple packet sniffing and intrusion detection program")]
struct Args {
    // Name of the interface to perform packet sniffing on
    // If not provided, the program will try to find the first non-loopback
    // interface
    #[arg(short, long)]
    iface: Option<String>,

    // Path to file containing the rules
    #[arg(short, long, value_name = "FILE")]
    rules: PathBuf,

    // Path to directory to output log files
    // If not provided, the program will write logs in a 'logs' directory in the
    // current working directory
    #[arg(short, long, value_name = "DIR")]
    outlog: Option<PathBuf>,

    // Flag indicating if the intrusion system should dynamically update its rule
    // or keep them static (default)
    #[arg(short, long)]
    dynamic: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Interface
    let iface = match nazar::get_iface(args.iface) {
        Some(x) => x,
        None => {
            return Err(anyhow!(
                "unable to find a suitable network interface to sniff packets on"
            ))
        }
    };

    println!("Dynamic: {}", args.dynamic);

    // Rules file
    if !nazar::validate_file_ext(&args.rules, "toml") {
        return Err(anyhow!("rules file must be a .toml file"));
    }
    let rules_file = File::open(&args.rules).with_context(|| {
        format!(
            "No rules file of the name `{}` exists",
            &args.rules.display()
        )
    })?;
    let mut _buf = BufReader::new(rules_file);
    println!("Reading rules from `{}`...", args.rules.display());

    // Logging with log4rs
    let log_path = args
        .outlog
        .unwrap_or_else(|| std::path::PathBuf::from("logs"));

    println!("Setting up logging in {:?} dir...", log_path);
    nazar::setup_logging(log_path, 5, 5 * 1024)?;
    println!("Done setting up logging...");

    // Packet capture
    println!("Initiating packet capture on interface {}...", iface);
    let rx = &mut (*nazar::setup_pcap_rec(&iface)?);
    nazar::handle_pcap(rx);

    Ok(())
}
