use std::fs::File;
use std::path::PathBuf;

use clap::Parser;

use anyhow::{anyhow, Context, Result};

#[derive(Parser, Debug)]
#[command(name = "nazar")]
#[command(author = "Furkan E. <f.ercevik21@gmail.com>")]
#[command(version = "0.1.0")]
#[command(about = "A simple packet sniffing and intrusion detection program")]
struct Args {
    /// Name of the interface to perform sniff packets on
    #[arg(short, long)]
    iface: Option<String>,

    /// Path to file containing the rule config
    #[arg(short, long, value_name = "FILE")]
    rules: PathBuf,

    /// Path to directory to output log files
    #[arg(short, long, value_name = "DIR")]
    outlog: Option<PathBuf>,

    /// Flag indicating if the IDS should dynamically update its rules
    #[arg(short, long)]
    dynamic: bool,
}

// TODO: add subcommands to do simple port scans

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
    if !nazar::validate_file_ext(&args.rules, "json") {
        return Err(anyhow!("rules file must be a .json file"));
    }
    let _rules_file = File::open(&args.rules).with_context(|| {
        format!(
            "No rules file of the name `{}` exists",
            &args.rules.display()
        )
    })?;
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
