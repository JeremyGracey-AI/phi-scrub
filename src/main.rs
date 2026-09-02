//! Command-line front end: reads text on stdin, writes redacted text (or JSON findings) to stdout.

use anyhow::Result;
use clap::Parser;
use phi_scrub::Scrubber;
use std::io::{self, Read, Write};

/// Redact PHI/PII from text on stdin.
#[derive(Parser)]
#[command(version, about)]
struct Cli {
    /// Print findings as JSON instead of redacted text.
    #[arg(long)]
    json: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;
    let scrubber = Scrubber::new();
    let mut out = io::stdout().lock();
    if cli.json {
        serde_json::to_writer_pretty(&mut out, &scrubber.detect(&input))?;
        writeln!(out)?;
    } else {
        out.write_all(scrubber.redact(&input).as_bytes())?;
    }
    Ok(())
}
