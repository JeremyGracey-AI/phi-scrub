//! Command-line front end: reads text on stdin, writes redacted text (or JSON findings) to stdout.
//!
//! Built with the `mcp` feature, `phi-scrub mcp` runs an MCP server on stdio instead.

use anyhow::Result;
use clap::Parser;
use phi_scrub::Scrubber;
use std::io::{self, Read, Write};

#[cfg(feature = "mcp")]
mod mcp;

/// Redact PHI/PII from text on stdin.
#[derive(Parser)]
#[command(version, about)]
struct Cli {
    /// Print findings as JSON instead of redacted text.
    #[arg(long)]
    json: bool,

    #[cfg(feature = "mcp")]
    #[command(subcommand)]
    command: Option<Command>,
}

/// Modes other than the default stdin filter.
#[cfg(feature = "mcp")]
#[derive(clap::Subcommand)]
enum Command {
    /// Run an MCP server on stdio with detect, redact, and restore tools.
    Mcp,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    #[cfg(feature = "mcp")]
    if let Some(Command::Mcp) = cli.command {
        return tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(mcp::serve());
    }
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
