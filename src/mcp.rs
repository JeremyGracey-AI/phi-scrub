//! MCP server on stdio: `detect`, `redact`, and `restore` as tools.
//!
//! stdout carries protocol frames only. The server keeps no state: `redact`
//! returns the token map to the client, and `restore` takes it back.

use anyhow::Result;
use phi_scrub::{restore, Category, Scrubber, TokenMap};
use rmcp::handler::server::wrapper::Parameters;
use rmcp::schemars::{self, JsonSchema};
use rmcp::{tool, tool_handler, tool_router, Json, ServerHandler, ServiceExt};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Arguments for `detect` and `redact`.
#[derive(Deserialize, JsonSchema)]
struct TextArgs {
    /// Text to scan.
    text: String,
}

/// One finding, by byte offset. The matched text is not echoed back.
#[derive(Serialize, JsonSchema)]
struct FindingOut {
    /// Byte offset where the match starts.
    start: usize,
    /// Byte offset where the match ends (exclusive).
    end: usize,
    /// Category name, e.g. `Ssn` or `Npi`.
    #[schemars(with = "String")]
    category: Category,
}

/// Result of `detect`.
#[derive(Serialize, JsonSchema)]
struct DetectResult {
    /// Findings sorted by start offset. They never overlap.
    findings: Vec<FindingOut>,
}

/// Result of `redact`.
#[derive(Serialize, JsonSchema)]
struct RedactResult {
    /// Text with each finding replaced by a numbered token such as `[SSN_1]`.
    text: String,
    /// Token to original value. This holds PHI.
    token_map: BTreeMap<String, String>,
}

/// Arguments for `restore`.
#[derive(Deserialize, JsonSchema)]
struct RestoreArgs {
    /// Text that contains numbered tokens.
    text: String,
    /// The `token_map` that `redact` returned.
    token_map: BTreeMap<String, String>,
}

/// Result of `restore`.
#[derive(Serialize, JsonSchema)]
struct RestoreResult {
    /// Text with known tokens replaced by their original values.
    text: String,
}

/// Stateless server: each call answers from its arguments alone.
struct PhiScrub;

#[tool_router]
impl PhiScrub {
    #[tool(
        name = "detect",
        description = "Find PHI/PII in text. Returns byte offsets and categories, never the matched text."
    )]
    fn detect(&self, Parameters(TextArgs { text }): Parameters<TextArgs>) -> Json<DetectResult> {
        let findings = Scrubber::new()
            .detect(&text)
            .into_iter()
            .map(|f| FindingOut {
                start: f.start,
                end: f.end,
                category: f.category,
            })
            .collect();
        Json(DetectResult { findings })
    }

    #[tool(
        name = "redact",
        description = "Replace PHI/PII with numbered tokens such as [SSN_1]. Returns the redacted text and a token_map for restore. The token_map holds the original values."
    )]
    fn redact(&self, Parameters(TextArgs { text }): Parameters<TextArgs>) -> Json<RedactResult> {
        let redaction = Scrubber::new().redact_reversible(&text);
        let token_map = redaction
            .map
            .iter()
            .map(|(token, value)| (token.to_owned(), value.to_owned()))
            .collect();
        Json(RedactResult {
            text: redaction.text,
            token_map,
        })
    }

    #[tool(
        name = "restore",
        description = "Put original values back into text using a token_map from redact. Tokens the map does not know are left alone."
    )]
    fn restore(
        &self,
        Parameters(RestoreArgs { text, token_map }): Parameters<RestoreArgs>,
    ) -> Json<RestoreResult> {
        let map: TokenMap = token_map.into_iter().collect();
        Json(RestoreResult {
            text: restore(&text, &map),
        })
    }
}

#[tool_handler(
    name = "phi-scrub",
    instructions = "PHI/PII redaction. redact returns a token_map that holds the original values: keep it out of anything sent to a remote model, and pass it to restore to undo the redaction."
)]
impl ServerHandler for PhiScrub {}

/// Serve the tools on stdio until the client disconnects.
pub async fn serve() -> Result<()> {
    let service = PhiScrub.serve(rmcp::transport::stdio()).await?;
    service.waiting().await?;
    Ok(())
}
