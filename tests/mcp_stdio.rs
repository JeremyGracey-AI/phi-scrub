#![cfg(feature = "mcp")]
//! Protocol test: drive `phi-scrub mcp` over stdio with newline-delimited JSON-RPC.

use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

/// Minimal MCP client for one `phi-scrub mcp` child process.
struct Client {
    child: Child,
    stdin: ChildStdin,
    lines: Receiver<String>,
    next_id: u64,
    /// `serverInfo` from the initialize response.
    server_info: Value,
}

impl Client {
    /// Spawn the server and complete the MCP handshake.
    fn start() -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_phi-scrub"))
            .arg("mcp")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn phi-scrub mcp");
        let stdin = child.stdin.take().expect("child stdin");
        let stdout = child.stdout.take().expect("child stdout");
        let (tx, lines) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        let mut client = Self {
            child,
            stdin,
            lines,
            next_id: 0,
            server_info: Value::Null,
        };
        let initialized = client.request(
            "initialize",
            json!({
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": { "name": "phi-scrub-test", "version": "0" }
            }),
        );
        client.server_info = initialized["serverInfo"].clone();
        client.send(&json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }));
        client
    }

    fn send(&mut self, message: &Value) {
        writeln!(self.stdin, "{message}").expect("write to server");
        self.stdin.flush().expect("flush to server");
    }

    /// Send a request and return its `result`. Every stdout line must be JSON.
    fn request(&mut self, method: &str, params: Value) -> Value {
        self.next_id += 1;
        let id = self.next_id;
        self.send(&json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }));
        loop {
            let line = self
                .lines
                .recv_timeout(Duration::from_secs(10))
                .expect("server replies within 10 seconds");
            let message: Value = serde_json::from_str(&line).expect("stdout carries JSON only");
            if message["id"] == json!(id) {
                assert!(message.get("error").is_none(), "{method} failed: {message}");
                return message["result"].clone();
            }
        }
    }

    /// Call a tool and return its structured result.
    fn call(&mut self, tool: &str, arguments: Value) -> Value {
        let result = self.request(
            "tools/call",
            json!({ "name": tool, "arguments": arguments }),
        );
        assert_ne!(
            result["isError"],
            json!(true),
            "{tool} returned an error: {result}"
        );
        result["structuredContent"].clone()
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn initialize_reports_server_name_and_version() {
    let client = Client::start();
    assert_eq!(client.server_info["name"], "phi-scrub");
    assert_eq!(client.server_info["version"], env!("CARGO_PKG_VERSION"));
}

#[test]
fn tools_list_names_three_tools() {
    let mut client = Client::start();
    let result = client.request("tools/list", json!({}));
    let mut names: Vec<&str> = result["tools"]
        .as_array()
        .expect("tools array")
        .iter()
        .map(|tool| tool["name"].as_str().expect("tool name"))
        .collect();
    names.sort_unstable();
    assert_eq!(names, ["detect", "redact", "restore"]);
}

#[test]
fn redact_then_restore_round_trips() {
    let mut client = Client::start();
    let input = "SSN 123-45-6789";
    let redacted = client.call("redact", json!({ "text": input }));
    assert_eq!(redacted["text"], "SSN [SSN_1]");
    assert_eq!(redacted["token_map"], json!({ "[SSN_1]": "123-45-6789" }));
    let restored = client.call(
        "restore",
        json!({ "text": redacted["text"], "token_map": redacted["token_map"] }),
    );
    assert_eq!(restored["text"], input);
}

#[test]
fn redact_with_no_phi_returns_empty_map() {
    let mut client = Client::start();
    for input in ["", "no phi here"] {
        let redacted = client.call("redact", json!({ "text": input }));
        assert_eq!(redacted["text"], input);
        assert_eq!(redacted["token_map"], json!({}));
    }
}

#[test]
fn detect_reports_offsets_and_category() {
    let mut client = Client::start();
    let result = client.call("detect", json!({ "text": "NPI 1234567893" }));
    assert_eq!(
        result["findings"],
        json!([{ "start": 4, "end": 14, "category": "Npi" }])
    );
}
