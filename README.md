# phi-scrub

Rust PHI/PII redaction engine for behavioral-health text. Library + CLI; Python bindings (PyO3) planned.

```bash
echo "SSN 123-45-6789, call 808-555-0100" | cargo run -q
# SSN [SSN], call [PHONE]
echo "mail me@x.org" | cargo run -q -- --json
```

```rust
use phi_scrub::Scrubber;
let out = Scrubber::new().redact("SSN 123-45-6789");
```

Dev: `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test`

License: MIT OR Apache-2.0
