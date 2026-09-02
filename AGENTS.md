# AGENTS.md — phi-scrub

Instructions for any coding agent (Codex, Claude Code, Cursor) working in this repo.

## Project
- Rust library crate `phi-scrub` (lib target `phi_scrub`) with a thin `phi-scrub` CLI binary.
- Purpose: detect and redact PHI/PII in free text. Python bindings (PyO3/maturin) come in M1 — do NOT add them yet.

## Repo location (do not change)
`/Users/jghome/src/github.com/JeremyGracey-AI/phi-scrub` — this is the crate root (the dir containing `Cargo.toml`).
If you find a nested `phi-scrub/phi-scrub/`, flatten it: move the inner crate's contents up one level and delete the empty inner dir.

## Rules
1. Never use `unwrap()`/`expect()` outside `static` pattern init and tests.
2. Public items must have doc comments (`#![deny(missing_docs)]` is on).
3. Library errors use `thiserror`; the binary uses `anyhow`.
4. No new dependencies without a one-line justification in the PR/commit message.
5. Preserve the public API in `src/lib.rs` (`Scrubber`, `Finding`, `Category`, `Error`). Additive changes only.
6. Do not create files outside this crate root. Do not touch `~/GitHub`, `~/Desktop`, or the home root.

## Definition of done for any change
All four must pass, in order:
```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo doc --no-deps
```
If any fail, fix them before reporting done. Paste the final output of `cargo test` in your summary.

## Files
- `Cargo.toml` — manifest
- `src/lib.rs` — engine (public API lives here)
- `src/main.rs` — CLI (stdin → stdout)
- `tests/integration.rs` — public-API tests
- `benches/redact.rs` — criterion benchmark
- `.github/workflows/ci.yml` — fmt/clippy/test on push
