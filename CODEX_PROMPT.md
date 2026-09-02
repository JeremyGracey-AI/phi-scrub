# Paste this into Codex

Read AGENTS.md first and follow it exactly.

Task: apply the M0 scaffold for phi-scrub.

1. Confirm the crate root is `/Users/jghome/src/github.com/JeremyGracey-AI/phi-scrub` (contains Cargo.toml). If there is a nested `phi-scrub/phi-scrub/`, flatten it so the inner crate's files sit at the outer path, then remove the empty dir.
2. Overwrite/create these files with the contents provided in the handoff zip, byte-for-byte: `Cargo.toml`, `src/lib.rs`, `src/main.rs`, `tests/integration.rs`, `benches/redact.rs`, `.github/workflows/ci.yml`, `.gitignore`, `rust-toolchain.toml`, `README.md`, `AGENTS.md`.
3. Run, in order, and fix anything that fails:
   cargo fmt
   cargo clippy --all-targets -- -D warnings
   cargo test
   cargo doc --no-deps
4. Smoke test: `echo "SSN 123-45-6789" | cargo run -q` must print `SSN [SSN]`.
5. `git init` if needed, then commit: `chore: M0 scaffold — lib + cli + tests + ci`.
6. Report: the `cargo test` summary line and the final `tree -L 2 -I target` output. Do not add features, dependencies, or Python bindings.
