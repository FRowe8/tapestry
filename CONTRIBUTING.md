# Contributing to Tapestry

Tapestry turns captured web app traffic into structured, safety-gated tools for AI agents. Before changing behavior, read [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [docs/SAFETY_SECURITY.md](docs/SAFETY_SECURITY.md), and [docs/OPEN_SOURCE_READINESS.md](docs/OPEN_SOURCE_READINESS.md).

## Hard rules

1. HARs from real browser sessions are secrets. Never commit one, never paste one into an issue, and never copy one out of `.tapestry-dev/`.
2. Only synthetic or verified-clean fixtures belong in `examples/fixtures/`.
3. Do not weaken redaction, approval gates, or the four-meta-tool MCP design to make a test pass.
4. Do not add an MCP mode that exposes generated tools individually. `search_tools`, `get_tool_schema`, `call_tool`, and `get_evidence` are the product surface.
5. Treat `.tapestry-dev/` as local-only storage. It may contain browser profiles and credential artifacts.

## Development setup

Tapestry pins the Rust toolchain in `rust-toolchain.toml`.

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

Run all three before opening a pull request.

## Project layout

- `crates/tapestry-core`: shared types.
- `crates/tapestry-input`: HAR import, CDP capture, redaction.
- `crates/tapestry-analyzer`: clustering, schema inference, tool generation.
- `crates/tapestry-runtime`: search, safety gates, live execution, drift handling.
- `crates/tapestry-cli`: CLI commands, MCP stdio server, benchmark/reporting glue.

## Pull requests

- Keep changes scoped. Separate mechanical refactors from behavior changes when possible.
- Add or update tests for any user-visible behavior change.
- Preserve existing safety defaults unless the change is explicitly about tightening them.
- Update docs when command behavior, limitations, or setup steps change.

## Reporting capture issues

Do not attach real HARs or raw credentialed traces to issues.

Preferred reproductions:

- a synthetic fixture added under `examples/fixtures/`
- a minimized `tapestry redact` output with sensitive values replaced by obvious sentinels
- a description of the site shape plus `tapestry doctor` output
