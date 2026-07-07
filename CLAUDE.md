# CLAUDE.md — agent onboarding for this repository

Tapestry turns captured web app traffic (HAR import or live CDP recording) into
structured, safety-gated tools that AI agents consume through four MCP
meta-tools: `search_tools`, `get_tool_schema`, `call_tool`, `get_evidence`.

## Read these before changing anything

1. `docs/OPEN_SOURCE_READINESS.md` — the current execution plan and its
   **Hard rules** section, which is binding for all work in this repo.
2. `docs/VISION.md` — where the project is going and why; use it to judge
   whether a proposed change fits the direction.
3. `docs/ARCHITECTURE.md` — crate layout and data flow.
4. `docs/SAFETY_SECURITY.md` — the security model. Changes that touch
   redaction, credentials, or approvals must keep every guarantee in it true.

## The rules that most often bite agents

- **Real browser captures (HARs, CDP recordings) are secrets.** Never commit
  one, never copy one out of `.tapestry-dev/`, never paste their contents
  anywhere. Only synthetic or verified-clean fixtures belong in
  `examples/fixtures/`.
- **`cargo test --workspace` must pass before every commit** (~191 tests,
  seconds after first build). Also keep `cargo clippy --workspace -- -D
  warnings` and `cargo fmt --all -- --check` clean — CI enforces all three on
  Linux and Windows, and the CI toolchain may be newer than local (a lint that
  passes locally can still fail CI).
- **Never weaken redaction, approval gates, or safety classification** to make
  a test or demo pass.
- **The four-meta-tool MCP design is the product.** Do not expose generated
  tools as individual MCP tools.
- `.tapestry-dev/` is local site storage (contains live session cookies and
  credentials). Never commit it or print its credential files.

## Layout and commands

- Workspace crates: `tapestry-core` (types + shared redaction),
  `tapestry-input` (HAR/CDP capture), `tapestry-analyzer` (clustering + schema
  inference), `tapestry-runtime` (execution + safety + the four meta-tool
  implementations), `tapestry-cli` (commands in `src/commands/`, MCP stdio
  server in `src/mcp.rs`, shared CLI infra in `src/support.rs`, tests in
  `src/tests.rs`).
- Run the CLI from source: `cargo run -q -p tapestry-cli -- <command>`.
- Quick smoke test: `cargo run -q -p tapestry-cli -- import
  examples/fixtures/dummyjson-api.har --site demo --generate` then
  `agent-task demo "search for phones"`.
- The MCP server (`tapestry serve`) speaks newline-delimited JSON-RPC on
  stdio; you can drive it in tests by piping an `initialize` line followed by
  `tools/call` lines.

## Current state (update this section when it changes)

- All of Phases 0-2 of the readiness plan are complete; CI is green.
- Next up: Phase 3 (capture parity — needs maintainer) and Phases 4-7
  (benchmark suite, real-agent measurement, community scaffolding, launch).
- The pre-cleanup repo `FRowe8/tapestry-archive-prehistory` contains personal
  data in history and is pending deletion by the maintainer. Never base work
  on it.
