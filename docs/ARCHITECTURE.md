# Tapestry Architecture

## Core pipeline

```text
Capture (HAR import or CDP record) -> Observations -> Analyzer -> ToolSpec -> Runtime -> CLI / MCP server
```

## Crates

### tapestry-core

Shared domain types with no I/O, used by every other crate:

- `ToolSpec`, `SiteInfo`, `ToolDefinition`
- `ResourceKind`, `SafetyClassification`, `SafetyInfo`
- `ConfidenceScores`, `Evidence`
- `GraphqlInfo`, `PathParameter`, `AuthRequirement`
- `IdempotencyInfo`, `PaginationInfo`, `RateLimitInfo`
- `Observation`, `RuntimeErrorResponse`
- redaction helpers: `is_secret_field_name`, `redact_sensitive_fields`

### tapestry-input

Capture and redaction: turns external traffic into normalized, redacted `Observation`s.

- `import_har` / `redact_har` (`lib.rs`) — parse a browser DevTools HAR export.
- `record` / `reauth` / `resolve_browser` (`cdp.rs`) — drive a real Chrome/Chromium/Edge
  process over the Chrome DevTools Protocol for live capture and credential refresh
  (`RecordOptions`, `CaptureSummary`, `CredentialHarvester`, `ReauthOptions`).

Both paths produce the same `Observation` type, so the analyzer never needs to know
which capture method was used.

### tapestry-analyzer

Turns a site's observations into a `ToolSpec`: clusters requests into endpoints,
infers input/response JSON schemas, classifies safety and resource kind, scores
confidence, and attaches evidence. No LLM step exists in the pipeline today — schema
and safety inference are purely structural/heuristic.

### tapestry-runtime

Executes tools using a low-token, four-function native interface (the same surface
the MCP server exposes):

- `search_tools(spec, query, limit)`
- `get_tool_schema(spec, tool_id)`
- `call_tool` / `call_tool_with_options(spec, tool_id, arguments, options)`
- `get_evidence(spec, tool_id)`

Also owns: approval storage and overlay (`load_approvals`, `apply_approvals`,
`tool_fingerprint`, `ApprovalRecord`), response-schema drift detection
(`response_field_compatibility`), and task-intent classification for ranking
(`classify_task_intent`).

### tapestry-cli

CLI frontend and MCP server over input, analyzer, and runtime. Layout:

```text
crates/tapestry-cli/src/
  main.rs              clap Cli/Command enum + main() dispatch only
  support.rs           cross-cutting infra shared by every command: site
                        storage paths, site metadata/tool-health tracking,
                        observation merge-on-import, credential/ToolSpec
                        loading, small date/format utilities
  mcp.rs                MCP stdio server (`tapestry serve`) — the four
                        meta-tools only; never exposes generated tools
                        individually
  tests.rs              the CLI test suite (191 tests live here and in
                        the other crates' own `mod tests`)
  commands/
    approve.rs          `tapestry approve`
    agent.rs            `tapestry agent-task` — the deterministic agent
                        loop (search-rank, plan arguments, execute, summarize)
    benchmark.rs         `tapestry benchmark` — benchmark_cases.json suite
    capture.rs           capture-summary formatting and the post-capture
                        "run generate next" nudge shared by import/record
    diagnose.rs          `tapestry diagnose`
    doctor.rs            `tapestry doctor`
    review.rs            `tapestry review`
    validate.rs          `tapestry validate`
```

`import`/`record`/`generate`/`redact`/`purge`/`tools`/`credentials`/`reauth`/`serve`/
`run` stay inline in `main.rs`'s dispatch `match` — each arm is a short, self-contained
block; only the larger single-purpose command logic (and everything it depends on)
was pulled into its own `commands/*.rs` module.

## Local registry

```text
.tapestry-dev/
  sites/
    <site>/
      observations.json
      toolspec.json
      approvals.json
      credentials.json
      meta.json
      browser-profile/
```

This is the actual on-disk layout (see `support.rs::sites_root`/`site_dir`).
`.tapestry-dev/` is repo-local and gitignored; it also holds the maintainer's private
browser-profile data and must never be committed (see the Hard Rules in
`docs/OPEN_SOURCE_READINESS.md` and `docs/SAFETY_SECURITY.md`).
