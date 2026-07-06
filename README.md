# Tapestry

Tapestry turns captured web app traffic into structured, safety-gated tools for AI agents. Instead of stuffing dozens of API schemas into an agent's context, Tapestry exposes four MCP meta-tools (`search_tools`, `get_tool_schema`, `call_tool`, `get_evidence`) that let an agent find and call the right tool on demand — no matter how many endpoints a site has.

## Quickstart (10 minutes, no compiling required)

This walks through the bundled `dummyjson-api.har` fixture, so you don't need a live site or a browser to try it.

### 1. Install

Download the latest binary for your OS from the [Releases page](https://github.com/FRowe8/tapestry/releases) and put `tapestry` (`tapestry.exe` on Windows) on your `PATH`.

No binary for your platform yet, or you'd rather build from git? See [Building from source](#building-from-source) below — `cargo install` is the fallback path, not the primary one.

Sanity-check the install:

```bash
tapestry doctor
```

### 2. Generate tools from a capture

Use the bundled fixture (11 requests, no network access needed):

```bash
tapestry import examples/fixtures/dummyjson-api.har --site demo --generate
```

`--generate` chains straight into tool generation, so this one command leaves you with a ready ToolSpec (8 tools). Prefer to capture your own site instead? See [Capturing your own site](#capturing-your-own-site) below.

### 3. Review what was generated

```bash
tapestry review demo
```

This grades each tool (schema completeness, examples, confidence) so you can see what an agent will actually be able to call before you wire anything up.

### 4. Serve it over MCP

```bash
tapestry serve --site demo
```

This starts an MCP stdio server. Leave it as a command an MCP client launches — don't run it standalone and expect interactive output.

### 5. Connect an agent

Add a `.mcp.json` in your project (e.g. for Claude Code):

```json
{
  "mcpServers": {
    "tapestry": {
      "command": "tapestry",
      "args": ["serve", "--site", "demo"]
    }
  }
}
```

Then ask your agent something like *"List the first 5 users"* or *"Find a product called iPhone 9"*. It will call `search_tools`, load the matching tool's schema with `get_tool_schema`, and execute it with `call_tool` — never seeing the other 7 tools' schemas until it needs them.

Want to see this loop without wiring up a full agent first? Tapestry ships a deterministic harness that exercises the same four calls:

```bash
tapestry agent-task demo "List the first 5 users" --trace
```

That's the whole loop: capture -> generate -> review -> serve -> agent call.

## Capturing your own site

Two ways to capture traffic:

```bash
tapestry record https://your-app.example.com --site myapp   # live CDP recording
tapestry import path/to/exported.har --site myapp            # DevTools HAR export
```

Both accept `--generate` to chain straight into tool generation, and both merge repeated captures into the same site's observations (pass `--replace` to start fresh instead).

**Good sites to try this on first:** [dummyjson.com](https://dummyjson.com) (a free public JSON API, no auth) or any internal/self-hosted app you control. **Out of scope:** consumer sites with bot defense (Amazon, most large retail/travel sites) — Tapestry does not do anti-bot evasion, and captures against those sites will be low-signal or blocked outright. See [docs/LIMITATIONS.md](docs/LIMITATIONS.md) for the full list of what doesn't work yet.

For what makes a capture good (response bodies, login state, GraphQL quirks), see [docs/CAPTURE_GUIDE.md](docs/CAPTURE_GUIDE.md).

## What Tapestry is for

Tapestry is built for internal tools, self-hosted apps, and B2B products you or your organization control — places where you can capture your own authenticated traffic and decide what an agent is allowed to touch. It is explicitly **not** for bypassing bot defenses, automating around a site's Terms of Service, or defeating CAPTCHAs.

Safety is the differentiator, not an afterthought: every generated tool is classified by safety (read / write / unknown) and confidence; write and low-confidence tools are blocked from execution until you explicitly `tapestry approve` them; and every live response is checked against its inferred schema so drifting APIs get flagged (`degraded`/`broken`) instead of silently returning garbage to an agent.

## Keeping tools alive

Captured sessions expire and internal APIs drift. Two mechanisms handle this:

- **Credential refresh** — when calls fail with `auth_expired`, run `tapestry reauth <site>`. A browser opens, you log in and perform one authenticated action, and Tapestry harvests the fresh auth headers (your keystrokes are never captured).
- **Tool health** — every live execution is checked against the inferred response schema. Drifted tools are marked `degraded`/`broken` in `tools search`, `review`, and MCP `search_tools` results. Nothing is auto-disabled; regenerate when you're ready.

## Approving write tools

```bash
tapestry approve demo --list            # see what is pending and why
tapestry tools evidence demo <tool_id>   # inspect before approving
tapestry approve demo <tool_id>          # unblock it
```

Approvals are pinned to a tool's request shape: re-running `generate` keeps approvals for unchanged tools and drops them when a tool's method, path, or input schema changes.

## Reference

- [Command reference and demo walkthrough](examples/demo.md)
- [Capture guide](docs/CAPTURE_GUIDE.md) — what makes a capture good, live recording vs. HAR export
- [Architecture](docs/ARCHITECTURE.md) — crate layout for contributors
- [Limitations](docs/LIMITATIONS.md) — what doesn't work yet, and why
- [Safety & security model](docs/SAFETY_SECURITY.md)
- [Launch readiness roadmap](docs/ROADMAP.md)

## Building from source

Requires a recent stable Rust toolchain.

```bash
git clone https://github.com/FRowe8/tapestry.git
cd tapestry
cargo install --path crates/tapestry-cli
```

Or run without installing, prefixing every command with `cargo run -p tapestry-cli --`:

```bash
cargo run -p tapestry-cli -- import examples/fixtures/dummyjson-api.har --site demo --generate
```

To build and test the workspace itself: `cargo test --workspace`, `cargo clippy --workspace -- -D warnings`, `cargo fmt --all -- --check` (all three run in CI on every PR).
