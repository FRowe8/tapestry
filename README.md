# Tapestry

Tapestry turns captured web app traffic into structured tools for AI agents.

## 30-Second Demo

From the repository root:

```bash
cargo run -p tapestry-cli -- import examples/fixtures/simple.har --site demo
cargo run -p tapestry-cli -- generate demo
cargo run -p tapestry-cli -- agent-task demo "List the most recent 5 items" --trace
```

Example output:

```text
Imported 4 observations for site 'demo'
Generated 3 tools for site 'demo'
[agent] search_tools query="List the most recent 5 items"
[agent] selected tool=list_items score=24
[agent] schema loaded
[agent] arguments={"limit":5}
[agent] call_tool success
Summary: 1 item(s) returned. One
```

For HAR-only demo and fixture sites, Tapestry replays captured responses first so the demo does not wait on a missing local server. Pass `--live` to `agent-task` or `run` when you intentionally want live HTTP execution.

## How It Works

HAR captures browser network traffic.
The analyzer filters noise and clusters API-like requests.
It infers schemas and writes a ToolSpec.
The native runtime searches tools, validates arguments, and executes or replays calls.
The agent harness uses `search_tools -> get_tool_schema -> call_tool`.

## Key Commands

```bash
tapestry import <har> --site <site>
tapestry generate <site>
tapestry tools search <site> "<query>"
tapestry approve <site> --list
tapestry approve <site> <tool_id>
tapestry run <site> <tool> --args '{"limit":5}'
tapestry agent-task <site> "<task>"
tapestry agent-task <site> "<task>" --live
tapestry review <site>
tapestry diagnose <site>
tapestry reauth <site>
tapestry serve --site <site>
```

Repeated `import`/`record` runs on the same site merge new observations into the existing ones (exact duplicates are skipped), so you can build coverage across several sessions. Pass `--replace` to start a site fresh.

When running from source, prefix commands with:

```bash
cargo run -p tapestry-cli --
```

## Approving Write Tools

Write, unknown-safety, and low-confidence tools are blocked until you approve them:

```bash
tapestry approve demo --list            # see what is pending and why
tapestry tools evidence demo <tool_id>  # inspect before approving
tapestry approve demo <tool_id>         # unblock it
```

Approvals live in `approvals.json` next to the ToolSpec and are pinned to the tool's request shape: re-running `generate` keeps approvals for unchanged tools and drops them when a tool's method, path, or input schema changes.

## Keeping Tools Alive

Captured sessions expire and internal APIs drift. Two mechanisms keep a site usable:

**Credential refresh.** When calls start failing with `auth_expired`, run:

```bash
tapestry reauth demo
```

A browser opens; log in as usual, perform one authenticated action, and press Enter. Tapestry harvests the fresh auth headers from first-party traffic and updates the site's stored credentials. Your keystrokes are never captured — only the resulting request headers.

**Tool health.** Every live execution is checked against the inferred response schema. Tools whose responses drift are marked `degraded` (and failing endpoints `broken`) in the site's `meta.json`; the state surfaces as warnings in `tools search`, `review`, and MCP `search_tools` results, with a prompt to re-capture. Nothing is auto-disabled — you decide when to regenerate.

## Connect an Agent (MCP)

`tapestry serve` exposes the native runtime as an MCP stdio server. Agents see only four meta-tools (`search_tools`, `get_tool_schema`, `call_tool`, `get_evidence`) no matter how many tools a site has.

Add to your MCP client config (e.g. `.mcp.json` for Claude Code):

```json
{
  "mcpServers": {
    "tapestry": {
      "command": "cargo",
      "args": ["run", "-q", "-p", "tapestry-cli", "--", "serve", "--site", "demo"]
    }
  }
}
```

With an installed binary, use `"command": "tapestry", "args": ["serve", "--site", "demo"]`. Omit `--site` to let the agent pass a `site` argument per call.

## Useful Next Reads

- [Demo walkthrough](examples/demo.md)
- [Capture guide](docs/CAPTURE_GUIDE.md)
- [Limitations](docs/LIMITATIONS.md)
- [Launch readiness roadmap](docs/ROADMAP.md)
