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
tapestry run <site> <tool> --args '{"limit":5}'
tapestry agent-task <site> "<task>"
tapestry agent-task <site> "<task>" --live
tapestry review <site>
tapestry diagnose <site>
```

When running from source, prefix commands with:

```bash
cargo run -p tapestry-cli --
```

## Useful Next Reads

- [Demo walkthrough](examples/demo.md)
- [Capture guide](docs/CAPTURE_GUIDE.md)
- [Limitations](docs/LIMITATIONS.md)
