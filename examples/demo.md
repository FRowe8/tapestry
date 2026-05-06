# Demo Walkthrough

This walkthrough uses `examples/fixtures/simple.har` and runs entirely from local fixture data.

## 1. Import HAR

```bash
cargo run -p tapestry-cli -- import examples/fixtures/simple.har --site demo
```

Output:

```text
Imported 4 observations for site 'demo'
```

## 2. Generate Tools

```bash
cargo run -p tapestry-cli -- generate demo
```

Output:

```text
Generated 3 tools for site 'demo'
```

## 3. Inspect Tools

```bash
cargo run -p tapestry-cli -- tools search demo "list items" --limit 3
```

Output:

```json
[
  {
    "name": "list_items",
    "summary": "Observed GET endpoint /api/items",
    "safety": "read",
    "confidence": 0.7,
    "score": 24
  }
]
```

## 4. Run Agent Task

```bash
cargo run -p tapestry-cli -- agent-task demo "List the most recent 5 items" --trace
```

Output:

```text
[agent] search_tools query="List the most recent 5 items"
[agent] selected tool=list_items score=24
[agent] schema loaded
[agent] arguments={"limit":5}
[agent] call_tool success
Summary: 1 item(s) returned. One
```

Because `demo` is generated from a HAR fixture, the runtime replays the captured response before trying live HTTP. Use `--live` only if a matching live service is running and you want to force a network call.

## 5. Review Tool Quality

```bash
cargo run -p tapestry-cli -- review demo
```

Output excerpt:

```text
Site: demo
Tools: 3 total
Safety: 2 read, 1 write, 0 unknown
Missing response schema: 0
Missing examples: 0

Tools:
- list_items  B
- get_item_by_id  B
- create_items  C
```

## 6. Diagnose Capture Issues

```bash
cargo run -p tapestry-cli -- diagnose demo
```

Output excerpt:

```text
Observations: 4
Candidate API observations: 4
Observations with response bodies: 4
JSON responses: 4
Tools missing examples: 0
Tools with empty response schemas: 0
```

If `diagnose` reports missing response bodies, re-capture the HAR using the settings in [docs/CAPTURE_GUIDE.md](../docs/CAPTURE_GUIDE.md).
