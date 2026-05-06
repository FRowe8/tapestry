# Codex Prompt: Start Here

You are working in the Tapestry starter repository.

Tapestry turns captured web app traffic into structured, low-token tools for AI agents.

Your first objective is the v0.0 vertical slice:

```text
HAR file -> endpoint clusters -> ToolSpec -> native runtime -> one agent task succeeds
```

Read these files before coding:

1. `docs/PRD.md`
2. `docs/ANALYZER.md`
3. `docs/RUNTIME_PROTOCOL.md`
4. `docs/SAFETY_SECURITY.md`
5. `docs/VERTICAL_SLICE.md`

Do not implement MCP, live proxy recording, OAuth automation, JS crawling, or team sharing.

Focus on:

- HAR import
- request normalization
- endpoint clustering
- schema inference
- ToolSpec JSON
- native runtime methods
- CLI commands
- detailed instrumentation

Use tests and fixtures wherever possible.
