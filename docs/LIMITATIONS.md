# Limitations

Tapestry is currently a HAR-first vertical slice.

- Requires real API traffic. Static pages and homepage-only captures do not produce useful tools.
- HAR quality matters. Missing response bodies lead to weak response schemas and missing examples.
- GraphQL batching is supported, but incomplete HAR responses can still prevent operation-specific examples.
- Auth flows are not automated yet. Capture authenticated API traffic after login.
- No live proxy recording yet. Import HAR files exported from browser DevTools.
- No MCP server yet. The current runtime is native CLI/library behavior.
- No OAuth automation, JS crawling, browser automation, team sharing, or LLM-based analyzer.
- Write tools are blocked by default unless explicitly approved in the ToolSpec/runtime path.
