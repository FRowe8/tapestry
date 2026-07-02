# Limitations

Tapestry is currently a HAR-first vertical slice.

- Requires real API traffic. Static pages and homepage-only captures do not produce useful tools.
- HAR quality matters. Missing response bodies lead to weak response schemas and missing examples.
- GraphQL batching is supported, but incomplete HAR responses can still prevent operation-specific examples.
- Auth flows are not automated. Capture authenticated API traffic after login; when sessions expire, `tapestry reauth` reopens a browser for a manual login and harvests the fresh headers. OAuth token refresh without a browser is not supported.
- No live proxy recording yet. Import HAR files exported from browser DevTools, or use `tapestry record` (CDP).
- No OAuth automation, JS crawling, browser automation, team sharing, or LLM-based analyzer.
- Write, unknown-safety, and low-confidence tools are blocked until approved with `tapestry approve`.
- The MCP server (`tapestry serve`) is stdio-only; there is no HTTP transport.
