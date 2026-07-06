# Limitations

Tapestry is currently a HAR-first vertical slice.

- Requires real API traffic. Static pages and homepage-only captures do not produce useful tools.
- HAR quality matters. Missing response bodies lead to weak response schemas and missing examples.
- GraphQL batching is supported, but incomplete HAR responses can still prevent operation-specific examples.
- Auth flows are not automated. Capture authenticated API traffic after login; when sessions expire, `tapestry reauth` reopens a browser for a manual login and harvests the fresh headers. OAuth token refresh without a browser is not supported.
- No live proxy recording yet. Import HAR files exported from browser DevTools, or use `tapestry record` (CDP).
- **Streamed/chunked responses are not captured by `tapestry record`.** The CDP recorder reads response bodies via `Network.getResponseBody`, which cannot return a body that is still being streamed or that was delivered in chunked transfer-encoding (notably Google's `batchexecute` protocol used by many Google Workspace and Firebase-backed apps). Affected requests are still recorded — method, URL, headers, and request body are captured — but the response body is empty and the observation carries a `cdp_response_body_unavailable` warning. This lowers response-schema confidence and can prevent an accurate example response for that endpoint. Workaround: export a HAR from browser DevTools for those specific flows (`tapestry import`), which captures bodies through the browser's own network stack instead of live CDP interception. Candidate future fix: switch to `Network.streamResourceContent`, which is designed for in-flight/streamed bodies.
- No OAuth automation, JS crawling, browser automation, team sharing, or LLM-based analyzer.
- Write, unknown-safety, and low-confidence tools are blocked until approved with `tapestry approve`.
- The MCP server (`tapestry serve`) is stdio-only; there is no HTTP transport.
