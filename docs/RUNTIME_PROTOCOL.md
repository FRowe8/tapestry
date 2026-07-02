# Native Runtime Protocol

The native runtime keeps agent context small by exposing a compact interface regardless of the number of generated tools.

## Methods

### search_tools

Request:

```json
{
  "site": "acme",
  "query": "list shipped orders",
  "limit": 5
}
```

Response:

```json
{
  "tools": [
    {
      "id": "tool_abc123",
      "name": "listOrders",
      "summary": "List orders with optional filters",
      "safety": "read",
      "confidence": 0.94
    }
  ]
}
```

### get_tool_schema

Request:

```json
{
  "site": "acme",
  "tool_id": "tool_abc123"
}
```

Response: full tool schema from ToolSpec.

### call_tool

Request:

```json
{
  "site": "acme",
  "tool_id": "tool_abc123",
  "arguments": {
    "status": "shipped"
  }
}
```

Response:

```json
{
  "status": "success",
  "data": [],
  "execution": { "mode": "live" },
  "conformance": {
    "field_compatibility": 0.83,
    "missing_fields": ["owner"]
  }
}
```

`execution.mode` is `live` or `har_replay`. `conformance` is present on live calls when the inferred schema has fields to compare; `field_compatibility` below 0.8 marks the tool `degraded` in the site's health state (see below).

### get_evidence

Request:

```json
{
  "site": "acme",
  "tool_id": "tool_abc123"
}
```

Response:

```json
{
  "evidence": [
    {
      "source": "har",
      "type": "observed_requests",
      "count": 18,
      "confidence": 0.96
    }
  ]
}
```

## Structured errors

Runtime errors must be structured and agent-readable.

```json
{
  "status": "error",
  "error_type": "auth_expired",
  "retryable": false,
  "message": "Authentication expired for site 'acme'",
  "action": "reauth_required"
}
```

Error types:

- `auth_expired`
- `rate_limited`
- `schema_mismatch`
- `network_error`
- `endpoint_error`
- `dependency_failed`
- `approval_required`
- `tool_not_found`
- `site_not_specified` (MCP transport only)
- `site_not_ready` (MCP transport only)

## Approvals

Approvals are stored per site in `approvals.json`, keyed by stable tool id:

```json
{
  "tool_7f6f50a02b78": {
    "fingerprint": "814ebecc248a55ea",
    "approved_at": "2026-07-01T20:31:54Z",
    "note": "reviewed evidence"
  }
}
```

The fingerprint hashes the tool's request shape (method, path, input schema). At load time the runtime overlays approvals onto the ToolSpec; an approval whose fingerprint no longer matches is stale and is not applied, and `generate` prunes stale entries. This lets `generate` be re-run freely without either losing valid approvals or silently carrying an approval over to a changed request.

Execution policy enforced by `call_tool`:

```text
read + confidence >= threshold -> executable
read + low confidence -> blocked unless approved
write -> blocked unless approved
unknown -> blocked unless approved
```

## Tool health

Live executions update per-tool health in the site's `meta.json`:

- `healthy` — 2xx and field compatibility >= 0.8
- `degraded` — 2xx but the response drifted from the inferred schema
- `broken` — endpoint errors (non-auth, non-rate-limit HTTP failures)
- `unreachable` — network failures

Auth failures (`auth_expired`) update site-level auth state instead of tool health: stale credentials say nothing about endpoint drift. Non-healthy states are attached as `health:*` warnings when the ToolSpec loads, so `tools search`, `review`, and MCP `search_tools` surface them without extra plumbing. Health never auto-disables a tool.

## MCP transport

`tapestry serve` exposes these four methods as MCP tools over stdio (newline-delimited JSON-RPC 2.0). Generated tools are never exposed individually; agents always discover them through `search_tools`, which keeps agent context constant regardless of tool count.

- `--site <site>` binds the server to one site; otherwise each call takes a required `site` argument.
- `--offline` / `--live` select HAR replay or live execution, matching `run`.
- Structured runtime errors are returned verbatim as tool result content with `isError: true`, so agents can relay the remediation (`approval_required` -> `tapestry approve`, `auth_expired` -> refresh credentials) to the user instead of retrying.
