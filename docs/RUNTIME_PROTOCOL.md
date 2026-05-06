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
  "data": []
}
```

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
