# Safety and Security Requirements

## HAR sensitivity

HAR files may contain:

- session cookies
- bearer tokens
- CSRF tokens
- personal data
- request and response bodies

## v0.1 requirements

- Warn before import.
- Redact secrets from logs.
- Do not persist raw HAR by default.
- Store extracted observations separately from credentials.
- Credentials and browser profiles readable only by the current user: mode 0600/0700 on Unix; on Windows an explicit ACL (inheritance removed, current user granted) via `icacls`, with a warning if restriction fails.
- Provide secret cleanup commands.

Commands:

```bash
tapestry redact session.har
tapestry purge acme --secrets   # removes credentials and the browser profile
```

## Redaction coverage

Secrets are stripped before any observation is persisted, on both the HAR and CDP capture paths:

- request/response headers (Authorization, Cookie, Set-Cookie, CSRF and token headers)
- JSON body fields (token, password, secret, api_key, and similar)
- query string parameters (`?access_token=…`, `?sig=…`, `?api_key=…`) in both the parsed query map and the stored URL

This is enforced by a test suite built on `examples/fixtures/redaction.har`, a capture seeded with sentinel secrets in every channel; tests assert no sentinel survives into observations, ToolSpecs, review/diagnose reports, or agent trace output. The one deliberate exception: `credentials from-har` and `reauth` extract secrets *into* the credentials store, which is the protected file above.

Live responses get the same treatment: `call_tool` masks secret-named JSON fields (and JSON error-body snippets) before returning data, so a live payload and a stored example can never disagree about what is sensitive. An agent's context window is no safer a place for a session token than a JSON file on disk. This is field-name-based masking, not value detection — a secret stored under an innocuous field name will pass through.

## Safety classification

Tools are classified as:

- `read`
- `write`
- `unknown`

Rules:

- GET, HEAD, OPTIONS default toward read.
- POST, PUT, PATCH, DELETE default toward write.
- GraphQL query defaults toward read.
- GraphQL mutation defaults toward write.
- Unknown is treated as write.
- LLMs cannot upgrade safety classification.

## Execution policy

```text
read + confidence >= threshold -> executable
read + low confidence -> approval required
write -> blocked unless approved
unknown -> blocked unless approved
```

## Idempotency

Writes are non-retryable by default unless explicitly marked idempotent.

```json
{
  "idempotency": {
    "safe_to_retry": false,
    "confidence": 0.85
  }
}
```

## Auth lifecycle

States:

- valid
- expiring
- expired
- unknown

Detection:

- 401/403
- redirect to login
- response body signals such as unauthorized
- known token expiry metadata

v0.1 remediation:

- return structured `auth_expired`
- ask user to re-import HAR or inject a new token
