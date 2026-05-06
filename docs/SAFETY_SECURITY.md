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
- Credentials stored with file permissions 0600.
- Provide secret cleanup commands.

Commands:

```bash
tapestry redact session.har
tapestry purge acme --secrets
```

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
