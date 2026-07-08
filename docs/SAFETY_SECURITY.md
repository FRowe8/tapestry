# Safety and Security Model

This document describes the security model as shipped. Changes that touch
redaction, credentials, or approvals must keep every guarantee here true
(see CLAUDE.md); if behavior changes deliberately, change this document in
the same commit.

## What is sensitive

Real browser captures — HAR exports and CDP recordings — may contain session
cookies, bearer tokens, CSRF tokens, personal data, and full request/response
bodies. They are treated as secrets everywhere: never committed, never copied
out of local storage, never quoted in issues or fixtures. Only synthetic or
verified-clean captures belong in `examples/fixtures/`.

Local site storage lives under `.tapestry-dev/sites/<site>/`:

| File | Contents | Protection |
| --- | --- | --- |
| `credentials.json` | harvested auth headers/cookies | user-only (see below) |
| `browser-profile/` | persistent login profile for record/reauth | user-only (see below) |
| `observations.json` | redacted request/response observations | standard file perms |
| `toolspec.json`, `meta.json`, `approvals.json` | generated artifacts | standard file perms |

## Storage protections

- **Credentials and browser profiles** are written via `write_secret`: mode
  0600/0700 on Unix; on Windows an explicit ACL via `icacls` (inheritance
  removed, current user granted full control). If the restriction fails, a
  warning names the file — the write is kept, the failure is never silent.
- **Generated artifacts** (`observations.json`, `toolspec.json`, `meta.json`,
  `approvals.json`) get 0600 on Unix. On Windows they rely on the containing
  directory's default ACLs rather than per-file `icacls`. This scope is
  deliberate: these files are post-redaction artifacts, and the explicit-ACL
  treatment is reserved for raw secrets. They still contain browsing-derived
  data — treat `.tapestry-dev/` as private in its entirety.
- **Raw HARs are never persisted.** `import` warns that HARs may contain
  credentials, extracts redacted observations, and does not copy the HAR.
- **Cleanup commands:** `tapestry purge <site> --secrets` removes credentials
  and the browser profile; `tapestry redact <file.har>` produces a
  sanitized HAR for sharing or bug reports.

## Redaction at capture time

Secrets are stripped before any observation is persisted, identically on the
HAR and CDP paths:

- request/response headers (Authorization, Cookie, Set-Cookie, CSRF and
  token-bearing headers)
- JSON body fields with secret names (`token`, `password`, `secret`,
  `api_key`, and similar — `is_secret_field_name` in tapestry-core)
- query-string parameters (`?access_token=…`, `?sig=…`, `?api_key=…`), in
  both the parsed query map and the stored URL

This is enforced by a seeded-sentinel test suite built on
`examples/fixtures/redaction.har`: fake secrets are planted in every channel,
and tests assert none survives into observations, ToolSpecs, review/diagnose
reports, or agent trace output. The one deliberate exception: `credentials
from-har` and `reauth` extract secrets *into* the credentials store, which is
the user-only file above.

## Redaction at execution time

An agent's context window is no safer a place for a session token than a JSON
file on disk, so live traffic gets the same treatment as stored captures:

- `call_tool` masks secret-named JSON fields in live responses before
  returning data, using the same field-name rule as capture-time redaction,
  so a live payload and a stored example can never disagree about what is
  sensitive.
- Error bodies quoted back to the agent (HTTP 4xx/5xx snippets) are masked
  before quoting: JSON bodies by secret field name; non-JSON bodies through
  token-shape masking (`mask_token_like`: JWTs, `Bearer` values, long hex
  digests, dense base64-like runs), then truncated to 200 characters.

**Known limits, stated plainly:** field-name masking does not detect a secret
stored under an innocuous name, and token-shape masking is heuristic — it
catches credential shapes, not every possible secret. These limits are why
HTML fragment support (which cannot use field-name masking at all) is
designed as opt-in and approval-gated — see `docs/FRAGMENT_TOOLS.md`; its
text redactor must be added to this document as a first-class section when
built.

## Safety classification

Every generated tool is classified `read`, `write`, or `unknown`:

- GET, HEAD, OPTIONS default toward read.
- POST, PUT, PATCH, DELETE default toward write.
- GraphQL queries default toward read; mutations toward write.
- Unknown is treated as write.
- LLMs cannot upgrade a safety classification.

## Execution policy

```text
read + confidence >= threshold -> executable
read + low confidence -> approval required
write -> blocked unless approved
unknown -> blocked unless approved
```

Approvals are granted with `tapestry approve <site> <tool_id>` and stored in
`approvals.json`, pinned to the tool's request shape: re-running `generate`
keeps approvals for unchanged tools and drops them (loudly) when a tool's
method, path, or input schema changes. An approval is for what was reviewed,
not for the tool ID forever.

## Idempotency

Writes are non-retryable by default unless explicitly marked idempotent:

```json
{
  "idempotency": {
    "safe_to_retry": false,
    "confidence": 0.85
  }
}
```

## Auth lifecycle

States: valid, expiring, expired, unknown. Detection: 401/403 responses,
redirects to login, response-body signals, token expiry metadata.
`last_successful_call` and auth failures are tracked per site in `meta.json`,
and likely-stale credentials are flagged before an agent wastes a task on
a 401.

Remediation is `tapestry reauth <site>`: a browser opens, the human logs in
manually (keystrokes are never captured), and fresh auth headers are
harvested from first-party traffic into the credentials store. There is no
OAuth/SSO/MFA automation by design — a human stays in the login loop.

## Transport surface

The MCP server (`tapestry serve`) is stdio-only. There is no HTTP transport,
no listening socket, and therefore no network authentication surface of our
own. Credentials never leave the machine.
