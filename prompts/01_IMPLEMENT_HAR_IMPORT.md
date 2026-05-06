# Codex Prompt: Implement HAR Import

Task: Implement HAR import in `tapestry-input`.

Requirements:

- Parse HAR JSON files.
- Extract request method, URL, headers, query params, body, response status, response headers, response body if JSON.
- Produce normalized observations using types from `tapestry-core`.
- Redact sensitive headers in debug output:
  - Authorization
  - Cookie
  - Set-Cookie
  - X-CSRF-Token
  - X-XSRF-Token
- Add unit tests using a small fixture HAR.

Do not persist raw HAR by default.

Acceptance criteria:

- `cargo test` passes.
- A fixture HAR produces a list of observations.
- Secrets are not printed in logs or debug strings.
