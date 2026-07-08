# Security Policy

## Reporting a vulnerability

Please report security issues privately through GitHub Security Advisories for this repository.

Do not open a public issue for:

- credential leakage
- redaction failures
- approval-gate bypasses
- unsafe MCP exposure
- browser-profile or local storage permission flaws

Include:

- affected version or commit
- reproduction steps
- whether the issue requires a real capture or can be shown with a synthetic fixture
- whether any secrets were exposed, and in what artifact or output path

## Security scope

The following areas are security-sensitive and should be treated as part of Tapestry's security surface:

- capture redaction
- credential harvesting and persistence
- approval requirements for write, unknown-safety, and low-confidence tools
- MCP transport behavior and tool exposure
- local file permissions for secrets and browser profiles

## Handling test data

Never send real HAR files, cookies, bearer tokens, or browser profiles in reports. Use synthetic fixtures or sanitized reproductions only.
