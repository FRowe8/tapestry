# HAR Capture Guide

Tapestry quality depends on HAR quality. A good HAR contains real API requests and their response bodies.

## Required Settings

In browser DevTools Network tab:

- Preserve log: ON
- Disable cache: ON
- Record network: ON
- Include response bodies in the exported HAR

If response bodies are missing, Tapestry can often infer request inputs but cannot infer useful response schemas or examples.

## What To Do

- Perform real product actions: search, list, open detail pages, create/update only if safe.
- Trigger the API calls you want agents to use.
- Capture at least one successful response for each important operation.
- For GraphQL apps, perform each operation separately when possible, especially searches and detail views.
- Export the HAR after the actions complete.

## What Not To Do

- Do not only load the homepage.
- Do not export a HAR with empty or omitted response bodies.
- Do not filter the Network panel so API requests are hidden before export.
- Do not capture only static assets, documentation pages, analytics, or ads.
- Do not rely on login pages alone to infer authenticated APIs.

## Common Issues

### Missing Response Bodies

Symptoms:

- `tapestry review <site>` shows missing examples or empty response schemas.
- `tapestry diagnose <site>` says request observed, but no response body captured.

Fix:

- Re-capture with Preserve log enabled.
- Ensure the HAR export includes response bodies.
- Wait for API calls to finish before exporting.

### Too Much Noise

Symptoms:

- Many static assets, consent scripts, telemetry requests, or analytics calls.

Fix:

- Tapestry filters common browser noise automatically.
- Prefer focused captures around the workflow you want to automate.

### Login Flows Not Captured

Symptoms:

- Tools are generated, but runtime calls fail with auth errors.

Fix:

- Capture after login.
- Include the authenticated API call you want to use.
- Auth automation is not implemented yet.

### GraphQL Batching

Symptoms:

- GraphQL tools are named, but some have missing examples.

Fix:

- Re-capture the specific operation.
- Avoid interrupting navigation before batched responses return.
- Prefer captures where the operation response body is present in the HAR.
