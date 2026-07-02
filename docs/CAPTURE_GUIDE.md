# Capture Guide

Tapestry quality depends on capture quality. A good capture contains real API requests and their response bodies.

## Live Recording (preferred)

```bash
tapestry record https://app.example.com --site acme
```

`record` launches a browser, attaches network capture *before* navigating (so the initial page load — usually the richest API traffic — is never missed), and also captures traffic from service workers, popups, and embedded frames. Each site gets a persistent browser profile: log in once and later `record` and `reauth` sessions start already authenticated. The profile contains session cookies, so `tapestry purge <site> --secrets` deletes it along with stored credentials; pass `--ephemeral-profile` for a throwaway session instead.

Interact with the app while recording (search, open detail pages), then press Enter to finish. Repeated recordings merge into the site's existing observations.

## HAR Import (alternative)

If you prefer capturing in your own browser, export a HAR from DevTools and run `tapestry import <har> --site <site>`. The settings below matter.

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
