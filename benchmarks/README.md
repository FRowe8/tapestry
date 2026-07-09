# Self-hosted benchmark suite

This directory is the readiness plan's Phase 4: reproducible, version-pinned
apps that Tapestry is benchmarked against, and a one-command runner that
produces the four metrics defined in `docs/BENCHMARKS.md`.

## Quick start

```bash
# Full suite (needs Docker; ~5 min first run for image pulls)
python benchmarks/run.py

# No Docker? Prove the harness end to end against the deterministic local app
python benchmarks/run.py --apps localapp
```

The runner brings up `docker-compose.yml` itself, seeds each app over its
HTTP API, captures browser traffic headlessly, generates tools, approves the
write tools, and measures:

| Metric | Definition | Target |
| --- | --- | --- |
| Endpoint callability | live call with the tool's own example input returns 2xx with ≥80% schema field compatibility | ≥70% |
| Task completion | `tapestry validate --live` succeeds for each predefined task | ≥60% |
| Time to first working tool | recording start → first callable tool | <10 min |
| Manual correction rate | tools whose own example input fails with an argument/schema error (a human would have to fix them before use) | <30% |

Results print as a table and land in `benchmarks/results/` (gitignored).

## How capture works (and why there's a "driver" page)

`tapestry record` captures what a browser does. In CI there is no human to
log in and click around, so for each app the runner serves a small **driver
page** on localhost whose JavaScript performs a realistic authenticated
workload against the app's real API — the same endpoints the app's own UI
calls (NocoDB's v2 meta/records API, Ghost's Content API). The recorder
captures that as ordinary same-site browser traffic.

This measures Tapestry's actual pipeline (capture → analysis → generation →
safety gates → live execution) against real apps. What it does *not*
measure is capture fidelity for human UI sessions — service workers, consent
walls, fragment endpoints. That is what the capture-parity pairs in
`benchmark_cases.json` and the retail stress tests (private, maintainer-only)
are for.

## The apps

- **localapp** — `scripts/localapp_server.py`, no Docker. Exists so the
  harness itself can be smoke-tested anywhere; it is deliberately trivial.
- **NocoDB** (pinned in `docker-compose.yml`) — seeded with a base, an
  `Items` table, and rows. Token-header auth (`xc-auth`), which Tapestry's
  credential store injects on live calls: the full read+write loop works,
  including the approval gate on the create-record tool.
- **Ghost** (pinned) — seeded with an owner account; the driver exercises
  the Content API. **Known expected failure:** Ghost's Content API
  authenticates with a `?key=` query parameter. Tapestry redacts secret
  query params at capture (correctly) and its credential store injects
  headers only, so live calls to keyed endpoints fail auth. This is kept in
  the suite on purpose — the benchmark exists to surface real gaps, and
  query-parameter credential injection is a candidate roadmap item. Judge
  Ghost's numbers accordingly.

## Real-agent measurement

`python benchmarks/agent_bench.py` drives the tasks in `agent_tasks.json`
through Claude Code's actual headless MCP client (`claude -p
--strict-mcp-config` → `tapestry serve --live`), restricted to the four
meta-tools, and records success (verifiable string checks), turns, and real
token usage. The model is pinned to a realistic mid-tier default
(`claude-sonnet-5`); note the model next to any published numbers. Results
feed the table in `docs/BENCHMARKS.md`.

## Planned: browser-control baseline

The project's strongest qualitative claim — direct tool calls are far
cheaper and faster than driving a browser — is **not yet measured**, and no
public copy should put numbers on it until it is. The defined method, once
the Docker suite runs (NocoDB has a real UI):

1. Same tasks, same client (`claude -p`), same pinned model.
2. Arm A: tapestry MCP (four meta-tools), as `agent_bench.py` does today.
3. Arm B: a browser-automation MCP (e.g. Playwright MCP) pointed at the
   app's UI, with the agent completing the identical tasks by navigating,
   logging in, and reading the page.
4. Publish side by side: success rate, turns, fresh/cached/output tokens,
   wall-clock time, and cost per task. The harness overhead (the client's
   own system prompt) is identical in both arms and cancels out; the delta
   is the per-step payload — structured JSON versus page snapshots.

## Reproducibility rules

- Image versions are pinned in `docker-compose.yml`. Bump them deliberately,
  as their own commit, and re-run the suite.
- Both containers bind to `127.0.0.1` only and hold throwaway seeded
  credentials — never expose them publicly, and never point the suite at an
  instance holding real data.
- `benchmark_cases.json` carries `expected_endpoints` ground truth for the
  bench sites, so `tapestry benchmark` scores capture coverage against
  reality rather than only HAR-vs-CDP agreement.
