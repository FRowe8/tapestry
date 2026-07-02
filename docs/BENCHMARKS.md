# Benchmarks

## Purpose

Benchmarks measure whether Tapestry produces usable tools, not whether it produces plausible-looking JSON.

## Benchmark types

Prefer self-hosted, version-pinned apps for reproducibility:

- NocoDB fixed version
- Ghost fixed version
- Directus fixed version
- Strapi fixed version

Live SaaS sandboxes can be secondary signals but should not be primary release gates because their internals can change without notice.

## Metrics

### Endpoint callability

A generated tool is callable if:

- execution returns HTTP 2xx
- response conforms to inferred schema at >=80% field compatibility

Target v0.1: >=70% on benchmark suite.

### Task completion rate

An agent task succeeds if the agent completes a predefined task using only the native runtime interface.

Target v0.1: >=60%.

### Time to first working tool

Time from HAR import to successful tool call.

Target v0.1: <30 minutes manual, <10 minutes automated.

### Manual correction rate

Percentage of generated tools requiring manual edits before working.

Target v0.1: <30%.

### Context reduction

`tapestry benchmark` estimates (chars/4) the token cost of the four meta-tool definitions an MCP agent sees versus serializing every generated tool schema into context, per site and as a mean.

Measured on the current corpus: the meta-tool surface is ~519 tokens regardless of site size; real sites (7-35 tools) show 92.8-99.9% reduction, consistent with the PRD's 90-99% claim. Small sites (~3 tools) show ~46% — the fixed meta-tool cost only pays off once a site has more than a handful of tools. Token *estimates* validate the interface design; actual per-task token usage with a real agent (Gap 7) remains to be measured.

### Capture parity (HAR vs CDP)

Sites captured both ways (HAR export and `tapestry record`) share a `parity_group` in `benchmark_cases.json`. `tapestry benchmark` compares the pair on observations, API observations, response bodies, tools, replayable tools, ground-truth endpoint coverage, and agent task outcome, and reports whether CDP meets HAR.

Cases may declare `expected_endpoints` — the app's known API surface — so both capture methods are scored against ground truth rather than only against each other (two methods missing the same traffic would otherwise look equal).

The deterministic pair is `localapp` (examples/fixtures/localapp.har) vs `localapp-cdp`, recorded live from `scripts/localapp_server.py`, whose page fires every API call at page load — the exact traffic the pre-fix recorder lost.

Release gate: CDP meets HAR on every parity pair before the README recommends `record` over HAR export.
