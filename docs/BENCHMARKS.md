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

Measured on the current corpus: the meta-tool surface is ~519 tokens regardless of site size; real sites (7-35 tools) show 92.8-99.9% reduction, consistent with the PRD's 90-99% claim. Small sites (~3 tools) show ~46% — the fixed meta-tool cost only pays off once a site has more than a handful of tools.

## Real-agent measurement (measured 2026-07-08)

Produced by `python benchmarks/agent_bench.py`: each task runs in a fresh
headless Claude Code instance (`claude -p --strict-mcp-config`, model
claude-fable-5) connected to `tapestry serve --live` over actual MCP and
restricted to the four meta-tools. Success is judged by pinned,
verifiable string checks against the final answer (`benchmarks/agent_tasks.json`);
token counts come from the CLI's own usage report.

| site | tools | tasks completed | mean turns | fresh input tok/task | cache-read tok/task | output tok/task | naive schema dump (est) |
| --- | --- | --- | --- | --- | --- | --- | --- |
| demo (dummyjson.com, live) | 8 | **5/5** | 5.0 | 21,046 | 95,982 | 534 | 23,281 |
| bench-localapp (live) | 3 | **5/5** | 4.8 | 11,400 | 93,668 | 515 | 1,073 |

How to read this honestly:

- **Task completion through the real MCP client is 10/10.** The agent used
  only `search_tools` → `get_tool_schema` → `call_tool`, averaging ~5 turns
  and ~$0.26-0.51/task at Fable pricing.
- **Most measured context is the client harness, not the tool design.**
  Claude Code's own system prompt (~13k tokens, cached after the first
  request) dominates both fresh input and cache reads, and would be
  identical under any tool-exposure design. The *design-controlled* context
  is the tool-definition surface: ~519 tokens of meta-tools plus one
  on-demand schema, versus the full schema dump (rightmost column) that the
  naive design adds to **every request** of every task. For the 8-tool demo
  site that is a 97.8% reduction in definition surface (23,281 → ~519 + one
  schema); for real captured sites at 7-35 tools the estimate range is
  92.8-99.9% (section above), now validated by a real agent completing
  tasks with only the meta surface in context.
- **Small sites don't benefit**: bench-localapp's entire schema dump
  (1,073 tokens) is about twice the meta surface — consistent with the
  estimate-based finding that the design pays off past a handful of tools.
- `bench-nocodb` and `bench-ghost` tasks are defined and will join the
  table after the Docker suite's first run (Phase 4 remainder).

### Capture parity (HAR vs CDP)

Sites captured both ways (HAR export and `tapestry record`) share a `parity_group` in `benchmark_cases.json`. `tapestry benchmark` compares the pair on observations, API observations, response bodies, tools, replayable tools, ground-truth endpoint coverage, and agent task outcome, and reports whether CDP meets HAR.

Cases may declare `expected_endpoints` — the app's known API surface — so both capture methods are scored against ground truth rather than only against each other (two methods missing the same traffic would otherwise look equal).

The deterministic pair is `localapp` (examples/fixtures/localapp.har) vs `localapp-cdp`, recorded live from `scripts/localapp_server.py`, whose page fires every API call at page load — the exact traffic the pre-fix recorder lost.

Release gate: CDP meets HAR on every parity pair before the README recommends `record` over HAR export.
