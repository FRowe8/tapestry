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
