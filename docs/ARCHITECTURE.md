# Tapestry Architecture

## Core pipeline

```text
Input -> Observations -> Analyzer -> ToolSpec -> Runtime -> Agent/CLI
```

## Crates

### tapestry-core

Shared domain types:

- `ToolSpec`
- `ToolDefinition`
- `Evidence`
- `Confidence`
- `SafetyClassification`
- `RuntimeError`

### tapestry-input

Responsible for reading external inputs and producing normalized observations.

v0.1 only supports HAR import.

### tapestry-analyzer

Turns observations into ToolSpec entries.

Phases:

1. request normalization
2. endpoint clustering
3. schema inference
4. auth detection
5. dependency mapping
6. optional LLM refinement

### tapestry-runtime

Executes tools using a low-token native interface.

Core methods:

- `search_tools(query, site, limit)`
- `get_tool_schema(site, tool_id)`
- `call_tool(site, tool_id, arguments)`
- `get_evidence(site, tool_id)`

### tapestry-cli

CLI frontend over input, analyzer, and runtime.

## Local registry

```text
~/.tapestry/
  config.toml
  registry.json
  sites/
    acme/
      toolspec.json
      evidence.json
      approvals.json
      overrides.json
      meta.json
      .env
```

For the v0.0 slice, storing under a repo-local `.tapestry-dev/` is acceptable.
