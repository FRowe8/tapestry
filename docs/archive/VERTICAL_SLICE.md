# v0.0 Vertical Slice Plan (archived)

> **Archived July 2026.** This was the original build plan; its success
> criteria were met long ago. See `docs/ARCHITECTURE.md` for what was
> actually built.

## Goal

From one HAR file, generate three tools and have an agent complete one task using only the native runtime interface.

Binary success criterion:

> Agent completes the task using search_tools -> get_tool_schema -> call_tool.

## Target app

Use a self-hosted app you control.

Recommended:

- NocoDB
- Ghost local instance
- Directus
- Strapi

Avoid live SaaS for v0.0.

## Required tools

Generate three tools from the HAR:

1. Simple read: `list_*`
2. Parameterized read: `get_*_by_id`
3. Write: `create_*` or `update_*`

The write tool should be classified as write and blocked unless approved.

## Agent task

```text
List the most recent 5 items and summarize them.
```

## Instrumentation

Log every:

- clustering decision
- inferred parameter
- inferred schema field
- confidence score
- warning
- LLM call, if any
- runtime request
- structured error

The first build's job is to reveal which analyzer phase fails on real data.

## Two-week outline

Week 1:

- HAR ingestion
- request normalization
- endpoint clustering
- schema inference
- ToolSpec JSON generation

Week 2:

- native runtime methods
- basic execution
- CLI commands
- agent loop smoke test
- end-to-end demo
