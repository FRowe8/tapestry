# Tapestry Product Requirements Document

## 1. Product Summary

Tapestry is a local-first system that converts captured web application behavior into structured, low-token, agent-usable tools.

It is designed for SaaS tools, internal portals, admin dashboards, and legacy web applications that expose useful behavior through a browser but lack complete public APIs, SDKs, or MCP servers.

## 2. Positioning

**Tapestry turns captured web app traffic into structured, low-token tools for AI agents and automation.**

Tapestry is not a scraper, not a bot framework, and not primarily an MCP server generator. MCP is an optional adapter. The core artifact is a ToolSpec, and the primary runtime is a compact low-token protocol.

## 3. Primary Use Cases

### 3.1 Agent access to SaaS tools without clean API coverage

A user demonstrates a browser workflow once. Tapestry converts the observed network traffic into callable tools an agent can discover and use.

Example:

```text
Capture: search customers, view invoices, export account status
Generate: searchCustomers, getInvoice, listAccountStatuses
Agent: “Find overdue accounts and summarize follow-up actions.”
```

### 3.2 Internal and legacy web app automation

Internal dashboards often have no documented API but still communicate with backend endpoints. Tapestry generates typed automation layers from captured behavior.

### 3.3 Rapid integration prototyping

Teams can capture a browser session and generate a provisional ToolSpec before investing in a full integration.

## 4. Goals

- Generate useful tools from HAR captures.
- Avoid browser automation for execution.
- Keep agent context small through lazy tool discovery.
- Provide safety classification and approval gates.
- Surface evidence and confidence for every inferred tool.
- Treat HARs and credentials as sensitive secrets.

## 5. Non-Goals for v0.1

- Full browser automation.
- CAPTCHA solving or anti-bot bypass.
- Universal compatibility with all web apps.
- Automatic OAuth/SSO/MFA handling.
- MCP as the primary architecture.
- Team sharing or marketplace distribution.

## 6. Architecture

```text
HAR / JS / Schema
      ↓
Input Layer
      ↓
Analyzer: deterministic extraction + optional LLM assist
      ↓
ToolSpec
      ↓
Native low-token runtime
      ↓
Agents / CLI / exports
```

## 7. Low-Token Runtime

Traditional tool integrations often expose 50–500 full tool schemas to an agent up front. Tapestry exposes 3–4 core runtime methods regardless of how many tools exist:

- `search_tools`
- `get_tool_schema`
- `call_tool`
- `get_evidence`

This is intended to reduce tool-related context by roughly 90–99% for large tool sets.

## 8. Safety Pipeline

An observed request becomes an executable tool only after passing through the safety pipeline:

1. Observation: raw requests captured from HAR or other inputs.
2. Clustering: requests grouped into candidate endpoints.
3. Schema inference: input/output schemas inferred.
4. Confidence scoring: field-level confidence assigned from evidence.
5. Safety classification: method and behavior classified as read, write, or unknown.
6. LLM refinement: may explain or downgrade safety, never upgrade it.
7. Approval layer: write, unknown, and low-confidence tools require approval.
8. Runtime enforcement: execution gated by safety, confidence, auth state, and approval state.

Key guarantee:

> No tool is executable unless it passes safety classification, confidence threshold, and approval rules.

## 9. MVP Scope

Required:

- HAR ingestion.
- Request normalization.
- Endpoint clustering.
- Basic schema inference.
- ToolSpec generation.
- Native runtime: search/schema/call/evidence.
- Structured errors.
- Basic auth failure detection.
- Stable tool IDs.
- CLI commands for import, generate, run, tools search, tools schema.

Deferred:

- Live recording proxy.
- JS crawling.
- MCP adapter.
- OAuth automation.
- Team sharing.
- WebSocket/SSE support.
