# Codex Prompt: Implement Native Runtime v0

Task: Implement native low-token runtime in `tapestry-runtime`.

Methods:

- `search_tools(site, query, limit)`
- `get_tool_schema(site, tool_id)`
- `call_tool(site, tool_id, arguments)`
- `get_evidence(site, tool_id)`

Requirements:

- Load ToolSpec from local path.
- Search by name, description, path, and params.
- Enforce safety rules:
  - read allowed if confidence threshold passes
  - write blocked unless approved
  - unknown blocked
- Return structured errors.
- Implement dry-run mode if easy.

Acceptance criteria:

- Agent can search for a tool.
- Agent can fetch its schema.
- Agent can call a read tool.
- Write tool returns `approval_required` unless approved.
