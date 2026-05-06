# Codex Instructions

## Mission

Build Tapestry v0.0 vertical slice.

## Hard constraints

Do not build:

- MCP server
- live recording proxy
- JS crawler
- OAuth automation
- community registry
- browser automation

Do build:

- HAR importer
- deterministic analyzer
- ToolSpec model
- native runtime
- CLI commands
- instrumentation

## Quality bar

- Prefer explicit, simple code over clever abstractions.
- Add tests for each analyzer rule.
- Keep security-sensitive data out of logs.
- Use structured errors everywhere.
- Preserve stable tool IDs.

## Definition of done

A fixture HAR can generate a ToolSpec, and a runtime client can search for a read tool, fetch its schema, and call it.
