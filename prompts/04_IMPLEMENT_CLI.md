# Codex Prompt: Implement CLI v0

Task: Implement CLI commands in `tapestry-cli`.

Commands:

```bash
tapestry import <har> --site <site>
tapestry generate <site>
tapestry tools search <site> <query>
tapestry tools schema <site> <tool_id>
tapestry run <site> <tool_id> --args '<json>'
tapestry verify <site>
tapestry approvals <site>
tapestry redact <har>
tapestry purge <site> --secrets
```

For v0, commands may use a repo-local `.tapestry-dev/` directory instead of `~/.tapestry`.

Acceptance criteria:

- CLI can import fixture HAR.
- CLI can generate ToolSpec.
- CLI can search tools.
- CLI can show schema.
- CLI can run read tool against a configured base URL or dry-run.
