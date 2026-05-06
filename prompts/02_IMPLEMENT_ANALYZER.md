# Codex Prompt: Implement Analyzer v0

Task: Implement deterministic analyzer in `tapestry-analyzer`.

Requirements:

1. Request normalization.
2. Endpoint clustering:
   - group by method
   - infer dynamic path params
   - preserve static action segments like search, login, logout, export
   - preserve API versions
3. Schema inference:
   - query params
   - JSON request bodies
   - JSON response bodies
   - required/optional fields
   - nullable fields
   - inconsistent types fallback to string with warning
4. Safety classification:
   - GET/HEAD/OPTIONS = read
   - POST/PUT/PATCH/DELETE = write
   - unknown treated as write
5. Stable tool IDs from hash(method + normalized_path).
6. Emit ToolSpec JSON.
7. Add instrumentation logs for clustering and schema decisions.

Do not use an LLM in v0 unless a clean trait stub is helpful.

Acceptance criteria:

- Given a fixture with `/api/items/1` and `/api/items/2`, analyzer emits `/api/items/{id}`.
- Given `/api/items/search`, analyzer does not merge it into `/api/items/{id}`.
- Write endpoints are blocked by default in ToolSpec.
