# Codex Prompt: Build Vertical Slice Test

Task: Create an end-to-end test that proves the v0.0 architecture.

Scenario:

1. Use a fixture HAR from a controlled app.
2. Generate a ToolSpec with at least:
   - one list tool
   - one get-by-id tool
   - one write tool
3. Start or mock runtime.
4. Simulate an agent flow:
   - search_tools("recent items")
   - get_tool_schema(selected_tool)
   - call_tool(selected_tool, args)
5. Assert that the task succeeds.

The test does not need to use a real LLM.

Acceptance criteria:

- End-to-end test passes.
- Logs reveal clustering decisions and confidence scores.
- Write tool is present but blocked.
