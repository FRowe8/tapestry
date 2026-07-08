# Launch Readiness Roadmap (archived)

> **Archived July 2026.** Eight of its ten gaps are closed and recorded here
> for history. The live plans are `docs/OPEN_SOURCE_READINESS.md` (getting to
> the OSS launch — its Phases 3-5 absorb the open remainders of Gaps 6, 7,
> and 10) and `docs/VISION.md` (post-launch direction and coverage tiers).

This document lists the gaps between the current vertical slice and something that can be handed to real testers, why each gap matters, and how to close it. It is ordered by priority: items near the top block a pilot launch; items near the bottom improve it.

## Where we are

The pipeline works end to end and is further along than the docs elsewhere suggest:

- HAR import and live CDP recording both produce observations.
- Analyzer clusters endpoints, infers schemas, detects auth, and handles batched GraphQL.
- Runtime enforces the safety pipeline: write/unknown/low-confidence tools return `approval_required`, credentials are injected per-site, and 401/403 maps to structured `auth_expired`.
- CLI covers import, record, generate, search, run, review, diagnose, validate, benchmark, redact, purge, and credentials management.
- A scripted agent harness (`agent-task`) demonstrates the search -> schema -> call loop.

## Launch target

**Pilot definition:** 3-5 external testers automate an internal, self-hosted, or B2B web app (not a consumer site) end to end: capture a session, generate tools, approve what needs approving, and have a real LLM agent complete tasks against it over multiple days without re-capturing.

That definition drives the priority order below. Everything that blocks "real agent, multiple days, no hand-editing JSON" comes first.

## Gap 1: No integration surface for real agents (MCP adapter)

**Status: closed.** `tapestry serve` is an MCP stdio server exposing the four meta-tools; see RUNTIME_PROTOCOL.md and the README snippet.

**Why this is the top priority.** The runtime's whole thesis is low-token agent access, but today no real agent can reach it except by shelling out to the CLI. `agent-task` uses a scripted heuristic, not an LLM, so we have never actually validated the core claim with a real model. Without this, a pilot tester cannot connect Tapestry to Claude Code, Claude Desktop, or any other harness. The PRD deferred MCP because it is "not the primary architecture" — that reasoning was about identity, not usefulness, and it no longer holds: MCP is the on-ramp every pilot tester already has installed.

**How to close it.**

1. Add a `tapestry-mcp` crate (or `tapestry serve --mcp` subcommand) exposing exactly the four runtime methods as MCP tools: `search_tools`, `get_tool_schema`, `call_tool`, `get_evidence`. Do not expose generated tools individually — the meta-tool design is the product; MCP is just transport.
2. stdio transport only for v0.2. No HTTP server, no auth story of our own to build.
3. `call_tool` responses must surface the structured errors (`approval_required`, `auth_expired`) verbatim so the agent can explain to the user what to do next, instead of retrying blindly.
4. Ship a copy-paste `.mcp.json` snippet in the README.

**Done when:** Claude Code, configured with the snippet, completes the demo fixture task and one live self-hosted task using only the four meta-tools.

## Gap 2: Auth expiry breaks the "capture once" promise

**Status: closed.** `tapestry reauth <site>` opens a browser for a manual login and harvests fresh credential headers from first-party traffic (keystrokes never captured). Auth success/failure timestamps live in `meta.json`; stale credentials trigger a warning at spec load, and the `auth_expired` error names the fix.

**Why.** Session cookies and bearer tokens expire in hours. Today the remediation is "re-import a HAR," which collapses the value proposition into "re-capture before every session." This is the single biggest determinant of real-world usability: if tools survive a week, Tapestry is a product; if they survive an hour, it is a demo. We do not need OAuth automation (correctly a non-goal) — we need cheap re-auth.

**How to close it.**

1. **Credential refresh via CDP.** We already launch a browser for `record`. Add `tapestry reauth <site>`: open the site in a browser, let the user log in manually, harvest the fresh cookies/headers from the session, and update the stored credentials. No login-flow automation, no secrets in scripts — the human does the login, we capture the result. This reuses the existing CDP machinery and is the highest-leverage feature in this document after the MCP adapter.
2. **Proactive expiry state.** SAFETY_SECURITY.md already defines auth states (valid/expiring/expired/unknown). Persist `last_successful_call` and `last_auth_failure` per site in `meta.json`, and have `review`/`search_tools` surface "credentials likely stale" before the agent wastes a task on a 401.
3. **Actionable `auth_expired`.** The structured error should name the fix: "run `tapestry reauth <site>`". Agents relay error text; make the text the documentation.

**Done when:** a tester whose session expired gets back to working tools with one command and one manual browser login, without touching HAR files or JSON.

## Gap 3: Approval exists in the runtime but not in the workflow

**Status: closed.** `tapestry approve <site> [--list|--revoke]` stores fingerprint-pinned approvals in `approvals.json`; `generate` prunes stale ones. The runtime now also honors approvals on unknown-safety tools, matching the documented policy.

**Why.** The runtime correctly blocks write/unknown/low-confidence tools, but there is no CLI command to approve anything — the `approved` flag can only be set by hand-editing `toolspec.json`. Hand-editing generated files is exactly the failure mode the safety pipeline exists to prevent, and regeneration will silently discard those edits. For a pilot, the approval gate must be a first-class action or testers will either give up on write tools or bypass the gate.

**How to close it.**

1. `tapestry approve <site> <tool_id>` and `tapestry approve <site> --list` (pending approvals with safety class, confidence, and evidence summary so the decision is informed).
2. Store approvals in the `approvals.json` file that ARCHITECTURE.md already specifies, keyed by stable tool ID — not in `toolspec.json` — so `generate` can be re-run without losing approval state. Merge at load time in the runtime.
3. If a tool's request shape changes on regeneration (different method/path/body schema), drop its approval and say so. An approval is for what was reviewed, not for the tool ID forever.

**Done when:** import -> generate -> approve -> call a write tool works with no manual file edits, and re-running `generate` preserves approvals for unchanged tools only.

## Gap 4: No drift detection against live responses

**Status: closed.** Live `call_tool` responses report field-level conformance against the inferred schema; per-tool health (healthy/degraded/broken/unreachable) persists in `meta.json` and surfaces as warnings in search, review, and MCP results. Read tools are flagged, never auto-disabled.

**Why.** Every ToolSpec is a snapshot of an unversioned, undocumented API. Endpoints change without notice, and a tool that silently returns a differently-shaped response is worse than one that errors, because the agent will act on wrong data. `validate` currently measures search-ranking drift, which is useful but does not tell a tester "this tool no longer works."

**How to close it.**

1. On every live `call_tool`, compare the response against the inferred response schema (field-presence check, the same >=80% compatibility rule BENCHMARKS.md uses). Record the result per tool in `meta.json`.
2. Add tool health to `review`: healthy / degraded (schema mismatch) / broken (non-2xx) / untested, with last-checked timestamps.
3. On mismatch, attach a warning to the tool that `search_tools` surfaces, and lower effective confidence. Do not auto-disable read tools; do flag them.
4. Recommend re-capture in the warning text, reusing the `diagnose` remediation strings.

**Done when:** deliberately changing a fixture response causes `review` to mark the tool degraded and `search_tools` to warn on it, with no false alarms on the unchanged tools.

## Gap 5: Imports overwrite instead of merge

**Status: closed.** `import` and `record` merge into existing observations with exact-duplicate dedupe (`--replace` starts fresh); capture sessions are tracked in `meta.json`.

**Why.** Real coverage of an app takes several sessions — you capture search today and invoices tomorrow. Today a second `import --site acme` replaces the first session's observations, so testers must assemble one giant HAR per site or lose work. Schema inference also improves materially with more observations per endpoint (optional fields, enums, pagination only become visible across examples), so merging isn't just convenience — it raises tool quality.

**How to close it.**

1. Make `import` and `record` append observations to an existing site by default, deduplicating identical request/response pairs. Add `--replace` for the current behavior.
2. `generate` already runs over all observations; verify clustering treats multi-session evidence as more, not conflicting, evidence, and that evidence entries cite which capture they came from.
3. Track capture sessions in `meta.json` (source file/date) so `purge` and `diagnose` can report per-session.

**Done when:** two HARs imported to the same site produce one ToolSpec whose per-field confidence is >= what either HAR alone produced.

## Gap 6: Benchmarks point at the wrong targets

**Why.** The fixture set is dominated by consumer retail and travel sites (Amazon, Tesco, Next, Argos, Skyscanner). These sit behind anti-bot infrastructure that actively fights non-browser replay, are ToS-hostile to automation, and are explicitly not the PRD's use case. Testing against them measures our ability to win an unwinnable fight and tells us nothing about the internal/B2B apps we are positioned for. BENCHMARKS.md already names the right suite; it just is not built.

**How to close it.**

1. Stand up the self-hosted suite from BENCHMARKS.md — NocoDB, Ghost, Directus, Strapi at pinned versions (docker compose in `benchmarks/`).
2. Script the capture -> generate -> validate -> agent-task loop against each, reporting the four metrics BENCHMARKS.md defines (callability >=70%, task completion >=60%, time-to-first-tool, manual correction rate <30%).
3. Move the retail HARs out of `examples/fixtures/` into a clearly-labeled `fixtures/adversarial/` (they remain useful as analyzer stress tests for noise filtering) and say in LIMITATIONS.md that consumer sites with bot defense are out of scope. This is a positioning decision, not just housekeeping: the safety-first story is one of the project's strongest assets, and shipping Amazon fixtures undermines it.

**Done when:** the benchmark suite runs from a clean checkout with one command and produces the four metrics against at least two pinned self-hosted apps.

## Gap 7: The demo agent is not a real agent

**Status: partially closed.** The context-reduction half is now measured, not asserted: `tapestry benchmark` reports the meta-tool surface (~519 tokens) against each site's full toolspec — 92.8-99.9% reduction on real sites, ~46% on trivial 3-tool sites. The task-completion half still needs a real LLM agent driving the MCP server.

**Why.** `agent-task` proves the runtime loop but uses keyword-scoring heuristics to pick tools and build arguments. Every claim in the PRD about token savings and agent usability is unvalidated until a real model drives the loop. This gap mostly dissolves once Gap 1 lands, but it needs to be measured, not assumed.

**How to close it.**

1. After the MCP adapter ships, define 5-10 tasks per benchmark app and run them via a real LLM agent using only the four meta-tools.
2. Record task completion rate and tokens consumed; compare tokens against a naive baseline that stuffs all generated tool schemas into context. This turns the "90-99% context reduction" claim from marketing into a measurement.
3. Keep the heuristic `agent-task` as a fast, deterministic smoke test — it is good CI; it is just not evidence.

**Done when:** BENCHMARKS.md gains a table of real-agent task completion and token usage on the self-hosted suite.

## Gap 8: No install or onboarding story

**Why.** Pilot testers will not clone a repo and run `cargo run -p tapestry-cli --`. Every step of friction before the first working tool costs testers, and the "time to first working tool" metric starts at install.

**How to close it.**

1. Release binaries for Windows/macOS/Linux via `cargo dist` or a GitHub Actions release workflow; `cargo install tapestry-cli` as the fallback.
2. A single QUICKSTART path in the README: install -> record or import -> generate -> review -> connect agent via MCP -> first task. One page, no forks in the road.
3. A `tapestry doctor` check (browser found for CDP, storage writable, credentials file permissions) so support requests come with diagnostics attached.

**Done when:** a tester on a clean machine reaches a working tool call in under 10 minutes without building from source (matching the BENCHMARKS.md automated target).

## Gap 9: Security hardening before external users

**Status: closed.** The audit found and fixed a real leak: query-string secrets (`?access_token=…`, `?sig=…`) survived into observations on both capture paths; they are now redacted in the query map and the stored URL. The redaction test suite (`examples/fixtures/redaction.har`, seeded with sentinel secrets in every channel) asserts nothing leaks into observations, ToolSpecs, review/diagnose reports, or agent traces. Secret files are now genuinely user-only on Windows too (explicit `icacls` ACL on credentials and browser profiles, verified). `tapestry doctor` (Gap 8) reports environment and site problems with fixes.

**Why.** SAFETY_SECURITY.md sets the right requirements, but pilot users mean real session tokens for real accounts on other people's machines. The gap between "documented requirement" and "verified behavior" must be closed before, not after, testers arrive.

**How to close it.**

1. Audit each SAFETY_SECURITY.md requirement against the code and fix shortfalls: import warning shown, secrets redacted from all log paths (including `--trace` output), raw HAR not persisted by default, credentials never written into `toolspec.json`/`evidence.json`.
2. File permissions: 0600 is a no-op on Windows — use an explicit ACL restriction or, at minimum, document the limitation honestly in LIMITATIONS.md.
3. Add a redaction test suite: a fixture HAR seeded with known fake tokens, and a test asserting those strings never appear in any generated artifact or log output.

**Done when:** the redaction test suite passes and each requirement in SAFETY_SECURITY.md has a test or a documented, deliberate exception.

## Gap 10: Live capture exists but loses to HAR export

**Why.** `tapestry record` (CDP) was built to replace the awkward DevTools-export-a-HAR workflow, but the benchmark corpus shows it underperforming the thing it replaces: `next` and `justkandy` produce working tools from HAR captures and `no_matching_tool` from CDP captures of the same sites. If live capture is worse than HAR, testers will fall back to HAR, and the friction we meant to remove stays. The causes are identifiable, not mysterious:

1. **Attach race.** The browser is launched with the target URL as an argument; `Network.enable` happens only after the DevTools handshake. Everything the page loads in that window — usually the densest API traffic of the whole session — is lost.
2. **Fresh throwaway profile.** Every recording starts logged out, behind consent walls, and looking exactly like a bot. HAR export runs in the user's real, logged-in browser; our capture doesn't.
3. **Single page target.** Requests served through service workers, popups, and out-of-process iframes never reach the page-level Network domain. Modern storefronts lean on service workers heavily.
4. **Body-capture fragility.** `Network.getResponseBody` after `loadingFinished` fails once the frame navigates away or the target detaches.

**How to close it.**

*Phase A — fidelity fixes (highest value first): **done.***

1. ~~Launch at `about:blank`, connect, enable Network/Page, *then* `Page.navigate`.~~ Shipped; verified against a local app whose API calls fire at page-load — instant fetches are now captured reliably across repeated fresh-profile runs.
2. ~~Persistent per-site browser profile.~~ Shipped: `<site>/browser-profile`, absolutized for Chrome (a relative `--user-data-dir` silently disables remote debugging on recent Chrome), shared by `record` and `reauth`, deleted by `purge --secrets`, bypassed with `--ephemeral-profile`.
3. ~~`Target.setAutoAttach` (flattened).~~ Shipped: child sessions (service workers, popups, OOPIFs) get Network enabled and their request ids are session-namespaced to prevent collisions in the observation builder.
4. ~~Eager body fetch.~~ Shipped: JSON bodies are fetched at `responseReceived` (failures silent — body may not be complete) with the `loadingFinished` fetch remaining authoritative.

*Phase B — measurement (how we know it worked): **harness done.***

5. ~~Make the har/cdp pairing a first-class benchmark axis.~~ Shipped: cases sharing a `parity_group` are compared HAR vs CDP on observations, API observations, bodies, tools, replayable tools, endpoint coverage, and agent outcome, with an explicit "CDP meets HAR" verdict per pair.
6. ~~Ground-truth endpoint lists.~~ Shipped as `expected_endpoints` per benchmark case (with `{param}` segment wildcards); used by the deterministic `localapp` pair, ready for the self-hosted suite.
7. Release gate stands: current results — `localapp` pair passes (CDP 100% coverage, agent success, ≥ HAR on every metric); `next` and `justkandy` pairs still carry empty pre-fix CDP captures and are flagged below parity until re-recorded with the fixed recorder against a real browsing session.

*Phase C — deferred capture routes:*

- **Proxy capture** (mitm CA): only route to non-browser clients (mobile/desktop apps), but CA install friction and cert pinning make it a poor default. Revisit after the CDP path wins its benchmark.
- **Browser extension**: zero-launch capture inside the user's real browser; real distribution and review overhead. Revisit if the persistent-profile approach still leaves login friction.

**Done when:** the benchmark's capture-parity table shows CDP ≥ HAR on all self-hosted apps and at least parity on the retained real-site corpus, and the README can honestly recommend `tapestry record` over HAR export.

## Deliberately not closing

These stay out of scope, and saying so is part of the roadmap:

- **Anti-bot evasion.** Unwinnable arms race, off-mission, and corrosive to the safety-first positioning. Consumer sites with bot defense are documented as unsupported (Gap 6).
- **OAuth/SSO/MFA automation.** The `reauth` flow (Gap 2) deliberately keeps a human in the login loop. Automating credential entry adds enormous surface area for marginal gain at this stage.
- **Team sharing / marketplace.** Sharing ToolSpecs means sharing artifacts derived from credentialed sessions; the redaction guarantees needed to do that safely are a project of their own. Local-first until the single-user loop is proven.
- **WebSocket/SSE, JS crawling, live proxy.** More capture breadth does not help until the capture we have survives auth expiry and drift. Depth before breadth.

## Suggested sequence

Work in three chunks, each independently shippable:

1. **v0.2 — "a real agent can use it":** Gap 1 (MCP) + Gap 3 (approvals CLI). Small, mostly plumbing over existing runtime behavior, and unblocks everything downstream.
2. **v0.3 — "it survives the week":** Gap 2 (reauth) + Gap 4 (drift/health) + Gap 5 (merge). This is the version worth putting in testers' hands.
3. **v0.4 — "capture wins":** Gap 10 Phase A (attach-before-navigate, persistent profiles, multi-target) + Phase B (capture-parity benchmarks). Capture is the front door; it must beat HAR export before testers arrive.
4. **v0.5 — "pilot":** Gap 6 (benchmark suite) + Gap 7 (real-agent measurement) + Gap 8 (packaging) + Gap 9 (hardening audit), then invite the 3-5 testers.

The ordering principle: prove the core claim with a real agent first (cheapest, highest information), then fix the things that make it fail on day two (auth, drift), and only then spend on distribution.
