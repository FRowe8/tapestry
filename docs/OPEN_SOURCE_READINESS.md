# Open Source Readiness Plan

This document is the working plan for taking Tapestry from its current state to a public open-source release. It is written to be executable by an agent (or human) without additional context: each phase has concrete tasks and a verifiable "done when." Work the phases in order — each one builds on the last, and the launch phase assumes everything above it is finished.

## Context: what Tapestry is and where it stands

Tapestry turns captured web app traffic (HAR import or live CDP recording) into structured, safety-gated tools that AI agents consume through four MCP meta-tools (`search_tools`, `get_tool_schema`, `call_tool`, `get_evidence`). Read `docs/PRD.md` for positioning, `docs/ROADMAP.md` for the product gap analysis, and `docs/SAFETY_SECURITY.md` for the security model.

Already done (do not redo):

- End-to-end pipeline works and is field-tested: capture -> analyze -> ToolSpec -> runtime -> MCP stdio server.
- A real LLM agent (Claude Sonnet, driving the MCP server turn by turn) completed 4/4 tasks against a live API at the theoretical-minimum call count. Its findings (ranking, naming, schema token bloat, approval message text, unknown-key handling, live-response redaction, pagination defaults) are all fixed with regression tests.
- Git history was rewritten with `git filter-repo` to purge all personal browser captures; the repo pack is ~200KB. The 13 private HARs live untracked in `.tapestry-dev/private-fixtures/` on the maintainer's machine only.
- License is MIT. The GitHub repo `FRowe8/tapestry` is a fresh private repo containing only the cleaned history (the pre-cleanup repo was renamed to `tapestry-archive-prehistory` and should eventually be deleted).
- Test suite: 191 tests, all passing, across tapestry-core / -input / -analyzer / -runtime / -cli.

## Hard rules for anyone working in this repo

1. **HARs from real browser sessions are secrets.** Never commit one, never copy one out of `.tapestry-dev/`, never paste their contents into issues, docs, or fixtures. Only synthetic or verified-clean fixtures belong in `examples/fixtures/` (current clean set: `simple.har`, `localapp.har`, `redaction.har`, `browser-noise.har`, `dummyjson-api.har`).
2. **Never weaken the redaction or approval pipeline** to make a test or demo pass. If a test needs sensitive-looking data, seed it with obvious sentinels (see `redaction.har`'s `FAKESECRET` pattern).
3. **The four-meta-tool design is the product.** Do not add an MCP mode that exposes generated tools individually.
4. **Run `cargo test --workspace` before every commit.** All 191+ tests must pass. Run `cargo fmt --all` and keep `cargo clippy` from getting worse.
5. `.tapestry-dev/` is the maintainer's local site storage (includes browser profiles with live cookies). Never commit it, never print its credential files.

## Phase 0 — Repo mechanics

- [x] **CI.** Add `.github/workflows/ci.yml`: on push/PR run `cargo test --workspace`, `cargo clippy --workspace -- -D warnings` (fix or explicitly allow existing warnings first), and `cargo fmt --all -- --check` on Linux + Windows runners. Cache cargo.
- [x] **Fix existing clippy warnings** so `-D warnings` is honest (there are a handful of pre-existing ones: derivable impls, needless refs, `Iterator::last` on double-ended iterators).
- [x] **Branch hygiene.** `master` is the default branch and is current. Delete or archive the `phase2-cdp-comparison` branch once its content is confirmed merged (it already is; the branch is historical).
- [ ] **Delete `FRowe8/tapestry-archive-prehistory`** once the maintainer confirms nothing else is needed from it. It contains personal data in its history and must never be made public. (Requires the maintainer: `gh auth refresh -s delete_repo` then `gh repo delete FRowe8/tapestry-archive-prehistory`.)

Done when: CI is green on master, clippy is clean, the archive repo is gone.

## Phase 1 — The ten-minute quickstart

The whole first impression is: clean machine -> working agent tool call in under 10 minutes. Everything in this phase serves that.

- [x] **Rewrite README.md around one linear path**: install -> capture (or use the bundled `dummyjson-api.har`) -> `generate` -> `review` -> `serve` -> connect Claude Code via `.mcp.json` -> agent completes a task. One page, no forks. Move everything else to `docs/`.
- [x] **Demo must not require Rust.** Ship release binaries (next item) and make the README quickstart use them; `cargo install` is the fallback, `cargo run` appears only in the "Building from source" section (no CONTRIBUTING.md yet — that's Phase 6, out of scope for this pass).
- [x] **Release binaries.** Added `.github/workflows/release.yml`: hand-rolled GitHub Actions workflow (not cargo-dist) producing Windows/macOS(x64+arm64)/Linux binaries on `v*.*.*` tag push, uploaded to a GitHub release. **Not yet verified against a real release** — no tag has been pushed; needs the maintainer to push a `v0.x.y` tag and confirm the release job succeeds and `tapestry doctor` passes on a machine that has never seen the repo.
- [x] **Fix the post-capture nudge.** `import`/`record` now both accept `--generate` to chain generation immediately, and otherwise print an unmissable banner naming the exact next command.
- [x] **Demo site guidance.** README points first-time users at the bundled fixture and dummyjson.com, states plainly that bot-defended consumer sites are out of scope, and links `docs/LIMITATIONS.md`.

Done when: a person on a clean machine, following only the README, reaches a successful agent task in under 10 minutes without compiling anything.

## Phase 2 — Code health for contributors

- [x] **Split `crates/tapestry-cli/src/main.rs`** (~6,600 lines) into modules: `commands/import.rs`, `commands/record.rs`, `commands/generate.rs`, `commands/serve.rs` (moves with `mcp.rs`), `commands/approve.rs`, `commands/benchmark.rs`, etc. Pure mechanical refactor — no behavior change, tests must pass unchanged. (Actual layout: `main.rs` keeps the clap `Cli`/`Command` enum and dispatch `match`; `support.rs` holds cross-cutting infra; `commands/{approve,agent,benchmark,capture,diagnose,doctor,review,validate}.rs` hold the larger single-command logic; small commands — import/record/generate/redact/purge/tools/credentials/reauth/serve/run — stay inline in `main.rs`'s dispatch since each arm is already short and self-contained. `mcp.rs` was left at `src/mcp.rs` rather than physically moved into `commands/` — lower risk, no effect on file size or behavior. `tests.rs` (1,842 lines) holds the full test suite; see note below.)
- [x] **Document the crate layout** in `docs/ARCHITECTURE.md` if it drifted (core = types, input = capture+redaction, analyzer = clustering+schema inference, runtime = execution+safety, cli = commands+MCP). It had drifted (stale "v0.1 only supports HAR import", an unimplemented "optional LLM refinement" phase, and a `~/.tapestry/config.toml` registry layout that was never built) — rewritten to match the actual code.
- [ ] **Add doc comments** to the public functions of tapestry-core and tapestry-runtime (the crates a contributor touches first).

Done when: no source file exceeds ~1,500 lines, CI still green.

## Phase 3 — Close the capture story (product Gap 10 remainder)

- [ ] **Re-record the two real-site CDP captures** (`next`, `justkandy`) with the fixed recorder, or retire those parity pairs from `crates/tapestry-cli/benchmark_cases.json` and rely on the self-hosted suite (Phase 4) for the parity gate. The current pairs compare against empty pre-fix captures and measure nothing. Requires a human to browse during recording — coordinate with the maintainer, or retire the pairs.
- [x] **Document the streamed-response limitation** in `docs/LIMITATIONS.md`: chunked/streamed bodies (e.g. Google `batchexecute`) fail `Network.getResponseBody` and are recorded with the `cdp_response_body_unavailable` warning. Candidate future fix: `Network.streamResourceContent`.
- [ ] **README recommendation.** Only after the parity gate passes may the README recommend `tapestry record` over DevTools HAR export; until then it presents both neutrally.

Done when: every parity pair in the benchmark either passes "CDP meets HAR" or has been deliberately retired with a note.

## Phase 4 — Self-hosted benchmark suite (product Gap 6)

- [ ] **`benchmarks/` directory** with a pinned docker-compose for two apps to start: NocoDB and Ghost (add Directus/Strapi later). Fixed versions, seeded demo data.
- [ ] **One-command run**: script that captures (headless CDP against the compose apps), generates, validates, and runs `agent-task`, then reports the four metrics from `docs/BENCHMARKS.md` (callability >=70%, task completion >=60%, time-to-first-tool, manual correction rate <30%).
- [ ] **Wire into benchmark_cases.json** with `expected_endpoints` ground truth so capture parity is scored against reality, not just HAR-vs-CDP agreement.
- [ ] Retail-site stress tests stay private (they need the maintainer's local `.tapestry-dev/private-fixtures/`); the public suite is self-hosted apps only.

Done when: `docker compose up` + one script produces the four metrics against two pinned apps from a clean checkout.

## Phase 5 — Real-agent measurement (product Gap 7 remainder)

- [ ] **Native MCP hookup**: add the `.mcp.json` to a test project and drive tasks through Claude Code's actual MCP client (not the stdio-piping harness used so far — that validated semantics; this validates the integration and measures real token usage).
- [ ] **Define 5-10 tasks per benchmark app** (Phase 4) and record: task completion rate, tokens consumed per task, and tokens versus a naive baseline that stuffs every generated tool schema into context.
- [ ] **Publish the table in `docs/BENCHMARKS.md`.** This turns the "90-99% context reduction" estimate into a measurement — it is the project's headline claim and must be evidence-backed before launch publicity.

Done when: BENCHMARKS.md contains a real-agent results table produced by a reproducible script/procedure.

## Phase 6 — Community scaffolding

- [ ] **CONTRIBUTING.md**: build instructions, test instructions, the hard rules from this document (especially the HAR-secrecy rule), PR expectations (tests for behavior changes), and the "capture fixtures must be synthetic" policy.
- [ ] **SECURITY.md**: private vulnerability reporting path (GitHub security advisories), scope statement (credential handling, redaction, approval gates are all security surface).
- [ ] **Issue templates**: bug report (require `tapestry doctor` output; forbid attaching real HARs — ask for `tapestry redact`ed or synthetic reproductions), feature request, capture-quality report.
- [ ] **Decide crates.io publishing.** Check name availability for the five crates; publishing is optional at launch but reserve names early if desired.
- [ ] **README positioning section**: what Tapestry is for (internal, self-hosted, B2B apps), what it is explicitly not for (consumer sites with bot defense, ToS-hostile automation, CAPTCHA bypass), and the safety model in three sentences. The safety-first stance is the project's differentiator — lead with it.

Done when: all files exist and a stranger could file a useful bug and submit a compliant PR without asking anything.

## Phase 7 — Launch pre-flight and flip

Run every check even if it "should" pass:

- [ ] **Secret sweep**: run a scanner (gitleaks or trufflehog) over the full history; manually verify `git log --all -- 'examples/fixtures/www.*'` is empty; grep history for a few known-personal strings (maintainer's name, email fragments) beyond the standard patterns.
- [ ] **Fresh-clone verification**: clone to a new directory on a machine (or container) without `.tapestry-dev`, run the full test suite, run the README quickstart verbatim.
- [ ] **Fixture audit**: open every file in `examples/fixtures/` and confirm it is synthetic or verified-clean (no cookies, no auth headers, no real user data).
- [ ] **Docs read-through**: README, LIMITATIONS, SAFETY_SECURITY, CAPTURE_GUIDE — no stale claims (e.g. do not claim CDP > HAR unless Phase 3 closed it; do not cite token numbers Phase 5 didn't measure).
- [ ] **Flip to public** (Settings -> visibility), or push to a brand-new public repo if there is any doubt about server-side retention of old objects.
- [ ] **Tag `v0.5.0`**, publish release binaries, then announce (Show HN / r/rust / r/LocalLLaMA / MCP community). The demo GIF or asciinema of capture-to-agent-task in under a minute is worth more than any text.

Done when: the repo is public, CI badge is green, binaries are downloadable, and the quickstart works for someone who has never spoken to the maintainer.

## Explicitly out of scope for the OSS launch

Per `docs/ROADMAP.md`, do not build these now: anti-bot evasion, OAuth/SSO/MFA automation, team sharing / ToolSpec marketplace, WebSocket/SSE capture, proxy capture, browser extension. Saying no to these is part of the positioning.
