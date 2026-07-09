# Vision: where Tapestry goes after launch

This document is the strategic companion to `docs/OPEN_SOURCE_READINESS.md`
(which covers *getting to* the open-source launch). It exists so that any
future contributor or agent can judge whether a proposed piece of work moves
the project toward its actual goal, and so the maintainer has a written
position on the "why" questions: what real-world value this adds, how it could
grow, and what the honest risks are.

## The value thesis

**The long tail of software has no API.** Internal admin panels, legacy ERPs,
small B2B SaaS, self-hosted tools — an enormous amount of the software people
actually operate every day exposes useful behavior only through a browser.
Agents today have two options there:

1. **Drive a browser** (computer-use / browser-use agents). Works, but every
   action costs seconds and thousands of tokens, breaks on UI changes, and is
   nearly impossible to audit or govern ("what exactly can this agent do?").
2. **Skip those apps entirely.** The common outcome.

Tapestry offers a third path: **demonstrate the workflow once, get
deterministic tools forever.** A captured session becomes typed, evidence-
backed, safety-classified tools that execute as direct HTTP calls — a small
structured JSON response per step instead of a page snapshot per click,
which should make it far cheaper and faster than browser driving (the
side-by-side browser-agent measurement is a defined follow-up in
`benchmarks/README.md`; until it runs, keep that comparison qualitative in
public copy). And *governable*: every tool has provenance (`get_evidence`),
a safety class, an approval gate, drift detection, and redaction guarantees.

The durable differentiator is **not** token savings — model prices fall and
context windows grow. It is **determinism, auditability, and the safety
pipeline**. Those matter most exactly where browser-driving agents are least
acceptable: businesses automating real operations on systems of record.

## Coverage tiers: what Tapestry bridges, and what it deliberately doesn't

Websites serve data in more ways than JSON APIs, and "why can't my agent use
this site?" is the demand Tapestry exists to answer. But not every delivery
mode can be bridged without destroying the properties (determinism,
auditability, redaction) that make Tapestry worth using. The official
position is a three-tier model; a site's tier is a property of how it serves
data, not a roadmap promise:

- **Tier 1 — structured APIs (today, full guarantees).** JSON/REST and
  GraphQL endpoints get the whole pipeline: inferred schemas in both
  directions, structural redaction, safety classification, evidence, drift
  detection.
- **Tier 2 — fragment endpoints (planned, request-side guarantees).** Some
  sites fetch server-rendered HTML fragments over XHR for their listing and
  search flows (e.g. `next.co.uk`'s `/products-fragment`). The *request* side
  is exactly as structured as a JSON API — inferable input schema, replayable
  auth, method-based safety class — only the response is unstructured.
  Tapestry will tool these: size-capped, text-redacted HTML responses,
  explicitly labeled low-confidence and approval-gated, behind an opt-in.
  The scoped design (including the redaction model) is
  `docs/FRAGMENT_TOOLS.md`; it ships post-launch under growth step 3's
  evidence rule. Until then the pipeline detects fragments and reports them
  in capture warnings and `diagnose` rather than failing silently.
- **Tier 3 — page scraping (never).** Sites with no XHR data traffic at all,
  where data exists only inside full page HTML. Bridging those means DOM
  extraction and browser puppeteering: brittle per-site logic, no meaningful
  safety classification, no redaction story, and a crowded field
  (computer-use and browser-use agents) where Tapestry adds nothing. The
  answer there is *pairing* Tapestry with a browser-automation agent — hot
  path through captured tools, cold path through the browser — and the docs
  say so plainly instead of implying Tapestry will absorb that job.

The tier boundary protects the thesis: every mode Tapestry supports must
keep the safety pipeline honest, or the differentiator dissolves.

## The OpenClaw lesson (and why we are not OpenClaw)

OpenClaw (the viral open-source personal assistant) demonstrated what makes an
agent project explode: a visceral, personal magic moment ("my AI texts me and
actually does things"), local-first trust, a hackable single-binary feel, and
a maintainer shipping relentlessly in public. It also demonstrated the cost of
that path: a huge, scary permission surface treated as a feature.

Tapestry is infrastructure, not a companion. Its ceiling is dev-tool adoption,
not consumer virality, and pretending otherwise would misallocate effort. But
three OpenClaw lessons transfer directly:

1. **The 60-second demo is the product's ambassador.** Ours is: *record
   yourself clicking around an app for a minute → an agent completes a task
   against it via MCP → show the token/latency delta vs a browser agent.*
   Everything about launch materials should serve that clip.
2. **Local-first is a trust feature.** Credentials never leave the machine;
   the code is inspectable; there is no cloud dependency. Keep it that way in
   the free core, and say it loudly.
3. **Momentum compounds.** Visible, frequent, honest iteration (changelogs,
   benchmark tables that admit weaknesses, LIMITATIONS.md) is itself a
   differentiator in a space full of overclaiming.

And one strategic connection rather than comparison: **agent assistants create
Tapestry's demand.** Every OpenClaw-style user eventually asks "why can't my
agent use \<web app with no API\>?" Being the standard answer to that question
— the thing agent communities recommend to each other — is the realistic
version of "going viral" for an infrastructure tool.

## Growth path (in order; do not skip ahead)

**1. Prove it (pilot, current focus).** Readiness plan Phases 3-7: benchmark
suite, real-agent measurements, launch. Success = 3-5 external testers keep
tools working across multiple days without hand-editing JSON, and published
numbers back the headline claims.

**2. Meet agents where they live (integrations).** Lowest-effort, highest-
leverage growth after launch:
- A polished `.mcp.json` story for Claude Code / Claude Desktop (packaging as
  a one-click extension where supported).
- An OpenClaw skill and adapters/examples for the popular agent frameworks —
  a few dozen lines each, disproportionate discovery value.
- A "works great with" list of self-hosted apps (from the benchmark suite)
  that doubles as SEO for people searching "\<app\> API automation".

**3. Deepen capture (only where testers actually hit walls).** Candidate
order, driven by pilot feedback, not speculation: streamed-response bodies
(`Network.streamResourceContent`), HTML fragment tools (Tier 2 — designed in
`docs/FRAGMENT_TOOLS.md`, the largest coverage win available), browser-
extension capture (records from the user's real browser — removes
login/profile friction entirely), proxy capture for native/mobile clients,
WebSocket/SSE. Each of these is listed as deliberately-not-now in the PRD;
they graduate only on evidence.

**4. The team layer (the commercial option).** The single-user local loop
stays free and open source, permanently — it is the trust foundation. If (and
only if) pilot demand pulls this way, the open-core paid layer is:
- shared ToolSpec registries with org-level approval workflows,
- fleet health/drift dashboards across many sites and users,
- audit logs, SSO, policy controls (who may approve write tools),
- managed credential re-auth for teams.
Sharing ToolSpecs safely is a genuine engineering project (artifacts derive
from credentialed sessions); its difficulty is exactly why it is worth money.

**5. The registry endgame (speculative, do not build).** If the benchmark
suite proves ToolSpecs for common self-hosted apps (NocoDB, Ghost, Directus,
Strapi...) are portable across instances, a community registry of clean,
synthetic-capture-derived ToolSpecs gives Tapestry network effects: install →
pull the spec for your app → agent works immediately, no capture needed. This
is the most plausible "big" outcome and also the easiest place to burn months
prematurely. Revisit only after the pilot proves the single-user loop.

## Honest risks

- **Browser-use agents get cheap and reliable faster than expected.** Mitigant:
  governance and determinism remain differentiators even then; also Tapestry
  can coexist (use captured tools for the hot path, a browser for the cold).
- **Anthropic/OpenAI ship first-party "record to tools".** Mitigant: local-
  first + open source + self-hosted focus is precisely the segment first-party
  cloud offerings serve worst. Speed and community are the real defense.
- **The drift problem proves worse than the health system handles.** If
  internal APIs churn weekly, "capture once" collapses. The pilot must measure
  tool half-life honestly; if it is short, auto-heal (re-capture diffing,
  semi-automatic re-inference) jumps the priority queue.
- **A security incident.** For a credential-handling tool, one real leak ends
  trust permanently. This is why redaction tests, `cargo audit`, and the
  SECURITY.md reporting path are launch blockers, not nice-to-haves.

## Success metrics worth tracking (post-launch)

- Time-to-first-working-tool for a new user (target: under 10 minutes).
- Tool half-life: median days a generated tool keeps working without
  re-capture (the "capture once" claim, quantified).
- Real-agent task completion rate and per-task token cost vs the browser-agent
  baseline on the benchmark suite (the headline table in BENCHMARKS.md).
- Number of apps in the community "works with" list.
- External contributors with a merged PR (the open-source health signal).
