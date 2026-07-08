# HTML fragment tools — the Tier 2 design

**Status: designed, not scheduled.** This is post-launch work under the growth
sequence in `docs/VISION.md` (capture depth graduates on pilot evidence, not
speculation). Nothing in this document is launch-blocking. It exists so the
decision — what Tapestry will bridge and how, without weakening its
guarantees — is made once, deliberately, instead of during a demo crunch.

## Problem

Some sites serve their main listing/search flows as server-rendered HTML
fragments fetched by page JavaScript, not as JSON APIs. The canonical example
is `next.co.uk`: its product search issues `GET /products-fragment?...`
returning `text/html`. Today the pipeline is JSON-native at every stage —
import drops non-JSON bodies, the analyzer filters non-API `text/html` as
page noise, and the runtime errors on non-JSON responses — so these sites
capture plenty of traffic but generate only secondary config/read tools.
Since the fragment-visibility change, this is at least *loud*:
`Observation::is_html_fragment` detects the pattern, `record`/`generate`
warn, and `diagnose` reports an `html-fragments` count. This document is the
design for actually tooling those endpoints.

## Position (see the coverage tiers in `docs/VISION.md`)

The request side of a fragment endpoint is exactly as structured as a JSON
API: inferable input schema from query/path, replayable auth headers, a
method-based safety classification. Only the *response* is unstructured — and
modern agents read HTML competently; what they cannot do is discover the
endpoint, know its parameters, and call it safely. So Tapestry tools these
endpoints with full request-side guarantees and explicitly degraded,
clearly-labeled response-side ones. What Tapestry does **not** do (Tier 3,
permanently): scrape full pages, infer DOM selectors, or drive a browser —
sites with no XHR data traffic at all remain the domain of browser-automation
agents, which Tapestry should complement, not compete with.

## Scope

- **In:** XHR/fetch-initiated `text/html` responses on the primary site — the
  population `Observation::is_html_fragment` already identifies.
- **Out (unchanged non-goals):** full page navigations, selector-based
  extraction, JS crawling, bot-defended consumer sites, WebSocket/SSE,
  anti-bot evasion.

## Design, by pipeline stage

### 1. Capture and import: keep fragment bodies as text

- **HAR import:** when an entry is a fragment, keep the body as a
  `Value::String` instead of discarding non-JSON text. Strip `<script>`,
  `<style>`, and HTML comments *before persistence* (smaller, and removes the
  most common inline-secret carriers, e.g. CSRF tokens in script blobs). Cap
  at `FRAGMENT_BODY_MAX_BYTES` (proposed 64 KB); add an
  `html_fragment_truncated` observation warning when capped.
- **CDP:** `mark_response_body` currently persists JSON only; extend it to
  keep stripped/capped `text/html` bodies for fragment observations under
  the same rules. (Fragments served with chunked/streamed encoding still hit
  the separate `Network.getResponseBody` limitation; the
  `Network.streamResourceContent` work benefits both.)

### 2. Redaction — the load-bearing part

Structural JSON redaction (`redact_sensitive_fields`) cannot apply to HTML.
Fragment bodies pass through a dedicated **text redactor at capture time**,
the same stage where JSON redaction runs today, applying in order:

1. **Exact-value masking:** any literal occurrence of values already known to
   be secrets for this capture — stored credential header values, cookie
   values, redacted query-param values. Highest confidence, no heuristics.
2. **Token-shape masking:** JWTs (`eyJ…` dot-triplets), `Bearer <…>` strings,
   and high-entropy base64/hex runs ≥ 32 chars.
3. **Form-field masking:** values of HTML inputs whose `name`/`id` matches
   `is_secret_field_name` (e.g. `<input name="csrf_token" value="…">`).

Stated honestly: (a) everything the JSON pipeline masks by exact value is
masked here too; (b) heuristic masking of *unknown* secrets is best-effort,
so fragment bodies carry more residual-leak risk than JSON bodies —
LIMITATIONS.md must say so, and this asymmetry is the reason for the opt-in
and approval gates below. The seeded-sentinel test approach
(`redaction.har`'s `FAKESECRET` pattern) extends to a fragment fixture:
sentinels seeded in HTML text, attributes, and script blobs must never
survive into observations, ToolSpecs, evidence, traces, or live responses.

### 3. Analyzer

- Keep fragments (flip today's `html_fragment_unsupported` drop) **only**
  when generation runs with the opt-in flag (below).
- New `ResourceKind::HtmlFragment`. Input-schema inference is unchanged — it
  already works on query/path/headers. Response schema is
  `{"type": "string", "contentMediaType": "text/html"}` with
  `confidence.response_schema` fixed low (proposed 0.3) so `overall` lands
  below `DEFAULT_CONFIDENCE_THRESHOLD` and the existing low-confidence rule
  forces approval. Tool warning `html_fragment_response`; the description
  states the tool returns HTML text, not JSON.
- Search ranking deprioritizes `HtmlFragment` the way it already does
  `ConfigResource`/`Telemetry`, so a fragment tool never outranks a real API
  tool for the same task.

### 4. Runtime

- `call_tool` branches on response content-type for fragment tools:
  `text/html` → strip scripts/styles/comments, collapse whitespace, cap at
  `FRAGMENT_RESPONSE_MAX_CHARS` (proposed 20,000, ≈5k tokens), apply the same
  text redactor as capture, and return
  `{"status": "ok", "response_format": "html_fragment", "data": {"html": "…"}, "truncated": bool}`.
- **JSON paths are untouched.** `parse_response_body` and
  `redact_sensitive_fields` behavior for JSON tools does not change, and a
  non-fragment tool receiving unexpected HTML keeps today's error behavior
  (that is a drift signal, not something to silently accept).
- Drift/health for fragments is status-code based plus "response is
  non-empty HTML" — field-level conformance does not apply.

### 5. Opt-in and safety gates (stacked, not either/or)

1. **Generation opt-in:** `tapestry generate --html-fragments`, default off.
   Without the flag, behavior is exactly today's: filtered, counted, warned.
2. **Approval gate:** fragment tools always arrive `approved: false` via the
   low-confidence rule. `tapestry approve --list` shows the resource kind and
   a redacted body preview so the human sees what the agent would receive.
3. **Meta-tool surface unchanged:** the four meta-tools remain the only MCP
   surface.

## Explicit trade-offs

- Response usefulness depends on the agent parsing HTML, and per-call token
  cost is far higher than JSON tools — hence the cap and the ranking
  deprioritization.
- Textual redaction is weaker than structural redaction. That justifies the
  opt-in and approval gates; it must never be argued the other direction
  (loosening JSON-path guarantees for symmetry).

## Test plan

- A synthetic fragment fixture HAR in `examples/fixtures/` with `FAKESECRET`
  sentinels in text, attribute, and script positions.
- Round trip: import → `generate --html-fragments` → tool exists with kind
  `HtmlFragment` and approval required → approve → call against a local stub
  server → response is stripped, capped, redacted.
- Regression: without the flag, output is byte-identical to today for the
  same capture.
- Private acceptance check: re-run the retired `next` HAR locally (never
  committed — real captures are secrets) and confirm the listing flow
  produces a usable tool.

## Done when

A fragment-based listing flow (the `next` shape) produces an approved,
callable tool whose response an MCP agent uses to complete a task; the
seeded-sentinel suite is green; and there is zero behavior change for sites
without fragments or users without the flag.
