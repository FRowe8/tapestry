# Analyzer Requirements

The analyzer is the most important component in Tapestry. It converts raw observations into structured tools.

## Phase 1: Request normalization

Input: raw HAR request/response entries.

Steps:

1. Remove protocol and host from URL.
2. Split paths into segments.
3. Canonicalize query params by sorting keys.
4. Infer primitive query/body value types.
5. Group by HTTP method and initial path similarity.

Output: normalized request set.

## Phase 2: Endpoint clustering

Goal: group observed requests into parameterized endpoint definitions.

Rules:

- Same method + similar path pattern = candidate cluster.
- Varying path segments with consistent type become parameters.
- Static action words remain static: `search`, `export`, `bulk`, `me`, `current`, `login`, `logout`.
- API versions are static: `v1`, `v2`, `api/v1`.
- Same path with different method creates different tools.
- Ambiguous clusters must be split rather than over-merged.

Examples:

```text
GET /api/orders/123
GET /api/orders/456
=> GET /api/orders/{id}

GET /api/orders/search
GET /api/orders/123
=> separate clusters
```

## Phase 3: Schema inference

Infer from request query params, request bodies, and response bodies.

Rules:

- Field present in all observations: required.
- Field present in subset: optional.
- Null + concrete type: nullable.
- Arrays: infer item schema from union of observed elements.
- Conflicting concrete types: fallback to string, lower confidence, add warning.
- Small finite string sets may be enum candidates.

Type inconsistency example:

```json
{
  "field": "id",
  "type": "string",
  "confidence": 0.62,
  "warnings": ["type_inconsistency_observed"]
}
```

## Phase 4: Auth detection

Detect:

- Authorization headers.
- Cookie-based sessions.
- CSRF headers.
- Login or refresh patterns.

For v0.1, detection can be descriptive. Automatic refresh is deferred.

## Phase 5: Dependency mapping

Goal: identify when a response value is used in a subsequent request.

Algorithm:

1. Extract candidate values from responses:
   - strings length >= 6
   - UUID-like values
   - JWT-like values
   - numeric IDs, except very small integers
2. Look at the next 10–20 requests.
3. Match exact substrings in:
   - headers
   - query params
   - request body
4. Ignore common/noisy values:
   - booleans
   - timestamps
   - integers under 100
5. Create dependency only when pattern repeats at least twice.
6. Prefer precision over recall.

Example:

```json
{
  "from": "auth_login",
  "to": "list_orders",
  "field": "access_token",
  "confidence": 0.88
}
```

## Phase 6: Optional LLM refinement

LLMs may be used for:

- naming tools
- writing descriptions
- resolving ambiguous dynamic URLs from JS mode
- explaining safety ambiguity

LLMs may not:

- invent unobserved endpoints
- upgrade safety classification
- receive raw HARs by default
- receive tokens, cookies, or full payloads by default

## Confidence model

Evidence weights:

| Evidence | Base confidence |
|---|---:|
| HAR observed 10+ times | 0.95 |
| HAR observed 3–9 times | 0.85 |
| HAR observed 1–2 times | 0.70 |
| Schema source | 0.85–0.95 |
| JS static extraction | 0.60–0.80 |
| LLM-only inference | 0.40–0.65 |

Track confidence separately for:

- path
- method
- input schema
- response schema
- auth
- safety
- overall
