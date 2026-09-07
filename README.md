# unidpp-resolver
Part of UniDPP (github.com/unidpp).
Rust workspace implementing the international DPP framework per
the UniDPP design framework invariants I1–I14. License: Apache-2.0.

Reference implementation of the the UniDPP design framework **L5 resolution** layer and the
**S2 seam** (mirrors, national intermediary layers, dark IDs): a
federated resolver serving **RFC 9264 JSON linksets** with context
routing (profile × role × language × region), carrier→identifier
normalization (GS1 Digital Link / GB/T 33993 / legacy EAN-13 /
ISO/IEC 15459 URN passthrough), **Accept-header content negotiation**
(discovery protocol C4), **dark identities** (enumeration
resistance, I12), **as-of stamped** resolution (I13), and
**national-intermediary mode** (upstream proxy with cache + as-of
stamping + stale-on-outage). Carrier and routing semantics mirror the
TypeScript reference `unidpp-ts/packages/resolver` (`@unidpp/resolver`);
the crate conventions mirror `unidpp-core`.

## Server choice

**axum** (0.8) over tokio — it compiles cleanly on this toolchain and
keeps the dependency set small: `axum`, `tokio`, `serde_json`. No
tracing, no metrics, no TLS stack. The bundled HTTP client (used for
upstream fetching and the integration tests) is a hand-rolled async
HTTP/1.1 implementation over `tokio::net` and therefore speaks
`http://` only — production deployments terminate TLS (or TLCP, CN
profile) at a fronting proxy, which is the the UniDPP design framework L6 pattern.

## Crate map

| Module | Purpose |
|---|---|
| `src/main.rs` | env-driven entrypoint |
| `src/lib.rs` | module wiring and re-exports |
| `src/time.rs` | deterministic UTC timestamps (RFC 3339), ported from `unidpp-core`'s `unidpp_model::time` |
| `src/gs1dl.rs` | GS1 Digital Link parsing: AIs 01/10/21, mod-10 check digit, canonical element string, URL splitting/percent-decoding |
| `src/gbt33993.rs` | GB/T 33993 shapes: GDS `/g/` paths, enterprise custom codes, bare legacy EAN-13 |
| `src/carrier.rs` | unified carrier→identifier normalization (TS `carrier.ts` port) + identifier-key forms + invalid/unrecognized classification |
| `src/context.rs` | L5 context routing: request context, specificity scoring (TS table), selection ordering |
| `src/negotiate.rs` | Accept-header content negotiation (C4): media-type → routing-context table with RFC 9110 q-weights |
| `src/linkset.rs` | RFC 9264 JSON linkset emit/parse and store-entry ↔ wire-link conversion |
| `src/store.rs` | identifier-keyed linkset store, dark intervals, revocations, append-only record log + JSONL journal, proxy cache |
| `src/discovery.rs` | `/.well-known/unidpp-resolver` discovery document |
| `src/httpc.rs` | minimal async HTTP/1.1 client (upstream + tests) |
| `src/proxy.rs` | national-intermediary mode: upstream fetch, cache, as-of stamping, stale serving |
| `src/api.rs` | axum router, handlers, resolution core, `Config`, `TestServer` |

## Endpoints

Public:

- `GET /.well-known/unidpp-resolver` (and `/`) — discovery document:
 supported identifier keys, carrier syntaxes, link types, context
 dimensions and scoring, intermediary mode, enumeration-resistance
 properties. Never exposes registered identifiers.
- `GET /resolve?carrier=…|identifier=…&profile&role&lang&region&linkType&asof`
 — resolve any carrier (GS1 DL URI, GB/T URL, bare EAN-13, 15459 URN)
 or an already-normalized identifier key (`gs1:(01)…`,
 `iso-15459:urn:…`, `gbt-33993:https://…`, or a bare `(01)…` element
 string). Returns `application/linkset+json`.
- `GET /<carrier-key>/linkset` — GS1-conventions-style path form:
 `/01/09506000134352/21/X/linkset`, `/g/6901234567892/AB2026111/linkset`
 (query qualifiers `?10=LOT` accepted).
- `GET /<carrier-key>` — **default-link rule**: 303 See Other to the
 best-scoring destination for the request context.
- `POST /normalize` — `{"carrier": …}` → the TS `parseCarrier` result
 (kind, origin, normalized identifier, granularity, resolver base).
- `GET /healthz`.

Admin (Bearer `UNIDPP_ADMIN_TOKEN` when set; open in dev mode):

- `POST /admin/linksets` — register linkset entries (append-only;
 `asOf` may lie in the past for historical reconstruction).
- `PUT /admin/linksets` — replace the currently-effective set
 (append-only: revocation records + new registrations).
- `POST /admin/revocations` — revoke one entry as of an instant.
- `POST /admin/dark` — `{"identifier", "dark": bool, "effectiveAt"?}`:
 mark/clear a dark identity.
- `GET /admin/log?limit&offset` — the append-only record log.
- `GET /admin/identifiers/{identifier}` — full state incl. revoked
 entries and dark intervals.

## Semantics

- **Linkset entries** carry `{linkType (rel), href (uri), context:
 profile/role/language(s)/region, title, type, asOf, expiry}`. Validity
 is `[asOf, expiry]` (expiry absent = open); revocations are themselves
 as-of stamped, so historical linksets reconstruct exactly.
- **Context routing** mirrors the TS scoring table: exact match 4,
 primary-subtag language fallback 3, specific link with no request
 preference 2, wildcard 1; a mismatched dimension disqualifies the
 link; ties break by registration order (first-in-document wins).
 Responses with a context return matching links best-first; without a
 context they preserve document order. The default link is announced
 via `Link: <uri>; rel="…"` and by the 303 redirect form.
- **Accept negotiation (C4)**: a declarative media-type → routing-
 context table (`application/untp+json` → `role=machine`,
 `application/en18222+json` → `role=customs`, `text/html` →
 `role=consumer`) applies **only when the request carries no explicit
 context parameters** — explicit `profile`/`role`/`lang`/`region`
 always outrank the header. Selection honours RFC 9110 q-weights
 (q=0 dropped, client order breaks ties); the negotiated context
 flows through the ordinary scoring, default-link, and 303-redirect
 machinery (query form and path form alike) and is visible in
 `x-unidpp-context`. The table is declared in the discovery document.
 `curl -H 'Accept: application/en18222+json' localhost:8080/01/09506000134352`
 routes the default link to the customs render.
- **As-of**: every response carries `X-As-Of` (the effective instant —
 `now` unless `?asof=` was given).
- **Dark identities (I12)**: the no-information 404
 (`{"error":"not found"}`) is byte-identical for unknown identifiers,
 known-but-empty ones, and dark ones. Darkening denies the identity's
 existence at and *before* its effective instant; clearing restores
 service from the clear instant. There is no listing endpoint; dark
 identifiers are never proxied upstream.
- **National intermediary (S2/I13)**: with `UNIDPP_UPSTREAM` set,
 locally-absent identifiers are fetched upstream
 (`/resolve?identifier=…&linkType=all`), cached per identifier with a
 fetch-time as-of stamp, and served through the same context-routing
 path (`X-Cache: miss|hit|refresh|stale`). Local entries always take
 precedence; a stale cache serves on upstream outage with an explicit
 stale marker; explicit `?asof=` queries are forwarded verbatim and not
 cached; upstream 404s are not cached.
- **Append-only history**: every state change (registration,
 revocation, darkening) is a record in a sequence-numbered log;
 `UNIDPP_STATE_FILE` persists it as JSONL and replays it on start.

## Configuration

| Env var | Default | Meaning |
|---|---|---|
| `UNIDPP_BIND` | `127.0.0.1:8080` | listen address |
| `UNIDPP_ADMIN_TOKEN` | unset (open) | Bearer token for `/admin/*` |
| `UNIDPP_UPSTREAM` | unset | national-intermediary mode (http:// base URL) |
| `UNIDPP_CACHE_TTL_SECS` | `300` | upstream cache TTL |
| `UNIDPP_STATE_FILE` | unset (in-memory) | JSONL journal for the record log |

## Build & test

```
cargo build # zero warnings
cargo test # 36 unit + 14 integration tests
```

Integration tests spawn real servers on ephemeral ports and speak real
HTTP: routing specificity (exact > primary-subtag fallback > wildcard
default), as-of behaviour and replacement history, dark-identity
indistinguishability, legacy EAN/GDS/DL carrier acceptance, RFC 9264
conformance (round trip with the `@unidpp/resolver` fixture shapes),
intermediary cache/stale/local-precedence/dark-never-proxied, discovery,
303 redirects, admin auth, the append-only log, and Accept negotiation
(three headers → three render destinations, explicit params outranking
the header, the redirect form).

## Deviations from the TS (documented)

- Wildcard-language entries emit `hreflang: ["*"]` (the TS treats an
 absent `hreflang` and `["*"]` identically) and every emitted link is
 stamped `unidpp:as-of` (the TS leaves validity to the store).
- A GS1-DL-shaped URL with a bad check digit demotes to a GB/T
 custom-code identifier — TS `parseCarrier` parity — so the query form
 answers 404 (unknown) for it; the path form (`/01/…`) surfaces the
 syntax error as 400.
- A linkset's `anchor` is the canonical identifier value: a URI when the
 identifier is one (15459 URNs, GB/T URLs), otherwise the canonical GS1
 element string (the TS `identifier.value`). RFC 9264 prefers URI
 anchors; the element string is used as the opaque identity token.
- The intermediary serves the normalized view of upstream documents
 (anchor/uri/rel/hreflang/unidpp:* parameters preserved; unrelated
 extension parameters dropped), and `https://` upstreams are rejected
 by the reference client (see “Server choice”).
