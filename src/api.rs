//! HTTP surface: axum router, handlers, and the shared resolution core
//! (local store → national-intermediary upstream → 404-with-no-
//! information). Public surface: discovery, resolution (query form,
//! GS1-style path form, redirect form), carrier normalization; admin
//! surface: linkset registration/replacement, revocations, dark
//! identities, supersessions (identity rotation), same-subject
//! correlations, the append-only record log.
//!
//! The endpoint table is the served contract itself: every handler
//! carries its `#[utoipa::path]` declaration, the document is served
//! at `/openapi.yaml` (and `/openapi.json`), browsable at `/docs`,
//! and committed as the golden `openapi.yaml`.
//!
//! the UniDPP design framework anchors: L5 resolution (linksets keyed by profile/role/
//! language/region, default-link rule); S2 seam (mirrors, national
//! intermediary layers, dark IDs); I12 enumeration resistance
//! (resolution is by-identity pull, unknown and dark are byte-identical
//! 404s, no listing); I13 as-of stamps (every response carries the
//! effective instant; caches are stamped and may serve stale).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use axum::extract::{Path, Query, Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::routing::{get, post};
use axum::Router;
use serde_json::{json, Value};
use tokio::net::TcpListener;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use crate::carrier::{
    classify_carrier, classify_path, parse_identifier_param, CarrierLookup, CarrierParse,
    ResolvedIdentifier,
};
use crate::context::{select_ordered, RequestContext};
use crate::discovery::discovery_json;
use crate::gs1dl::percent_decode;
use crate::proxy;
use crate::store::{LinkEntry, Lookup, Store};
use crate::time::Timestamp;

/// Deployment configuration (environment-driven; see `main.rs`).
#[derive(Debug, Clone)]
pub struct Config {
    pub bind: SocketAddr,
    /// Bearer token guarding `/admin/*`; `None` = open (dev mode).
    pub admin_token: Option<String>,
    /// National-intermediary mode: upstream resolver base URL
    /// (`http://…`; the reference client speaks plain http only).
    pub upstream: Option<String>,
    pub cache_ttl_secs: i64,
    /// Optional JSONL journal file (append-only record log, replayed on
    /// start).
    pub state_file: Option<PathBuf>,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            bind: "127.0.0.1:8080".parse().unwrap(),
            admin_token: None,
            upstream: None,
            cache_ttl_secs: 300,
            state_file: None,
        }
    }
}

impl Config {
    /// The environment variables this service consumes. This is the
    /// deployment contract: unidpp-config renders exactly these names
    /// for the resolver, and the contract document carries them as
    /// `x-unidpp-env-keys`.
    pub const ENV_KEYS: &'static [&'static str] = &[
        "UNIDPP_BIND",
        "UNIDPP_ADMIN_TOKEN",
        "UNIDPP_UPSTREAM",
        "UNIDPP_CACHE_TTL_SECS",
        "UNIDPP_STATE_FILE",
    ];

    pub fn from_env() -> Config {
        let mut c = Config::default();
        let mut vars: HashMap<&str, String> = HashMap::new();
        for key in Self::ENV_KEYS {
            if let Ok(value) = std::env::var(key) {
                vars.insert(*key, value);
            }
        }
        if let Some(bind) = vars.get("UNIDPP_BIND") {
            if let Ok(addr) = bind.parse() {
                c.bind = addr;
            } else {
                eprintln!("unidpp-resolver: ignoring bad UNIDPP_BIND `{bind}`");
            }
        }
        if let Some(token) = vars.get("UNIDPP_ADMIN_TOKEN") {
            if !token.is_empty() {
                c.admin_token = Some(token.clone());
            }
        }
        if let Some(upstream) = vars.get("UNIDPP_UPSTREAM") {
            if !upstream.is_empty() {
                if upstream.starts_with("https://") {
                    eprintln!(
                        "unidpp-resolver: UNIDPP_UPSTREAM is https:// — the reference \
                         client speaks http only; upstream fetches will fail"
                    );
                }
                c.upstream = Some(upstream.clone());
            }
        }
        if let Some(ttl) = vars.get("UNIDPP_CACHE_TTL_SECS") {
            if let Ok(ttl) = ttl.parse() {
                c.cache_ttl_secs = ttl;
            }
        }
        if let Some(path) = vars.get("UNIDPP_STATE_FILE") {
            if !path.is_empty() {
                c.state_file = Some(PathBuf::from(path));
            }
        }
        c
    }
}

/// Shared application state.
pub struct AppState {
    pub config: Config,
    pub store: Mutex<Store>,
}

impl AppState {
    pub fn new(config: Config) -> std::io::Result<AppState> {
        let store = Store::open(config.state_file.as_deref())?;
        Ok(AppState {
            config,
            store: Mutex::new(store),
        })
    }
}

// ---------------------------------------------------------------------------
// Response helpers
// ---------------------------------------------------------------------------

/// The no-information 404: identical bytes for unknown identifiers and
/// dark identities alike (I12). Never vary this response.
pub const NOT_FOUND_BODY: &str = "{\"error\":\"not found\"}";

pub(crate) fn not_found() -> Response {
    build_response(
        StatusCode::NOT_FOUND,
        vec![("content-type", "application/json")],
        NOT_FOUND_BODY.to_string(),
    )
}

fn bad_request(msg: &str) -> Response {
    build_response(
        StatusCode::BAD_REQUEST,
        vec![("content-type", "application/json")],
        json!({ "error": msg }).to_string(),
    )
}

fn unauthorized() -> Response {
    build_response(
        StatusCode::UNAUTHORIZED,
        vec![("content-type", "application/json")],
        "{\"error\":\"unauthorized\"}".to_string(),
    )
}

fn build_response(status: StatusCode, headers: Vec<(&str, &str)>, body: String) -> Response {
    let mut builder = Response::builder().status(status);
    for (k, v) in headers {
        builder = builder.header(k, v);
    }
    builder
        .body(axum::body::Body::from(body))
        .expect("static response parts are valid")
}

fn build_owned_response(
    status: StatusCode,
    headers: Vec<(String, String)>,
    body: String,
) -> Response {
    let mut builder = Response::builder().status(status);
    for (k, v) in headers {
        builder = builder.header(k, v);
    }
    builder
        .body(axum::body::Body::from(body))
        .expect("static response parts are valid")
}

// ---------------------------------------------------------------------------
// Resolution core
// ---------------------------------------------------------------------------

/// Effective-instant stamp for a rendered response (I13).
pub(crate) enum Stamp {
    /// Locally computed at this instant.
    Local(Timestamp),
    /// Served from the intermediary cache, fetched at this instant
    /// (mirrors/caches carry as-of stamps).
    Cached {
        fetched_at: Timestamp,
        cache: &'static str,
    },
}

/// The response view over a set of effective entries: ordered linkset
/// members plus the default link (Link header / 303 target).
struct View {
    ordered: Vec<LinkEntry>,
    default_link: Option<(String, String)>, // (href, rel)
}

fn build_view(entries: &[LinkEntry], ctx: &RequestContext, link_type: &str) -> View {
    let filtered: Vec<&LinkEntry> = if link_type == "all" {
        entries.iter().collect()
    } else {
        entries
            .iter()
            .filter(|e| e.link_type == link_type)
            .collect()
    };
    let ordered: Vec<LinkEntry> = if ctx.is_empty() {
        filtered.into_iter().cloned().collect()
    } else {
        let mut scored: Vec<(u32, &LinkEntry)> = filtered
            .iter()
            .filter_map(|e| {
                let rel = if link_type == "all" {
                    e.link_type.as_str()
                } else {
                    link_type
                };
                crate::context::score_entry(&e.routing(), ctx, rel).map(|s| (s, *e))
            })
            .collect();
        scored.sort_by_key(|(score, _)| std::cmp::Reverse(*score));
        scored.into_iter().map(|(_, e)| e.clone()).collect()
    };
    // Default-link rule: best match under the request context (or, with
    // no context, the most specific published destination); ties break
    // by registration order. With `linkType=all` the default rel `dpp`
    // still selects the redirect target.
    let default_rel = if link_type == "all" { "dpp" } else { link_type };
    let default_link = select_ordered(entries, ctx, default_rel)
        .into_iter()
        .next()
        .map(|s| (s.entry.href.clone(), s.entry.link_type.clone()));
    View {
        ordered,
        default_link,
    }
}

fn stamp_value(stamp: &Stamp) -> (Timestamp, Option<&'static str>) {
    match stamp {
        Stamp::Local(t) => (*t, None),
        Stamp::Cached { fetched_at, cache } => (*fetched_at, Some(cache)),
    }
}

/// The distinct counterpart identifiers, first-seen order (multiple
/// claims about the same counterpart are one header entry — the
/// linkset members carry the full claims).
fn distinct_others(correlations: &[crate::store::Correlation]) -> String {
    let mut seen: Vec<&str> = Vec::new();
    for c in correlations {
        if !seen.contains(&c.other.as_str()) {
            seen.push(c.other.as_str());
        }
    }
    seen.join(", ")
}

pub(crate) fn render_linkset_response(
    anchor: &str,
    entries: &[LinkEntry],
    ctx: &RequestContext,
    link_type: &str,
    stamp: Stamp,
    supersession: Option<&crate::store::Supersession>,
    correlations: &[crate::store::Correlation],
) -> Response {
    let view = build_view(entries, ctx, link_type);
    let (t, cache) = stamp_value(&stamp);
    let mut headers: Vec<(String, String)> = vec![
        ("content-type".into(), "application/linkset+json".into()),
        ("x-as-of".into(), t.to_string()),
    ];
    if let Some(s) = supersession {
        headers.push(("x-unidpp-superseded-by".into(), s.successor.clone()));
    }
    if !correlations.is_empty() {
        headers.push((
            "x-unidpp-correlated-with".into(),
            distinct_others(correlations),
        ));
    }
    if let Some(c) = cache {
        headers.push(("x-cache".into(), c.to_string()));
    }
    if !ctx.is_empty() {
        headers.push(("x-unidpp-context".into(), ctx.context_key()));
    }
    if link_type != "all" {
        if let Some((href, rel)) = &view.default_link {
            headers.push(("link".into(), format!("<{href}>; rel=\"{rel}\"")));
        }
    }
    let body = crate::linkset::emit_document_full(
        anchor,
        &view.ordered.iter().collect::<Vec<_>>(),
        supersession,
        correlations,
    );
    build_owned_response(StatusCode::OK, headers, body)
}

pub(crate) fn render_redirect(
    entries: &[LinkEntry],
    ctx: &RequestContext,
    link_type: &str,
    stamp: Stamp,
    supersession: Option<&crate::store::Supersession>,
    correlations: &[crate::store::Correlation],
) -> Response {
    let view = build_view(entries, ctx, link_type);
    let Some((href, _)) = view.default_link else {
        return not_found();
    };
    let (t, cache) = stamp_value(&stamp);
    let mut headers: Vec<(String, String)> =
        vec![("location".into(), href), ("x-as-of".into(), t.to_string())];
    // The rotation is stated on the redirect too (a header — the 303
    // carries no body).
    if let Some(s) = supersession {
        headers.push(("x-unidpp-superseded-by".into(), s.successor.clone()));
    }
    if !correlations.is_empty() {
        headers.push((
            "x-unidpp-correlated-with".into(),
            distinct_others(correlations),
        ));
    }
    if let Some(c) = cache {
        headers.push(("x-cache".into(), c.to_string()));
    }
    build_owned_response(StatusCode::SEE_OTHER, headers, String::new())
}

/// Shared resolution flow: local store first (dark/KnownEmpty never
/// reach the upstream), then the national intermediary, then the
/// no-information 404. When the request carries no explicit context
/// parameters, the Accept header negotiates the routing context
/// (discovery protocol C4): the table-mapped context selects the
/// default destination exactly like an explicit one.
async fn resolve(
    app: &AppState,
    ident: &ResolvedIdentifier,
    ctx: &RequestContext,
    accept: Option<&str>,
    link_type: &str,
    asof: Option<Timestamp>,
    redirect: bool,
) -> Response {
    let negotiated: RequestContext = if ctx.is_empty() {
        accept
            .and_then(crate::negotiate::context_for_accept)
            .unwrap_or_default()
    } else {
        ctx.clone()
    };
    let ctx = &negotiated;
    let t = asof.unwrap_or_else(Timestamp::now);
    let key = ident.key();
    let (lookup, supersession, correlations) = {
        let store = app.store.lock().expect("store poisoned");
        let lookup = store.lookup(&key, t);
        // The rotation statement and the same-subject correlations
        // ride every non-dark outcome: dark is no-information (I12)
        // and stays bare; everything else states its successor and its
        // counterparts — a resolved identity shows both, an emptied
        // one states where it went and what it correlates with
        // (absence stated, never silence).
        match lookup {
            Lookup::Dark => (lookup, None, Vec::new()),
            _ => (
                lookup,
                store.supersession_at(&key, t).cloned(),
                store
                    .correlations_at(&key, t)
                    .into_iter()
                    .cloned()
                    .collect(),
            ),
        }
    };
    match lookup {
        Lookup::Dark => not_found(),
        Lookup::KnownEmpty | Lookup::Absent
            if supersession.is_some() || !correlations.is_empty() =>
        {
            // The identifier's entries are gone (or never resolved
            // here) but its statements are published: state them
            // instead of a bare 404.
            let mut body = json!({ "error": "not found" });
            if let Some(s) = supersession.as_ref() {
                body["unidpp:superseded-by"] = json!(s.successor);
                body["unidpp:superseded-effective-at"] = json!(s.effective_at.to_string());
                body["unidpp:superseded-by-authority"] = json!(s.authority);
                body["unidpp:supersession-reason"] = json!(s.reason);
            }
            if !correlations.is_empty() {
                body["unidpp:correlated-with"] =
                    Value::Array(correlations.iter().map(|c| c.to_json()).collect());
            }
            build_response(
                StatusCode::NOT_FOUND,
                vec![("content-type", "application/json")],
                body.to_string(),
            )
        }
        Lookup::KnownEmpty => not_found(),
        Lookup::Absent => match &app.config.upstream {
            Some(upstream) => {
                proxy::try_upstream(
                    &app.store,
                    upstream,
                    app.config.cache_ttl_secs,
                    proxy::UpstreamRequest {
                        ident,
                        ctx,
                        link_type,
                        asof,
                        redirect,
                    },
                )
                .await
            }
            None => not_found(),
        },
        Lookup::Resolved(entries) => {
            let stamp = Stamp::Local(t);
            if redirect {
                render_redirect(
                    &entries,
                    ctx,
                    link_type,
                    stamp,
                    supersession.as_ref(),
                    &correlations,
                )
            } else {
                render_linkset_response(
                    ident.anchor(),
                    &entries,
                    ctx,
                    link_type,
                    stamp,
                    supersession.as_ref(),
                    &correlations,
                )
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Public handlers
// ---------------------------------------------------------------------------

fn parse_context_params(params: &HashMap<String, String>) -> RequestContext {
    let dim = |k: &str| {
        params
            .get(k)
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    };
    RequestContext {
        profile: dim("profile"),
        role: dim("role"),
        language: dim("lang"),
        region: dim("region"),
    }
}

fn parse_asof(params: &HashMap<String, String>) -> Result<Option<Timestamp>, Response> {
    match params.get("asof") {
        None => Ok(None),
        Some(s) if s.is_empty() => Ok(None),
        Some(s) => Timestamp::parse(s)
            .map(Some)
            .map_err(|e| bad_request(&e.to_string())),
    }
}

fn link_type_of(params: &HashMap<String, String>) -> String {
    params
        .get("linkType")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "dpp".to_string())
}

/// Serve the discovery document.
#[utoipa::path(
    get,
    path = "/",
    tag = "resolution",
    responses(
        (status = 200, description = "The discovery document: identifier keys, carrier syntaxes, context routing, link types, content negotiation, entry points, rotation and correlation semantics, the national-intermediary posture and the enumeration-resistance statement", body = Value, content_type = "application/json"),
    )
)]
async fn discovery(State(app): State<Arc<AppState>>) -> Response {
    build_response(
        StatusCode::OK,
        vec![("content-type", "application/json")],
        serde_json::to_string_pretty(&discovery_json(&app.config)).unwrap(),
    )
}

/// Serve the discovery document at its well-known path.
#[utoipa::path(
    get,
    path = "/.well-known/unidpp-resolver",
    tag = "resolution",
    responses(
        (status = 200, description = "The discovery document (identical bytes to `GET /`)", body = Value, content_type = "application/json"),
    )
)]
async fn discovery_wellknown(State(app): State<Arc<AppState>>) -> Response {
    discovery(State(app)).await
}

/// Liveness probe.
#[utoipa::path(
    get,
    path = "/healthz",
    tag = "resolution",
    responses(
        (status = 200, description = "The service is serving"),
    )
)]
async fn healthz() -> Response {
    build_response(StatusCode::OK, vec![], "ok".to_string())
}

/// Resolve an identifier to its linkset.
#[utoipa::path(
    get,
    path = "/resolve",
    tag = "resolution",
    params(
        ("identifier" = Option<String>, Query, description = "The identifier in any supported syntax (ISO/IEC 15459 URN, GS1 element string or Digital Link, GB/T 33993 path or custom code, legacy EAN-13); mutually exclusive with `carrier`"),
        ("carrier" = Option<String>, Query, description = "A complete carrier value; translated, then resolved — mutually exclusive with `identifier`"),
        ("asof" = Option<String>, Query, description = "An RFC 3339 instant; the record is resolved as of that instant (I13)"),
        ("profile" = Option<String>, Query, description = "Context dimension: profile"),
        ("role" = Option<String>, Query, description = "Context dimension: verifier role"),
        ("lang" = Option<String>, Query, description = "Context dimension: language (BCP 47, exact match then primary-subtag fallback)"),
        ("region" = Option<String>, Query, description = "Context dimension: region"),
        ("linkType" = Option<String>, Query, description = "The link type to resolve (default `dpp`; `all` returns every link)"),
    ),
    responses(
        (status = 200, description = "The linkset document (RFC 9264), carrying the rotation and same-subject correlation statements as members and `X-UniDPP-*` headers; the `Link` header names the default link", body = Value, content_type = "application/linkset+json"),
        (status = 400, description = "Unparseable identifier, invalid carrier check digit, or mutually exclusive parameters"),
        (status = 404, description = "The no-information 404: unknown and dark identifiers answer byte-identically (I12)"),
    )
)]
async fn resolve_query(
    State(app): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    let accept = headers.get("accept").and_then(|v| v.to_str().ok());
    let (carrier, identifier) = (params.get("carrier"), params.get("identifier"));
    let parsed: Result<ResolvedIdentifier, Response> = match (carrier, identifier) {
        (Some(_), Some(_)) => Err(bad_request(
            "`carrier` and `identifier` are mutually exclusive",
        )),
        (None, Some(i)) => parse_identifier_param(i).map_err(|e| bad_request(&e)),
        (Some(c), None) => match classify_carrier(c) {
            CarrierLookup::Ok(cp) => Ok(cp.identifier),
            CarrierLookup::Invalid => Err(bad_request("invalid carrier (check digit / values)")),
            CarrierLookup::Unrecognized => Err(bad_request("unrecognized carrier")),
        },
        (None, None) => Err(bad_request("one of `carrier` or `identifier` is required")),
    };
    let ident = match parsed {
        Ok(i) => i,
        Err(resp) => return resp,
    };
    let ctx = parse_context_params(&params);
    let link_type = link_type_of(&params);
    let asof = match parse_asof(&params) {
        Ok(a) => a,
        Err(resp) => return resp,
    };
    resolve(&app, &ident, &ctx, accept, &link_type, asof, false).await
}

/// Fallback handler implementing the GS1-conventions-style path form:
/// `/<carrier-key>/linkset` returns the linkset document,
/// `/<carrier-key>` redirects (303) to the default link. Carrier keys
/// are AI paths (`01/09506000134352/21/X`) or GDS paths
/// (`g/6901234567892/AB2026111`); unrecognized shapes fall to the
/// no-information 404.
async fn path_entry(
    State(app): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
    req: Request,
) -> Response {
    let raw_path = req.uri().path().trim_start_matches('/');
    let accept = req.headers().get("accept").and_then(|v| v.to_str().ok());
    if raw_path.is_empty() {
        return not_found();
    }
    let (key_path, want_linkset) = match raw_path.strip_suffix("/linkset") {
        Some(k) => (k, true),
        None => (raw_path, false),
    };
    let mut segments = Vec::new();
    for seg in key_path.split('/').filter(|s| !s.is_empty()) {
        match percent_decode(seg) {
            Some(s) => segments.push(s),
            None => return not_found(),
        }
    }
    // Split qualifier AIs (numeric two-digit keys) from context params.
    let qualifiers: Vec<(String, String)> = params
        .iter()
        .filter(|(k, _)| k.len() == 2 && k.bytes().all(|b| b.is_ascii_digit()))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let ctx = parse_context_params(&params);
    let link_type = link_type_of(&params);
    let asof = match parse_asof(&params) {
        Ok(a) => a,
        Err(resp) => return resp,
    };
    let ident = match classify_path(&segments, &qualifiers) {
        CarrierLookup::Ok(cp) => cp.identifier,
        CarrierLookup::Invalid => return bad_request("invalid carrier (check digit / values)"),
        CarrierLookup::Unrecognized => return not_found(),
    };
    resolve(&app, &ident, &ctx, accept, &link_type, asof, !want_linkset).await
}

fn carrier_parse_json(cp: &CarrierParse, carrier: &str) -> Value {
    json!({
        "carrier": carrier,
        "kind": cp.kind.as_str(),
        "origin": cp.origin,
        "resolverBaseUrl": cp.resolver_base_url,
        "identifier": {
            "scheme": cp.identifier.scheme,
            "value": cp.identifier.value,
            "granularity": cp.identifier.granularity,
            "key": cp.identifier.key(),
        }
    })
}

/// Translate a carrier value to its canonical identifier.
#[utoipa::path(
    post,
    path = "/normalize",
    tag = "resolution",
    request_body(content = Value, description = "The carrier under test: `{\"carrier\": \"...\"}`"),
    responses(
        (status = 200, description = "The parsed carrier: scheme, identifier components and the canonical form", body = Value, content_type = "application/json"),
        (status = 400, description = "Invalid JSON, a missing `carrier`, an invalid check digit or an unrecognized syntax"),
    )
)]
async fn normalize(body: String) -> Response {
    let parsed: Result<Value, _> = serde_json::from_str(&body);
    let v = match parsed {
        Ok(v) => v,
        Err(e) => return bad_request(&format!("invalid JSON body: {e}")),
    };
    let Some(carrier) = v.get("carrier").and_then(Value::as_str) else {
        return bad_request("`carrier` is required");
    };
    match classify_carrier(carrier) {
        CarrierLookup::Ok(cp) => build_response(
            StatusCode::OK,
            vec![("content-type", "application/json")],
            serde_json::to_string(&carrier_parse_json(&cp, carrier)).unwrap(),
        ),
        CarrierLookup::Invalid => bad_request("invalid carrier (check digit / values)"),
        CarrierLookup::Unrecognized => bad_request("unrecognized carrier"),
    }
}

// ---------------------------------------------------------------------------
// Admin handlers
// ---------------------------------------------------------------------------

fn require_admin(app: &AppState, headers: &HeaderMap) -> Option<Response> {
    let token = app.config.admin_token.as_ref()?;
    let got = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    if got == Some(token.as_str()) {
        None
    } else {
        Some(unauthorized())
    }
}

fn parse_admin_body(body: &str) -> Result<Value, Response> {
    serde_json::from_str(body).map_err(|e| bad_request(&format!("invalid JSON body: {e}")))
}

fn parse_body_identifier(v: &Value) -> Result<ResolvedIdentifier, Response> {
    let ident = v
        .get("identifier")
        .and_then(Value::as_str)
        .ok_or_else(|| bad_request("`identifier` is required"))?;
    parse_identifier_param(ident).map_err(|e| bad_request(&e))
}

fn parse_body_links(v: &Value) -> Result<Vec<LinkEntry>, Response> {
    let links = v
        .get("links")
        .and_then(Value::as_array)
        .filter(|a| !a.is_empty())
        .ok_or_else(|| bad_request("`links` must be a non-empty array"))?;
    links
        .iter()
        .map(|l| LinkEntry::from_admin_json(l).map_err(|e| bad_request(&e)))
        .collect()
}

fn parse_body_effective_at(v: &Value) -> Result<Timestamp, Response> {
    match v.get("effectiveAt") {
        None | Some(Value::Null) => Ok(Timestamp::now()),
        Some(Value::String(s)) => Timestamp::parse(s).map_err(|e| bad_request(&e.to_string())),
        Some(_) => Err(bad_request("`effectiveAt` must be an RFC 3339 string")),
    }
}

/// Register linkset entries for an identifier (append-only).
#[utoipa::path(
    post,
    path = "/admin/linksets",
    tag = "admin",
    request_body(content = Value, description = "`{{\"identifier\": ..., \"links\": [entry, ...]}}` — at least one entry; `identifier` in any supported syntax"),
    responses(
        (status = 201, description = "Registered; the stored entries and the record count are stated", body = Value, content_type = "application/json"),
        (status = 400, description = "Invalid JSON, an unparseable identifier, or an empty `links` array"),
        (status = 401, description = "A bearer token is configured and the request does not carry it"),
    )
)]
async fn admin_register(
    State(app): State<Arc<AppState>>,
    headers: HeaderMap,
    body: String,
) -> Response {
    if let Some(resp) = require_admin(&app, &headers) {
        return resp;
    }
    let v = match parse_admin_body(&body) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let ident = match parse_body_identifier(&v) {
        Ok(i) => i,
        Err(resp) => return resp,
    };
    let entries = match parse_body_links(&v) {
        Ok(e) => e,
        Err(resp) => return resp,
    };
    let key = ident.key();
    let (registered, record_count) = {
        let mut store = app.store.lock().expect("store poisoned");
        let registered = store.register(&key, entries);
        (registered, store.log_len())
    };
    let entries_json: Vec<Value> = registered.iter().map(LinkEntry::to_json).collect();
    build_response(
        StatusCode::CREATED,
        vec![("content-type", "application/json")],
        json!({
            "identifier": key,
            "registered": entries_json,
            "recordCount": record_count,
        })
        .to_string(),
    )
}

/// Replace the effective linkset of an identifier (append-only: the
/// currently effective entries are revoked, the new set appended).
#[utoipa::path(
    put,
    path = "/admin/linksets",
    tag = "admin",
    request_body(content = Value, description = "`{{\"identifier\": ..., \"links\": [entry, ...]}}`; optional `effectiveAt` (RFC 3339, default now)"),
    responses(
        (status = 200, description = "Replaced; the revoked ids, the new entries and the record count are stated", body = Value, content_type = "application/json"),
        (status = 400, description = "Invalid JSON, an unparseable identifier, or an empty `links` array"),
        (status = 401, description = "A bearer token is configured and the request does not carry it"),
    )
)]
async fn admin_replace(
    State(app): State<Arc<AppState>>,
    headers: HeaderMap,
    body: String,
) -> Response {
    if let Some(resp) = require_admin(&app, &headers) {
        return resp;
    }
    let v = match parse_admin_body(&body) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let ident = match parse_body_identifier(&v) {
        Ok(i) => i,
        Err(resp) => return resp,
    };
    let entries = match parse_body_links(&v) {
        Ok(e) => e,
        Err(resp) => return resp,
    };
    let effective_at = match parse_body_effective_at(&v) {
        Ok(t) => t,
        Err(resp) => return resp,
    };
    let key = ident.key();
    // Revoke everything currently effective (append-only), then append
    // the new set.
    let effective_ids: Vec<u64> = {
        let store = app.store.lock().expect("store poisoned");
        match store.lookup(&key, effective_at) {
            Lookup::Resolved(current) => current.iter().map(|e| e.id).collect(),
            _ => Vec::new(),
        }
    };
    {
        let mut store = app.store.lock().expect("store poisoned");
        for id in &effective_ids {
            store.revoke(&key, *id, effective_at, "superseded by replacement");
        }
    }
    let (registered, record_count) = {
        let mut store = app.store.lock().expect("store poisoned");
        let registered = store.register(&key, entries);
        (registered, store.log_len())
    };
    let entries_json: Vec<Value> = registered.iter().map(LinkEntry::to_json).collect();
    build_response(
        StatusCode::OK,
        vec![("content-type", "application/json")],
        json!({
            "identifier": key,
            "revoked": effective_ids,
            "registered": entries_json,
            "recordCount": record_count,
        })
        .to_string(),
    )
}

/// Revoke one linkset entry of an identifier.
#[utoipa::path(
    post,
    path = "/admin/revocations",
    tag = "admin",
    request_body(content = Value, description = "`{{\"identifier\": ..., \"entryId\": <id>}}`; optional `effectiveAt` (RFC 3339, default now) and `reason` (default `revoked`)"),
    responses(
        (status = 200, description = "Revoked as of the effective instant", body = Value, content_type = "application/json"),
        (status = 400, description = "An unknown identifier-entry pair or an invalid body"),
        (status = 401, description = "A bearer token is configured and the request does not carry it"),
    )
)]
async fn admin_revoke(
    State(app): State<Arc<AppState>>,
    headers: HeaderMap,
    body: String,
) -> Response {
    if let Some(resp) = require_admin(&app, &headers) {
        return resp;
    }
    let v = match parse_admin_body(&body) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let ident = match parse_body_identifier(&v) {
        Ok(i) => i,
        Err(resp) => return resp,
    };
    let entry_id = match v.get("entryId").and_then(Value::as_u64) {
        Some(id) => id,
        None => return bad_request("`entryId` is required"),
    };
    let effective_at = match parse_body_effective_at(&v) {
        Ok(t) => t,
        Err(resp) => return resp,
    };
    let reason = v
        .get("reason")
        .and_then(Value::as_str)
        .unwrap_or("revoked")
        .to_string();
    let key = ident.key();
    let exists = {
        let store = app.store.lock().expect("store poisoned");
        store
            .admin_view(&key)
            .map(|view| {
                view.get("entries")
                    .and_then(Value::as_array)
                    .map(|a| a.iter().any(|e| e.get("id") == Some(&json!(entry_id))))
                    .unwrap_or(false)
            })
            .unwrap_or(false)
    };
    if !exists {
        return bad_request(&format!("entry {entry_id} is not registered for `{key}`"));
    }
    app.store
        .lock()
        .expect("store poisoned")
        .revoke(&key, entry_id, effective_at, &reason);
    build_response(
        StatusCode::OK,
        vec![("content-type", "application/json")],
        json!({"identifier": key, "revoked": entry_id, "effectiveAt": effective_at.to_string()})
            .to_string(),
    )
}

/// Set or clear the dark state of an identifier (I12: a dark
/// identifier answers the byte-identical no-information 404).
#[utoipa::path(
    post,
    path = "/admin/dark",
    tag = "admin",
    request_body(content = Value, description = "`{{\"identifier\": ..., \"dark\": <boolean>}}`; optional `effectiveAt` (RFC 3339, default now)"),
    responses(
        (status = 200, description = "The dark state is recorded; the sequence number is stated", body = Value, content_type = "application/json"),
        (status = 400, description = "An invalid body"),
        (status = 401, description = "A bearer token is configured and the request does not carry it"),
    )
)]
async fn admin_dark(
    State(app): State<Arc<AppState>>,
    headers: HeaderMap,
    body: String,
) -> Response {
    if let Some(resp) = require_admin(&app, &headers) {
        return resp;
    }
    let v = match parse_admin_body(&body) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let ident = match parse_body_identifier(&v) {
        Ok(i) => i,
        Err(resp) => return resp,
    };
    let dark = match v.get("dark") {
        Some(Value::Bool(b)) => *b,
        _ => return bad_request("`dark` (boolean) is required"),
    };
    let effective_at = match parse_body_effective_at(&v) {
        Ok(t) => t,
        Err(resp) => return resp,
    };
    let key = ident.key();
    let op = if dark {
        crate::store::Op::SetDark {
            identifier: key.clone(),
            effective_at,
        }
    } else {
        crate::store::Op::ClearDark {
            identifier: key.clone(),
            effective_at,
        }
    };
    let rec = app.store.lock().expect("store poisoned").record(op);
    build_response(
        StatusCode::OK,
        vec![("content-type", "application/json")],
        json!({
            "identifier": key,
            "dark": dark,
            "effectiveAt": effective_at.to_string(),
            "seq": rec.seq,
        })
        .to_string(),
    )
}

/// POST /admin/correlations — record a same-subject correlation
/// (TODO.impl 225 / spec 6.3 k): `identifierA` and `identifierB`
/// denote one physical subject under different schemes. The local
/// side (A) must be known here — a correlation is a statement about
/// registered content; the counterpart (B) must be well-formed but
/// need NOT be locally registered (the cross-registry reality: a
/// national resolver may hold only one side of the claim). Direction
/// is `mutual` | `from-a` | `from-b`.
/// Record a same-subject correlation (spec 6.3 k): `identifierA`
/// (known here) and `identifierB` (well-formed; local registration
/// not required — the cross-registry case) denote one physical
/// subject under different schemes. Correlates, never consolidates.
#[utoipa::path(
    post,
    path = "/admin/correlations",
    tag = "admin",
    request_body(content = Value, description = "`{{\"identifierA\": ..., \"identifierB\": ...}}`; optional `assertor`, `evidence` and `direction` (`mutual` | `from-a` | `from-b`, default `mutual`)"),
    responses(
        (status = 201, description = "The correlation is recorded on both identifiers and is stated on every subsequent resolution of either side", body = Value, content_type = "application/json"),
        (status = 400, description = "The local side is not known here, the counterpart is not well-formed, the pair is identical, or the direction is not one of the three"),
        (status = 401, description = "A bearer token is configured and the request does not carry it"),
    )
)]
async fn admin_correlate(
    State(app): State<Arc<AppState>>,
    headers: HeaderMap,
    body: String,
) -> Response {
    if let Some(resp) = require_admin(&app, &headers) {
        return resp;
    }
    let v = match parse_admin_body(&body) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let Some(raw_a) = v.get("identifierA").and_then(Value::as_str).map(str::trim) else {
        return bad_request("`identifierA` is required");
    };
    if raw_a.is_empty() {
        return bad_request("`identifierA` must not be empty");
    }
    // The local side must be well-formed AND known here.
    let key_a = match parse_identifier_param(raw_a) {
        Ok(id) => id.key(),
        Err(e) => return bad_request(&format!("`identifierA`: {e}")),
    };
    let Some(raw_b) = v.get("identifierB").and_then(Value::as_str).map(str::trim) else {
        return bad_request("`identifierB` is required");
    };
    if raw_b.is_empty() {
        return bad_request("`identifierB` must not be empty");
    }
    // The counterpart must be well-formed; local registration is not
    // required (cross-registry).
    let key_b = match parse_identifier_param(raw_b) {
        Ok(id) => id.key(),
        Err(e) => return bad_request(&format!("`identifierB`: {e}")),
    };
    if key_b == key_a {
        return bad_request("a self-correlation states nothing");
    }
    let direction = v
        .get("direction")
        .and_then(Value::as_str)
        .unwrap_or("mutual");
    if !matches!(direction, "mutual" | "from-a" | "from-b") {
        return bad_request("`direction` must be one of `mutual`, `from-a`, `from-b`");
    }
    let assertor = v
        .get("assertor")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let evidence = v
        .get("evidence")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let known = app
        .store
        .lock()
        .expect("store poisoned")
        .admin_view(&key_a)
        .is_some();
    if !known {
        return bad_request(&format!(
            "identifier `{key_a}` is not known here — register it before correlating it"
        ));
    }
    let rec = {
        let mut store = app.store.lock().expect("store poisoned");
        store.correlate(&key_a, &key_b, &assertor, &evidence, direction);
        store.log_json(1, store.log_len().saturating_sub(1))
    };
    let record = rec
        .get("records")
        .and_then(Value::as_array)
        .and_then(|a| a.first())
        .cloned()
        .unwrap_or(Value::Null);
    build_response(
        StatusCode::CREATED,
        vec![("content-type", "application/json")],
        json!({
            "identifierA": key_a,
            "identifierB": key_b,
            "assertor": assertor,
            "direction": direction,
            "record": record,
        })
        .to_string(),
    )
}

/// POST /admin/supersessions — record an identity rotation (TODO.impl
/// 224): from `effectiveAt` the identifier's responses state the
/// successor (linkset block + `X-UniDPP-Superseded-By`, and a stated
/// 404 once its entries are gone). The identifier must already be
/// known here — a rotation record is a statement *about* registered
/// content, and refusing unknown identifiers keeps typos from
/// manufacturing phantom history.
/// Record an identity rotation: from `effectiveAt`, every non-dark
/// response for the identifier states its successor.
#[utoipa::path(
    post,
    path = "/admin/supersessions",
    tag = "admin",
    request_body(content = Value, description = "`{{\"identifier\": ..., \"successor\": ...}}`; optional `effectiveAt` (RFC 3339), `authority` and `reason`. The identifier must already be known here, and the successor must not be empty — an unstated successor is a revocation, not a rotation"),
    responses(
        (status = 200, description = "The rotation is recorded; the journal record is stated", body = Value, content_type = "application/json"),
        (status = 400, description = "An unknown identifier, an empty successor, or an invalid body"),
        (status = 401, description = "A bearer token is configured and the request does not carry it"),
    )
)]
async fn admin_supersede(
    State(app): State<Arc<AppState>>,
    headers: HeaderMap,
    body: String,
) -> Response {
    if let Some(resp) = require_admin(&app, &headers) {
        return resp;
    }
    let v = match parse_admin_body(&body) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let ident = match parse_body_identifier(&v) {
        Ok(i) => i,
        Err(resp) => return resp,
    };
    let Some(successor) = v.get("successor").and_then(Value::as_str).map(str::trim) else {
        return bad_request("`successor` is required");
    };
    if successor.is_empty() {
        return bad_request(
            "`successor` must not be empty — an unstated successor is a revocation, not a rotation",
        );
    }
    let effective_at = match parse_body_effective_at(&v) {
        Ok(t) => t,
        Err(resp) => return resp,
    };
    let authority = v
        .get("authority")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let reason = v
        .get("reason")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let key = ident.key();
    let known = app
        .store
        .lock()
        .expect("store poisoned")
        .admin_view(&key)
        .is_some();
    if !known {
        return bad_request(&format!(
            "identifier `{key}` is not known here — register it before recording its rotation"
        ));
    }
    let rec = {
        let mut store = app.store.lock().expect("store poisoned");
        store.supersede(&key, successor, effective_at, &authority, &reason);
        store.log_json(1, store.log_len().saturating_sub(1))
    };
    let record = rec
        .get("records")
        .and_then(Value::as_array)
        .and_then(|a| a.first())
        .cloned()
        .unwrap_or(Value::Null);
    build_response(
        StatusCode::OK,
        vec![("content-type", "application/json")],
        json!({
            "identifier": key,
            "supersededBy": successor,
            "effectiveAt": effective_at.to_string(),
            "record": record,
        })
        .to_string(),
    )
}

/// Read the append-only record log.
#[utoipa::path(
    get,
    path = "/admin/log",
    tag = "admin",
    params(
        ("limit" = Option<u64>, Query, description = "Records to return (default 100, maximum 10 000)"),
        ("offset" = Option<u64>, Query, description = "Records to skip (default 0)"),
    ),
    responses(
        (status = 200, description = "The journal window", body = Value, content_type = "application/json"),
        (status = 401, description = "A bearer token is configured and the request does not carry it"),
    )
)]
async fn admin_log(
    State(app): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    if let Some(resp) = require_admin(&app, &headers) {
        return resp;
    }
    let limit = params
        .get("limit")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(100)
        .min(10_000);
    let offset = params
        .get("offset")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(0);
    let view = app
        .store
        .lock()
        .expect("store poisoned")
        .log_json(limit, offset);
    build_response(
        StatusCode::OK,
        vec![("content-type", "application/json")],
        serde_json::to_string_pretty(&view).unwrap(),
    )
}

/// The operator's view of one identifier.
#[utoipa::path(
    get,
    path = "/admin/identifiers/{identifier}",
    tag = "admin",
    params(("identifier" = String, Path, description = "The identifier key, in any supported syntax")),
    responses(
        (status = 200, description = "The identifier's entries, dark state, rotation and correlations", body = Value, content_type = "application/json"),
        (status = 401, description = "A bearer token is configured and the request does not carry it"),
        (status = 404, description = "Not known here (the no-information form)"),
    )
)]
async fn admin_identifier(
    State(app): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(identifier): Path<String>,
) -> Response {
    if let Some(resp) = require_admin(&app, &headers) {
        return resp;
    }
    let view = app
        .store
        .lock()
        .expect("store poisoned")
        .admin_view(&identifier);
    match view {
        Some(v) => build_response(
            StatusCode::OK,
            vec![("content-type", "application/json")],
            serde_json::to_string_pretty(&v).unwrap(),
        ),
        None => not_found(),
    }
}

// ---------------------------------------------------------------------------
// Interface contract
// ---------------------------------------------------------------------------

/// The routed paths, declared once. The router routes by these
/// constants, the contract document is tested against them, and no
/// route may be declared with a raw literal (the gates enforce both).
pub mod paths {
    pub const ROOT: &str = "/";
    pub const WELLKNOWN: &str = "/.well-known/unidpp-resolver";
    pub const HEALTHZ: &str = "/healthz";
    pub const RESOLVE: &str = "/resolve";
    pub const NORMALIZE: &str = "/normalize";
    pub const ADMIN_LINKSETS: &str = "/admin/linksets";
    pub const ADMIN_REVOCATIONS: &str = "/admin/revocations";
    pub const ADMIN_DARK: &str = "/admin/dark";
    pub const ADMIN_SUPERSESSIONS: &str = "/admin/supersessions";
    pub const ADMIN_CORRELATIONS: &str = "/admin/correlations";
    pub const ADMIN_LOG: &str = "/admin/log";
    pub const ADMIN_IDENTIFIER: &str = "/admin/identifiers/{*identifier}";
    /// The contract document itself (not an operation of the API).
    pub const CONTRACT_YAML: &str = "/openapi.yaml";
}

/// The OpenAPI model: one declaration per handler (`#[utoipa::path]`),
/// from which the served contract, the golden file and Swagger UI all
/// derive.
#[derive(OpenApi)]
#[openapi(
    info(
        title = "UniDPP resolver",
        version = env!("CARGO_PKG_VERSION"),
        description = "Federated digital product passport resolver: RFC 9264 linksets, context routing (profile x role x language x region), carrier translation (GS1 Digital Link, GB/T 33993, legacy EAN-13, ISO/IEC 15459), dark identities, identity rotation and same-subject correlation. The GS1-style path form (`/<carrier-key>[linkset]`, 303 redirects) is served by the router fallback and carries no operation of its own. Admin operations require `Authorization: Bearer <UNIDPP_ADMIN_TOKEN>` where a token is configured.",
        license(name = "Apache-2.0", identifier = "Apache-2.0"),
    ),
    paths(
        discovery, discovery_wellknown, healthz, resolve_query, normalize,
        admin_register, admin_replace, admin_revoke, admin_dark,
        admin_supersede, admin_correlate, admin_log, admin_identifier,
    ),
    tags(
        (name = "resolution", description = "Discovery, resolution and carrier normalization"),
        (name = "admin", description = "The operator surface: linksets, revocations, dark identities, rotation, correlation, the record log"),
    )
)]
struct ApiDoc;

/// The contract document: the OpenAPI model plus the deployment keys
/// (`x-unidpp-env-keys`). Served at `/openapi.yaml` and committed as
/// the golden `openapi.yaml`.
pub fn contract_yaml() -> String {
    let mut doc = serde_json::to_value(ApiDoc::openapi()).expect("contract serializes");
    doc["info"]["x-unidpp-env-keys"] = json!(Config::ENV_KEYS);
    serde_yaml::to_string(&doc).expect("contract renders as YAML")
}

async fn openapi_yaml() -> Response {
    build_response(
        StatusCode::OK,
        vec![("content-type", "application/yaml")],
        contract_yaml(),
    )
}

// ---------------------------------------------------------------------------
// Server wiring
// ---------------------------------------------------------------------------

pub fn router(app: Arc<AppState>) -> Router {
    Router::new()
        .merge(SwaggerUi::new("/docs").url("/openapi.json", ApiDoc::openapi()))
        .route(paths::ROOT, get(discovery))
        .route(paths::WELLKNOWN, get(discovery_wellknown))
        .route(paths::HEALTHZ, get(healthz))
        .route(paths::RESOLVE, get(resolve_query))
        .route(paths::NORMALIZE, post(normalize))
        .route(
            paths::ADMIN_LINKSETS,
            post(admin_register).put(admin_replace),
        )
        .route(paths::ADMIN_REVOCATIONS, post(admin_revoke))
        .route(paths::ADMIN_DARK, post(admin_dark))
        .route(paths::ADMIN_SUPERSESSIONS, post(admin_supersede))
        .route(paths::ADMIN_CORRELATIONS, post(admin_correlate))
        .route(paths::ADMIN_LOG, get(admin_log))
        .route(paths::ADMIN_IDENTIFIER, get(admin_identifier))
        .route(paths::CONTRACT_YAML, get(openapi_yaml))
        .fallback(path_entry)
        .with_state(app)
}

/// Run until stopped (used by `main`).
pub async fn run(config: Config) -> std::io::Result<()> {
    let app = Arc::new(AppState::new(config.clone())?);
    let listener = TcpListener::bind(config.bind).await?;
    eprintln!("unidpp-resolver listening on http://{}", config.bind);
    if let Some(upstream) = &config.upstream {
        eprintln!("national-intermediary mode: upstream {upstream}");
    }
    axum::serve(listener, router(app)).await
}

/// A spawned server on an ephemeral port (integration tests and
/// embedders). `stop()` waits for the listener to be released.
pub struct TestServer {
    pub addr: SocketAddr,
    pub base_url: String,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    join: Option<tokio::task::JoinHandle<()>>,
}

impl TestServer {
    pub async fn spawn(config: Config) -> std::io::Result<TestServer> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let app = Arc::new(AppState::new(config)?);
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let join = tokio::spawn(async move {
            let serve = axum::serve(listener, router(app)).with_graceful_shutdown(async {
                let _ = rx.await;
            });
            if let Err(e) = serve.await {
                eprintln!("unidpp-resolver: server task ended: {e}");
            }
        });
        Ok(TestServer {
            addr,
            base_url: format!("http://{addr}"),
            shutdown: Some(tx),
            join: Some(join),
        })
    }

    /// Stop the server and wait until its listener is released.
    pub async fn stop(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(join) = self.join.take() {
            let _ = join.await;
        }
    }
}

// ---------------------------------------------------------------------------
// Contract gates
// ---------------------------------------------------------------------------

#[cfg(test)]
mod contract_gates {
    use super::*;
    use crate::httpc::{request, Url};
    use std::time::Duration;

    /// The contract form of a routed path: the router's tail
    /// wildcard (`{*identifier}`) is a captured parameter in the
    /// document (`{identifier}`).
    fn to_doc(path: &str) -> String {
        path.replace("{*", "{")
    }

    /// The contract paths with their documented methods.
    fn documented() -> std::collections::BTreeMap<String, Vec<String>> {
        let doc: Value = serde_yaml::from_str(&contract_yaml()).expect("contract parses");
        doc["paths"]
            .as_object()
            .expect("paths object")
            .iter()
            .map(|(path, item)| {
                let methods = VERBS
                    .iter()
                    .filter(|v| item.get(*v).is_some())
                    .map(|v| v.to_string())
                    .collect();
                (path.clone(), methods)
            })
            .collect()
    }

    const VERBS: [&str; 5] = ["get", "post", "put", "delete", "patch"];

    /// The routed paths, from the constants the router routes by
    /// (the contract route itself carries no operation).
    fn routed() -> Vec<&'static str> {
        [
            paths::ROOT,
            paths::WELLKNOWN,
            paths::HEALTHZ,
            paths::RESOLVE,
            paths::NORMALIZE,
            paths::ADMIN_LINKSETS,
            paths::ADMIN_REVOCATIONS,
            paths::ADMIN_DARK,
            paths::ADMIN_SUPERSESSIONS,
            paths::ADMIN_CORRELATIONS,
            paths::ADMIN_LOG,
            paths::ADMIN_IDENTIFIER,
        ]
        .to_vec()
    }

    #[test]
    fn the_golden_matches_the_committed_contract() {
        assert_eq!(contract_yaml(), include_str!("../openapi.yaml"));
    }

    #[test]
    #[ignore = "regenerates openapi.yaml after a route change: cargo test -- --ignored export"]
    fn export_golden() {
        std::fs::write(
            concat!(env!("CARGO_MANIFEST_DIR"), "/openapi.yaml"),
            contract_yaml(),
        )
        .expect("golden written");
    }

    #[test]
    fn every_routed_path_is_documented() {
        let doc = documented();
        for path in routed() {
            let key = to_doc(path);
            assert!(
                doc.contains_key(&key),
                "routed but undocumented: {path} (contract speaks `{key}`)"
            );
        }
    }

    #[test]
    fn every_documented_path_is_routed() {
        let routed: Vec<String> = routed().iter().map(|p| to_doc(p)).collect();
        for path in documented().keys() {
            assert!(routed.contains(path), "documented but not routed: {path}");
        }
    }

    #[test]
    fn routes_are_declared_by_constant_not_literal() {
        let src = include_str!("api.rs");
        assert_eq!(
            src.matches(".route(\"").count(),
            0,
            "route paths come from the paths:: constants"
        );
    }

    /// The `VERB /path` endpoint references embedded in the discovery
    /// document must all be contracted operations.
    #[test]
    fn discovery_names_only_contracted_endpoints() {
        let doc = discovery_json(&Config::default()).to_string();
        let documented: Vec<String> = documented().into_keys().collect();
        for verb in VERBS.map(str::to_uppercase) {
            let mut rest = doc.as_str();
            while let Some(pos) = rest.find(&verb) {
                let after = &rest[pos + verb.len()..];
                rest = after;
                let Some(path) = after.strip_prefix(" /") else {
                    continue;
                };
                let taken: String = path
                    .chars()
                    .take_while(|c| !matches!(c, ' ' | '"' | '{' | '<'))
                    .collect();
                let path = taken.split('?').next().unwrap_or("").to_string();
                if path.is_empty() {
                    continue;
                }
                assert!(
                    documented.contains(&format!("/{path}")),
                    "discovery names `{verb} /{path}` — no such operation in the contract"
                );
            }
        }
    }

    /// The behavioral half: every documented operation answers
    /// anything but 405, and every undocumented method on a documented
    /// path answers 405 — on the live router.
    #[tokio::test]
    async fn the_router_serves_the_contract_exactly() {
        let ts = TestServer::spawn(Config::default())
            .await
            .expect("test server");
        for (path, methods) in documented() {
            let concrete = path.replace("{identifier}", "probe-x");
            for verb in VERBS {
                let resp = request(
                    &verb.to_uppercase(),
                    &Url::parse(&format!("{}{concrete}", ts.base_url)).expect("probe url"),
                    &[],
                    if verb == "get" {
                        None
                    } else {
                        Some(b"{}".as_slice())
                    },
                    Duration::from_secs(5),
                )
                .await
                .expect("probe answered");
                if methods.contains(&verb.to_string()) {
                    assert_ne!(
                        resp.status, 405,
                        "{verb} {concrete}: the contract says routed, the router says otherwise"
                    );
                } else {
                    assert_eq!(
                        resp.status, 405,
                        "{verb} {concrete}: served but not in the contract"
                    );
                }
            }
        }
        ts.stop().await;
    }
}
