//! National-intermediary mode (S2 seam: resolver↔hosts — mirrors,
//! national intermediary layers, dark IDs). When configured with an
//! upstream resolver, identifiers absent from the local store are
//! fetched upstream, cached with an as-of stamp, and served through the
//! same context-routing path. I13 doctrine: caches carry as-of stamps,
//! availability decouples from origin servers — a stale cache is served
//! with an explicit stale marker when the upstream is unreachable.
//!
//! Precedence rules:
//! - locally registered identifiers (including dark and known-empty)
//!   are always answered locally and never proxied;
//! - dark identifiers never reach the upstream (national-only serving).

use std::sync::Mutex;
use std::time::Duration;

use axum::http::StatusCode;
use axum::response::Response;

use crate::api::{not_found, render_linkset_response, render_redirect, Stamp};
use crate::carrier::ResolvedIdentifier;
use crate::context::RequestContext;
use crate::httpc::{self, Url};
use crate::linkset::entries_from_document;
use crate::store::{CacheEntry, LinkEntry, Store};
use crate::time::Timestamp;

const FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// What the API layer asks the intermediary to serve.
pub struct UpstreamRequest<'a> {
    pub ident: &'a ResolvedIdentifier,
    pub ctx: &'a RequestContext,
    pub link_type: &'a str,
    pub asof: Option<Timestamp>,
    pub redirect: bool,
}

/// Serve an identifier via the upstream, through the cache.
pub async fn try_upstream(
    store: &Mutex<Store>,
    upstream: &str,
    ttl_secs: i64,
    req: UpstreamRequest<'_>,
) -> Response {
    let UpstreamRequest {
        ident,
        ctx,
        link_type,
        asof,
        redirect,
    } = req;
    let key = ident.key();
    let now = Timestamp::now();

    let render = |entries: &[LinkEntry], stamp: Stamp| -> Response {
        if redirect {
            render_redirect(entries, ctx, link_type, stamp)
        } else {
            render_linkset_response(ident.anchor(), entries, ctx, link_type, stamp)
        }
    };

    // Explicit historical queries are forwarded verbatim (the upstream
    // reconstructs as-of state) and stamped, but not cached — caching
    // would pin a historical snapshot under the live key.
    if let Some(t) = asof {
        return match fetch(upstream, &key, Some(t)).await {
            FetchOutcome::Entries(entries) if !entries.is_empty() => render(
                &entries,
                Stamp::Cached {
                    fetched_at: now,
                    cache: "miss",
                },
            ),
            FetchOutcome::Entries(_) | FetchOutcome::NotFound => not_found(),
            FetchOutcome::Error(e) => upstream_error(&e),
        };
    }

    // Cache path.
    let cached = store
        .lock()
        .expect("store poisoned")
        .cache_get(&key)
        .cloned();
    if let Some(ce) = cached {
        let fresh = now.secs.saturating_sub(ce.fetched_at.secs) < ttl_secs;
        if fresh {
            return render(
                &ce.entries,
                Stamp::Cached {
                    fetched_at: ce.fetched_at,
                    cache: "hit",
                },
            );
        }
        // TTL expired: revalidate; serve stale on upstream outage (I13).
        return match fetch(upstream, &key, None).await {
            FetchOutcome::Entries(entries) if !entries.is_empty() => {
                store.lock().expect("store poisoned").cache_put(
                    &key,
                    CacheEntry {
                        fetched_at: now,
                        entries: entries.clone(),
                    },
                );
                render(
                    &entries,
                    Stamp::Cached {
                        fetched_at: now,
                        cache: "refresh",
                    },
                )
            }
            // A revalidated absence clears nothing (404s are not cached);
            // the stale snapshot keeps serving so availability does not
            // flap with the upstream.
            FetchOutcome::Entries(_) | FetchOutcome::NotFound => render(
                &ce.entries,
                Stamp::Cached {
                    fetched_at: ce.fetched_at,
                    cache: "stale",
                },
            ),
            FetchOutcome::Error(_) => render(
                &ce.entries,
                Stamp::Cached {
                    fetched_at: ce.fetched_at,
                    cache: "stale",
                },
            ),
        };
    }

    match fetch(upstream, &key, None).await {
        FetchOutcome::Entries(entries) if !entries.is_empty() => {
            store.lock().expect("store poisoned").cache_put(
                &key,
                CacheEntry {
                    fetched_at: now,
                    entries: entries.clone(),
                },
            );
            render(
                &entries,
                Stamp::Cached {
                    fetched_at: now,
                    cache: "miss",
                },
            )
        }
        FetchOutcome::Entries(_) | FetchOutcome::NotFound => not_found(),
        FetchOutcome::Error(e) => upstream_error(&e),
    }
}

enum FetchOutcome {
    Entries(Vec<LinkEntry>),
    NotFound,
    Error(String),
}

async fn fetch(upstream: &str, key: &str, asof: Option<Timestamp>) -> FetchOutcome {
    let run = async {
        let mut url = format!(
            "{}/resolve?identifier={}&linkType=all",
            upstream.trim_end_matches('/'),
            Url::encode_query_component(key)
        );
        if let Some(t) = asof {
            url.push_str("&asof=");
            url.push_str(&Url::encode_query_component(&t.to_string()));
        }
        let url = Url::parse(&url).map_err(|e| e.to_string())?;
        let resp = httpc::request("GET", &url, &[], None, FETCH_TIMEOUT)
            .await
            .map_err(|e| e.to_string())?;
        if resp.status == 404 {
            return Ok(FetchOutcome::NotFound);
        }
        if resp.status != 200 {
            return Err(format!("upstream returned {}", resp.status));
        }
        let fetched_at = Timestamp::now();
        let entries = entries_from_document(&resp.body_string(), fetched_at)
            .map_err(|e| format!("upstream linkset: {e}"))?;
        Ok(FetchOutcome::Entries(entries))
    };
    match run.await {
        Ok(outcome) => outcome,
        Err(e) => FetchOutcome::Error(e),
    }
}

fn upstream_error(detail: &str) -> Response {
    let body = serde_json::json!({ "error": "upstream unavailable", "detail": detail }).to_string();
    let mut builder = axum::http::Response::builder().status(StatusCode::BAD_GATEWAY);
    builder = builder.header("content-type", "application/json");
    builder
        .body(axum::body::Body::from(body))
        .expect("static response parts are valid")
}
