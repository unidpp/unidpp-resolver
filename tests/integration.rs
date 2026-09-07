//! Integration tests: real HTTP against servers spawned on ephemeral
//! ports. Covers the required behaviours: routing specificity
//! (exact > language fallback > default), as-of reconstruction,
//! dark-identity indistinguishability, legacy EAN acceptance, RFC 9264
//! format conformance (round trip with the TS fixtures' shapes), plus
//! the national-intermediary mode, discovery, redirects, admin auth and
//! the append-only record log.

use std::time::Duration;

use serde_json::{json, Value};
use unidpp_resolver::httpc::{self, HttpResponse, Url};
use unidpp_resolver::linkset::{entry_from_link_object, parse_document};
use unidpp_resolver::store::LinkEntry;
use unidpp_resolver::{Config, TestServer, Timestamp};

const EU_PROFILE: &str = "urn:unidpp:profile:eu-espr-electronics";
const JP_PROFILE: &str = "urn:unidpp:profile:jp-meti-pse";
const EAN_ID: &str = "gs1:(01)06901234567892";
const ISO_ID: &str = "iso-15459:urn:iso:std:iso-iec:15459:unidpp:inst:84120099012345";
const AS_OF: &str = "2026-01-01T00:00:00Z";

async fn request(method: &str, url: &str, body: Option<&str>, token: Option<&str>) -> HttpResponse {
    let url = Url::parse(url).expect("test URL");
    let mut headers: Vec<(String, String)> = Vec::new();
    if body.is_some() {
        headers.push(("content-type".into(), "application/json".into()));
    }
    if let Some(t) = token {
        headers.push(("authorization".into(), format!("Bearer {t}")));
    }
    httpc::request(
        method,
        &url,
        &headers,
        body.map(str::as_bytes),
        Duration::from_secs(5),
    )
    .await
    .expect("http request")
}

async fn get(url: &str) -> HttpResponse {
    request("GET", url, None, None).await
}

fn enc(s: &str) -> String {
    Url::encode_query_component(s)
}

fn json_of(resp: &HttpResponse) -> Value {
    serde_json::from_str(&resp.body_string()).expect("response JSON")
}

fn links_of(resp: &HttpResponse) -> Vec<Value> {
    parse_document(&resp.body_string()).expect("linkset document")
}

/// Register links through the admin API.
async fn register(server: &TestServer, identifier: &str, links: Value) -> HttpResponse {
    let body = json!({"identifier": identifier, "links": links}).to_string();
    request("POST", &format!("{}/admin/linksets", server.base_url), Some(&body), None).await
}

fn four_links() -> Value {
    json!([
        {"linkType": "dpp", "href": "https://dpp.unidpp.org/eu/1",
         "profile": EU_PROFILE, "role": "consumer", "language": ["en", "fr"],
         "region": "EU", "asOf": AS_OF, "type": "application/json",
         "title": "EU ESPR passport"},
        {"linkType": "dpp", "href": "https://dpp-jp.meti.example.go.jp/passport/1",
         "profile": JP_PROFILE, "role": "consumer", "language": ["ja"],
         "region": "JP", "asOf": AS_OF},
        {"linkType": "dpp", "href": "https://dpp.unidpp.org/generic/1", "asOf": AS_OF},
        {"linkType": "dpp", "href": "https://dpp.unidpp.org/recycler/1",
         "role": "recycler", "language": ["en"], "asOf": AS_OF}
    ])
}

async fn spawn() -> TestServer {
    TestServer::spawn(Config::default()).await.expect("spawn server")
}

// ---------------------------------------------------------------------------
// Routing specificity
// ---------------------------------------------------------------------------

#[tokio::test]
async fn routing_specificity_exact_over_fallback_over_default() {
    let server = spawn().await;
    assert_eq!(register(&server, ISO_ID, four_links()).await.status, 201);
    let base = &server.base_url;

    // Exact profile+role+language+region: the EU link wins, the generic
    // wildcard stays in the multi-link response.
    let resp = get(&format!(
        "{base}/resolve?identifier={}&profile={}&role=consumer&lang=fr&region=EU",
        enc(ISO_ID),
        enc(EU_PROFILE)
    ))
    .await;
    assert_eq!(resp.status, 200);
    let links = links_of(&resp);
    assert_eq!(links[0]["uri"], "https://dpp.unidpp.org/eu/1");
    assert!(links.len() >= 2, "multi-link response keeps wildcard alternates");
    assert_eq!(
        resp.header("link").unwrap(),
        "<https://dpp.unidpp.org/eu/1>; rel=\"dpp\""
    );
    assert_eq!(
        resp.header("x-unidpp-context").unwrap(),
        format!("profile={EU_PROFILE};role=consumer;lang=fr;region=EU")
    );

    // Language primary-subtag fallback: ja-JP routes to the ja link.
    let resp = get(&format!(
        "{base}/resolve?identifier={}&profile={}&role=consumer&lang=ja-JP&region=JP",
        enc(ISO_ID),
        enc(JP_PROFILE)
    ))
    .await;
    let links = links_of(&resp);
    assert_eq!(links[0]["uri"], "https://dpp-jp.meti.example.go.jp/passport/1");

    // Language mismatch: an English speaker in the JP profile context
    // falls back to the wildcard default (the ja link is rejected).
    let resp = get(&format!(
        "{base}/resolve?identifier={}&profile={}&role=consumer&lang=en&region=JP",
        enc(ISO_ID),
        enc(JP_PROFILE)
    ))
    .await;
    let links = links_of(&resp);
    assert_eq!(links[0]["uri"], "https://dpp.unidpp.org/generic/1");

    // Role routing with no profile preference.
    let resp = get(&format!("{base}/resolve?identifier={}&role=recycler", enc(ISO_ID))).await;
    let links = links_of(&resp);
    assert_eq!(links[0]["uri"], "https://dpp.unidpp.org/recycler/1");

    // No context at all: all four links in registration (document)
    // order — reordering is a context-routing concern; the default
    // link comes from the scoring pass.
    let resp = get(&format!("{base}/resolve?identifier={}", enc(ISO_ID))).await;
    let links = links_of(&resp);
    assert_eq!(links.len(), 4);
    let uris: Vec<&str> = links
        .iter()
        .map(|l| l["uri"].as_str().unwrap())
        .collect();
    assert_eq!(
        uris,
        vec![
            "https://dpp.unidpp.org/eu/1",
            "https://dpp-jp.meti.example.go.jp/passport/1",
            "https://dpp.unidpp.org/generic/1",
            "https://dpp.unidpp.org/recycler/1"
        ]
    );
    assert_eq!(
        resp.header("link").unwrap(),
        "<https://dpp.unidpp.org/eu/1>; rel=\"dpp\""
    );

    // A rel nothing serves: the identifier resolves (linkset exists),
    // so an empty linkset document — not a 404 — comes back.
    let resp = get(&format!(
        "{base}/resolve?identifier={}&linkType=dss-archive",
        enc(ISO_ID)
    ))
    .await;
    assert_eq!(resp.status, 200);
    assert_eq!(links_of(&resp).len(), 0);

    server.stop().await;
}

// ---------------------------------------------------------------------------
// As-of behaviour
// ---------------------------------------------------------------------------

#[tokio::test]
async fn as_of_reconstruction_and_replacement_history() {
    let server = spawn().await;
    let base = &server.base_url;

    // v1 valid Jan-Jun 2026, v2 from June 2026.
    register(
        &server,
        EAN_ID,
        json!([
            {"linkType": "dpp", "href": "https://dpp.example.org/v1",
             "asOf": "2026-01-01T00:00:00Z", "expiry": "2026-06-01T00:00:00Z"},
            {"linkType": "dpp", "href": "https://dpp.example.org/v2",
             "asOf": "2026-06-01T00:00:00Z"}
        ]),
    )
    .await;

    let at = |when: &str| {
        format!("{base}/resolve?identifier={}&asof={}", enc(EAN_ID), enc(when))
    };
    let resp = get(&at("2026-03-01T00:00:00Z")).await;
    assert_eq!(resp.status, 200);
    assert_eq!(links_of(&resp)[0]["uri"], "https://dpp.example.org/v1");
    assert_eq!(resp.header("x-as-of").unwrap(), "2026-03-01T00:00:00Z");

    let resp = get(&at("2026-07-01T00:00:00Z")).await;
    assert_eq!(links_of(&resp)[0]["uri"], "https://dpp.example.org/v2");

    // Before any entry: unknown-at-that-instant -> the no-information 404.
    let resp = get(&at("2025-06-01T00:00:00Z")).await;
    assert_eq!(resp.status, 404);
    assert_eq!(resp.body_string(), "{\"error\":\"not found\"}");

    // Replace (append-only: revocation record + new registration).
    let body = json!({
        "identifier": EAN_ID,
        "links": [{"linkType": "dpp", "href": "https://dpp.example.org/v3"}]
    })
    .to_string();
    let resp =
        request("PUT", &format!("{base}/admin/linksets"), Some(&body), None).await;
    assert_eq!(resp.status, 200);
    let replaced = json_of(&resp);
    assert_eq!(replaced["revoked"].as_array().unwrap().len(), 1);

    // After the replacement instant: v3. Before it (but after June): v2
    // — the revocation is itself as-of stamped, so history survives.
    let resp = get(&at("2030-01-01T00:00:00Z")).await;
    assert_eq!(links_of(&resp)[0]["uri"], "https://dpp.example.org/v3");
    let resp = get(&at("2026-08-01T00:00:00Z")).await;
    assert_eq!(links_of(&resp)[0]["uri"], "https://dpp.example.org/v2");

    // The admin view keeps the revoked entry with its annotation.
    let resp = get(&format!("{base}/admin/identifiers/{}", enc(EAN_ID))).await;
    let view = json_of(&resp);
    let entries = view["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 3);
    assert!(entries.iter().any(|e| e.get("revoked").is_some()));

    // The append-only log records both initial registrations, the
    // revocation, and the replacement registration, in monotonic
    // sequence.
    let resp = get(&format!("{base}/admin/log?limit=100")).await;
    let log = json_of(&resp);
    assert_eq!(log["total"], 4);
    let records = log["records"].as_array().unwrap();
    let seqs: Vec<u64> = records.iter().map(|r| r["seq"].as_u64().unwrap()).collect();
    assert!(seqs.windows(2).all(|w| w[0] < w[1]));
    assert!(records.iter().any(|r| r["op"] == "revoke-entry"));
    assert!(records.iter().any(|r| r["op"] == "register-entry"));

    server.stop().await;
}

// ---------------------------------------------------------------------------
// Dark identities
// ---------------------------------------------------------------------------

#[tokio::test]
async fn dark_identity_indistinguishable_from_unknown() {
    let server = spawn().await;
    let base = &server.base_url;

    // A valid but unregistered identifier (canonical 14-digit GTIN).
    const UNKNOWN: &str = "gs1:(01)04006381333931";
    register(&server, ISO_ID, four_links()).await;

    // Register a second, dark identity with live links.
    const DARK: &str = "iso-15459:urn:iso:std:iso-iec:15459:unidpp:inst:777";
    register(
        &server,
        DARK,
        json!([{"linkType": "dpp", "href": "https://secret.example.org/x", "asOf": AS_OF}]),
    )
    .await;
    let body = json!({"identifier": DARK, "dark": true}).to_string();
    let resp = request("POST", &format!("{base}/admin/dark"), Some(&body), None).await;
    assert_eq!(resp.status, 200);

    // The dark identity and an unknown one must be indistinguishable.
    let dark_get = get(&format!("{base}/resolve?identifier={}", enc(DARK))).await;
    let unknown_get = get(&format!("{base}/resolve?identifier={}", enc(UNKNOWN))).await;
    assert_eq!(dark_get.status, 404);
    assert_eq!(unknown_get.status, 404);
    // Byte-identical responses (status, body, type, length).
    assert_eq!(dark_get.body_string(), unknown_get.body_string());
    assert_eq!(
        dark_get.header("content-type").unwrap(),
        unknown_get.header("content-type").unwrap()
    );
    assert_eq!(
        dark_get.header("content-length").unwrap(),
        unknown_get.header("content-length").unwrap()
    );
    // No leak of a dark marker anywhere in the headers.
    assert!(dark_get.header("x-unidpp-context").is_none());
    assert!(dark_get.header("link").is_none());

    // As-of queries (even before the darkening instant) are denied too.
    let historical = get(&format!("{base}/resolve?identifier={}&asof=2020-01-01T00:00:00Z", enc(DARK))).await;
    assert_eq!(historical.status, 404);
    assert_eq!(historical.body_string(), unknown_get.body_string());

    // Path form is equally blind.
    let path_dark = get(&format!("{base}/01/06901234567892/linkset")).await;
    // (that one is the live EAN identifier — not registered here)
    assert_eq!(path_dark.status, 404);

    // Clearing dark restores resolution.
    let body = json!({"identifier": DARK, "dark": false}).to_string();
    let resp = request("POST", &format!("{base}/admin/dark"), Some(&body), None).await;
    assert_eq!(resp.status, 200);
    let restored = get(&format!("{base}/resolve?identifier={}", enc(DARK))).await;
    assert_eq!(restored.status, 200);
    assert_eq!(links_of(&restored)[0]["uri"], "https://secret.example.org/x");

    server.stop().await;
}

// ---------------------------------------------------------------------------
// Legacy EAN / carrier forms
// ---------------------------------------------------------------------------

#[tokio::test]
async fn legacy_ean_and_carrier_forms() {
    let server = spawn().await;
    register(&server, EAN_ID, four_links()).await;
    let base = &server.base_url;

    // Bare legacy EAN-13 (GM2D transition) via the query form.
    let resp = get(&format!("{base}/resolve?carrier={}", enc("6901234567892"))).await;
    assert_eq!(resp.status, 200);
    let links = links_of(&resp);
    assert_eq!(links[0]["anchor"], "(01)06901234567892");

    // GDS-style path form.
    let resp = get(&format!("{base}/g/6901234567892/linkset")).await;
    assert_eq!(resp.status, 200);
    assert_eq!(links_of(&resp).len(), 4);

    // GS1 AI path form with a serial qualifier (item granularity).
    register(
        &server,
        "gs1:(01)06901234567892(21)AB2026111",
        json!([{"linkType": "dpp", "href": "https://item.example.org/1", "asOf": AS_OF}]),
    )
    .await;
    let resp = get(&format!("{base}/01/06901234567892/21/AB2026111/linkset")).await;
    assert_eq!(resp.status, 200);
    assert_eq!(links_of(&resp)[0]["uri"], "https://item.example.org/1");

    // A GS1 DL carrier URI, percent-encoded as a query parameter.
    let dl = "https://id.example.com/01/06901234567892?10=LOT42";
    register(
        &server,
        "gs1:(01)06901234567892(10)LOT42",
        json!([{"linkType": "dpp", "href": "https://batch.example.org/1", "asOf": AS_OF}]),
    )
    .await;
    let resp = get(&format!("{base}/resolve?carrier={}", enc(dl))).await;
    assert_eq!(resp.status, 200);
    assert_eq!(links_of(&resp)[0]["uri"], "https://batch.example.org/1");

    // Bad check digit on a bare EAN: syntax error (400), not a 404.
    let resp = get(&format!("{base}/resolve?carrier={}", enc("6901234567893"))).await;
    assert_eq!(resp.status, 400);

    // Bad check digit on the path form: syntax error.
    let resp = get(&format!("{base}/g/6901234567893/linkset")).await;
    assert_eq!(resp.status, 400);

    // 15459 URN passthrough.
    register(
        &server,
        ISO_ID,
        json!([{"linkType": "dpp", "href": "https://dpp.unidpp.org/eu/1", "asOf": AS_OF}]),
    )
    .await;
    let resp = get(&format!("{base}/resolve?carrier={}", enc("urn:iso:std:iso-iec:15459:unidpp:inst:84120099012345"))).await;
    assert_eq!(resp.status, 200);
    assert_eq!(links_of(&resp)[0]["anchor"], "urn:iso:std:iso-iec:15459:unidpp:inst:84120099012345");

    // Normalize endpoint mirrors the TS parseCarrier result.
    let resp = request(
        "POST",
        &format!("{base}/normalize"),
        Some(r#"{"carrier":"https://gds.example.cn/g/6901234567892/AB2026111"}"#),
        None,
    )
    .await;
    assert_eq!(resp.status, 200);
    let v = json_of(&resp);
    assert_eq!(v["kind"], "gbt-33993");
    assert_eq!(v["origin"], "gds-path");
    assert_eq!(v["identifier"]["value"], "(01)06901234567892(21)AB2026111");
    assert_eq!(v["identifier"]["granularity"], "item");
    assert_eq!(v["identifier"]["scheme"], "gs1");
    assert_eq!(v["resolverBaseUrl"], "https://gds.example.cn");

    server.stop().await;
}

// ---------------------------------------------------------------------------
// RFC 9264 format conformance (TS fixture round trip)
// ---------------------------------------------------------------------------

/// The `@unidpp/resolver` test fixture, verbatim in shape.
const TS_FIXTURE: &str = r#"{
  "linkset": [
    {"anchor": "urn:iso:std:iso-iec:15459:unidpp:inst:84120099012345",
     "uri": "https://dpp.unidpp.org/eu/84120099012345",
     "rel": "dpp", "hreflang": ["en", "fr"], "type": "application/json",
     "unidpp:profile": "urn:unidpp:profile:eu-espr-electronics",
     "unidpp:role": "consumer", "unidpp:region": "EU"},
    {"anchor": "urn:iso:std:iso-iec:15459:unidpp:inst:84120099012345",
     "uri": "https://dpp-jp.meti.example.go.jp/passport/84120099012345",
     "rel": "dpp", "hreflang": ["ja"],
     "unidpp:profile": "urn:unidpp:profile:jp-meti-pse",
     "unidpp:role": "consumer", "unidpp:region": "JP"},
    {"anchor": "urn:iso:std:iso-iec:15459:unidpp:inst:84120099012345",
     "uri": "https://dpp.unidpp.org/generic/84120099012345",
     "rel": "dpp", "hreflang": ["*"],
     "unidpp:profile": "*", "unidpp:role": "*", "unidpp:region": "*"},
    {"anchor": "urn:iso:std:iso-iec:15459:unidpp:inst:84120099012345",
     "uri": "https://dpp.unidpp.org/recycler/84120099012345",
     "rel": "dpp", "hreflang": ["en"],
     "unidpp:profile": "*", "unidpp:role": "recycler", "unidpp:region": "*"}
  ]
}"#;

#[tokio::test]
async fn linkset_format_conformance_with_ts_fixture_shapes() {
    let server = spawn().await;
    let base = &server.base_url;

    // Wire links -> store entries -> admin registration.
    let fixture_links = parse_document(TS_FIXTURE).unwrap();
    let t0 = Timestamp::parse(AS_OF).unwrap();
    let entries: Vec<Value> = fixture_links
        .iter()
        .map(|l| {
            let entry: LinkEntry = entry_from_link_object(l, t0).unwrap();
            entry.to_json()
        })
        .collect();
    let resp = register(&server, ISO_ID, Value::Array(entries)).await;
    assert_eq!(resp.status, 201);

    // Fetch back and compare against the fixture fields.
    let resp = get(&format!("{base}/resolve?identifier={}", enc(ISO_ID))).await;
    assert_eq!(resp.status, 200);
    assert_eq!(resp.header("content-type").unwrap(), "application/linkset+json");
    let out = links_of(&resp);
    assert_eq!(out.len(), 4);
    for (fixture, wire) in fixture_links.iter().zip(out.iter()) {
        for key in [
            "anchor",
            "uri",
            "rel",
            "hreflang",
            "type",
            "unidpp:profile",
            "unidpp:role",
            "unidpp:region",
        ] {
            assert_eq!(fixture.get(key), wire.get(key), "field {key}");
        }
        assert_eq!(wire["unidpp:as-of"], AS_OF);
    }
    // Multi-language hreflang lists survive; the wildcard stays ["*"].
    assert_eq!(out[0]["hreflang"], json!(["en", "fr"]));
    assert_eq!(out[2]["hreflang"], json!(["*"]));

    // The emitted document parses with the TS parseLinkset semantics
    // (single-link and array forms are unit-tested).
    assert_eq!(parse_document(&resp.body_string()).unwrap().len(), 4);

    // Context routing over the fixture data (mirrors the TS assertions).
    let resp = get(&format!(
        "{base}/resolve?identifier={}&profile={}&role=consumer&lang=fr&region=EU",
        enc(ISO_ID),
        enc(EU_PROFILE)
    ))
    .await;
    assert_eq!(links_of(&resp)[0]["uri"], "https://dpp.unidpp.org/eu/84120099012345");

    server.stop().await;
}

// ---------------------------------------------------------------------------
// National intermediary mode
// ---------------------------------------------------------------------------

#[tokio::test]
async fn national_intermediary_caches_stamps_and_serves_stale() {
    let upstream = spawn().await;
    register(
        &upstream,
        EAN_ID,
        json!([
            {"linkType": "dpp", "href": "https://dpp.example.org/eu/9", "asOf": AS_OF},
            {"linkType": "dpp", "href": "https://dpp.example.org/recycler/9",
             "role": "recycler", "asOf": AS_OF}
        ]),
    )
    .await;

    let config = Config {
        upstream: Some(upstream.base_url.clone()),
        cache_ttl_secs: 1,
        ..Config::default()
    };
    let node = TestServer::spawn(config).await.expect("spawn intermediary");
    let base = &node.base_url;

    // Miss -> fetched upstream, stamped, cached.
    let resp = get(&format!("{base}/resolve?identifier={}", enc(EAN_ID))).await;
    assert_eq!(resp.status, 200);
    assert_eq!(resp.header("x-cache").unwrap(), "miss");
    let as_of = resp.header("x-as-of").unwrap().to_string();
    assert!(Timestamp::parse(&as_of).is_ok());
    assert_eq!(links_of(&resp).len(), 2);

    // Hit -> served from cache with the snapshot stamp.
    let resp = get(&format!("{base}/resolve?identifier={}", enc(EAN_ID))).await;
    assert_eq!(resp.header("x-cache").unwrap(), "hit");
    assert_eq!(resp.header("x-as-of").unwrap(), as_of);

    // Context routing works against the cached view.
    let resp = get(&format!("{base}/resolve?identifier={}&role=recycler", enc(EAN_ID))).await;
    assert_eq!(links_of(&resp)[0]["uri"], "https://dpp.example.org/recycler/9");

    // Stale serving: TTL expires, the upstream goes away, the cached
    // snapshot keeps serving with an explicit stale marker (I13).
    tokio::time::sleep(Duration::from_millis(1200)).await;
    upstream.stop().await;
    let resp = get(&format!("{base}/resolve?identifier={}", enc(EAN_ID))).await;
    assert_eq!(resp.status, 200);
    assert_eq!(resp.header("x-cache").unwrap(), "stale");
    assert_eq!(links_of(&resp).len(), 2);

    node.stop().await;
}

#[tokio::test]
async fn intermediary_dark_and_local_precedence() {
    let upstream = spawn().await;
    // The upstream knows both identifiers.
    register(
        &upstream,
        EAN_ID,
        json!([{"linkType": "dpp", "href": "https://dpp.example.org/upstream-ean", "asOf": AS_OF}]),
    )
    .await;
    register(
        &upstream,
        ISO_ID,
        json!([{"linkType": "dpp", "href": "https://dpp.example.org/upstream-iso", "asOf": AS_OF}]),
    )
    .await;

    let config = Config {
        upstream: Some(upstream.base_url.clone()),
        ..Config::default()
    };
    let node = TestServer::spawn(config).await.expect("spawn intermediary");
    let base = &node.base_url;

    // Locally-registered entries take precedence over the upstream.
    register(
        &node,
        EAN_ID,
        json!([{"linkType": "dpp", "href": "https://dpp.example.org/local-ean", "asOf": AS_OF}]),
    )
    .await;
    let resp = get(&format!("{base}/resolve?identifier={}", enc(EAN_ID))).await;
    assert_eq!(resp.status, 200);
    assert_eq!(links_of(&resp)[0]["uri"], "https://dpp.example.org/local-ean");
    assert!(resp.header("x-cache").is_none(), "local answers are not cache-stamped");

    // A locally-dark identifier is never proxied (national-only
    // serving): the upstream has it, the intermediary denies it.
    let body = json!({"identifier": ISO_ID, "dark": true}).to_string();
    let resp = request("POST", &format!("{base}/admin/dark"), Some(&body), None).await;
    assert_eq!(resp.status, 200);
    let dark_resp = get(&format!("{base}/resolve?identifier={}", enc(ISO_ID))).await;
    assert_eq!(dark_resp.status, 404);
    let unknown = get(&format!("{base}/resolve?identifier={}", enc("gs1:(01)04006381333931"))).await;
    assert_eq!(dark_resp.body_string(), unknown.body_string());

    node.stop().await;
    upstream.stop().await;
}

// ---------------------------------------------------------------------------
// Discovery, redirect, auth
// ---------------------------------------------------------------------------

#[tokio::test]
async fn discovery_document_declares_keys_and_contexts() {
    let server = spawn().await;
    for path in ["/.well-known/unidpp-resolver", "/"] {
        let resp = get(&format!("{}{}", server.base_url, path)).await;
        assert_eq!(resp.status, 200);
        let doc = json_of(&resp);
        assert_eq!(doc["identifierKeys"]["gs1ApplicationIdentifiers"], json!(["01", "10", "21"]));
        assert_eq!(doc["identifierKeys"]["carrierSyntaxes"].as_array().unwrap().len(), 6);
        assert_eq!(
            doc["contextRouting"]["dimensions"],
            json!(["profile", "role", "language", "region"])
        );
        assert_eq!(doc["linkset"]["mediaType"], "application/linkset+json");
        assert_eq!(doc["linkTypes"]["default"], "dpp");
        assert_eq!(doc["nationalIntermediary"]["enabled"], false);
        assert_eq!(doc["enumerationResistance"]["identifierListing"], "none");
    }
    // The intermediary declares its mode.
    let upstream = spawn().await;
    let node = TestServer::spawn(Config {
        upstream: Some(upstream.base_url.clone()),
        ..Config::default()
    })
    .await
    .unwrap();
    let resp = get(&format!("{}/.well-known/unidpp-resolver", node.base_url)).await;
    assert_eq!(json_of(&resp)["nationalIntermediary"]["enabled"], true);
    node.stop().await;
    upstream.stop().await;
}

#[tokio::test]
async fn bare_path_redirects_to_the_default_link() {
    let server = spawn().await;
    register(&server, EAN_ID, four_links()).await;
    let base = &server.base_url;

    // No context: the most specific published destination (EU, first
    // registered among the 8-point ties).
    let resp = get(&format!("{base}/01/06901234567892")).await;
    assert_eq!(resp.status, 303);
    assert_eq!(resp.header("location").unwrap(), "https://dpp.unidpp.org/eu/1");
    assert!(resp.header("x-as-of").is_some());

    // Context applies to the redirect too.
    let resp = get(&format!("{base}/g/6901234567892?role=recycler")).await;
    assert_eq!(resp.status, 303);
    assert_eq!(resp.header("location").unwrap(), "https://dpp.unidpp.org/recycler/1");

    // Unknown identifier: no-information 404, never a redirect.
    let resp = get(&format!("{base}/01/4006381333931")).await;
    assert_eq!(resp.status, 404);

    server.stop().await;
}

#[tokio::test]
async fn admin_requires_the_bearer_token_when_configured() {
    let server = TestServer::spawn(Config {
        admin_token: Some("s3cret".to_string()),
        ..Config::default()
    })
    .await
    .unwrap();
    let base = &server.base_url;
    let body = json!({
        "identifier": EAN_ID,
        "links": [{"linkType": "dpp", "href": "https://dpp.example.org/x", "asOf": AS_OF}]
    })
    .to_string();

    let resp = request("POST", &format!("{base}/admin/linksets"), Some(&body), None).await;
    assert_eq!(resp.status, 401);
    let resp = request("POST", &format!("{base}/admin/linksets"), Some(&body), Some("wrong")).await;
    assert_eq!(resp.status, 401);
    let resp = request("POST", &format!("{base}/admin/linksets"), Some(&body), Some("s3cret")).await;
    assert_eq!(resp.status, 201);

    // Public resolution is unauthenticated.
    let resp = get(&format!("{base}/resolve?identifier={}", enc(EAN_ID))).await;
    assert_eq!(resp.status, 200);

    server.stop().await;
}

#[tokio::test]
async fn healthz_and_bad_requests() {
    let server = spawn().await;
    let base = &server.base_url;
    assert_eq!(get(&format!("{base}/healthz")).await.status, 200);

    // Missing carrier/identifier, bad asof, both given.
    assert_eq!(get(&format!("{base}/resolve")).await.status, 400);
    assert_eq!(
        get(&format!("{base}/resolve?identifier={}&asof=Yesterday", enc(EAN_ID))).await.status,
        400
    );
    assert_eq!(
        get(&format!("{base}/resolve?carrier=1&identifier=2")).await.status,
        400
    );
    // Malformed admin body.
    let resp = request("POST", &format!("{base}/admin/linksets"), Some("{"), None).await;
    assert_eq!(resp.status, 400);
    // href must be an absolute URI.
    let resp = request(
        "POST",
        &format!("{base}/admin/linksets"),
        Some(r#"{"identifier":"gs1:(01)06901234567892","links":[{"linkType":"dpp","href":"relative"}]}"#),
        None,
    )
    .await;
    assert_eq!(resp.status, 400);

    server.stop().await;
}
