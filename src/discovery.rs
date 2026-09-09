//! `/.well-known/unidpp-resolver` discovery document —
//! GS1-resolver-inspired (`/.well-known/gs1-resolver`) but neutral:
//! declares the identifier keys, carrier syntaxes, link types and
//! context dimensions this resolver supports, without ever exposing
//! registered identifiers (I12: verifiable without being browsable).

use serde_json::{json, Value};

use crate::api::Config;

/// Build the discovery document for this deployment.
pub fn discovery_json(config: &Config) -> Value {
    json!({
        "profile": "https://unidpp.org/ns/resolver/1.0",
        "service": "unidpp-resolver",
        "version": env!("CARGO_PKG_VERSION"),
        "build_id": option_env!("UNIDPP_BUILD_ID").unwrap_or("dev"),
        "version": env!("CARGO_PKG_VERSION"),
        "linkset": {
            "mediaType": "application/linkset+json",
            "specification": "https://www.rfc-editor.org/rfc/rfc9264",
            "parameters": {
                "anchor": "identifier (15459 URN, GB/T URL, or canonical GS1 element string)",
                "uri": "target href",
                "rel": "linkType",
                "hreflang": "languages (\"*\" = any)",
                "unidpp:profile": "profile context (\"*\" = any)",
                "unidpp:role": "verifier role (\"*\" = any)",
                "unidpp:region": "request region (\"*\" = any)",
                "unidpp:as-of": "RFC 3339 validity start",
                "unidpp:expiry": "RFC 3339 validity end (absent = open)"
            }
        },
        "identifierKeys": {
            "schemes": ["gs1", "gbt-33993", "iso-15459"],
            "gs1ApplicationIdentifiers": ["01", "10", "21"],
            "gs1CheckDigit": true,
            "carrierSyntaxes": [
                "gs1-digital-link-uri",
                "gs1-application-identifier-path",
                "gbt-33993-gds-path",
                "gbt-33993-custom-code",
                "legacy-ean13",
                "iso-15459-urn"
            ]
        },
        "contextRouting": {
            "dimensions": ["profile", "role", "language", "region"],
            "wildcard": "*",
            "languageTags": "BCP 47, exact match then primary-subtag fallback",
            "queryParameters": {
                "profile": "profile",
                "role": "role",
                "language": "lang",
                "region": "region"
            },
            "specificity": {
                "exactMatch": 4,
                "primarySubtagFallback": 3,
                "specificLinkWithoutRequestContext": 2,
                "wildcard": 1,
                "tieBreak": "first-registered wins"
            }
        },
        "linkTypes": {
            "default": "dpp",
            "allKeyword": "all",
            "queryParameter": "linkType"
        },
        "contentNegotiation": {
            "header": "Accept",
            "rule": "the most preferred offered media type routes the default link when the request carries no explicit context parameters",
            "mediaTypes": crate::negotiate::ACCEPT_CONTEXTS
                .iter()
                .map(|(media_type, role)| {
                    json!({"mediaType": media_type, "context": format!("role={role}")})
                })
                .collect::<Vec<_>>()
        },
        "entryPoints": {
            "queryForm": "/resolve?carrier=<carrier>|identifier=<normalized>",
            "pathForm": "/<carrier-key>/linkset (linkset document)",
            "redirectForm": "/<carrier-key> (303 to the default link)",
            "normalize": "POST /normalize {\"carrier\": ...}"
        },
        "asOf": {
            "queryParameter": "asof",
            "format": "RFC 3339 UTC",
            "responseHeader": "X-As-Of"
        },
        "defaultLinkRule": {
            "header": "Link: <uri>; rel=\"<linkType>\" on linkset responses",
            "redirect": "303 See Other on the bare path form"
        },
        "nationalIntermediary": {
            "enabled": config.upstream.is_some(),
            "cacheTtlSeconds": config.cache_ttl_secs,
            "staleServingOnOutage": true,
            "cacheHeader": "X-Cache",
            "asOfStampHeader": "X-As-Of"
        },
        "enumerationResistance": {
            "unknownIdentifier": "404",
            "darkIdentifier": "404 (byte-identical to unknown)",
            "identifierListing": "none"
        }
    })
}
