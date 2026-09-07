//! RFC 9264 linkset emit/parse (`application/linkset+json`) plus the
//! conversions between store entries and wire links. Port of
//! `@unidpp/resolver` `linkset.ts`.
//!
//! UniDPP routing uses the open link parameters `unidpp:profile`,
//! `unidpp:role`, `unidpp:region` alongside the standard `hreflang`
//! for language, and the validity stamps `unidpp:as-of` /
//! `unidpp:expiry` (I13: explicit freshness on every link).
//!
//! Known deviations from the TS (documented): this resolver emits
//! `hreflang: ["*"]` for wildcard-language entries (the TS treats an
//! absent `hreflang` and `["*"]` identically) and always stamps
//! `unidpp:as-of` (the TS leaves validity to the store).

use serde_json::{json, Map, Value};

use crate::store::LinkEntry;
use crate::time::Timestamp;

/// Emit one RFC 9264 link object for a store entry.
pub fn link_object(anchor: &str, e: &LinkEntry) -> Value {
    let mut m = Map::new();
    m.insert("anchor".into(), json!(anchor));
    m.insert("uri".into(), json!(e.href));
    m.insert("rel".into(), json!(e.link_type));
    let langs: Vec<&str> = if e.languages.is_empty() {
        vec!["*"]
    } else {
        e.languages.iter().map(String::as_str).collect()
    };
    m.insert("hreflang".into(), json!(langs));
    if let Some(t) = &e.title {
        m.insert("title".into(), json!(t));
    }
    if let Some(t) = &e.media_type {
        m.insert("type".into(), json!(t));
    }
    m.insert(
        "unidpp:profile".into(),
        json!(e.profile.as_deref().unwrap_or("*")),
    );
    m.insert(
        "unidpp:role".into(),
        json!(e.role.as_deref().unwrap_or("*")),
    );
    m.insert(
        "unidpp:region".into(),
        json!(e.region.as_deref().unwrap_or("*")),
    );
    m.insert("unidpp:as-of".into(), json!(e.as_of.to_string()));
    if let Some(x) = e.expiry {
        m.insert("unidpp:expiry".into(), json!(x.to_string()));
    }
    Value::Object(m)
}

/// Emit a full RFC 9264 JSON linkset document (2-space pretty print,
/// matching the TS `emitLinkset` shape).
pub fn emit_document(anchor: &str, entries: &[&LinkEntry]) -> String {
    let links: Vec<Value> = entries.iter().map(|e| link_object(anchor, e)).collect();
    serde_json::to_string_pretty(&json!({ "linkset": links })).unwrap()
}

/// Parse a linkset document (TS `parseLinkset` semantics). Accepts a
/// full `{"linkset": [...]}` document, a bare array of links, or a
/// single link object. Returns the link objects; each must carry
/// string `anchor`, `uri` and `rel`.
pub fn parse_document(document: &str) -> Result<Vec<Value>, String> {
    let parsed: Value =
        serde_json::from_str(document).map_err(|e| format!("invalid linkset JSON: {e}"))?;
    let links = match parsed {
        Value::Array(a) => a,
        Value::Object(ref o) if o.contains_key("linkset") => match &o["linkset"] {
            Value::Array(a) => a.clone(),
            _ => return Err("`linkset` must be an array".to_string()),
        },
        Value::Object(_) => vec![parsed],
        _ => return Err("linkset document must be an object or array".to_string()),
    };
    for link in &links {
        let o = link.as_object().ok_or("linkset entry must be an object")?;
        for k in ["anchor", "uri", "rel"] {
            if !o.get(k).map(Value::is_string).unwrap_or(false) {
                return Err(format!("link requires string `{k}`"));
            }
        }
    }
    Ok(links)
}

/// Convert a wire link object into a store entry (used for upstream
/// ingestion in national-intermediary mode and for fixture round
/// trips). `default_as_of` applies when the link carries no
/// `unidpp:as-of`.
pub fn entry_from_link_object(link: &Value, default_as_of: Timestamp) -> Result<LinkEntry, String> {
    let o = link.as_object().ok_or("link must be an object")?;
    let str_field = |k: &str| -> Result<Option<String>, String> {
        match o.get(k) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(s)) if s.is_empty() || s == "*" => Ok(None),
            Some(Value::String(s)) => Ok(Some(s.clone())),
            Some(_) => Err(format!("`{k}` must be a string")),
        }
    };
    let href = o
        .get("uri")
        .and_then(Value::as_str)
        .ok_or("link requires string `uri`")?
        .to_string();
    let link_type = o
        .get("rel")
        .and_then(Value::as_str)
        .ok_or("link requires string `rel`")?
        .to_string();
    let languages = match o.get("hreflang") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::String(s)) => {
            if s.is_empty() || s == "*" {
                Vec::new()
            } else {
                vec![s.clone()]
            }
        }
        Some(Value::Array(a)) => {
            let mut langs = Vec::new();
            for item in a {
                let s = item
                    .as_str()
                    .ok_or("`hreflang` array items must be strings")?;
                if !s.is_empty() && s != "*" {
                    langs.push(s.to_string());
                }
            }
            langs
        }
        Some(_) => return Err("`hreflang` must be a string or array of strings".into()),
    };
    let as_of = match o.get("unidpp:as-of") {
        Some(Value::String(s)) => Timestamp::parse(s).map_err(|e| e.to_string())?,
        _ => default_as_of,
    };
    let expiry = match o.get("unidpp:expiry") {
        Some(Value::String(s)) => Some(Timestamp::parse(s).map_err(|e| e.to_string())?),
        _ => None,
    };
    if let Some(e) = expiry {
        if e < as_of {
            return Err(format!("`unidpp:expiry` {e} before `unidpp:as-of` {as_of}"));
        }
    }
    Ok(LinkEntry {
        id: 0,
        link_type,
        href,
        title: str_field("title")?,
        media_type: str_field("type")?,
        profile: str_field("unidpp:profile")?,
        role: str_field("unidpp:role")?,
        languages,
        region: str_field("unidpp:region")?,
        as_of,
        expiry,
    })
}

/// Parse a whole upstream document into store entries.
pub fn entries_from_document(
    document: &str,
    default_as_of: Timestamp,
) -> Result<Vec<LinkEntry>, String> {
    parse_document(document)?
        .iter()
        .map(|l| entry_from_link_object(l, default_as_of))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `@unidpp/resolver` test fixture (resolver.test.ts), embedded
    /// for shape-conformance round trips.
    pub const TS_FIXTURE: &str = r#"{
  "linkset": [
    {
      "anchor": "urn:iso:std:iso-iec:15459:unidpp:inst:84120099012345",
      "uri": "https://dpp.unidpp.org/eu/84120099012345",
      "rel": "dpp",
      "hreflang": ["en", "fr"],
      "type": "application/json",
      "unidpp:profile": "urn:unidpp:profile:eu-espr-electronics",
      "unidpp:role": "consumer",
      "unidpp:region": "EU"
    },
    {
      "anchor": "urn:iso:std:iso-iec:15459:unidpp:inst:84120099012345",
      "uri": "https://dpp-jp.meti.example.go.jp/passport/84120099012345",
      "rel": "dpp",
      "hreflang": ["ja"],
      "unidpp:profile": "urn:unidpp:profile:jp-meti-pse",
      "unidpp:role": "consumer",
      "unidpp:region": "JP"
    },
    {
      "anchor": "urn:iso:std:iso-iec:15459:unidpp:inst:84120099012345",
      "uri": "https://dpp.unidpp.org/generic/84120099012345",
      "rel": "dpp",
      "hreflang": ["*"],
      "unidpp:profile": "*",
      "unidpp:role": "*",
      "unidpp:region": "*"
    },
    {
      "anchor": "urn:iso:std:iso-iec:15459:unidpp:inst:84120099012345",
      "uri": "https://dpp.unidpp.org/recycler/84120099012345",
      "rel": "dpp",
      "hreflang": ["en"],
      "unidpp:profile": "*",
      "unidpp:role": "recycler",
      "unidpp:region": "*"
    }
  ]
}"#;

    const T0: Timestamp = Timestamp {
        secs: 1_800_000_000,
    };

    #[test]
    fn fixture_parses_and_round_trips() {
        let links = parse_document(TS_FIXTURE).unwrap();
        assert_eq!(links.len(), 4);
        let t0 = Timestamp::UNIX_EPOCH;
        let entries: Vec<LinkEntry> = links
            .iter()
            .map(|l| entry_from_link_object(l, t0).unwrap())
            .collect();
        // Round trip: entry -> wire preserves the fixture shapes.
        let refs: Vec<&LinkEntry> = entries.iter().collect();
        let doc = emit_document(
            "urn:iso:std:iso-iec:15459:unidpp:inst:84120099012345",
            &refs,
        );
        let round = parse_document(&doc).unwrap();
        assert_eq!(round.len(), 4);
        for (orig, rt) in links.iter().zip(round.iter()) {
            for k in [
                "anchor",
                "uri",
                "rel",
                "hreflang",
                "unidpp:profile",
                "unidpp:role",
                "unidpp:region",
            ] {
                assert_eq!(orig.get(k), rt.get(k), "field {k}");
            }
            assert!(rt.get("unidpp:as-of").unwrap().is_string());
        }
        // multi-language lists survive the round trip
        assert_eq!(round[0].get("hreflang").unwrap(), &json!(["en", "fr"]));
        // as-of default injection
        let default = entry_from_link_object(&links[0], T0).unwrap();
        assert_eq!(default.as_of, T0);
    }

    #[test]
    fn accepts_single_link_and_bare_array() {
        let single = r#"{"anchor":"a","uri":"https://x/","rel":"dpp"}"#;
        assert_eq!(parse_document(single).unwrap().len(), 1);
        let arr = r#"[{"anchor":"a","uri":"https://x/","rel":"dpp"}]"#;
        assert_eq!(parse_document(arr).unwrap().len(), 1);
    }

    #[test]
    fn rejects_malformed_documents() {
        assert!(parse_document("{").is_err());
        assert!(parse_document(r#"{"linkset":[{"uri":"x","rel":"dpp"}]}"#).is_err());
        assert!(parse_document(r#"{"linkset":"nope"}"#).is_err());
        assert!(parse_document("42").is_err());
    }
}
