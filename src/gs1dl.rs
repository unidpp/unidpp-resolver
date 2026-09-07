//! GS1 Digital Link parsing (S1 carrier seam): AIs 01 (GTIN), 10
//! (batch/lot), 21 (serial) — in path and/or query position —
//! normalized to UniDPP identifiers (L0). Port of
//! `@unidpp/resolver` `gs1dl.ts`; semantics are kept compatible
//! (GS1 mod-10 check digit, 14-digit canonical GTIN, fixed AI order
//! `01 10 21`, GS1 DL value charset, 1..=20 length bound).

use crate::carrier::ResolvedIdentifier;

/// AIs supported by the neutral-core carrier subset (mirrors the TS
/// `SUPPORTED_AIS`).
pub const SUPPORTED_AIS: [&str; 3] = ["01", "10", "21"];

/// GS1 element string: canonical 14-digit GTIN plus optional lot/serial.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gs1ElementString {
    pub gtin: String,
    pub lot: Option<String>,
    pub serial: Option<String>,
}

/// GS1 mod-10 check digit over the data digits (GTIN-8/12/13/14 forms).
/// Rightmost data digit carries weight 3; zero-padding to 17 positions
/// contributes nothing, so iterating the real digits is equivalent.
pub fn gs1_check_digit(data_digits: &str) -> Option<u32> {
    if data_digits.is_empty() || !data_digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let mut sum = 0u32;
    let mut weight = 3u32;
    for &b in data_digits.as_bytes().iter().rev() {
        sum += (b - b'0') as u32 * weight;
        weight = if weight == 3 { 1 } else { 3 };
    }
    Some((10 - (sum % 10)) % 10)
}

/// Validate a full GTIN (any length 8/12/13/14) including its check digit.
pub fn valid_gtin(gtin: &str) -> bool {
    let len = gtin.len();
    if !(len == 8 || (12..=14).contains(&len)) {
        return false;
    }
    if !gtin.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let (data, check) = gtin.split_at(gtin.len() - 1);
    gs1_check_digit(data) == check.parse::<u32>().ok()
}

/// Normalize to the canonical GS1 element string,
/// e.g. `(01)X(10)Y(21)Z` — fixed AI order 01, 10, 21.
pub fn canonical_element_string(el: &Gs1ElementString) -> String {
    let mut s = format!("(01){}", el.gtin);
    if let Some(lot) = &el.lot {
        s.push_str(&format!("(10){lot}"));
    }
    if let Some(serial) = &el.serial {
        s.push_str(&format!("(21){serial}"));
    }
    s
}

/// Convert to a normalized identifier (scheme `gs1`, granularity derived).
pub fn to_identifier(el: &Gs1ElementString) -> ResolvedIdentifier {
    ResolvedIdentifier {
        scheme: "gs1".to_string(),
        value: canonical_element_string(el),
        granularity: granularity_of(el),
    }
}

fn granularity_of(el: &Gs1ElementString) -> &'static str {
    if el.serial.is_some() {
        "item"
    } else if el.lot.is_some() {
        "batch"
    } else {
        "model"
    }
}

/// GS1 DL value charset for AIs 10/21 (TS: `/^[!%-?A-Z_a-z0-9]{1,20}$/`),
/// i.e. `!`, `%`..=`?`, `A`..=`Z`, `_`, `a`..=`z`, `0`..=`9`.
pub(crate) fn valid_dl_value(v: &str) -> bool {
    let len = v.len();
    if !(1..=20).contains(&len) {
        return false;
    }
    v.bytes().all(|b| {
        b == b'!'
            || (0x25..=0x3F).contains(&b)
            || b.is_ascii_uppercase()
            || b == b'_'
            || b.is_ascii_lowercase()
            || b.is_ascii_digit()
    })
}

/// Parsed pieces of an `http(s)` URL, enough for GS1 DL / GB/T carriers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UrlParts {
    pub scheme: String,
    pub origin: String,
    /// Percent-decoded path segments (empty segments dropped).
    pub path_segments: Vec<String>,
    pub query_pairs: Vec<(String, String)>,
}

/// Split an absolute `http(s)` URL (mirrors what the TS does with `URL`).
pub fn split_url(uri: &str) -> Option<UrlParts> {
    let (scheme, rest) = uri.split_once("://")?;
    let scheme_l = scheme.to_ascii_lowercase();
    if scheme_l != "http" && scheme_l != "https" {
        return None;
    }
    let (authority, path_query) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    if authority.is_empty() || authority.contains(' ') {
        return None;
    }
    let (path, query) = match path_query.split_once('?') {
        Some((p, q)) => (p, q),
        None => (path_query, ""),
    };
    let mut path_segments = Vec::new();
    for seg in path.split('/').filter(|s| !s.is_empty()) {
        path_segments.push(percent_decode(seg)?);
    }
    let mut query_pairs = Vec::new();
    for pair in query.split('&').filter(|s| !s.is_empty()) {
        let (k, v) = match pair.split_once('=') {
            Some((k, v)) => (k, v),
            None => (pair, ""),
        };
        query_pairs.push((percent_decode_plus(k)?, percent_decode_plus(v)?));
    }
    let origin = format!("{scheme_l}://{authority}");
    Some(UrlParts {
        scheme: scheme_l,
        origin,
        path_segments,
        query_pairs,
    })
}

/// Percent-decode a path segment; `None` on a malformed escape or
/// non-UTF-8 result (`decodeURIComponent` throws in the TS, failing the
/// parse).
pub fn percent_decode(s: &str) -> Option<String> {
    fn hex_val(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            if i + 3 > b.len() {
                return None;
            }
            out.push(hex_val(b[i + 1])? << 4 | hex_val(b[i + 2])?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// Percent-decode a query component (`+` means space, as
/// `URLSearchParams` does in the TS).
fn percent_decode_plus(s: &str) -> Option<String> {
    percent_decode(&s.replace('+', " "))
}

/// Assemble an element string from already-split AI values (path pairs
/// first, query pairs as fallback, path winning on conflict).
fn assemble(
    gtin_raw: &str,
    path: &[(&str, &str)],
    query: &[(String, String)],
) -> Option<Gs1ElementString> {
    let find_path =
        |ai: &str| path.iter().find(|(k, _)| *k == ai).map(|(_, v)| v.to_string());
    let find_query = |ai: &str| query.iter().find(|(k, _)| k == ai).map(|(_, v)| v.clone());
    let check = |v: Option<String>| match v {
        None => None,
        Some(v) if valid_dl_value(&v) => Some(v),
        Some(_) => None,
    };
    let gtin = format!("{:0>14}", gtin_raw);
    if gtin.len() != 14 || !gtin.bytes().all(|b| b.is_ascii_digit()) || !valid_gtin(&gtin) {
        return None;
    }
    Some(Gs1ElementString {
        gtin,
        lot: check(find_path("10").or_else(|| find_query("10"))),
        serial: check(find_path("21").or_else(|| find_query("21"))),
    })
}

/// Parse a GS1 Digital Link URI. Path AIs come as
/// `/01/09506000134352/21/1234`; key-value AIs (10, 21) may also appear
/// as query parameters (`?10=ABC&21=1234`). Returns `None` when the URI
/// carries no recognized GS1 AI structure.
pub fn parse_gs1_digital_link(uri: &str) -> Option<Gs1ElementString> {
    let url = split_url(uri)?;
    let segs = &url.path_segments;
    let mut path_ais: Vec<(&str, &str)> = Vec::new();
    let mut i = 0;
    while i + 1 < segs.len() {
        let ai = &segs[i];
        let value = &segs[i + 1];
        if is_supported_ai(ai) {
            path_ais.push((ai.as_str(), value.as_str()));
        }
        i += 2;
    }
    let query_ais: Vec<(String, String)> = url
        .query_pairs
        .iter()
        .filter(|(k, _)| is_supported_ai(k))
        .cloned()
        .collect();
    let gtin_raw = path_ais
        .iter()
        .find(|(k, _)| *k == "01")
        .map(|(_, v)| v.to_string())?;
    assemble(&gtin_raw, &path_ais, &query_ais)
}

/// Parse a resolver key *path* (no scheme/authority) in AI form,
/// e.g. `01/09506000134352/21/BP52`, with optional query qualifiers
/// (`?10=LOT`).
pub fn parse_key_path(
    path_segments: &[String],
    query_pairs: &[(String, String)],
) -> Option<Gs1ElementString> {
    let mut path_ais: Vec<(&str, &str)> = Vec::new();
    let mut i = 0;
    while i + 1 < path_segments.len() {
        let ai = &path_segments[i];
        if is_supported_ai(ai) {
            path_ais.push((ai.as_str(), path_segments[i + 1].as_str()));
        }
        i += 2;
    }
    let gtin_raw = path_ais
        .iter()
        .find(|(k, _)| *k == "01")
        .map(|(_, v)| v.to_string())?;
    assemble(&gtin_raw, &path_ais, query_pairs)
}

fn is_supported_ai(s: &str) -> bool {
    s.len() == 2 && s.bytes().all(|b| b.is_ascii_digit()) && SUPPORTED_AIS.contains(&s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_digits() {
        assert_eq!(gs1_check_digit("950600013435"), Some(2));
        assert!(valid_gtin("09506000134352"));
        assert!(!valid_gtin("09506000134353"));
        assert!(valid_gtin("6901234567892")); // CN-prefix example
        assert!(valid_gtin("4006381333931"));
    }

    #[test]
    fn path_position_ais() {
        let el =
            parse_gs1_digital_link("https://id.example.com/01/09506000134352/21/BP52-000841")
                .unwrap();
        assert_eq!(el.gtin, "09506000134352");
        assert_eq!(el.serial.as_deref(), Some("BP52-000841"));
        let id = to_identifier(&el);
        assert_eq!(id.granularity, "item");
        assert_eq!(id.value, "(01)09506000134352(21)BP52-000841");
    }

    #[test]
    fn query_position_ai_10() {
        let el =
            parse_gs1_digital_link("https://id.example.com/01/09506000134352?10=LOT2026Q3")
                .unwrap();
        assert_eq!(el.lot.as_deref(), Some("LOT2026Q3"));
        assert_eq!(to_identifier(&el).granularity, "batch");
    }

    #[test]
    fn path_and_query_combined() {
        let el =
            parse_gs1_digital_link("https://id.example.com/01/09506000134352/21/8765?10=ABC")
                .unwrap();
        assert_eq!(el.serial.as_deref(), Some("8765"));
        assert_eq!(el.lot.as_deref(), Some("ABC"));
        assert_eq!(
            canonical_element_string(&el),
            "(01)09506000134352(10)ABC(21)8765"
        );
    }

    #[test]
    fn rejects_bad_input() {
        assert!(parse_gs1_digital_link("https://id.example.com/01/09506000134353").is_none());
        assert!(parse_gs1_digital_link("https://id.example.com/10/LOT123").is_none());
        assert!(parse_gs1_digital_link("not-a-uri").is_none());
        // An over-long serial is dropped-and-invalidated like the TS
        // (`check` returns undefined), leaving a model-granularity GTIN.
        let long = parse_gs1_digital_link("https://id.example.com/01/09506000134352/21/ABCDEFGHIJKLMNOPQRSTUV")
            .unwrap();
        assert_eq!(long.serial, None);
        assert_eq!(to_identifier(&long).granularity, "model");
    }

    #[test]
    fn key_path_form() {
        let segs: Vec<String> = ["01", "09506000134352", "21", "8765"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let el = parse_key_path(&segs, &[]).unwrap();
        assert_eq!(el.serial.as_deref(), Some("8765"));
        let with_lot = parse_key_path(
            &["01".to_string(), "09506000134352".to_string()],
            &[("10".to_string(), "ABC".to_string())],
        )
        .unwrap();
        assert_eq!(with_lot.lot.as_deref(), Some("ABC"));
    }
}
