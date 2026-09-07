//! Unified carrier entry point (S1 seam): translate whatever the
//! physical carrier encodes into a normalized L0 identifier, then
//! resolve. The carrier retains identity; resolution is reproducible
//! (resolver-outage doctrine). Port of `@unidpp/resolver`
//! `carrier.ts`, extended with the resolver's identifier-key forms.
//!
//! Normalized identifier (mirror of the TS `ProductIdentifier` subset
//! the resolver needs): `{scheme, value, granularity}` with schemes
//! `gs1` (canonical element string `(01)K[(10)L][(21)S]`),
//! `gbt-33993` (enterprise custom code URL) and `iso-15459` (URN
//! passthrough). The store key is `scheme:value`.

use crate::gbt33993::{parse_gbt33993, parse_gds_path};
use crate::gs1dl::{parse_gs1_digital_link, parse_key_path, split_url, to_identifier, valid_gtin};

/// Carrier kinds recognized by the resolver (TS `CarrierKind`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CarrierKind {
    Gs1DigitalLink,
    Gbt33993,
    Unknown,
}

impl CarrierKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            CarrierKind::Gs1DigitalLink => "gs1-digital-link",
            CarrierKind::Gbt33993 => "gbt-33993",
            CarrierKind::Unknown => "unknown",
        }
    }
}

/// Normalized L0 identifier (scheme + canonical value + granularity).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedIdentifier {
    pub scheme: String,
    pub value: String,
    pub granularity: &'static str,
}

impl ResolvedIdentifier {
    /// Canonical store key (`scheme:value`).
    pub fn key(&self) -> String {
        format!("{}:{}", self.scheme, self.value)
    }

    /// Linkset anchor for this identifier. URI-valued identifiers
    /// (15459 URNs, GB/T custom-code URLs) anchor to themselves; GS1
    /// identities anchor to the canonical element string (the TS
    /// identifier value — an opaque token for routing purposes).
    pub fn anchor(&self) -> &str {
        &self.value
    }
}

/// Result of carrier parsing (TS `CarrierParse`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CarrierParse {
    pub kind: CarrierKind,
    pub identifier: ResolvedIdentifier,
    /// Resolver base URL when the carrier URI itself is the entry point.
    pub resolver_base_url: Option<String>,
    /// Sub-origin for GB/T parses (`gds-path` / `legacy-ean13` /
    /// `custom-code`).
    pub origin: Option<&'static str>,
}

/// ISO/IEC 15459 / EN 18219 URN carriers (neutral primary scheme).
pub fn is_iso15459_urn(s: &str) -> bool {
    let prefix = "urn:iso:std:iso-iec:15459";
    match s.strip_prefix(prefix) {
        Some(rest) => matches!(rest.as_bytes().first(), Some(b':') | Some(b'#')) && rest.len() > 1,
        None => false,
    }
}

/// Parse any carrier into a normalized identifier (TS `parseCarrier`).
/// GS1 DL is tried first (a `/g/...` GDS path never matches the GS1 DL
/// AI grammar, but a plain GS1 DL URI must not be swallowed as a GB/T
/// custom code); then GB/T shapes; then ISO/IEC 15459 URN passthrough.
pub fn parse_carrier(scanned: &str) -> Option<CarrierParse> {
    let trimmed = scanned.trim();

    if let Some(el) = parse_gs1_digital_link(trimmed) {
        return Some(CarrierParse {
            kind: CarrierKind::Gs1DigitalLink,
            identifier: to_identifier(&el),
            resolver_base_url: split_url(trimmed).map(|u| u.origin),
            origin: None,
        });
    }

    if let Some(gbt) = parse_gbt33993(trimmed) {
        return Some(CarrierParse {
            kind: CarrierKind::Gbt33993,
            identifier: gbt.identifier,
            resolver_base_url: split_url(trimmed).map(|u| u.origin),
            origin: Some(gbt.origin.as_str()),
        });
    }

    if is_iso15459_urn(trimmed) {
        return Some(CarrierParse {
            kind: CarrierKind::Unknown,
            identifier: ResolvedIdentifier {
                scheme: "iso-15459".to_string(),
                value: trimmed.to_string(),
                granularity: "item",
            },
            resolver_base_url: None,
            origin: None,
        });
    }

    None
}

/// Why a carrier-shaped input did not yield an identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CarrierLookup {
    /// Parsed successfully.
    Ok(CarrierParse),
    /// Recognized GS1/GB/T shape with an invalid check digit or value
    /// (a syntax error: public knowledge, no registry information).
    Invalid,
    /// Not a carrier shape this resolver understands.
    Unrecognized,
}

/// Classify a carrier string for the query-form entry point
/// (`?carrier=`): distinguish syntactically invalid carriers (400)
/// from unrecognized input (no information). Note that a GS1-DL-shaped
/// URL with a bad check digit normalizes to a GB/T custom-code
/// identifier (TS parity: `parseCarrier` demotes it the same way) and
/// therefore resolves as unknown rather than invalid; the path form
/// (`/01/...`) is where bad check digits surface as 400.
pub fn classify_carrier(scanned: &str) -> CarrierLookup {
    if let Some(parsed) = parse_carrier(scanned) {
        return CarrierLookup::Ok(parsed);
    }
    let trimmed = scanned.trim();
    if let Some(url) = split_url(trimmed) {
        // A `/g/`-shaped path that failed GTIN validation.
        if url.path_segments.first().map(|s| s.as_str()) == Some("g") {
            return CarrierLookup::Invalid;
        }
        return CarrierLookup::Unrecognized;
    }
    let gtin_shaped =
        (trimmed.len() == 13 || trimmed.len() == 14) && trimmed.bytes().all(|b| b.is_ascii_digit());
    if gtin_shaped {
        return CarrierLookup::Invalid; // GTIN shape, bad check digit
    }
    CarrierLookup::Unrecognized
}

/// Classify a resolver key *path* (e.g. `01/09506000134352/21/X` or
/// `g/6901234567892/AB2026111`) for the path-form entry points.
pub fn classify_path(segments: &[String], query_pairs: &[(String, String)]) -> CarrierLookup {
    let first = segments.first().map(|s| s.as_str());
    if first.map(|s| s.len() == 2 && s.bytes().all(|b| b.is_ascii_digit())) == Some(true) {
        return match parse_key_path(segments, query_pairs) {
            Some(el) => CarrierLookup::Ok(CarrierParse {
                kind: CarrierKind::Gs1DigitalLink,
                identifier: to_identifier(&el),
                resolver_base_url: None,
                origin: None,
            }),
            None => CarrierLookup::Invalid,
        };
    }
    if first == Some("g") {
        return match parse_gds_path(segments) {
            Some(gbt) => CarrierLookup::Ok(CarrierParse {
                kind: CarrierKind::Gbt33993,
                identifier: gbt.identifier,
                resolver_base_url: None,
                origin: Some(gbt.origin.as_str()),
            }),
            None => CarrierLookup::Invalid,
        };
    }
    CarrierLookup::Unrecognized
}

/// Parse an already-normalized identifier (the `?identifier=` entry
/// point and the admin API's `identifier` field). Accepts:
/// - the canonical store key (`gs1:(01)...`, `iso-15459:urn:...`,
///   `gbt-33993:https://...`),
/// - a bare canonical element string (`(01)K[(10)L][(21)S]`),
/// - any carrier (URL, URN, bare EAN-13) — normalized the usual way.
pub fn parse_identifier_param(input: &str) -> Result<ResolvedIdentifier, String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err("empty identifier".to_string());
    }
    for scheme in ["gs1", "iso-15459", "gbt-33993"] {
        if let Some(rest) = trimmed.strip_prefix(&format!("{scheme}:")) {
            let id = match scheme {
                "gs1" => parse_element_string(rest)?,
                "iso-15459" => {
                    if is_iso15459_urn(rest) {
                        ResolvedIdentifier {
                            scheme: scheme.to_string(),
                            value: rest.to_string(),
                            granularity: "item",
                        }
                    } else {
                        return Err(format!("not an ISO/IEC 15459 URN: `{rest}`"));
                    }
                }
                _ => {
                    if split_url(rest).is_some() {
                        ResolvedIdentifier {
                            scheme: scheme.to_string(),
                            value: rest.to_string(),
                            granularity: "item",
                        }
                    } else {
                        return Err(format!("not an http(s) URL: `{rest}`"));
                    }
                }
            };
            return Ok(id);
        }
    }
    if trimmed.starts_with("(01)") {
        return parse_element_string(trimmed);
    }
    match classify_carrier(trimmed) {
        CarrierLookup::Ok(parsed) => Ok(parsed.identifier),
        CarrierLookup::Invalid => Err(format!("invalid carrier: `{trimmed}`")),
        CarrierLookup::Unrecognized => Err(format!("unrecognized identifier form: `{trimmed}`")),
    }
}

/// Parse a canonical GS1 element string `(01)K[(10)L][(21)S]` (fixed
/// AI order, check digit and qualifier charset enforced).
fn parse_element_string(s: &str) -> Result<ResolvedIdentifier, String> {
    let err = |m: &str| format!("malformed element string `{s}`: {m}");
    let body = s
        .strip_prefix("(01)")
        .ok_or_else(|| err("expected `(01)` prefix"))?;
    let gtin_len = body.find('(').unwrap_or(body.len());
    let (gtin, mut tail) = body.split_at(gtin_len);
    if gtin.len() != 14 || !gtin.bytes().all(|b| b.is_ascii_digit()) || !valid_gtin(gtin) {
        return Err(err("expected a 14-digit GTIN with a valid check digit"));
    }
    let mut lot = None;
    let mut serial = None;
    while !tail.is_empty() {
        let (prefix, rest) = if let Some(r) = tail.strip_prefix("(10)") {
            ("(10)", r)
        } else if let Some(r) = tail.strip_prefix("(21)") {
            ("(21)", r)
        } else {
            return Err(err("expected `(10)`/`(21)` qualifiers"));
        };
        let (val, next) = match rest.find('(') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, ""),
        };
        if val.is_empty() || !crate::gs1dl::valid_dl_value(val) {
            return Err(err("invalid qualifier value"));
        }
        match prefix {
            "(10)" => {
                if lot.is_some() {
                    return Err(err("duplicate (10)"));
                }
                if serial.is_some() {
                    return Err(err("qualifiers out of canonical order (10 before 21)"));
                }
                lot = Some(val.to_string());
            }
            _ => {
                if serial.is_some() {
                    return Err(err("duplicate (21)"));
                }
                serial = Some(val.to_string());
            }
        }
        tail = next;
    }
    let granularity = if serial.is_some() {
        "item"
    } else if lot.is_some() {
        "batch"
    } else {
        "model"
    };
    Ok(ResolvedIdentifier {
        scheme: "gs1".to_string(),
        value: s.to_string(),
        granularity,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gbt33993::GbtOrigin;

    #[test]
    fn routes_gs1_and_gbt_carriers_to_normalized_identifiers() {
        let dl = parse_carrier("https://id.example.com/01/09506000134352/21/8765").unwrap();
        assert_eq!(dl.kind, CarrierKind::Gs1DigitalLink);
        assert_eq!(
            dl.resolver_base_url.as_deref(),
            Some("https://id.example.com")
        );
        assert_eq!(dl.identifier.key(), "gs1:(01)09506000134352(21)8765");

        let gbt = parse_carrier("https://gds.example.cn/g/6901234567892").unwrap();
        assert_eq!(gbt.kind, CarrierKind::Gbt33993);
        assert_eq!(gbt.identifier.value, "(01)06901234567892");
        assert_eq!(gbt.origin, Some(GbtOrigin::GdsPath.as_str()));
    }

    #[test]
    fn passes_through_15459_urns() {
        let iso = parse_carrier("urn:iso:std:iso-iec:15459:unidpp:inst:84120099012345").unwrap();
        assert_eq!(iso.identifier.scheme, "iso-15459");
        assert_eq!(
            iso.identifier.key(),
            "iso-15459:urn:iso:std:iso-iec:15459:unidpp:inst:84120099012345"
        );
        assert!(parse_carrier("garbage").is_none());
        assert!(parse_carrier("urn:iso:std:iso-iec:15459").is_none());
    }

    #[test]
    fn classification_distinguishes_invalid_from_unrecognized() {
        // Bad check digit in a GDS path is a syntax error.
        assert!(matches!(
            classify_carrier("https://gds.example.cn/g/6901234567893"),
            CarrierLookup::Invalid
        ));
        // Bad check digit in a bare EAN-13 is a syntax error.
        assert!(matches!(
            classify_carrier("6901234567893"),
            CarrierLookup::Invalid
        ));
        // A GS1-DL-shaped URL with a bad check digit demotes to a GB/T
        // custom code (TS parity), i.e. parses fine and resolves as
        // unknown.
        assert!(matches!(
            classify_carrier("https://id.example.com/01/09506000134353"),
            CarrierLookup::Ok(_)
        ));
        assert!(matches!(
            classify_carrier("https://example.org/wiki/Page"),
            CarrierLookup::Ok(_)
        ));
        assert!(matches!(
            classify_carrier("hello world"),
            CarrierLookup::Unrecognized
        ));
    }

    #[test]
    fn identifier_param_forms() {
        let a = parse_identifier_param("gs1:(01)09506000134352(21)8765").unwrap();
        let b = parse_identifier_param("(01)09506000134352(21)8765").unwrap();
        let c = parse_identifier_param("6901234567892").unwrap();
        let d = parse_identifier_param(
            "iso-15459:urn:iso:std:iso-iec:15459:unidpp:inst:84120099012345",
        )
        .unwrap();
        assert_eq!(a, b);
        assert_eq!(c.value, "(01)06901234567892");
        assert_eq!(c.granularity, "model");
        assert_eq!(d.granularity, "item");
        assert!(parse_identifier_param("(01)09506000134353").is_err());
        assert!(parse_identifier_param("gs1:nope").is_err());
        assert!(parse_identifier_param("").is_err());
    }
}
