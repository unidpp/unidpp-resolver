//! GB/T 33993-2017-style commodity QR codes (GS1-China 商品二维码 /
//! gds.org.cn pattern): a national wrapper over GS1 syntax. Cross-carrier
//! translation rules are registry content (PLAN.md interop lessons);
//! this module implements the documented subset of carrier shapes
//! (port of `@unidpp/resolver` `gbt33993.ts`):
//!
//! 1. `https://<host>/g/<13-digit GTIN>[/<serial-or-lot>]` (GDS-style)
//! 2. `https://<host>/253/<...>` — NOT supported (AI out of Tier-A scope)
//! 3. a bare EAN-13/GTIN scanned from a legacy 1D code
//!    (GM2D transition: 1D->2D coexistence accepts legacy entry points)
//!
//! GTIN-bearing shapes normalize to the same `gs1` identifiers as GS1
//! DL; enterprise-custom codes normalize to scheme `gbt-33993`.

use crate::carrier::ResolvedIdentifier;
use crate::gs1dl::{split_url, valid_gtin};

/// How the identifier (if any) was carried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GbtOrigin {
    GdsPath,
    LegacyEan13,
    CustomCode,
}

impl GbtOrigin {
    pub fn as_str(&self) -> &'static str {
        match self {
            GbtOrigin::GdsPath => "gds-path",
            GbtOrigin::LegacyEan13 => "legacy-ean13",
            GbtOrigin::CustomCode => "custom-code",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GbtParseResult {
    pub identifier: ResolvedIdentifier,
    pub origin: GbtOrigin,
}

/// Parse a GDS-style `/g/` path (already percent-decoded segments).
pub fn parse_gds_path(segments: &[String]) -> Option<GbtParseResult> {
    if segments.first().map(|s| s.as_str()) != Some("g") {
        return None;
    }
    let gtin13 = segments.get(1)?;
    if gtin13.len() != 13 || !gtin13.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let qualifier = segments.get(2);
    if segments.len() > 3 {
        return None;
    }
    let gtin14 = format!("0{gtin13}");
    if !valid_gtin(&gtin14) {
        return None;
    }
    // A qualifier segment is treated as serial when alphanumeric with a
    // letter, else as a lot (national practice; ambiguity resolved by
    // the registered translation rule, default documented here).
    let (lot, serial) = match qualifier {
        Some(q) if !q.is_empty() && q.len() <= 20 && gbt_qualifier_charset(q) => {
            if q.chars().any(|c| c.is_ascii_alphabetic()) {
                (None, Some(q.clone()))
            } else {
                (Some(q.clone()), None)
            }
        }
        _ => (None, None),
    };
    let mut value = format!("(01){gtin14}");
    if let Some(l) = &lot {
        value.push_str(&format!("(10){l}"));
    }
    if let Some(s) = &serial {
        value.push_str(&format!("(21){s}"));
    }
    let granularity = if serial.is_some() {
        "item"
    } else if lot.is_some() {
        "batch"
    } else {
        "model"
    };
    Some(GbtParseResult {
        identifier: ResolvedIdentifier {
            scheme: "gs1".to_string(),
            value,
            granularity,
        },
        origin: GbtOrigin::GdsPath,
    })
}

/// GDS qualifier charset (TS: `/^[\w.-]{1,20}$/`).
fn gbt_qualifier_charset(q: &str) -> bool {
    q.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.' || b == b'-')
}

/// Parse a GB/T 33993 carrier: full URL (GDS path or custom code) or a
/// bare legacy EAN-13/GTIN-14. A `/g/`-shaped path with an invalid
/// GTIN check digit is rejected outright (not demoted to a custom
/// code), mirroring the TS.
pub fn parse_gbt33993(code: &str) -> Option<GbtParseResult> {
    let trimmed = code.trim();
    if trimmed.is_empty() {
        return None;
    }

    if let Some(url) = split_url(trimmed) {
        let gds_shaped = url.path_segments.first().map(|s| s.as_str()) == Some("g")
            && url
                .path_segments
                .get(1)
                .map(|s| s.len() == 13 && s.bytes().all(|b| b.is_ascii_digit()))
                .unwrap_or(false);
        if gds_shaped {
            return parse_gds_path(&url.path_segments);
        }
        // Other GB/T 33993 carriers (enterprise custom codes) keep their
        // own scheme.
        return Some(GbtParseResult {
            identifier: ResolvedIdentifier {
                scheme: "gbt-33993".to_string(),
                value: trimmed.to_string(),
                granularity: "item",
            },
            origin: GbtOrigin::CustomCode,
        });
    }

    // Shape 3: bare legacy EAN-13 / GTIN-14.
    let gtin_shaped =
        (trimmed.len() == 13 || trimmed.len() == 14) && trimmed.bytes().all(|b| b.is_ascii_digit());
    if gtin_shaped {
        let gtin = format!("{:0>14}", trimmed);
        if valid_gtin(&gtin) {
            return Some(GbtParseResult {
                identifier: ResolvedIdentifier {
                    scheme: "gs1".to_string(),
                    value: format!("(01){gtin}"),
                    granularity: "model",
                },
                origin: GbtOrigin::LegacyEan13,
            });
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gds_path_with_serial_qualifier() {
        let r = parse_gbt33993("https://gds.example.cn/g/6901234567892/AB2026111").unwrap();
        assert_eq!(r.origin, GbtOrigin::GdsPath);
        assert_eq!(r.identifier.value, "(01)06901234567892(21)AB2026111");
        assert_eq!(r.identifier.granularity, "item");
    }

    #[test]
    fn all_numeric_qualifier_is_a_lot() {
        let r = parse_gbt33993("https://gds.example.cn/g/6901234567892/20260901").unwrap();
        assert_eq!(r.identifier.value, "(01)06901234567892(10)20260901");
        assert_eq!(r.identifier.granularity, "batch");
    }

    #[test]
    fn bare_legacy_ean13() {
        let r = parse_gbt33993("6901234567892").unwrap();
        assert_eq!(r.origin, GbtOrigin::LegacyEan13);
        assert_eq!(r.identifier.value, "(01)06901234567892");
        assert_eq!(r.identifier.granularity, "model");
    }

    #[test]
    fn custom_enterprise_codes_keep_their_scheme() {
        let r = parse_gbt33993("https://qr.enterprise.cn/x/MA-2026-8841").unwrap();
        assert_eq!(r.origin, GbtOrigin::CustomCode);
        assert_eq!(r.identifier.scheme, "gbt-33993");
    }

    #[test]
    fn rejects_bad_check_digits() {
        assert!(parse_gbt33993("6901234567893").is_none());
        assert!(parse_gbt33993("https://gds.example.cn/g/6901234567893").is_none());
    }
}
