//! L5 context routing: resolver linksets are keyed by (profile context,
//! role, language, request region) — one QR, many destinations. Default
//! by request context, overridable. Port of `@unidpp/resolver`
//! `contextKey.ts` plus the scoring half of `linkset.ts`.
//!
//! Scoring table (mirrors the TS exactly; ties break by registration
//! order — first-in-document wins):
//!
//! | dimension | wildcard link | specific link, no request pref | exact | fallback |
//! |---|---|---|---|---|
//! | profile / role / region | 1 | 2 | 4 | — (mismatch: no match) |
//! | language (`hreflang`) | 1 | 2 | 4 | 3 (primary subtag) |

/// Request context (TS `RequestContext`); `None` means "no preference"
/// (wildcard) on that dimension.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RequestContext {
    /// Profile context (profile-manifest URN, typically).
    pub profile: Option<String>,
    /// Verifier role (EN 18239 roles): consumer, recycler, repairer,
    /// customs, ...
    pub role: Option<String>,
    /// BCP-47 language tag.
    pub language: Option<String>,
    /// ISO 3166-1 alpha-2 request region (or an "EU"-style region code).
    pub region: Option<String>,
}

impl RequestContext {
    /// True when no routing dimension was supplied (plain resolution).
    pub fn is_empty(&self) -> bool {
        self.profile.is_none()
            && self.role.is_none()
            && self.language.is_none()
            && self.region.is_none()
    }

    /// Canonical routing-key display (TS `contextKey`), wildcards
    /// explicit: `profile=P;role=*;lang=fr;region=*`.
    pub fn context_key(&self) -> String {
        format!(
            "profile={};role={};lang={};region={}",
            self.profile.as_deref().unwrap_or("*"),
            self.role.as_deref().unwrap_or("*"),
            self.language.as_deref().unwrap_or("*"),
            self.region.as_deref().unwrap_or("*")
        )
    }
}

/// Primary subtag: `fr-CA` -> `fr` (TS `primarySubtag`).
pub fn primary_subtag(language: &str) -> &str {
    language.split('-').next().unwrap_or(language)
}

/// Per-dimension scoring for profile/role/region: link wildcard (`*`)
/// → 1; request has no preference but the link is specific → 2; exact
/// match → 4; mismatch → no match.
fn dim_score(link: Option<&str>, ctx: Option<&str>) -> Option<u32> {
    match ctx {
        None => Some(match link {
            None => 1,
            Some(_) => 2,
        }),
        Some(c) => match link {
            None => Some(1),
            Some(l) if l == c => Some(4),
            Some(_) => None,
        },
    }
}

/// Language scoring over the entry's `hreflang` list: missing/empty
/// list or a `*` entry → wildcard (1); a specific list with no
/// language preference → 2; exact tag → 4; primary-subtag fallback →
/// 3; otherwise no match.
fn language_score(link_langs: &[String], ctx: Option<&str>) -> Option<u32> {
    let wildcard = link_langs.is_empty() || link_langs.iter().any(|l| l == "*");
    match ctx {
        None => Some(if wildcard { 1 } else { 2 }),
        Some(_) if wildcard => Some(1),
        Some(c) if link_langs.iter().any(|l| l == c) => Some(4),
        Some(c) if link_langs.iter().any(|l| primary_subtag(l) == primary_subtag(c)) => Some(3),
        Some(_) => None,
    }
}

/// Routing dimensions borrowed from a store entry (the TS `Link`'s
/// `unidpp:profile` / `unidpp:role` / `unidpp:region` / `hreflang`).
#[derive(Debug, Clone, Copy)]
pub struct EntryRouting<'a> {
    pub link_type: &'a str,
    pub profile: Option<&'a str>,
    pub role: Option<&'a str>,
    pub language: &'a [String],
    pub region: Option<&'a str>,
}

/// Specificity score of an entry against a request context for
/// `link_type`; `None` = no match.
pub fn score_entry(
    routing: &EntryRouting<'_>,
    ctx: &RequestContext,
    link_type: &str,
) -> Option<u32> {
    if routing.link_type != link_type {
        return None;
    }
    Some(
        dim_score(routing.profile, ctx.profile.as_deref())?
            + dim_score(routing.role, ctx.role.as_deref())?
            + dim_score(routing.region, ctx.region.as_deref())?
            + language_score(routing.language, ctx.language.as_deref())?,
    )
}

/// A scored view over one store entry for a request context.
pub struct ScoredEntry<'a> {
    pub entry: &'a crate::store::LinkEntry,
    pub score: u32,
}

/// Select and order the destinations for a request context: exact
/// matches outrank wildcards; language falls back to the primary
/// subtag. Descending score, ties broken by first-in-document
/// (registration) order — deterministic, mirroring the TS `selectLink`.
pub fn select_ordered<'a>(
    entries: &'a [crate::store::LinkEntry],
    ctx: &RequestContext,
    link_type: &str,
) -> Vec<ScoredEntry<'a>> {
    let mut scored: Vec<ScoredEntry<'a>> = entries
        .iter()
        .filter_map(|e| {
            score_entry(&e.routing(), ctx, link_type).map(|score| ScoredEntry { entry: e, score })
        })
        .collect();
    scored.sort_by_key(|s| std::cmp::Reverse(s.score));
    scored
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(
        profile: Option<&str>,
        role: Option<&str>,
        language: Option<&str>,
        region: Option<&str>,
    ) -> RequestContext {
        RequestContext {
            profile: profile.map(str::to_string),
            role: role.map(str::to_string),
            language: language.map(str::to_string),
            region: region.map(str::to_string),
        }
    }

    fn routing<'a>(
        link_type: &'a str,
        profile: Option<&'a str>,
        role: Option<&'a str>,
        langs: &'a [String],
        region: Option<&'a str>,
    ) -> EntryRouting<'a> {
        EntryRouting {
            link_type,
            profile,
            role,
            language: langs,
            region,
        }
    }

    fn langs(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn context_key_formats_wildcards() {
        let c = ctx(
            Some("urn:unidpp:profile:jp-meti-pse"),
            None,
            Some("ja-JP"),
            None,
        );
        assert_eq!(
            c.context_key(),
            "profile=urn:unidpp:profile:jp-meti-pse;role=*;lang=ja-JP;region=*"
        );
        assert_eq!(primary_subtag("fr-CA"), "fr");
    }

    #[test]
    fn scoring_table() {
        let fr = langs(&["fr"]);
        let multi_l = langs(&["en", "fr"]);
        let eu = routing("dpp", Some("urn:p:eu"), Some("consumer"), &fr, Some("EU"));
        // exact on all four dimensions
        let c = ctx(Some("urn:p:eu"), Some("consumer"), Some("fr"), Some("EU"));
        assert_eq!(score_entry(&eu, &c, "dpp"), Some(4 + 4 + 4 + 4));
        // wrong rel
        assert_eq!(score_entry(&eu, &c, "dss-archive"), None);
        // profile mismatch
        let jp = ctx(Some("urn:p:jp"), Some("consumer"), Some("fr"), Some("EU"));
        assert_eq!(score_entry(&eu, &jp, "dpp"), None);
        // no preferences: specific link scores 2 per dimension
        assert_eq!(
            score_entry(&eu, &RequestContext::default(), "dpp"),
            Some(2 + 2 + 2 + 2)
        );
        // wildcard link with preferences scores 1 per dimension
        let wc = routing("dpp", None, None, &[], None);
        assert_eq!(score_entry(&wc, &c, "dpp"), Some(1 + 1 + 1 + 1));
        // language primary-subtag fallback
        let c2 = ctx(Some("urn:p:eu"), Some("consumer"), Some("fr-CA"), Some("EU"));
        assert_eq!(score_entry(&eu, &c2, "dpp"), Some(4 + 4 + 4 + 3));
        // language mismatch kills the link
        let c3 = ctx(Some("urn:p:eu"), Some("consumer"), Some("ja"), Some("EU"));
        assert_eq!(score_entry(&eu, &c3, "dpp"), None);
        // multi-language lists match on any member
        let multi = routing("dpp", None, None, &multi_l, None);
        assert_eq!(
            score_entry(&multi, &ctx(None, None, Some("fr"), None), "dpp"),
            Some(1 + 1 + 1 + 4)
        );
    }

    #[test]
    fn selection_orders_by_score_then_registration() {
        use crate::store::LinkEntry;
        use crate::time::Timestamp;
        let t = Timestamp::UNIX_EPOCH;
        let mk = |href: &str, profile: Option<&str>| LinkEntry {
            id: 0,
            link_type: "dpp".into(),
            href: href.into(),
            title: None,
            media_type: None,
            profile: profile.map(str::to_string),
            role: None,
            languages: Vec::new(),
            region: None,
            as_of: t,
            expiry: None,
        };
        let entries = vec![
            mk("https://eu/", Some("urn:p:eu")),
            mk("https://generic/", None),
            mk("https://jp/", Some("urn:p:jp")),
        ];
        let scored: Vec<&str> = select_ordered(&entries, &RequestContext::default(), "dpp")
            .into_iter()
            .map(|s| s.entry.href.as_str())
            .collect();
        // both specific links score 8 (tie -> registration order), wildcard 4
        assert_eq!(scored, vec!["https://eu/", "https://jp/", "https://generic/"]);
    }
}
