//! Discovery-protocol content negotiation (PLAN-OPERATORS C4): an
//! `Accept` header names the representation the client wants; the
//! resolver answers with the linkset entry published for that
//! representation's routing context (L5: linksets keyed by context).
//!
//! The mapping is a declarative table — media type → routing context
//! (the role dimension) — never an if-else chain; adding a
//! representation is adding a row. The table is applied only when the
//! request carries no explicit context parameters (`profile` / `role`
//! / `lang` / `region`): explicit parameters always outrank the
//! Accept header, and the negotiated context flows through the same
//! scoring machinery as an explicit one.

use crate::context::RequestContext;

/// The Accept→context table: each row maps a representation media
/// type to the linkset routing context that selects it.
pub const ACCEPT_CONTEXTS: &[(&str, &str)] = &[
    // UN Transparency Protocol verifiable credential — the
    // machine-to-machine render (`role=machine`).
    ("application/untp+json", "machine"),
    // EN 18222 DPP API render — authority access, customs / market
    // surveillance (`role=customs`).
    ("application/en18222+json", "customs"),
    // Human-facing browser view — the consumer destination
    // (`role=consumer`).
    ("text/html", "consumer"),
];

/// The routing context an `Accept` header selects: the client's most
/// preferred media type that appears in the table (RFC 9110
/// q-weights, client order breaking ties); `None` when nothing
/// matches — plain no-context resolution.
pub fn context_for_accept(accept: &str) -> Option<RequestContext> {
    let preferences = media_type_preferences(accept);
    preferences.iter().find_map(|media_type| {
        ACCEPT_CONTEXTS
            .iter()
            .find(|(m, _)| m == media_type)
            .map(|(_, role)| RequestContext {
                role: Some((*role).to_string()),
                ..RequestContext::default()
            })
    })
}

/// The Accept header's media types in client-preference order:
/// q-weight descending (stable sort — client order breaks ties),
/// `q=0` (explicitly not acceptable) dropped, media types
/// lowercased (they are case-insensitive per RFC 9110).
fn media_type_preferences(accept: &str) -> Vec<String> {
    let mut candidates: Vec<(f32, usize, String)> = Vec::new();
    for (index, entry) in accept.split(',').enumerate() {
        let mut parts = entry.split(';');
        let Some(media_type) = parts.next().map(str::trim) else {
            continue;
        };
        if media_type.is_empty() {
            continue;
        }
        let mut q = 1.0f32;
        for param in parts {
            if let Some(v) = param.trim().strip_prefix("q=") {
                q = v.trim().parse().unwrap_or(1.0);
            }
        }
        if q > 0.0 {
            candidates.push((q, index, media_type.to_ascii_lowercase()));
        }
    }
    candidates.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
    candidates.into_iter().map(|(_, _, mt)| mt).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn role_of(accept: &str) -> Option<String> {
        context_for_accept(accept)?.role
    }

    #[test]
    fn table_maps_each_media_type_to_its_context() {
        assert_eq!(role_of("application/untp+json").as_deref(), Some("machine"));
        assert_eq!(
            role_of("application/en18222+json").as_deref(),
            Some("customs")
        );
        assert_eq!(role_of("text/html").as_deref(), Some("consumer"));
        // The negotiated context routes on the role dimension only.
        let ctx = context_for_accept("application/untp+json").unwrap();
        assert!(ctx.profile.is_none() && ctx.language.is_none() && ctx.region.is_none());
        assert_eq!(ctx.context_key(), "profile=*;role=machine;lang=*;region=*");
    }

    #[test]
    fn q_weights_and_client_order_pick_the_offered_representation() {
        // An unoffered type first: the best offered one still wins.
        assert_eq!(
            role_of("application/xml, application/untp+json").as_deref(),
            Some("machine")
        );
        // q-weights reorder the client's preference.
        assert_eq!(
            role_of("text/html;q=0.5, application/untp+json;q=0.9").as_deref(),
            Some("machine")
        );
        assert_eq!(
            role_of("application/untp+json;q=0.5, text/html;q=0.9").as_deref(),
            Some("consumer")
        );
        // Equal weights: client order breaks the tie.
        assert_eq!(
            role_of("text/html, application/untp+json").as_deref(),
            Some("consumer")
        );
        assert_eq!(
            role_of("application/untp+json, text/html").as_deref(),
            Some("machine")
        );
        // Media types are case-insensitive; parameters other than q
        // are ignored.
        assert_eq!(
            role_of("APPLICATION/EN18222+JSON; charset=utf-8").as_deref(),
            Some("customs")
        );
        // A browser's real-world Accept list routes to the consumer
        // destination.
        assert_eq!(
            role_of("text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
                .as_deref(),
            Some("consumer")
        );
    }

    #[test]
    fn unknown_or_unacceptable_media_types_negotiate_nothing() {
        assert_eq!(role_of("application/json"), None);
        assert_eq!(role_of("*/*"), None);
        assert_eq!(role_of(""), None);
        // q=0 means "not acceptable": the type is dropped entirely.
        assert_eq!(
            role_of("application/untp+json;q=0, text/html").as_deref(),
            Some("consumer")
        );
        assert_eq!(role_of("application/untp+json;q=0"), None);
        // Malformed q values fall back to weight 1.
        assert_eq!(
            role_of("application/untp+json;q=nonsense").as_deref(),
            Some("machine")
        );
    }
}
