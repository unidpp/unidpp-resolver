//! Linkset store: identifier → linkset entries with context routing
//! dimensions, as-of/expiry validity, dark-identity intervals, and the
//! append-only record of every resolver state change (I4 doctrine:
//! nothing is edited in place — updates are appended registrations plus
//! revocations). The optional JSONL journal persists the record log and
//! is replayed on start.
//!
//! the UniDPP design framework invariants implemented here:
//! - I12 enumeration resistance: dark identifiers are
//!   indistinguishable from unknown ones at the public surface
//!   (see [`Lookup`]); there is no listing; the log never leaves the
//!   admin boundary.
//! - I13 as-of stamps: every entry carries `[asOf, expiry]` validity;
//!   resolution reconstructs the linkset as of any instant.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

use serde_json::{json, Map, Value};

use crate::context::EntryRouting;
use crate::time::Timestamp;

/// One linkset entry: `linkType` (RFC 9264 `rel`), target `href`
/// (`uri`), routing context (profile / role / language(s) / region;
/// absent or `"*"` = wildcard), and validity `[asOf, expiry]`
/// (expiry absent = open).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkEntry {
    pub id: u64,
    pub link_type: String,
    pub href: String,
    pub title: Option<String>,
    pub media_type: Option<String>,
    pub profile: Option<String>,
    pub role: Option<String>,
    pub languages: Vec<String>,
    pub region: Option<String>,
    pub as_of: Timestamp,
    pub expiry: Option<Timestamp>,
}

impl LinkEntry {
    /// Routing view for context scoring.
    pub fn routing(&self) -> EntryRouting<'_> {
        EntryRouting {
            link_type: &self.link_type,
            profile: self.profile.as_deref(),
            role: self.role.as_deref(),
            language: self.languages.as_slice(),
            region: self.region.as_deref(),
        }
    }

    /// Effective at instant `t`? (Entry validity, ignoring revocations.)
    pub fn valid_at(&self, t: Timestamp) -> bool {
        self.as_of <= t && self.expiry.map_or(true, |e| t <= e)
    }

    /// Admin/journal JSON form.
    pub fn to_json(&self) -> Value {
        let mut m = Map::new();
        m.insert("id".into(), json!(self.id));
        m.insert("linkType".into(), json!(self.link_type));
        m.insert("href".into(), json!(self.href));
        if let Some(t) = &self.title {
            m.insert("title".into(), json!(t));
        }
        if let Some(t) = &self.media_type {
            m.insert("type".into(), json!(t));
        }
        if let Some(p) = &self.profile {
            m.insert("profile".into(), json!(p));
        }
        if let Some(r) = &self.role {
            m.insert("role".into(), json!(r));
        }
        m.insert("language".into(), json!(self.languages));
        if let Some(r) = &self.region {
            m.insert("region".into(), json!(r));
        }
        m.insert("asOf".into(), json!(self.as_of.to_string()));
        if let Some(e) = self.expiry {
            m.insert("expiry".into(), json!(e.to_string()));
        }
        Value::Object(m)
    }

    /// Parse an admin-body link object (`id` ignored on input).
    pub fn from_admin_json(v: &Value) -> Result<LinkEntry, String> {
        let obj = v.as_object().ok_or("link entry must be an object")?;
        let get_str = |k: &str| -> Result<Option<String>, String> {
            match obj.get(k) {
                None | Some(Value::Null) => Ok(None),
                Some(Value::String(s)) if s.is_empty() || s == "*" => Ok(None),
                Some(Value::String(s)) => Ok(Some(s.clone())),
                Some(_) => Err(format!("`{k}` must be a string")),
            }
        };
        let link_type = get_str("linkType")?
            .ok_or_else(|| "`linkType` is required (non-empty, not \"*\")".to_string())?;
        let href = get_str("href")?
            .ok_or_else(|| "`href` is required".to_string())?;
        let valid_href = href.starts_with("http://")
            || href.starts_with("https://")
            || href.starts_with("urn:");
        if !valid_href || href.contains(char::is_whitespace) {
            return Err(format!("`href` must be an absolute http(s)/urn URI: `{href}`"));
        }
        let languages = match obj.get("language") {
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
                        .ok_or("`language` array items must be strings")?;
                    if !s.is_empty() && s != "*" {
                        langs.push(s.to_string());
                    }
                }
                langs
            }
            Some(_) => return Err("`language` must be a string or array of strings".into()),
        };
        let as_of = match obj.get("asOf") {
            None | Some(Value::Null) => Timestamp::now(),
            Some(Value::String(s)) => Timestamp::parse(s).map_err(|e| e.to_string())?,
            Some(_) => return Err("`asOf` must be an RFC 3339 string".into()),
        };
        let expiry = match obj.get("expiry") {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) => Some(Timestamp::parse(s).map_err(|e| e.to_string())?),
            Some(_) => return Err("`expiry` must be an RFC 3339 string".into()),
        };
        if let Some(e) = expiry {
            if e < as_of {
                return Err(format!("`expiry` {e} before `asOf` {as_of}"));
            }
        }
        Ok(LinkEntry {
            id: 0,
            link_type,
            href,
            title: get_str("title")?,
            media_type: get_str("type")?,
            profile: get_str("profile")?,
            role: get_str("role")?,
            languages,
            region: get_str("region")?,
            as_of,
            expiry,
        })
    }
}

/// An append-only resolver operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op {
    RegisterEntry { identifier: String, entry: LinkEntry },
    RevokeEntry { identifier: String, entry_id: u64, effective_at: Timestamp, reason: String },
    SetDark { identifier: String, effective_at: Timestamp },
    ClearDark { identifier: String, effective_at: Timestamp },
}

/// One record in the append-only resolver history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogRecord {
    pub seq: u64,
    pub recorded_at: Timestamp,
    pub op: Op,
}

impl LogRecord {
    pub fn to_json(&self) -> Value {
        let base = match &self.op {
            Op::RegisterEntry { identifier, entry } => {
                json!({"op": "register-entry", "identifier": identifier, "entry": entry.to_json()})
            }
            Op::RevokeEntry { identifier, entry_id, effective_at, reason } => {
                json!({"op": "revoke-entry", "identifier": identifier, "entryId": entry_id,
                       "effectiveAt": effective_at.to_string(), "reason": reason})
            }
            Op::SetDark { identifier, effective_at } => {
                json!({"op": "set-dark", "identifier": identifier, "effectiveAt": effective_at.to_string()})
            }
            Op::ClearDark { identifier, effective_at } => {
                json!({"op": "clear-dark", "identifier": identifier, "effectiveAt": effective_at.to_string()})
            }
        };
        let mut m = base.as_object().cloned().unwrap_or_default();
        m.insert("seq".into(), json!(self.seq));
        m.insert("recordedAt".into(), json!(self.recorded_at.to_string()));
        Value::Object(m)
    }

    pub fn from_json(v: &Value) -> Result<LogRecord, String> {
        let obj = v.as_object().ok_or("log record must be an object")?;
        let seq = obj.get("seq").and_then(Value::as_u64).ok_or("missing `seq`")?;
        let recorded_at = obj
            .get("recordedAt")
            .and_then(Value::as_str)
            .and_then(|s| Timestamp::parse(s).ok())
            .ok_or("missing/invalid `recordedAt`")?;
        let ts = |k: &str| -> Result<Timestamp, String> {
            obj.get(k)
                .and_then(Value::as_str)
                .and_then(|s| Timestamp::parse(s).ok())
                .ok_or_else(|| format!("missing/invalid `{k}`"))
        };
        let identifier = |k: &str| -> Result<String, String> {
            obj.get(k)
                .and_then(Value::as_str)
                .map(str::to_string)
                .ok_or_else(|| format!("missing `{k}`"))
        };
        let op = match obj.get("op").and_then(Value::as_str) {
            Some("register-entry") => Op::RegisterEntry {
                identifier: identifier("identifier")?,
                entry: LinkEntry::from_admin_json(obj.get("entry").ok_or("missing `entry`")?)?,
            },
            Some("revoke-entry") => Op::RevokeEntry {
                identifier: identifier("identifier")?,
                entry_id: obj.get("entryId").and_then(Value::as_u64).ok_or("missing `entryId`")?,
                effective_at: ts("effectiveAt")?,
                reason: obj
                    .get("reason")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
            },
            Some("set-dark") => Op::SetDark {
                identifier: identifier("identifier")?,
                effective_at: ts("effectiveAt")?,
            },
            Some("clear-dark") => Op::ClearDark {
                identifier: identifier("identifier")?,
                effective_at: ts("effectiveAt")?,
            },
            _ => return Err("unknown `op`".to_string()),
        };
        Ok(LogRecord { seq, recorded_at, op })
    }
}

/// A dark interval `[from, to)`; `to` absent = dark from `on`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DarkInterval {
    pub from: Timestamp,
    pub to: Option<Timestamp>,
}

impl DarkInterval {
    fn contains(&self, t: Timestamp) -> bool {
        self.from <= t && self.to.map_or(true, |to| t < to)
    }
}

/// Per-identifier resolver state (all append-only).
#[derive(Debug, Clone, Default)]
pub struct IdentifierState {
    pub entries: Vec<LinkEntry>,
    pub revocations: Vec<(u64, Timestamp, String)>,
    pub dark: Vec<DarkInterval>,
}

/// Result of a public lookup at instant `t`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lookup {
    /// Registered dark at `t`: 404 with no information (I12).
    Dark,
    /// Served: effective entries (possibly empty for the requested
    /// rel — the doc-level filter happens in the API layer).
    Resolved(Vec<LinkEntry>),
    /// Locally known but nothing effective at `t` (treated exactly
    /// like `Absent` on the public surface).
    KnownEmpty,
    /// Never registered here.
    Absent,
}

/// Cached upstream linkset for national-intermediary mode (I13: caches
/// carry as-of stamps and serve stale on upstream outage).
#[derive(Debug, Clone)]
pub struct CacheEntry {
    pub fetched_at: Timestamp,
    pub entries: Vec<LinkEntry>,
}

/// The linkset store plus its append-only record log and intermediary
/// cache.
pub struct Store {
    ids: HashMap<String, IdentifierState>,
    log: Vec<LogRecord>,
    next_entry_id: u64,
    journal: Option<File>,
    cache: HashMap<String, CacheEntry>,
}

impl Store {
    /// Fresh store with an optional JSONL journal (opened for append;
    /// existing lines are replayed).
    pub fn open(journal: Option<&Path>) -> std::io::Result<Store> {
        let mut store = Store {
            ids: HashMap::new(),
            log: Vec::new(),
            next_entry_id: 1,
            journal: None,
            cache: HashMap::new(),
        };
        if let Some(path) = journal {
            if let Some(parent) = path.parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent)?;
                }
            }
            let existed = path.exists();
            if existed {
                store.replay(path)?;
            }
            store.journal = Some(
                OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)?,
            );
        }
        Ok(store)
    }

    fn replay(&mut self, path: &Path) -> std::io::Result<()> {
        let file = File::open(path)?;
        for (i, line) in BufReader::new(file).lines().enumerate() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<Value>(&line)
                .map_err(|e| e.to_string())
                .and_then(|v| LogRecord::from_json(&v))
            {
                Ok(rec) => {
                    self.apply(&rec);
                    self.log.push(rec);
                }
                Err(e) => {
                    // A torn final line (crash mid-write) is tolerated;
                    // anything else is reported and skipped loudly.
                    eprintln!("unidpp-resolver: journal line {}: {e}", i + 1);
                }
            }
        }
        Ok(())
    }

    /// Append a record to the log (and journal), then apply it.
    pub fn record(&mut self, op: Op) -> LogRecord {
        let rec = LogRecord {
            seq: self.log.len() as u64 + 1,
            recorded_at: Timestamp::now(),
            op,
        };
        if let Some(j) = self.journal.as_mut() {
            if let Err(e) = writeln!(j, "{}", rec.to_json()) {
                eprintln!("unidpp-resolver: journal write failed: {e}");
            }
        }
        self.apply(&rec);
        self.log.push(rec.clone());
        rec
    }

    /// Pure state transition used by both live recording and journal
    /// replay.
    fn apply(&mut self, rec: &LogRecord) {
        match &rec.op {
            Op::RegisterEntry { identifier, entry } => {
                let id = entry.id.max(1);
                self.next_entry_id = self.next_entry_id.max(id + 1);
                let mut entry = entry.clone();
                entry.id = id;
                self.ids
                    .entry(identifier.clone())
                    .or_default()
                    .entries
                    .push(entry);
            }
            Op::RevokeEntry { identifier, entry_id, effective_at, reason } => {
                self.ids
                    .entry(identifier.clone())
                    .or_default()
                    .revocations
                    .push((*entry_id, *effective_at, reason.clone()));
            }
            Op::SetDark { identifier, effective_at } => {
                let state = self.ids.entry(identifier.clone()).or_default();
                // Only append an interval if none is open.
                if !state.dark.iter().any(|d| d.to.is_none()) {
                    state.dark.push(DarkInterval { from: *effective_at, to: None });
                }
            }
            Op::ClearDark { identifier, effective_at } => {
                let state = self.ids.entry(identifier.clone()).or_default();
                for d in state.dark.iter_mut() {
                    if d.to.is_none() {
                        d.to = Some(*effective_at);
                    }
                }
            }
        }
    }

    /// Register entries for `identifier` (assigning fresh ids).
    pub fn register(
        &mut self,
        identifier: &str,
        entries: Vec<LinkEntry>,
    ) -> Vec<LinkEntry> {
        let mut registered = Vec::new();
        for mut entry in entries {
            entry.id = self.next_entry_id;
            self.next_entry_id += 1;
            registered.push(entry.clone());
            self.record(Op::RegisterEntry {
                identifier: identifier.to_string(),
                entry,
            });
        }
        registered
    }

    /// Revoke one entry (append-only).
    pub fn revoke(&mut self, identifier: &str, entry_id: u64, effective_at: Timestamp, reason: &str) {
        self.record(Op::RevokeEntry {
            identifier: identifier.to_string(),
            entry_id,
            effective_at,
            reason: reason.to_string(),
        });
    }

    /// Public lookup at instant `t`.
    ///
    /// Dark semantics (I12): a query inside a dark interval is denied,
    /// and so is a query *before* the first darkening — once an
    /// identity goes dark, this resolver denies its pre-dark past as
    /// well (the transition and the history must both disappear).
    /// Clearing dark restores service from the clear instant onward.
    pub fn lookup(&self, key: &str, t: Timestamp) -> Lookup {
        let Some(state) = self.ids.get(key) else {
            return Lookup::Absent;
        };
        if state.dark.iter().any(|d| d.contains(t) || t < d.from) {
            return Lookup::Dark;
        }
        let effective: Vec<LinkEntry> = state
            .entries
            .iter()
            .filter(|e| {
                e.valid_at(t)
                    && !state
                        .revocations
                        .iter()
                        .any(|(id, at, _)| *id == e.id && *at <= t)
            })
            .cloned()
            .collect();
        if effective.is_empty() {
            Lookup::KnownEmpty
        } else {
            Lookup::Resolved(effective)
        }
    }

    /// All entries currently known for `identifier` (admin view —
    /// includes not-yet-effective, expired and revoked ones, with
    /// revocation annotations).
    pub fn admin_view(&self, key: &str) -> Option<Value> {
        let state = self.ids.get(key)?;
        let entries: Vec<Value> = state
            .entries
            .iter()
            .map(|e| {
                let mut v = e.to_json();
                let revoked = state
                    .revocations
                    .iter()
                    .find(|(id, _, _)| *id == e.id)
                    .map(|(_, at, reason)| json!({"effectiveAt": at.to_string(), "reason": reason}));
                if let Some(r) = revoked {
                    if let Some(o) = v.as_object_mut() {
                        o.insert("revoked".into(), r);
                    }
                }
                v
            })
            .collect();
        let dark: Vec<Value> = state
            .dark
            .iter()
            .map(|d| {
                json!({"from": d.from.to_string(), "to": d.to.map(|t| t.to_string())})
            })
            .collect();
        Some(json!({
            "identifier": key,
            "entries": entries,
            "darkIntervals": dark,
            "recordCount": self.log.len(),
        }))
    }

    /// The append-only record log (admin view).
    pub fn log_json(&self, limit: usize, offset: usize) -> Value {
        let total = self.log.len();
        let slice: Vec<Value> = self
            .log
            .iter()
            .skip(offset)
            .take(limit)
            .map(LogRecord::to_json)
            .collect();
        json!({
            "total": total,
            "offset": offset,
            "records": slice,
        })
    }

    /// Upstream cache access (national-intermediary mode).
    pub fn cache_get(&self, key: &str) -> Option<&CacheEntry> {
        self.cache.get(key)
    }

    pub fn cache_put(&mut self, key: &str, entry: CacheEntry) {
        self.cache.insert(key.to_string(), entry);
    }

    /// Number of records in the log (for tests and admin stats).
    pub fn log_len(&self) -> usize {
        self.log.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(href: &str, as_of: Timestamp) -> LinkEntry {
        LinkEntry {
            id: 0,
            link_type: "dpp".to_string(),
            href: href.to_string(),
            title: None,
            media_type: None,
            profile: None,
            role: None,
            languages: Vec::new(),
            region: None,
            as_of,
            expiry: None,
        }
    }

    fn ts(s: &str) -> Timestamp {
        Timestamp::parse(s).unwrap()
    }

    #[test]
    fn register_and_lookup() {
        let mut store = Store::open(None).unwrap();
        let t0 = ts("2026-01-01T00:00:00Z");
        let registered = store.register("gs1:(01)06901234567892", vec![entry("https://a.example/x", t0)]);
        assert_eq!(registered[0].id, 1);
        match store.lookup("gs1:(01)06901234567892", t0) {
            Lookup::Resolved(v) => assert_eq!(v.len(), 1),
            other => panic!("{other:?}"),
        }
        // before as-of -> known but empty
        assert_eq!(store.lookup("gs1:(01)06901234567892", ts("2025-12-31T23:59:59Z")), Lookup::KnownEmpty);
        assert_eq!(store.lookup("gs1:(01)99999999999999", t0), Lookup::Absent);
    }

    #[test]
    fn revocation_and_as_of() {
        let mut store = Store::open(None).unwrap();
        let t0 = ts("2026-01-01T00:00:00Z");
        let t1 = ts("2026-06-01T00:00:00Z");
        store.register("gs1:(01)06901234567892", vec![entry("https://a.example/x", t0)]);
        store.revoke("gs1:(01)06901234567892", 1, t1, "superseded");
        assert!(matches!(store.lookup("gs1:(01)06901234567892", t1), Lookup::KnownEmpty));
        // historical query before the revocation still resolves
        assert!(matches!(store.lookup("gs1:(01)06901234567892", ts("2026-03-01T00:00:00Z")), Lookup::Resolved(_)));
    }

    #[test]
    fn dark_intervals() {
        let mut store = Store::open(None).unwrap();
        let t0 = ts("2026-01-01T00:00:00Z");
        store.register("iso-15459:urn:iso:std:iso-iec:15459:unidpp:inst:1", vec![entry("https://a.example/x", t0)]);
        store.record(Op::SetDark {
            identifier: "iso-15459:urn:iso:std:iso-iec:15459:unidpp:inst:1".into(),
            effective_at: ts("2026-02-01T00:00:00Z"),
        });
        assert_eq!(
            store.lookup("iso-15459:urn:iso:std:iso-iec:15459:unidpp:inst:1", ts("2026-03-01T00:00:00Z")),
            Lookup::Dark
        );
        // dark hides even historical (as-of before darkening) queries
        assert_eq!(
            store.lookup("iso-15459:urn:iso:std:iso-iec:15459:unidpp:inst:1", ts("2026-01-15T00:00:00Z")),
            Lookup::Dark
        );
        store.record(Op::ClearDark {
            identifier: "iso-15459:urn:iso:std:iso-iec:15459:unidpp:inst:1".into(),
            effective_at: ts("2026-04-01T00:00:00Z"),
        });
        assert!(matches!(
            store.lookup("iso-15459:urn:iso:std:iso-iec:15459:unidpp:inst:1", ts("2026-05-01T00:00:00Z")),
            Lookup::Resolved(_)
        ));
    }

    #[test]
    fn expiry_bounds() {
        let mut store = Store::open(None).unwrap();
        let mut e = entry("https://a.example/x", ts("2026-01-01T00:00:00Z"));
        e.expiry = Some(ts("2026-02-01T00:00:00Z"));
        store.register("gs1:(01)06901234567892", vec![e]);
        assert!(matches!(store.lookup("gs1:(01)06901234567892", ts("2026-01-15T00:00:00Z")), Lookup::Resolved(_)));
        assert_eq!(store.lookup("gs1:(01)06901234567892", ts("2026-02-02T00:00:00Z")), Lookup::KnownEmpty);
    }

    #[test]
    fn journal_round_trip() {
        let dir = std::env::temp_dir().join(format!("unidpp-resolver-test-{}", std::process::id()));
        let path = dir.join("journal.jsonl");
        let _ = std::fs::remove_file(&path);
        std::fs::create_dir_all(&dir).unwrap();
        {
            let mut store = Store::open(Some(&path)).unwrap();
            let t0 = ts("2026-01-01T00:00:00Z");
            store.register("gs1:(01)06901234567892", vec![entry("https://a.example/x", t0)]);
            store.revoke("gs1:(01)06901234567892", 1, t0, "test");
            store.record(Op::SetDark {
                identifier: "gs1:(01)4006381333931".into(),
                effective_at: t0,
            });
        }
        let store = Store::open(Some(&path)).unwrap();
        assert_eq!(store.log_len(), 3);
        assert_eq!(store.lookup("gs1:(01)4006381333931", ts("2026-06-01T00:00:00Z")), Lookup::Dark);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn admin_json_round_trip() {
        let v: Value = serde_json::from_str(
            r#"{"linkType":"dpp","href":"https://dpp.example.org/eu/1",
                "profile":"urn:unidpp:profile:eu-espr-electronics","role":"consumer",
                "language":["en","fr"],"region":"EU",
                "asOf":"2026-01-01T00:00:00Z","expiry":"2027-01-01T00:00:00Z"}"#,
        )
        .unwrap();
        let e = LinkEntry::from_admin_json(&v).unwrap();
        assert_eq!(e.languages, vec!["en".to_string(), "fr".to_string()]);
        assert_eq!(e.profile.as_deref(), Some("urn:unidpp:profile:eu-espr-electronics"));
        let e2 = LinkEntry::from_admin_json(&e.to_json()).unwrap();
        assert_eq!(e, e2);
        // wildcard normalizes to None
        let w: Value = serde_json::from_str(
            r#"{"linkType":"dpp","href":"https://x/","profile":"*","asOf":"2026-01-01T00:00:00Z"}"#,
        )
        .unwrap();
        let e3 = LinkEntry::from_admin_json(&w).unwrap();
        assert_eq!(e3.profile, None);
        // rejects bad hrefs and inverted validity
        assert!(LinkEntry::from_admin_json(&json!({"linkType":"dpp","href":"not a uri"})).is_err());
        assert!(LinkEntry::from_admin_json(
            &json!({"linkType":"dpp","href":"https://x/","asOf":"2027-01-01T00:00:00Z","expiry":"2026-01-01T00:00:00Z"})
        ).is_err());
    }
}
