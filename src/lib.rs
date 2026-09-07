//! UniDPP federated resolver (crate `unidpp-resolver`).
//!
//! Reference implementation of the the UniDPP design framework L5 resolution layer and the
//! S2 seam (mirrors, national intermediary layers, dark identities):
//! - carrier → identifier normalization across GS1 Digital Link
//!   (AIs 01/10/21, check digit enforced), GB/T 33993 shapes (GDS
//!   `/g/` paths, enterprise custom codes) and legacy EAN-13, with
//!   ISO/IEC 15459 URN passthrough — ported from `@unidpp/resolver`;
//! - an identifier-keyed linkset store with context routing
//!   (profile × role × language × region, specificity scoring,
//!   default-link rule) and RFC 9264 JSON responses;
//! - `/.well-known/unidpp-resolver` discovery (GS1-resolver-inspired,
//!   neutral);
//! - dark identities (404-with-no-information, indistinguishable from
//!   unknown — I12) and national-intermediary mode (upstream proxy with
//!   cache and as-of stamping — I13);
//! - an admin API whose every state change is appended to the record
//!   log (optionally journaled as JSONL and replayed on start).
//!
//! Server: axum (compiles cleanly, already in the toolchain cache).
//! Dependency-light on purpose: axum, tokio, serde_json — no tracing,
//! no metrics, no TLS stack (the reference client speaks `http://`
//! upstream only; production terminates TLS at a fronting proxy).

// Handlers and parse helpers return `Result<_, Response>` with the
// ready-made error response by value — the idiomatic axum pattern;
// boxing the error would complicate every call site for no gain.
#![allow(clippy::result_large_err)]

pub mod api;
pub mod carrier;
pub mod context;
pub mod discovery;
pub mod gbt33993;
pub mod gs1dl;
pub mod httpc;
pub mod linkset;
pub mod negotiate;
pub mod proxy;
pub mod store;
pub mod time;

pub use api::{run, Config, TestServer};
pub use carrier::{parse_carrier, CarrierKind, CarrierLookup, CarrierParse, ResolvedIdentifier};
pub use context::{EntryRouting, RequestContext};
pub use gs1dl::{gs1_check_digit, parse_gs1_digital_link, valid_gtin};
pub use linkset::{emit_document, parse_document};
pub use negotiate::{context_for_accept, ACCEPT_CONTEXTS};
pub use store::{LinkEntry, Lookup, Op, Store};
pub use time::Timestamp;
