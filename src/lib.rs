//! # usiem-query, the uSIEM search language
//!
//! A pipe search language, predicates and a query executor over
//! [uSIEM](https://github.com/u-siem/usiem) events, shared by every
//! application built on uSIEM:
//!
//! ```text
//! process.name:sshd source.ip:10.0.0.0/8 NOT user.name:root earliest=-24h
//!   | stats count, dc(source.ip) as sources by user.name
//!   | sort -count | head 20
//! ```
//!
//! - **Parsing.** [`query::parse`] turns query text into a [`query::Query`]:
//!   a filter ([`store::Predicate`]), a time range and pipe commands. The
//!   parser takes untrusted text: it reports errors with a byte position and
//!   refuses nesting deeper than [`query::MAX_NESTING`].
//! - **Planning.** [`query::exec::plan`] splits a query into what a storage
//!   backend evaluates ([`store::StoreQuery`]) and what runs here on top of
//!   the backend's result stream: virtual fields, residual filters, `sort`,
//!   `stats` and the rest.
//! - **Execution.** [`query::execute`] runs a query against any
//!   [`store::EventSource`], with row limits and cancellation
//!   ([`query::ExecOptions`]). A [`query::VirtualFields`] hook computes
//!   `field@attr` values at query time.
//! - **Per-event filters.** [`query::StreamFilter`] evaluates a filter and
//!   `| where` stages one event at a time, for live tails and detection.
//!
//! The full syntax is in [`query`] and, as plain text for help screens, in
//! [`query::HELP`].
//!
//! ## Features
//!
//! | Feature | Adds |
//! |---|---|
//! | `jsonl` (default) | `store::jsonl::JsonlStore`, a simple JSON-lines backend, also the oracle other backends are tested against. |
//! | `evstore` | `store::evstore::EvstoreSource`, the usiem-evstore backend. |
//!
//! ## Example
//!
//! ```
//! use usiem::event::{FieldValue, Origin, RawData, Timestamp};
//! use usiem_query::Event;
//! use usiem_query::query::StreamFilter;
//!
//! let mut event = Event::new(
//!     Timestamp::from_secs(10),
//!     Timestamp::from_secs(10),
//!     Origin::Collector("doc".into()),
//!     RawData::from_text("sshd: Accepted password for bob"),
//! );
//! event.add_field("process.name".into(), FieldValue::from("sshd"));
//! event.add_field("user.name".into(), FieldValue::from("Bob"));
//!
//! let filter = StreamFilter::parse("process.name:sshd user.name:(alice OR bob)")?;
//! assert!(filter.matches(&event));
//! let filter = StreamFilter::parse("process.name:ssh* NOT user.name:bob")?;
//! assert!(!filter.matches(&event));
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod query;
pub mod store;
pub mod text;

#[cfg(test)]
#[cfg(feature = "jsonl")]
mod test_util;

/// The real uSIEM event struct (`usiem::event::Event` is the object builder).
pub use usiem::event::CoreEvent as Event;
