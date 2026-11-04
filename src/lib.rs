//! Search language, predicates and query executor over uSIEM events.
//!
//! A query is a filter followed by pipe commands (see [`query`]). Planning
//! splits it into what a storage backend evaluates ([`store::StoreQuery`])
//! and what runs here on top of the backend's result stream: virtual fields,
//! residual filters, `sort`, `stats` and the rest.
//!
//! Backends implement [`store::EventSource`] (read side) and, when they take
//! writes through the same handle, [`store::EventStore`].

pub mod query;
pub mod store;
pub mod text;

#[cfg(all(test, feature = "jsonl"))]
mod test_util;

/// The real uSIEM event struct (`usiem::event::Event` is the object builder).
pub use usiem::event::CoreEvent as Event;
