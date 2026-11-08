//! Event storage interface.
//!
//! [`EventSource`] is deliberately small: search with a [`StoreQuery`] and
//! describe the fields seen so far. [`StoreQuery`] holds only what
//! usiem-evstore's design says it will push down (time range plus
//! eq/in/prefix/range/CIDR predicates). Everything else (virtual fields,
//! sorting, table commands) runs in the query executor on top of the result
//! iterator. A backend may also answer a leading `stats` itself through
//! [`EventSource::aggregate`]; the default declines and the executor
//! aggregates the event stream.
//!
//! [`EventStore`] adds appends for backends written through the same handle
//! they are read from. Backends with their own write path (a server's ingest
//! pipeline, say) only need [`EventSource`].

#[cfg(feature = "evstore")]
pub mod evstore;
#[cfg(feature = "jsonl")]
pub mod jsonl;
pub mod predicate;

use crate::Event;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use usiem::event::{FieldValue, Timestamp};

pub use predicate::{
    Cidr, FieldOp, FlatLookup, Literal, Pattern, Predicate, Record, Substrings, compare_values,
    lookup,
};

/// A storage backend failure.
#[derive(Debug)]
#[non_exhaustive]
pub enum StoreError {
    /// Reading or writing failed.
    Io(std::io::Error),
    /// A stored record could not be decoded.
    Corrupt {
        /// Where: the segment and line, or the record.
        location: String,
        /// What is wrong.
        reason: String,
    },
    /// An event could not be encoded for storage.
    Encode(String),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::Io(e) => write!(f, "store I/O error: {e}"),
            StoreError::Corrupt { location, reason } => {
                write!(f, "corrupt record at {location}: {reason}")
            }
            StoreError::Encode(e) => write!(f, "cannot encode event: {e}"),
        }
    }
}

impl std::error::Error for StoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            StoreError::Io(e) => Some(e),
            StoreError::Corrupt { .. } | StoreError::Encode(_) => None,
        }
    }
}

impl From<std::io::Error> for StoreError {
    fn from(e: std::io::Error) -> Self {
        StoreError::Io(e)
    }
}

/// Result of [`EventStore::append`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppendAck {
    /// Events written by this call.
    pub appended: usize,
    /// Events in the store after this call.
    pub total: u64,
    /// Everything appended so far (this batch included) is already on
    /// stable storage; when `false`, call [`EventStore::sync`] for that.
    pub synced: bool,
}

/// Half-open interval `[start, end)` on `original_time`. `None` is unbounded.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TimeRange {
    /// Inclusive start.
    pub start: Option<Timestamp>,
    /// Exclusive end.
    pub end: Option<Timestamp>,
}

impl TimeRange {
    /// Whether `t` is in the range.
    pub fn contains(&self, t: Timestamp) -> bool {
        self.start.is_none_or(|s| t >= s) && self.end.is_none_or(|e| t < e)
    }

    /// Whether `[min, max]` (inclusive) can contain any time in this range.
    pub fn overlaps(&self, min: Timestamp, max: Timestamp) -> bool {
        self.start.is_none_or(|s| max >= s) && self.end.is_none_or(|e| min < e)
    }
}

/// Result ordering.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Order {
    /// Whatever order the backend stores events in; the cheapest.
    #[default]
    Storage,
    /// Oldest `original_time` first.
    TimeAsc,
    /// Newest `original_time` first.
    TimeDesc,
}

/// What a backend is asked to evaluate.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct StoreQuery {
    /// Time range on `original_time`.
    pub time: TimeRange,
    /// Events must match this.
    pub filter: Predicate,
    /// Result order.
    pub order: Order,
    /// At most this many events.
    pub limit: Option<usize>,
}

/// The events a search yields, or the error that stopped it.
pub type EventIter<'a> = Box<dyn Iterator<Item = Result<Event, StoreError>> + 'a>;

/// A `stats` result: the `by` names then the aggregate names, and one row
/// per group, built exactly as the executor's own `stats` would.
#[derive(Debug, Clone, PartialEq)]
pub struct StatsTable {
    /// Column names.
    pub columns: Vec<String>,
    /// Rows, one value (or none) per column.
    pub rows: Vec<Vec<Option<FieldValue>>>,
}

/// Read side of an event store.
pub trait EventSource: Send + Sync {
    /// Events matching `query`, in its order and up to its limit.
    ///
    /// # Errors
    ///
    /// When the search cannot start; errors while reading come through the
    /// iterator.
    fn search(&self, query: &StoreQuery) -> Result<EventIter<'_>, StoreError>;

    /// Fields seen so far with their value kinds, for autocomplete and
    /// for planning.
    fn field_catalog(&self) -> &FieldCatalog;

    /// Number of stored events.
    fn len(&self) -> u64;

    /// Answers `<query> | stats <aggs> by <by>` without streaming events,
    /// or returns `Ok(None)` to let the executor do it. An implementation
    /// must return exactly what the executor would (see
    /// [`crate::query::exec::stats_table`]).
    ///
    /// # Errors
    ///
    /// When the backend fails while aggregating.
    fn aggregate(
        &self,
        _query: &StoreQuery,
        _aggs: &[crate::query::Agg],
        _by: &[crate::query::GroupKey],
    ) -> Result<Option<StatsTable>, StoreError> {
        Ok(None)
    }

    /// Whether the store holds no events.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Append-only event storage, read and written through one handle.
pub trait EventStore: EventSource {
    /// Appends a batch of events.
    ///
    /// # Errors
    ///
    /// When the batch cannot be encoded or written; how much of it was
    /// written is up to the backend.
    fn append(&mut self, batch: Vec<Event>) -> Result<AppendAck, StoreError>;

    /// Makes every event appended so far durable: once this returns, they
    /// survive a crash or power loss. Cheap when nothing is pending.
    ///
    /// # Errors
    ///
    /// When flushing or syncing fails.
    fn sync(&mut self) -> Result<(), StoreError>;

    /// Ends an ingest run: flushes and persists metadata. Appending again
    /// afterwards is allowed.
    ///
    /// # Errors
    ///
    /// When flushing or writing metadata fails.
    fn seal(&mut self) -> Result<(), StoreError>;
}

/// Kind of a stored [`FieldValue`], without the value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FieldKind {
    /// [`FieldValue::Str`].
    Str,
    /// [`FieldValue::Int`].
    Int,
    /// [`FieldValue::Uint`].
    Uint,
    /// [`FieldValue::Float`].
    Float,
    /// [`FieldValue::Bool`].
    Bool,
    /// [`FieldValue::Bytes`].
    Bytes,
    /// [`FieldValue::Time`].
    Time,
    /// [`FieldValue::Ip`].
    Ip,
    /// [`FieldValue::Object`].
    Object,
    /// [`FieldValue::Array`].
    Array,
}

impl FieldKind {
    /// The kind of `value`.
    pub fn of(value: &FieldValue) -> FieldKind {
        match value {
            FieldValue::Str(_) => FieldKind::Str,
            FieldValue::Int(_) => FieldKind::Int,
            FieldValue::Uint(_) => FieldKind::Uint,
            FieldValue::Float(_) => FieldKind::Float,
            FieldValue::Bool(_) => FieldKind::Bool,
            FieldValue::Bytes(_) => FieldKind::Bytes,
            FieldValue::Time(_) => FieldKind::Time,
            FieldValue::Ip(_) => FieldKind::Ip,
            FieldValue::Object(_) => FieldKind::Object,
            FieldValue::Array(_) => FieldKind::Array,
        }
    }
}

/// Per-field statistics.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct FieldStats {
    /// Events containing the field.
    pub count: u64,
    /// Value kinds seen.
    pub kinds: BTreeSet<FieldKind>,
}

/// Distinct values kept per inventory field; later values are not counted.
pub const MAX_INVENTORY_VALUES: usize = 1_000;

/// Every field name seen in a store, plus value counts for the
/// *inventory fields*: the few fields whose distinct values describe what a
/// store holds (artifact kinds and hosts for a forensic case, say).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct FieldCatalog {
    /// Field name → statistics.
    pub fields: BTreeMap<String, FieldStats>,
    /// Field → value → events. Empty for stores written before it existed.
    #[serde(default)]
    pub values: BTreeMap<String, BTreeMap<String, u64>>,
    /// Fields whose values [`observe`](Self::observe) counts into
    /// [`values`](Self::values). Configuration, not data: set by the store
    /// owner after loading.
    #[serde(skip)]
    pub inventory_fields: Vec<String>,
}

impl FieldCatalog {
    /// A catalog counting the values of `fields`.
    pub fn with_inventory(fields: &[&str]) -> FieldCatalog {
        FieldCatalog {
            inventory_fields: fields.iter().map(|f| (*f).to_string()).collect(),
            ..FieldCatalog::default()
        }
    }

    /// Counts `event`'s fields (and inventory values).
    pub fn observe(&mut self, event: &Event) {
        for (name, value) in event.fields() {
            let stats = match self.fields.get_mut(name) {
                Some(stats) => stats,
                None => self.fields.entry(name.clone()).or_default(),
            };
            stats.count += 1;
            stats.kinds.insert(FieldKind::of(value));
        }
        for field in &self.inventory_fields {
            let Some(value) = event.get_field(field) else {
                continue;
            };
            let value = value.to_string();
            let counts = self.values.entry(field.clone()).or_default();
            if let Some(n) = counts.get_mut(&value) {
                *n += 1;
            } else if counts.len() < MAX_INVENTORY_VALUES {
                counts.insert(value, 1);
            }
        }
    }

    /// Distinct values seen for an inventory field.
    pub fn inventory(&self, field: &str) -> impl Iterator<Item = (&str, u64)> {
        self.values
            .get(field)
            .into_iter()
            .flatten()
            .map(|(v, n)| (v.as_str(), *n))
    }

    /// Field names starting with `prefix`, for autocomplete.
    pub fn complete<'a>(&'a self, prefix: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.fields
            .range(prefix.to_string()..)
            .take_while(move |(name, _)| name.starts_with(prefix))
            .map(|(name, _)| name.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn time_range_is_half_open() {
        let r = TimeRange {
            start: Some(Timestamp::from_secs(10)),
            end: Some(Timestamp::from_secs(20)),
        };
        assert!(!r.contains(Timestamp::from_secs(9)));
        assert!(r.contains(Timestamp::from_secs(10)));
        assert!(!r.contains(Timestamp::from_secs(20)));
        assert!(r.overlaps(Timestamp::from_secs(0), Timestamp::from_secs(10)));
        assert!(!r.overlaps(Timestamp::from_secs(20), Timestamp::from_secs(30)));
        assert!(TimeRange::default().contains(Timestamp::from_secs(-5)));
    }

    #[test]
    fn catalog_counts_inventory_values_and_reads_old_metas() {
        use usiem::event::{Origin, RawData};
        let mut catalog = FieldCatalog::with_inventory(&["artifact.name", "artifact.host"]);
        for name in ["Windows::Prefetch", "Windows::Prefetch", "Windows::MFT"] {
            let mut e = Event::new(
                Timestamp::from_secs(0),
                Timestamp::from_secs(0),
                Origin::Collector("t".into()),
                RawData::from_text(""),
            );
            e.add_field("artifact.name".into(), FieldValue::from(name));
            catalog.observe(&e);
        }
        let inventory: Vec<_> = catalog.inventory("artifact.name").collect();
        assert_eq!(inventory, [("Windows::MFT", 1), ("Windows::Prefetch", 2)]);
        assert_eq!(catalog.inventory("artifact.host").count(), 0);

        let old: FieldCatalog = serde_json::from_str(r#"{"fields":{}}"#).unwrap();
        assert!(old.values.is_empty());
    }

    #[test]
    fn catalog_completes_by_prefix() {
        let mut catalog = FieldCatalog::default();
        for name in ["user.name", "user.domain", "source.ip"] {
            catalog
                .fields
                .insert(name.to_string(), FieldStats::default());
        }
        let found: Vec<_> = catalog.complete("user.").collect();
        assert_eq!(found, ["user.domain", "user.name"]);
    }
}
