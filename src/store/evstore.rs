//! [`EvstoreSource`]: the usiem-evstore backend (feature `evstore`).
//!
//! # Mapping
//!
//! Each [`Event`] becomes one evstore record whose time is `original_time`:
//!
//! - `@arrival` (time), `@origin` (the tagged JSON of the origin), and
//!   either `@raw` (raw text) or `@raw_json` (the tagged JSON of JSON raw
//!   data);
//! - each field by name; a name starting with `@` gets one more `@` so it
//!   cannot clash with the meta fields;
//! - objects are flattened: key `k` of object field `p` is stored as
//!   `p\x1fk`, and `p\x1c` marks that `p` is an object (so empty objects
//!   survive);
//! - an array of scalars of one kind becomes a multi-valued field `p\x1e`;
//!   any other array (empty, mixed kinds, nested objects or arrays) is
//!   stored whole as the tagged JSON bytes in `p\x1d`, and the record gets
//!   `@complex = true`.
//!
//! The mapping is lossless (except that an IPv6 address in `::ffff:0:0/96`
//! comes back as IPv4), so a reconstructed event equals the original,
//! including its id.
//!
//! # Queries
//!
//! The [`Predicate`] is translated into an evstore filter that matches a
//! **superset** of the events (`Not` becomes "anything", ambiguous
//! comparisons widen), and every candidate is re-checked with
//! [`Predicate::matches`] on the reconstructed event. Results are therefore
//! the same as [`JsonlStore`](super::jsonl::JsonlStore)'s, while evstore
//! still prunes segments, chunks and dictionary values. Limits apply after
//! the re-check.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};
use std::path::Path;

use serde::{Deserialize, Serialize};
use usiem::event::field::Text;
use usiem::event::{FieldValue, Ip, Origin, RawData, Timestamp};
use usiem_evstore as ev;

use super::{
    AppendAck, Cidr, EventIter, EventSource, EventStore, FieldCatalog, FieldKind, FieldOp, Literal,
    Order, Pattern, Predicate, StatsTable, StoreError, StoreQuery, compare_values,
};
use crate::Event;
use crate::query::exec::{StatsGroup, display_value, stats_table};
use crate::query::{Agg, AggFunc, GroupKey, Span};
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

pub use usiem_evstore::{MaintainReport, Options, RetentionPolicy, SyncPolicy};

const OBJ_SEP: char = '\u{1f}';
const ARRAY: char = '\u{1e}';
const COMPLEX: char = '\u{1d}';
const OBJECT: char = '\u{1c}';

const F_ARRIVAL: &str = "@arrival";
const F_ORIGIN: &str = "@origin";
const F_RAW: &str = "@raw";
const F_RAW_JSON: &str = "@raw_json";
const F_COMPLEX: &str = "@complex";

/// Events stored in usiem-evstore.
pub struct EvstoreSource {
    store: ev::Store,
    catalog: FieldCatalog,
    catalog_dirty: bool,
    catalog_rebuilt: bool,
    /// `stats` queries answered by evstore aggregation (for tests and stats).
    pushdowns: AtomicU64,
}

impl std::fmt::Debug for EvstoreSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EvstoreSource")
            .field("events", &self.store.len())
            .field("fields", &self.catalog.fields.len())
            .field("pushdowns", &self.pushdowns())
            .finish_non_exhaustive()
    }
}

#[derive(Serialize, Deserialize)]
struct CatalogMeta {
    events: u64,
    catalog: FieldCatalog,
}

fn ev_err(e: ev::StoreError) -> StoreError {
    match e {
        ev::StoreError::Io { path, source } => StoreError::Io(std::io::Error::new(
            source.kind(),
            format!("{}: {source}", path.display()),
        )),
        ev::StoreError::Corrupt {
            file,
            offset,
            reason,
        } => StoreError::Corrupt {
            location: format!("{}@{offset}", file.display()),
            reason,
        },
        other => StoreError::Io(std::io::Error::other(other.to_string())),
    }
}

impl EvstoreSource {
    /// Opens (or creates) the store in `dir` with default options.
    ///
    /// # Errors
    ///
    /// As [`EvstoreSource::open_with`].
    pub fn open(dir: &Path) -> Result<EvstoreSource, StoreError> {
        EvstoreSource::open_with(dir, Options::default())
    }

    /// Opens (or creates) the store in `dir`.
    ///
    /// # Errors
    ///
    /// When evstore cannot open the store, or a stored record does not
    /// decode while the field catalog is rebuilt.
    pub fn open_with(dir: &Path, opts: Options) -> Result<EvstoreSource, StoreError> {
        let store = ev::Store::open(dir, opts).map_err(ev_err)?;
        let saved = serde_json::from_slice::<CatalogMeta>(store.app_meta()).ok();
        let mut source = EvstoreSource {
            store,
            catalog: FieldCatalog::default(),
            catalog_dirty: false,
            catalog_rebuilt: false,
            pushdowns: AtomicU64::new(0),
        };
        match saved {
            Some(meta) if meta.events == source.store.len() => source.catalog = meta.catalog,
            _ => source.rebuild_catalog()?,
        }
        Ok(source)
    }

    /// Counts the values of `fields` in the field catalog (see
    /// [`FieldCatalog::inventory`]).
    ///
    /// # Errors
    ///
    /// When the catalog has to be rebuilt and a stored record cannot be
    /// read.
    pub fn with_inventory_fields(mut self, fields: &[&str]) -> Result<EvstoreSource, StoreError> {
        let wanted: Vec<String> = fields.iter().map(|f| (*f).to_string()).collect();
        let changed = wanted != self.catalog.inventory_fields;
        self.catalog.inventory_fields = wanted;
        if changed && self.catalog_rebuilt {
            self.rebuild_catalog()?;
        }
        Ok(self)
    }

    fn rebuild_catalog(&mut self) -> Result<(), StoreError> {
        let mut catalog = FieldCatalog {
            inventory_fields: self.catalog.inventory_fields.clone(),
            ..FieldCatalog::default()
        };
        let query = ev::Query {
            order: ev::Order::Storage,
            ..ev::Query::default()
        };
        for rec in self.store.search(&query).map_err(ev_err)? {
            catalog.observe(&decode(rec.map_err(ev_err)?)?);
        }
        self.catalog = catalog;
        self.catalog_dirty = true;
        self.catalog_rebuilt = true;
        Ok(())
    }

    fn save_catalog(&mut self) -> Result<(), StoreError> {
        if !self.catalog_dirty {
            return Ok(());
        }
        let meta = CatalogMeta {
            events: self.store.len(),
            catalog: self.catalog.clone(),
        };
        let bytes = serde_json::to_vec(&meta).map_err(|e| StoreError::Encode(e.to_string()))?;
        self.store.set_app_meta(bytes);
        self.catalog_dirty = false;
        Ok(())
    }

    /// Periodic housekeeping: WAL sync and flush, retention, compaction (see
    /// [`ev::Store::maintain`]). Call it every second or so.
    ///
    /// # Errors
    ///
    /// When evstore fails to sync, flush, expire or compact.
    pub fn maintain(&mut self, now: Timestamp) -> Result<MaintainReport, StoreError> {
        self.save_catalog()?;
        self.store.maintain(now.0).map_err(ev_err)
    }

    /// The underlying store, for statistics.
    pub fn store(&self) -> &ev::Store {
        &self.store
    }
}

impl EventSource for EvstoreSource {
    fn search(&self, query: &StoreQuery) -> Result<EventIter<'_>, StoreError> {
        let mut time = ev::TimeRange {
            start: query.time.start.map(|t| t.0),
            end: query.time.end.map(|t| t.0),
        };
        narrow_time(&query.filter, &mut time);
        let order = match query.order {
            Order::Storage => ev::Order::Storage,
            Order::TimeAsc => ev::Order::Asc,
            Order::TimeDesc => ev::Order::Desc,
        };
        let pushed = ev::Query {
            time,
            filter: translate(&query.filter),
            order,
            limit: None,
        };
        let records = self.store.search(&pushed).map_err(ev_err)?;
        let filter = query.filter.clone();
        let range = query.time;
        let events = records.filter_map(move |r| match r.map_err(ev_err).and_then(decode) {
            Ok(e) => (range.contains(e.original_time()) && filter.matches(&e)).then_some(Ok(e)),
            Err(e) => Some(Err(e)),
        });
        Ok(match query.limit {
            Some(n) => Box::new(events.take(n)),
            None => Box::new(events),
        })
    }

    fn field_catalog(&self) -> &FieldCatalog {
        &self.catalog
    }

    fn len(&self) -> u64 {
        self.store.len()
    }

    fn aggregate(
        &self,
        query: &StoreQuery,
        aggs: &[Agg],
        by: &[GroupKey],
    ) -> Result<Option<StatsTable>, StoreError> {
        let Some(pushed) = plan_aggregate(self.store.fields(), query, aggs, by) else {
            return Ok(None);
        };
        let rows = self.store.aggregate(&pushed).map_err(ev_err)?;
        self.pushdowns.fetch_add(1, AtomicOrdering::Relaxed);
        Ok(Some(merge_agg_rows(rows, aggs, by)))
    }
}

impl EvstoreSource {
    /// How many `stats` queries evstore answered by aggregation.
    pub fn pushdowns(&self) -> u64 {
        self.pushdowns.load(AtomicOrdering::Relaxed)
    }
}

// ---------------------------------------------------------------------------
// `stats` pushdown: only when evstore's answer is provably the executor's.

/// Types stored for `path` when `lookup(path)` can only ever resolve to the
/// plain stored field `path` (no arrays, objects or dotted object paths);
/// `None` otherwise.
fn plain_types(registry: &ev::FieldRegistry, path: &str) -> Option<Vec<ev::ValueType>> {
    if path == F_ARRIVAL {
        return Some(vec![ev::ValueType::Time]);
    }
    if path.starts_with('@') || path.contains([OBJ_SEP, ARRAY, COMPLEX, OBJECT]) {
        return None;
    }
    for c in candidates(path) {
        let mut names = vec![
            format!("{c}{ARRAY}"),
            format!("{c}{COMPLEX}"),
            format!("{c}{OBJECT}"),
        ];
        if c != path {
            names.push(c);
        }
        if names.iter().any(|n| !registry.ids(n).is_empty()) {
            return None;
        }
    }
    Some(
        registry
            .ids(path)
            .iter()
            .map(|id| registry.info(*id).ty)
            .collect(),
    )
}

/// The evstore filter matching exactly what `pred` matches, if there is one.
fn translate_exact(registry: &ev::FieldRegistry, pred: &Predicate) -> Option<ev::Filter> {
    use ev::ValueType as T;
    Some(match pred {
        Predicate::True => ev::Filter::True,
        Predicate::And(ps) => ev::Filter::And(
            ps.iter()
                .map(|p| translate_exact(registry, p))
                .collect::<Option<_>>()?,
        ),
        Predicate::Or(ps) => ev::Filter::Or(
            ps.iter()
                .map(|p| translate_exact(registry, p))
                .collect::<Option<_>>()?,
        ),
        Predicate::Not(p) => ev::Filter::Not(Box::new(translate_exact(registry, p)?)),
        Predicate::Text(_) => return None,
        Predicate::Field { field, op } => {
            let types = plain_types(registry, field)?;
            let ok = match &**op {
                FieldOp::Exists | FieldOp::Eq(_) | FieldOp::In(_) => true,
                FieldOp::Range { .. } => !types.contains(&T::Ip),
                FieldOp::Wildcard(_) => types.iter().all(|t| *t == T::Str),
                FieldOp::Cidr(c) => c.addr.is_ipv4() && types.iter().all(|t| *t == T::Ip),
                // Exact as globs only when no needle holds glob syntax.
                FieldOp::ContainsAny(subs) => {
                    types.iter().all(|t| *t == T::Str)
                        && subs.needles().iter().all(|n| !Pattern::has_wildcards(n))
                }
            };
            if !ok {
                return None;
            }
            let mut out = Vec::new();
            value_filters(field, op, &mut out);
            ev::Filter::Or(out)
        }
    })
}

/// Turns a pushable `stats` into an evstore aggregation (one metric per
/// aggregate, in order).
fn plan_aggregate(
    registry: &ev::FieldRegistry,
    query: &StoreQuery,
    aggs: &[Agg],
    by: &[GroupKey],
) -> Option<ev::AggQuery> {
    use ev::ValueType as T;
    // Past the field cap, new names go to the overflow field unregistered,
    // so the registry can no longer prove a field is plain.
    if registry.is_full() {
        return None;
    }
    let mut time = ev::TimeRange {
        start: query.time.start.map(|t| t.0),
        end: query.time.end.map(|t| t.0),
    };
    let conjuncts: Vec<&Predicate> = match &query.filter {
        Predicate::And(ps) => ps.iter().collect(),
        p => vec![p],
    };
    let mut filters = Vec::new();
    for p in conjuncts {
        if let Predicate::Field { field, op } = p
            && field == "@timestamp"
        {
            // Exact only as a time range with time literals.
            let times_ok = match &**op {
                FieldOp::Eq(l) => l.time.is_some(),
                FieldOp::Range { lower, upper } => [lower, upper]
                    .into_iter()
                    .flatten()
                    .all(|(l, _)| l.time.is_some()),
                _ => false,
            };
            if !times_ok {
                return None;
            }
            narrow_time(p, &mut time);
            continue;
        }
        filters.push(translate_exact(registry, p)?);
    }

    let group_by = by
        .iter()
        .map(|g| match g {
            GroupKey::Field(f) => {
                let types = plain_types(registry, f)?;
                let ok = types.len() <= 1
                    && types
                        .iter()
                        .all(|t| matches!(t, T::Str | T::I64 | T::U64 | T::Bool | T::Ip | T::Time));
                ok.then(|| ev::GroupBy::Field(f.clone()))
            }
            GroupKey::Bucket { field, span, .. } => match span {
                Span::Nanos(w) if field == "@timestamp" => {
                    Some(ev::GroupBy::TimeBucket { span_ns: *w })
                }
                _ => None,
            },
        })
        .collect::<Option<Vec<_>>>()?;

    let metrics = aggs
        .iter()
        .map(|a| {
            let field = a.field.as_deref();
            match (a.func, field) {
                (AggFunc::Count, None) => Some(ev::Metric::Count),
                (AggFunc::Count, Some(f)) => {
                    plain_types(registry, f).map(|_| ev::Metric::CountField(f.to_string()))
                }
                (AggFunc::Sum | AggFunc::Avg, Some(f)) => {
                    let types = plain_types(registry, f)?;
                    types
                        .iter()
                        .all(|t| matches!(t, T::I64 | T::U64))
                        .then(|| ev::Metric::Sum(f.to_string()))
                }
                (AggFunc::Min | AggFunc::Max, Some(f)) => {
                    let types = plain_types(registry, f)?;
                    let ok = types.len() <= 1
                        && types
                            .iter()
                            .all(|t| matches!(t, T::I64 | T::U64 | T::Time | T::Bool));
                    if !ok {
                        return None;
                    }
                    Some(if a.func == AggFunc::Min {
                        ev::Metric::Min(f.to_string())
                    } else {
                        ev::Metric::Max(f.to_string())
                    })
                }
                _ => None,
            }
        })
        .collect::<Option<Vec<_>>>()?;

    Some(ev::AggQuery {
        time,
        filter: ev::Filter::And(filters),
        group_by,
        metrics,
    })
}

enum MergeState {
    Count(u64),
    Sum(f64, u64),
    Extreme(Option<FieldValue>),
}

/// Regroups evstore rows by display key (as the executor does) and builds
/// the `stats` table.
fn merge_agg_rows(rows: Vec<ev::AggRow>, aggs: &[Agg], by: &[GroupKey]) -> StatsTable {
    let mut groups: HashMap<Vec<String>, (Vec<FieldValue>, Vec<MergeState>)> = HashMap::new();
    for row in rows {
        let values: Vec<FieldValue> = row.key.into_iter().map(from_scalar).collect();
        let key: Vec<String> = values.iter().map(display_value).collect();
        let (_, states) = groups.entry(key).or_insert_with(|| {
            let states = aggs
                .iter()
                .map(|a| match a.func {
                    AggFunc::Count => MergeState::Count(0),
                    AggFunc::Sum | AggFunc::Avg => MergeState::Sum(0.0, 0),
                    _ => MergeState::Extreme(None),
                })
                .collect();
            (values, states)
        });
        for ((state, metric), agg) in states.iter_mut().zip(row.metrics).zip(aggs) {
            match (state, metric) {
                (MergeState::Count(n), ev::MetricValue::Count(m)) => *n += m,
                (MergeState::Sum(sum, n), ev::MetricValue::Sum { sum: s, values }) => {
                    *sum += s;
                    *n += values;
                }
                (MergeState::Extreme(cur), ev::MetricValue::Value(Some(v))) => {
                    let v = from_scalar(v);
                    let better = match cur {
                        None => true,
                        Some(c) if agg.func == AggFunc::Min => compare_values(&v, c).is_lt(),
                        Some(c) => compare_values(&v, c).is_gt(),
                    };
                    if better {
                        *cur = Some(v);
                    }
                }
                _ => {}
            }
        }
    }
    let groups: Vec<StatsGroup> = groups
        .into_iter()
        .map(|(key, (values, states))| {
            let results = states
                .into_iter()
                .zip(aggs)
                .map(|(state, agg)| match state {
                    MergeState::Count(n) => Some(FieldValue::Uint(n)),
                    #[allow(
                        clippy::cast_precision_loss,
                        reason = "an average is floating point; counts past 2^53 round"
                    )]
                    MergeState::Sum(sum, n) if agg.func == AggFunc::Avg => {
                        (n > 0).then(|| FieldValue::Float(sum / n as f64))
                    }
                    MergeState::Sum(sum, n) => (n > 0).then_some(FieldValue::Float(sum)),
                    MergeState::Extreme(v) => v,
                })
                .collect();
            (key, values, results)
        })
        .collect();
    stats_table(aggs, by, groups)
}

impl EventStore for EvstoreSource {
    fn append(&mut self, batch: Vec<Event>) -> Result<AppendAck, StoreError> {
        let mut records = Vec::with_capacity(batch.len());
        for event in &batch {
            records.push(encode(event)?);
            self.catalog.observe(event);
        }
        self.catalog_dirty |= !batch.is_empty();
        let ack = self.store.append(records).map_err(ev_err)?;
        Ok(AppendAck {
            appended: ack.appended,
            total: ack.total,
            synced: ack.synced,
        })
    }

    fn sync(&mut self) -> Result<(), StoreError> {
        self.store.sync().map_err(ev_err)
    }

    fn seal(&mut self) -> Result<(), StoreError> {
        self.save_catalog()?;
        self.store.flush().map_err(ev_err)
    }
}

// ---------------------------------------------------------------------------
// Event <-> record

fn ip_to_u128(ip: &Ip) -> u128 {
    match ip.as_ip_addr() {
        IpAddr::V4(v4) => u128::from(v4.to_ipv6_mapped()),
        IpAddr::V6(v6) => u128::from(v6),
    }
}

fn u128_to_ip(n: u128) -> Ip {
    let v6 = Ipv6Addr::from(n);
    match v6.to_ipv4_mapped() {
        Some(v4) => Ip::from(IpAddr::V4(v4)),
        None => Ip::from(IpAddr::V6(v6)),
    }
}

fn scalar(v: &FieldValue) -> Option<ev::Value> {
    Some(match v {
        FieldValue::Str(s) => ev::Value::Str(s.to_string()),
        FieldValue::Int(i) => ev::Value::I64(*i),
        FieldValue::Uint(u) => ev::Value::U64(*u),
        FieldValue::Float(f) => ev::Value::F64(*f),
        FieldValue::Bool(b) => ev::Value::Bool(*b),
        FieldValue::Bytes(b) => ev::Value::Bytes(b.clone()),
        FieldValue::Time(t) => ev::Value::Time(t.0),
        FieldValue::Ip(ip) => ev::Value::Ip(ip_to_u128(ip)),
        FieldValue::Object(_) | FieldValue::Array(_) => return None,
    })
}

fn from_scalar(v: ev::Value) -> FieldValue {
    match v {
        ev::Value::Str(s) => FieldValue::Str(Text::from(s)),
        ev::Value::I64(i) => FieldValue::Int(i),
        ev::Value::U64(u) => FieldValue::Uint(u),
        ev::Value::F64(f) => FieldValue::Float(f),
        ev::Value::Bool(b) => FieldValue::Bool(b),
        ev::Value::Bytes(b) => FieldValue::Bytes(b),
        ev::Value::Time(t) => FieldValue::Time(Timestamp(t)),
        ev::Value::Ip(n) => FieldValue::Ip(u128_to_ip(n)),
    }
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "used as a `map_err` callback"
)]
fn encode_err(e: serde_json::Error) -> StoreError {
    StoreError::Encode(e.to_string())
}

fn put(
    rec: &mut ev::Record,
    path: String,
    value: &FieldValue,
    complex: &mut bool,
) -> Result<(), StoreError> {
    match value {
        FieldValue::Object(map) => {
            rec.push(format!("{path}{OBJECT}"), ev::Value::Bool(true));
            for (k, v) in map {
                put(rec, format!("{path}{OBJ_SEP}{k}"), v, complex)?;
            }
        }
        FieldValue::Array(items) => {
            let kind = items.first().map(FieldKind::of);
            let simple = kind.is_some_and(|k| {
                !matches!(k, FieldKind::Object | FieldKind::Array)
                    && items.iter().all(|v| FieldKind::of(v) == k)
            });
            if simple {
                let name = format!("{path}{ARRAY}");
                for v in items {
                    rec.push(name.clone(), scalar(v).expect("simple arrays hold scalars"));
                }
            } else {
                *complex = true;
                let bytes = serde_json::to_vec(value).map_err(encode_err)?;
                rec.push(format!("{path}{COMPLEX}"), ev::Value::Bytes(bytes));
            }
        }
        other => rec.push(path, scalar(other).expect("not a container")),
    }
    Ok(())
}

fn encode(event: &Event) -> Result<ev::Record, StoreError> {
    let mut rec = ev::Record::new(event.original_time().0);
    rec.push(F_ARRIVAL, ev::Value::Time(event.arrival_time().0));
    let origin = serde_json::to_string(event.origin()).map_err(encode_err)?;
    rec.push(F_ORIGIN, ev::Value::Str(origin));
    match event.raw_data() {
        RawData::Text(text) => rec.push(F_RAW, ev::Value::Str(text.clone())),
        raw @ RawData::Json(_) => {
            let json = serde_json::to_string(raw).map_err(encode_err)?;
            rec.push(F_RAW_JSON, ev::Value::Str(json));
        }
    }
    let mut complex = false;
    for (name, value) in event.fields() {
        let stored = if name.starts_with('@') {
            format!("@{name}")
        } else {
            name.clone()
        };
        put(&mut rec, stored, value, &mut complex)?;
    }
    if complex {
        rec.push(F_COMPLEX, ev::Value::Bool(true));
    }
    Ok(rec)
}

/// Field tree used while rebuilding objects.
enum Node {
    Leaf(FieldValue),
    Object(HashMap<String, Node>),
}

impl Node {
    fn into_value(self) -> FieldValue {
        match self {
            Node::Leaf(v) => v,
            Node::Object(map) => FieldValue::Object(
                map.into_iter()
                    .map(|(k, n)| (Text::from(k), n.into_value()))
                    .collect(),
            ),
        }
    }
}

fn corrupt(reason: impl Into<String>) -> StoreError {
    StoreError::Corrupt {
        location: "evstore record".into(),
        reason: reason.into(),
    }
}

/// Inserts a value at `path` (top-level key, then object keys).
fn insert(
    root: &mut HashMap<String, Node>,
    path: &[&str],
    kind: Option<char>,
    value: ev::Value,
) -> Result<(), StoreError> {
    let (last, parents) = path
        .split_last()
        .ok_or_else(|| corrupt("empty field path"))?;
    let mut map = root;
    for key in parents {
        let node = map
            .entry((*key).to_string())
            .or_insert_with(|| Node::Object(HashMap::new()));
        match node {
            Node::Object(m) => map = m,
            Node::Leaf(_) => return Err(corrupt(format!("{key} is both a value and an object"))),
        }
    }
    let key = (*last).to_string();
    match kind {
        Some(OBJECT) => {
            map.entry(key)
                .or_insert_with(|| Node::Object(HashMap::new()));
        }
        Some(ARRAY) => {
            let node = map
                .entry(key)
                .or_insert_with(|| Node::Leaf(FieldValue::Array(Vec::new())));
            match node {
                Node::Leaf(FieldValue::Array(items)) => items.push(from_scalar(value)),
                _ => return Err(corrupt("array field clashes with another value")),
            }
        }
        Some(COMPLEX) => {
            let ev::Value::Bytes(bytes) = value else {
                return Err(corrupt("complex field is not bytes"));
            };
            let v: FieldValue =
                serde_json::from_slice(&bytes).map_err(|e| corrupt(e.to_string()))?;
            map.insert(key, Node::Leaf(v));
        }
        _ => {
            map.insert(key, Node::Leaf(from_scalar(value)));
        }
    }
    Ok(())
}

fn decode(rec: ev::Record) -> Result<Event, StoreError> {
    let mut arrival = None;
    let mut origin = None;
    let mut raw = None;
    let mut root: HashMap<String, Node> = HashMap::new();
    for (name, value) in rec.fields {
        match (name.as_str(), value) {
            (F_ARRIVAL, ev::Value::Time(t)) => arrival = Some(Timestamp(t)),
            (F_ORIGIN, ev::Value::Str(s)) => {
                origin =
                    Some(serde_json::from_str::<Origin>(&s).map_err(|e| corrupt(e.to_string()))?);
            }
            (F_RAW, ev::Value::Str(s)) => raw = Some(RawData::Text(s)),
            (F_RAW_JSON, ev::Value::Str(s)) => {
                raw =
                    Some(serde_json::from_str::<RawData>(&s).map_err(|e| corrupt(e.to_string()))?);
            }
            (F_COMPLEX, _) => {}
            (n, value) if n.starts_with('@') && !n.starts_with("@@") => {
                return Err(corrupt(format!("unexpected meta field {n} = {value:?}")));
            }
            (n, value) => {
                let n = n
                    .strip_prefix('@')
                    .filter(|r| r.starts_with('@'))
                    .unwrap_or(n);
                let (base, kind) = match n.chars().last() {
                    Some(c @ (ARRAY | COMPLEX | OBJECT)) => (&n[..n.len() - c.len_utf8()], Some(c)),
                    _ => (n, None),
                };
                let path: Vec<&str> = base.split(OBJ_SEP).collect();
                insert(&mut root, &path, kind, value)?;
            }
        }
    }
    let mut event = Event::new(
        arrival.ok_or_else(|| corrupt("missing @arrival"))?,
        Timestamp(rec.ts),
        origin.ok_or_else(|| corrupt("missing @origin"))?,
        raw.ok_or_else(|| corrupt("missing raw data"))?,
    );
    for (k, node) in root {
        event.add_field(k, node.into_value());
    }
    Ok(event)
}

// ---------------------------------------------------------------------------
// Predicate -> evstore filter (superset)

/// Characters that can appear in the text form of numbers, booleans,
/// times and IPs (lowercase).
const RENDER_CHARS: &str = "0123456789abcdef.:-+tzrulsni";
/// Characters of an IP's text form.
const IP_CHARS: &str = "0123456789abcdef.:";

fn only_chars(text: &str, allowed: &str) -> bool {
    text.to_lowercase()
        .chars()
        .filter(|c| *c != '*' && *c != '?')
        .all(|c| allowed.contains(c))
}

/// Stored names that `lookup(path)` can resolve to: the flat key, or a flat
/// prefix holding an object followed by object keys.
fn candidates(path: &str) -> Vec<String> {
    let mut out = vec![path.to_string()];
    for (i, c) in path.char_indices() {
        if c == '.' {
            let rest = path[i + 1..].replace('.', &OBJ_SEP.to_string());
            out.push(format!("{}{OBJ_SEP}{rest}", &path[..i]));
        }
    }
    out
}

fn literal_values(lit: &Literal) -> Vec<ev::Value> {
    let mut out = vec![ev::Value::Str(lit.text.clone())];
    if let Some(i) = lit.int {
        if let Ok(x) = i64::try_from(i) {
            out.push(ev::Value::I64(x));
        }
        if let Ok(x) = u64::try_from(i) {
            out.push(ev::Value::U64(x));
        }
    }
    if let Some(f) = lit.float {
        out.push(ev::Value::F64(f));
    }
    if let Some(b) = lit.boolean {
        out.push(ev::Value::Bool(b));
    }
    if let Some(ip) = &lit.ip {
        out.push(ev::Value::Ip(ip_to_u128(ip)));
    }
    if let Some(t) = lit.time {
        out.push(ev::Value::Time(t.0));
    }
    out
}

fn cidr_range(c: &Cidr) -> (u128, u128) {
    let (base, bits) = match c.addr {
        IpAddr::V4(v4) => (u128::from(v4.to_ipv6_mapped()), 96 + u32::from(c.prefix)),
        IpAddr::V6(v6) => (u128::from(v6), u32::from(c.prefix)),
    };
    let host = u128::MAX.checked_shr(bits).unwrap_or(0);
    (base & !host, base | host)
}

fn non_str_types() -> impl Iterator<Item = ev::ValueType> {
    use ev::ValueType::{Bool, F64, I64, Ip, Time, U64};
    [I64, U64, F64, Bool, Time, Ip].into_iter()
}

/// Filters on one stored name that cover `op` (any may match).
fn value_filters(name: &str, op: &FieldOp, out: &mut Vec<ev::Filter>) {
    let f = |op| ev::Filter::field(name, op);
    match op {
        FieldOp::Exists => out.push(f(ev::FieldOp::Exists)),
        FieldOp::Eq(lit) => out.push(f(ev::FieldOp::In(literal_values(lit)))),
        FieldOp::In(lits) => out.push(f(ev::FieldOp::In(
            lits.iter().flat_map(literal_values).collect(),
        ))),
        FieldOp::Wildcard(p) => {
            out.push(f(ev::FieldOp::Glob(p.as_str().to_string())));
            if only_chars(p.as_str(), RENDER_CHARS) {
                out.extend(non_str_types().map(|t| f(ev::FieldOp::HasType(t))));
            }
        }
        FieldOp::Range { lower, upper } => {
            type Conv = fn(&Literal) -> Option<ev::Value>;
            let convs: [Conv; 3] = [
                |l| Some(ev::Value::Str(l.text.clone())),
                |l| l.float.map(ev::Value::F64),
                |l| l.time.map(|t| ev::Value::Time(t.0)),
            ];
            for conv in convs {
                let lo = lower.as_ref().map(|(l, inc)| conv(l).map(|v| (v, *inc)));
                let hi = upper.as_ref().map(|(l, inc)| conv(l).map(|v| (v, *inc)));
                if lo.as_ref().is_some_and(Option::is_none)
                    || hi.as_ref().is_some_and(Option::is_none)
                {
                    continue;
                }
                out.push(f(ev::FieldOp::Range {
                    lower: lo.flatten(),
                    upper: hi.flatten(),
                }));
            }
            let all_ip = [lower, upper]
                .into_iter()
                .flatten()
                .all(|(l, _)| l.ip.is_some());
            if all_ip {
                out.push(f(ev::FieldOp::HasType(ev::ValueType::Ip)));
            }
        }
        FieldOp::Cidr(c) => {
            let (lo, hi) = cidr_range(c);
            out.push(f(ev::FieldOp::Cidr { lo, hi }));
            out.push(f(ev::FieldOp::HasType(ev::ValueType::Str)));
        }
        FieldOp::ContainsAny(subs) => {
            for n in subs.needles() {
                value_filters(
                    name,
                    &FieldOp::Wildcard(Pattern::new(&format!("*{n}*"))),
                    out,
                );
            }
        }
    }
}

fn translate(p: &Predicate) -> ev::Filter {
    match p {
        Predicate::True | Predicate::Not(_) => ev::Filter::True,
        Predicate::And(ps) => ev::Filter::And(ps.iter().map(translate).collect()),
        Predicate::Or(ps) => ev::Filter::Or(ps.iter().map(translate).collect()),
        Predicate::Text(term) => {
            if only_chars(term, IP_CHARS) {
                ev::Filter::True
            } else {
                ev::Filter::Or(vec![
                    ev::Filter::field(ev::ANY_FIELD, ev::FieldOp::Contains(term.clone())),
                    ev::Filter::field(F_COMPLEX, ev::FieldOp::Exists),
                ])
            }
        }
        Predicate::Field { field, op } => {
            if field == F_ARRIVAL {
                let mut out = Vec::new();
                value_filters(F_ARRIVAL, op, &mut out);
                return ev::Filter::Or(out);
            }
            if field.starts_with('@') {
                return ev::Filter::True;
            }
            let mut out = Vec::new();
            for c in candidates(field) {
                value_filters(&c, op, &mut out);
                value_filters(&format!("{c}{ARRAY}"), op, &mut out);
                out.push(ev::Filter::field(
                    format!("{c}{COMPLEX}"),
                    ev::FieldOp::Exists,
                ));
                // Unbounded ranges match any value, objects included.
                let any_value = match &**op {
                    FieldOp::Exists => true,
                    FieldOp::Range { lower, upper } => lower.is_none() && upper.is_none(),
                    _ => false,
                };
                if any_value {
                    out.push(ev::Filter::field(
                        format!("{c}{OBJECT}"),
                        ev::FieldOp::Exists,
                    ));
                }
            }
            ev::Filter::Or(out)
        }
    }
}

/// Narrows `time` with top-level `@timestamp` conjuncts.
fn narrow_time(p: &Predicate, time: &mut ev::TimeRange) {
    match p {
        Predicate::And(ps) => ps.iter().for_each(|p| narrow_time(p, time)),
        Predicate::Field { field, op } if field == "@timestamp" => {
            let (lo, hi) = match &**op {
                FieldOp::Eq(lit) => match lit.time {
                    Some(t) => (Some(t.0), Some(t.0.saturating_add(1))),
                    None => (None, None),
                },
                FieldOp::Range { lower, upper } => (
                    lower.as_ref().and_then(|(lit, inc)| {
                        lit.time
                            .map(|t| if *inc { t.0 } else { t.0.saturating_add(1) })
                    }),
                    upper.as_ref().and_then(|(lit, inc)| {
                        lit.time
                            .map(|t| if *inc { t.0.saturating_add(1) } else { t.0 })
                    }),
                ),
                _ => (None, None),
            };
            if let Some(lo) = lo {
                time.start = Some(time.start.map_or(lo, |s| s.max(lo)));
            }
            if let Some(hi) = hi {
                time.end = Some(time.end.map_or(hi, |e| e.min(hi)));
            }
        }
        _ => {}
    }
}

#[cfg(test)]
#[cfg(feature = "jsonl")]
mod tests;
