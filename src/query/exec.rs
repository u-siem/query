//! Query planning and execution.
//!
//! Planning splits the filter: conjuncts that only touch stored fields go to
//! the store as a [`StoreQuery`]; conjuncts touching virtual fields stay
//! behind as a residual filter evaluated here, after resolution.
//!
//! Execution streams as long as it can. `where`, `head`, `dedup` and
//! `fields` stay lazy; `sort` and `tail` materialise; `stats` aggregates on
//! the fly and turns the stream into a table.

use super::{Agg, AggFunc, Command, GroupKey, Query, SortKey, Span, is_virtual_field};
use crate::Event;
use crate::store::{
    EventSource, Order, Predicate, Projection, Record, StatsTable, StoreError, StoreQuery,
    compare_values, lookup,
};
use std::borrow::Cow;
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use usiem::event::FieldValue;
use usiem::event::field::Text;

/// Computes virtual fields (`base@attr`) for an event at query time.
pub trait VirtualFields: Sync {
    /// `None` when the field can't be resolved for this event.
    fn resolve(&self, event: &Event, field: &str) -> Option<FieldValue>;

    /// Virtual fields worth showing next to the event's own fields (the
    /// event detail), with their values.
    fn suggest(&self, _event: &Event) -> Vec<(String, FieldValue)> {
        Vec::new()
    }
}

/// Resolves nothing.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoVirtualFields;

impl VirtualFields for NoVirtualFields {
    fn resolve(&self, _: &Event, _: &str) -> Option<FieldValue> {
        None
    }
}

/// Limits and settings for [`execute`].
#[derive(Debug, Clone)]
pub struct ExecOptions {
    /// Rows kept in the final result; the rest is dropped and
    /// [`QueryResult::truncated`] set.
    pub max_rows: usize,
    /// Upper bound on events held in memory by `sort`/`tail`.
    pub max_materialized: usize,
    /// Set from another thread to stop the query.
    pub cancel: Option<Arc<AtomicBool>>,
    /// Event order when the query doesn't sort by time itself: oldest first
    /// reads best as a timeline, newest first as a live log.
    pub default_order: Order,
}

impl Default for ExecOptions {
    fn default() -> Self {
        ExecOptions {
            max_rows: 10_000,
            max_materialized: 2_000_000,
            cancel: None,
            default_order: Order::TimeAsc,
        }
    }
}

/// Why a query could not run to the end.
#[derive(Debug)]
#[non_exhaustive]
pub enum ExecError {
    /// The storage backend failed.
    Store(StoreError),
    /// [`ExecOptions::cancel`] was set.
    Cancelled,
    /// `sort` would hold more than this many events
    /// ([`ExecOptions::max_materialized`]).
    TooManyEvents(usize),
}

impl fmt::Display for ExecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExecError::Store(e) => write!(f, "{e}"),
            ExecError::Cancelled => write!(f, "query cancelled"),
            ExecError::TooManyEvents(n) => write!(
                f,
                "more than {n} events to sort; narrow the search or aggregate with stats first"
            ),
        }
    }
}

impl std::error::Error for ExecError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ExecError::Store(e) => Some(e),
            ExecError::Cancelled | ExecError::TooManyEvents(_) => None,
        }
    }
}

impl From<StoreError> for ExecError {
    fn from(e: StoreError) -> Self {
        ExecError::Store(e)
    }
}

/// The rows a query produced.
#[derive(Debug, Clone)]
pub enum ResultRows {
    /// Events, when no `stats` ran.
    Events(Vec<Event>),
    /// A table, after `stats`: named columns and one value (or none) per
    /// column in each row.
    Table {
        /// Column names, in order.
        columns: Vec<String>,
        /// Rows, each as long as `columns`.
        rows: Vec<Vec<Option<FieldValue>>>,
    },
}

/// What [`execute`] returns.
#[derive(Debug, Clone)]
pub struct QueryResult {
    /// The result rows.
    pub rows: ResultRows,
    /// Columns chosen with `fields` (events only; tables carry their own).
    pub projection: Option<Vec<String>>,
    /// More rows existed than [`ExecOptions::max_rows`].
    pub truncated: bool,
    /// Wall time the query took.
    pub elapsed: Duration,
}

impl QueryResult {
    /// Number of rows (events or table rows).
    pub fn len(&self) -> usize {
        match &self.rows {
            ResultRows::Events(events) => events.len(),
            ResultRows::Table { rows, .. } => rows.len(),
        }
    }

    /// Whether there are no rows.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// An event seen through its virtual fields.
pub struct EnrichedEvent<'a> {
    /// The stored event.
    pub event: &'a Event,
    /// Resolves the event's `base@attr` fields.
    pub virtual_fields: &'a dyn VirtualFields,
}

impl fmt::Debug for EnrichedEvent<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EnrichedEvent")
            .field("event", self.event)
            .finish_non_exhaustive()
    }
}

impl Record for EnrichedEvent<'_> {
    fn get(&self, field: &str) -> Option<Cow<'_, FieldValue>> {
        if is_virtual_field(field) {
            self.virtual_fields
                .resolve(self.event, field)
                .map(Cow::Owned)
        } else {
            lookup(self.event, field)
        }
    }

    fn for_each_value(&self, f: &mut dyn FnMut(&FieldValue)) {
        self.event.for_each_value(f);
    }
}

/// One row of a table result.
#[derive(Debug, Clone, Copy)]
pub struct TableRow<'a> {
    /// The table's column names.
    pub columns: &'a [String],
    /// This row's values, one per column.
    pub values: &'a [Option<FieldValue>],
}

impl Record for TableRow<'_> {
    fn get(&self, field: &str) -> Option<Cow<'_, FieldValue>> {
        let index = self.columns.iter().position(|c| c == field)?;
        self.values.get(index)?.as_ref().map(Cow::Borrowed)
    }

    fn for_each_value(&self, f: &mut dyn FnMut(&FieldValue)) {
        self.values.iter().flatten().for_each(f);
    }
}

/// What gets sent to the store, and what's left to do here.
#[derive(Debug, Clone, PartialEq)]
pub struct Plan {
    /// What the backend evaluates.
    pub store: StoreQuery,
    /// Filter conjuncts on virtual fields, evaluated here.
    pub residual: Predicate,
    /// Commands left to run here, in order.
    pub commands: Vec<Command>,
}

/// [`plan_with_order`] with oldest-first events.
pub fn plan(query: &Query) -> Plan {
    plan_with_order(query, Order::TimeAsc)
}

/// [`plan`] with events in `default_order` unless the query sorts by time.
pub fn plan_with_order(query: &Query, default_order: Order) -> Plan {
    let (pushed, residual) = split_filter(&query.filter);
    let mut commands = query.commands.clone();
    let aggregates = commands.iter().any(|c| matches!(c, Command::Stats { .. }));
    // Aggregations don't care about order, and storage order lets the store
    // stream instead of sorting.
    let mut order = if aggregates {
        Order::Storage
    } else {
        default_order
    };
    if let Some(Command::Sort(keys)) = commands.first()
        && let [SortKey { field, descending }] = keys.as_slice()
        && field == "@timestamp"
    {
        order = if *descending {
            Order::TimeDesc
        } else {
            Order::TimeAsc
        };
        commands.remove(0);
    }
    let limit = match commands.first() {
        Some(Command::Head(n)) if residual == Predicate::True => Some(*n),
        _ => None,
    };
    Plan {
        store: StoreQuery {
            time: query.time,
            filter: pushed,
            order,
            limit,
            projection: None,
        },
        residual,
        commands,
    }
}

fn references_virtual(predicate: &Predicate) -> bool {
    let mut found = false;
    predicate.visit_fields(&mut |f| found |= is_virtual_field(f));
    found
}

/// Splits top-level conjuncts into (store-evaluable, residual).
fn split_filter(filter: &Predicate) -> (Predicate, Predicate) {
    let conjuncts: Vec<Predicate> = match filter {
        Predicate::And(items) => items.clone(),
        other => vec![other.clone()],
    };
    let (residual, pushed): (Vec<_>, Vec<_>) = conjuncts.into_iter().partition(references_virtual);
    (conjunction(pushed), conjunction(residual))
}

fn conjunction(mut items: Vec<Predicate>) -> Predicate {
    items.retain(|p| *p != Predicate::True);
    match items.len() {
        0 => Predicate::True,
        1 => items.swap_remove(0),
        _ => Predicate::And(items),
    }
}

type EventStream<'a> = Box<dyn Iterator<Item = Result<Event, ExecError>> + 'a>;

enum Stage<'a> {
    Stream(EventStream<'a>),
    Events(Vec<Event>),
    Table {
        columns: Vec<String>,
        rows: Vec<Vec<Option<FieldValue>>>,
    },
}

/// Runs a parsed query against `store`.
///
/// # Errors
///
/// [`ExecError::Store`] when the backend fails, [`ExecError::Cancelled`]
/// when [`ExecOptions::cancel`] is set, and [`ExecError::TooManyEvents`]
/// when `sort` would hold more than [`ExecOptions::max_materialized`]
/// events.
pub fn execute<S: EventSource + ?Sized>(
    store: &S,
    query: &Query,
    virtual_fields: &dyn VirtualFields,
    options: &ExecOptions,
) -> Result<QueryResult, ExecError> {
    let started = Instant::now();
    let mut plan = plan_with_order(query, options.default_order);
    // A bare filter keeps at most `max_rows`; one more tells truncation.
    if plan.commands.is_empty() && plan.residual == Predicate::True && plan.store.limit.is_none() {
        plan.store.limit = Some(options.max_rows.saturating_add(1));
    }
    // A leading `stats` the store can answer itself skips the event stream.
    let mut commands: &[Command] = &plan.commands;
    let mut pushed = None;
    if plan.residual == Predicate::True
        && plan.store.limit.is_none()
        && let Some(Command::Stats { aggs, by }) = plan.commands.first()
        && !by.iter().any(|g| is_virtual_field(g.field()))
        && !aggs
            .iter()
            .any(|a| a.field.as_deref().is_some_and(is_virtual_field))
        && let Some(table) = store.aggregate(&plan.store, aggs, by)?
    {
        pushed = Some(Stage::Table {
            columns: table.columns,
            rows: table.rows,
        });
        commands = &plan.commands[1..];
    }

    // A leading `tail n` over a time-ordered stream reads the stream
    // backwards and stops after `n` events. Both orders are exact mirrors
    // (ties included), so this equals keeping the last `n`.
    let mut tail = None;
    if pushed.is_none()
        && let Some(Command::Tail(n)) = commands.first()
        && plan.store.order != Order::Storage
    {
        plan.store.order = match plan.store.order {
            Order::TimeAsc => Order::TimeDesc,
            _ => Order::TimeAsc,
        };
        if plan.residual == Predicate::True {
            plan.store.limit = Some(*n);
        }
        tail = Some(*n);
        commands = &commands[1..];
    }

    if pushed.is_none() {
        plan.store.projection = stream_projection(&plan.residual, commands);
    }

    let cancel = options.cancel.clone();
    let residual = plan.residual.clone();
    let mut stage = if let Some(table) = pushed {
        table
    } else {
        let stream = event_stream(store, &plan.store, cancel, residual, virtual_fields)?;
        if let Some(n) = tail {
            let mut events = stream.take(n).collect::<Result<Vec<_>, _>>()?;
            events.reverse();
            Stage::Events(events)
        } else {
            Stage::Stream(stream)
        }
    };
    let mut projection: Option<Vec<String>> = None;
    for (i, command) in commands.iter().enumerate() {
        // `sort | head n` keeps only the best `n` instead of sorting all.
        if let (Command::Sort(keys), Some(Command::Head(n)), Stage::Stream(_)) =
            (command, commands.get(i + 1), &stage)
            && *n <= TOP_K_MAX
        {
            let Stage::Stream(stream) = stage else {
                unreachable!("matched above")
            };
            stage = Stage::Events(top_k(stream, keys, *n, virtual_fields)?);
            continue;
        }
        stage = apply(stage, command, virtual_fields, options, &mut projection)?;
    }
    finish_result(stage, options, started, projection)
}

/// What the event stream must carry when its events end up in a `stats`
/// and never reach the result: the residual's fields, then those read by
/// each command up to that `stats`. `None` (whole events) when the events
/// are the result, or when a virtual field is read.
fn stream_projection(residual: &Predicate, commands: &[Command]) -> Option<Projection> {
    let mut p = Projection::default();
    if !p.read(residual) {
        return None;
    }
    for command in commands {
        let ok = match command {
            Command::Where(pred) => p.read(pred),
            Command::Sort(keys) => keys.iter().all(|k| p.read_field(&k.field)),
            Command::Dedup(fields) => fields.iter().all(|f| p.read_field(f)),
            Command::Head(_) | Command::Tail(_) | Command::Fields(_) => true,
            Command::Stats { aggs, by } => {
                let ok = by.iter().all(|g| p.read_field(g.field()))
                    && aggs
                        .iter()
                        .filter_map(|a| a.field.as_deref())
                        .all(|f| p.read_field(f));
                return ok.then_some(p);
            }
        };
        if !ok {
            return None;
        }
    }
    None
}

/// Largest `head` that `sort | head` serves with a bounded buffer.
const TOP_K_MAX: usize = 10_000;

/// The first `n` events of `stream` sorted by `keys` (a stable sort, then
/// `head n`), keeping at most `n` events in memory.
fn top_k(
    stream: EventStream<'_>,
    keys: &[SortKey],
    n: usize,
    vf: &dyn VirtualFields,
) -> Result<Vec<Event>, ExecError> {
    let cmp = |a: &Event, b: &Event| compare_records(&enriched(a, vf), &enriched(b, vf), keys);
    let mut best: Vec<Event> = Vec::new();
    for item in stream {
        let event = item?;
        if best.len() == n {
            // Ties go to the earlier event, as in a stable sort.
            match best.last() {
                Some(last) if cmp(&event, last).is_lt() => {
                    best.pop();
                }
                _ => continue,
            }
        }
        let at = best.partition_point(|x| !cmp(x, &event).is_gt());
        best.insert(at, event);
    }
    Ok(best)
}

fn event_stream<'a, S: EventSource + ?Sized>(
    store: &'a S,
    query: &StoreQuery,
    cancel: Option<Arc<AtomicBool>>,
    residual: Predicate,
    virtual_fields: &'a dyn VirtualFields,
) -> Result<EventStream<'a>, ExecError> {
    let stream: EventStream<'_> = Box::new(
        store
            .search(query)?
            .map(move |item| {
                if cancel.as_ref().is_some_and(|c| c.load(Ordering::Relaxed)) {
                    return Err(ExecError::Cancelled);
                }
                item.map_err(ExecError::from)
            })
            .filter(move |item| match item {
                Ok(event) => residual.matches(&EnrichedEvent {
                    event,
                    virtual_fields,
                }),
                Err(_) => true,
            }),
    );

    Ok(stream)
}

fn finish_result(
    stage: Stage<'_>,
    options: &ExecOptions,
    started: Instant,
    projection: Option<Vec<String>>,
) -> Result<QueryResult, ExecError> {
    let mut truncated = false;
    let rows = match stage {
        Stage::Stream(mut stream) => {
            let mut events = Vec::new();
            for item in stream.by_ref() {
                if events.len() == options.max_rows {
                    item?;
                    truncated = true;
                    break;
                }
                events.push(item?);
            }
            ResultRows::Events(events)
        }
        Stage::Events(mut events) => {
            truncated = events.len() > options.max_rows;
            events.truncate(options.max_rows);
            ResultRows::Events(events)
        }
        Stage::Table { columns, mut rows } => {
            truncated = rows.len() > options.max_rows;
            rows.truncate(options.max_rows);
            ResultRows::Table { columns, rows }
        }
    };
    Ok(QueryResult {
        rows,
        projection,
        truncated,
        elapsed: started.elapsed(),
    })
}

fn materialize(stream: EventStream<'_>, max: usize) -> Result<Vec<Event>, ExecError> {
    let mut events = Vec::new();
    for item in stream {
        if events.len() == max {
            return Err(ExecError::TooManyEvents(max));
        }
        events.push(item?);
    }
    Ok(events)
}

fn apply<'a>(
    stage: Stage<'a>,
    command: &Command,
    vf: &'a dyn VirtualFields,
    options: &ExecOptions,
    projection: &mut Option<Vec<String>>,
) -> Result<Stage<'a>, ExecError> {
    Ok(match (stage, command) {
        (Stage::Stream(s), Command::Where(p)) => {
            let p = p.clone();
            Stage::Stream(Box::new(s.filter(move |item| match item {
                Ok(e) => p.matches(&EnrichedEvent {
                    event: e,
                    virtual_fields: vf,
                }),
                Err(_) => true,
            })))
        }
        (Stage::Events(mut events), Command::Where(p)) => {
            events.retain(|e| p.matches(&enriched(e, vf)));
            Stage::Events(events)
        }
        (Stage::Table { columns, mut rows }, Command::Where(p)) => {
            rows.retain(|r| {
                p.matches(&TableRow {
                    columns: &columns,
                    values: r,
                })
            });
            Stage::Table { columns, rows }
        }

        (Stage::Stream(s), Command::Head(n)) => Stage::Stream(Box::new(s.take(*n))),
        (Stage::Events(mut events), Command::Head(n)) => {
            events.truncate(*n);
            Stage::Events(events)
        }
        (Stage::Table { columns, mut rows }, Command::Head(n)) => {
            rows.truncate(*n);
            Stage::Table { columns, rows }
        }

        (Stage::Stream(s), Command::Tail(n)) => {
            // Not `with_capacity(n)`: `n` comes from the query text.
            let mut last = VecDeque::new();
            for item in s {
                last.push_back(item?);
                if last.len() > *n {
                    last.pop_front();
                }
            }
            Stage::Events(last.into())
        }
        (Stage::Events(mut events), Command::Tail(n)) => {
            events.drain(..events.len().saturating_sub(*n));
            Stage::Events(events)
        }
        (Stage::Table { columns, mut rows }, Command::Tail(n)) => {
            rows.drain(..rows.len().saturating_sub(*n));
            Stage::Table { columns, rows }
        }

        (Stage::Stream(s), Command::Sort(_)) => {
            let events = materialize(s, options.max_materialized)?;
            apply(Stage::Events(events), command, vf, options, projection)?
        }
        (Stage::Events(mut events), Command::Sort(keys)) => {
            events.sort_by(|a, b| compare_records(&enriched(a, vf), &enriched(b, vf), keys));
            Stage::Events(events)
        }
        (Stage::Table { columns, mut rows }, Command::Sort(keys)) => {
            rows.sort_by(|a, b| {
                let row = |values| TableRow {
                    columns: &columns,
                    values,
                };
                compare_records(&row(a), &row(b), keys)
            });
            Stage::Table { columns, rows }
        }

        (Stage::Stream(s), Command::Dedup(fields)) => {
            let fields = fields.clone();
            let mut seen = HashSet::new();
            Stage::Stream(Box::new(s.filter(move |item| match item {
                Ok(e) => seen.insert(key_of(&enriched(e, vf), &fields)),
                Err(_) => true,
            })))
        }
        (Stage::Events(mut events), Command::Dedup(fields)) => {
            let mut seen = HashSet::new();
            events.retain(|e| seen.insert(key_of(&enriched(e, vf), fields)));
            Stage::Events(events)
        }
        (Stage::Table { columns, mut rows }, Command::Dedup(fields)) => {
            let mut seen = HashSet::new();
            rows.retain(|r| {
                seen.insert(key_of(
                    &TableRow {
                        columns: &columns,
                        values: r,
                    },
                    fields,
                ))
            });
            Stage::Table { columns, rows }
        }

        (stage @ (Stage::Stream(_) | Stage::Events(_)), Command::Fields(fields)) => {
            *projection = Some(fields.clone());
            stage
        }
        (Stage::Table { columns, rows }, Command::Fields(fields)) => {
            let indexes: Vec<Option<usize>> = fields
                .iter()
                .map(|f| columns.iter().position(|c| c == f))
                .collect();
            let rows = rows
                .into_iter()
                .map(|row| {
                    indexes
                        .iter()
                        .map(|i| i.and_then(|i| row.get(i).cloned().flatten()))
                        .collect()
                })
                .collect();
            Stage::Table {
                columns: fields.clone(),
                rows,
            }
        }

        (Stage::Stream(s), Command::Stats { aggs, by }) => {
            let mut stats = Stats::new(aggs, by);
            for item in s {
                stats.add(&enriched(&item?, vf));
            }
            *projection = None;
            stats.finish()
        }
        (Stage::Events(events), Command::Stats { aggs, by }) => {
            let mut stats = Stats::new(aggs, by);
            for e in &events {
                stats.add(&enriched(e, vf));
            }
            *projection = None;
            stats.finish()
        }
        (Stage::Table { columns, rows }, Command::Stats { aggs, by }) => {
            let mut stats = Stats::new(aggs, by);
            for r in &rows {
                stats.add(&TableRow {
                    columns: &columns,
                    values: r,
                });
            }
            stats.finish()
        }
    })
}

fn enriched<'b>(event: &'b Event, vf: &'b dyn VirtualFields) -> EnrichedEvent<'b> {
    EnrichedEvent {
        event,
        virtual_fields: vf,
    }
}

fn compare_records(a: &dyn Record, b: &dyn Record, keys: &[SortKey]) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    for key in keys {
        let ordering = match (a.get(&key.field), b.get(&key.field)) {
            (Some(x), Some(y)) => {
                let o = compare_values(&x, &y);
                if key.descending { o.reverse() } else { o }
            }
            // Missing values sort last either way.
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (None, None) => Ordering::Equal,
        };
        if ordering != Ordering::Equal {
            return ordering;
        }
    }
    Ordering::Equal
}

/// Display form used for grouping and distinct counting: arrays
/// comma-joined, everything else as [`FieldValue`]'s `Display`.
pub fn display_value(value: &FieldValue) -> String {
    match value {
        FieldValue::Array(items) => items
            .iter()
            .map(display_value)
            .collect::<Vec<_>>()
            .join(", "),
        other => other.to_string(),
    }
}

fn key_of(record: &dyn Record, fields: &[String]) -> Vec<Option<String>> {
    fields
        .iter()
        .map(|f| record.get(f).map(|v| display_value(&v)))
        .collect()
}

#[allow(
    clippy::cast_precision_loss,
    reason = "aggregates are floating point; large integers round"
)]
fn as_number(value: &FieldValue) -> Option<f64> {
    match value {
        FieldValue::Int(i) => Some(*i as f64),
        FieldValue::Uint(u) => Some(*u as f64),
        FieldValue::Float(f) => Some(*f),
        FieldValue::Str(s) => s.trim().parse().ok(),
        _ => None,
    }
}

/// Distinct values kept by `values(f)`.
const MAX_VALUES: usize = 100;

enum AggState {
    Count(u64),
    Distinct(HashSet<String>),
    Min(Option<FieldValue>),
    Max(Option<FieldValue>),
    Sum(Option<f64>),
    Avg(f64, u64),
    Values(BTreeSet<String>),
}

impl AggState {
    fn new(func: AggFunc) -> AggState {
        match func {
            AggFunc::Count => AggState::Count(0),
            AggFunc::DistinctCount => AggState::Distinct(HashSet::new()),
            AggFunc::Min => AggState::Min(None),
            AggFunc::Max => AggState::Max(None),
            AggFunc::Sum => AggState::Sum(None),
            AggFunc::Avg => AggState::Avg(0.0, 0),
            AggFunc::Values => AggState::Values(BTreeSet::new()),
        }
    }

    fn add(&mut self, value: Option<&FieldValue>, field_given: bool) {
        match self {
            AggState::Count(n) => {
                if !field_given || value.is_some() {
                    *n += 1;
                }
            }
            AggState::Distinct(set) => {
                if let Some(v) = value {
                    set.insert(display_value(v));
                }
            }
            AggState::Min(current) => {
                if let Some(v) = value
                    && current
                        .as_ref()
                        .is_none_or(|c| compare_values(v, c).is_lt())
                {
                    *current = Some(v.clone());
                }
            }
            AggState::Max(current) => {
                if let Some(v) = value
                    && current
                        .as_ref()
                        .is_none_or(|c| compare_values(v, c).is_gt())
                {
                    *current = Some(v.clone());
                }
            }
            AggState::Sum(total) => {
                if let Some(n) = value.and_then(as_number) {
                    *total = Some(total.unwrap_or(0.0) + n);
                }
            }
            AggState::Avg(total, count) => {
                if let Some(n) = value.and_then(as_number) {
                    *total += n;
                    *count += 1;
                }
            }
            AggState::Values(set) => {
                if let Some(v) = value
                    && set.len() < MAX_VALUES
                {
                    set.insert(display_value(v));
                }
            }
        }
    }

    #[allow(
        clippy::cast_precision_loss,
        reason = "an average is floating point; counts past 2^53 round"
    )]
    fn finish(self) -> Option<FieldValue> {
        match self {
            AggState::Count(n) => Some(FieldValue::Uint(n)),
            AggState::Distinct(set) => Some(FieldValue::Uint(set.len() as u64)),
            AggState::Min(v) | AggState::Max(v) => v,
            AggState::Sum(total) => total.map(FieldValue::Float),
            AggState::Avg(total, count) => {
                (count > 0).then(|| FieldValue::Float(total / count as f64))
            }
            AggState::Values(set) => Some(FieldValue::Array(
                set.into_iter()
                    .map(|s| FieldValue::Str(Text::from(s)))
                    .collect(),
            )),
        }
    }
}

/// Floors `value` to a multiple of `span`; `None` when the kinds don't fit
/// or the bucket start is out of range.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    reason = "the float is integral and checked to be within i64's range"
)]
fn bucket(value: &FieldValue, span: Span) -> Option<FieldValue> {
    match (value, span) {
        (FieldValue::Time(t), Span::Nanos(width)) => {
            // Flooring a time near i64::MIN can step below it.
            let start = t.as_nanos().div_euclid(width).checked_mul(width)?;
            Some(FieldValue::Time(usiem::event::Timestamp::from_nanos(start)))
        }
        (v, Span::Number(width)) => {
            let floored = (as_number(v)? / width).floor() * width;
            Some(
                if floored.fract() == 0.0 && floored.abs() < i64::MAX as f64 {
                    FieldValue::Int(floored as i64)
                } else {
                    FieldValue::Float(floored)
                },
            )
        }
        _ => None,
    }
}

struct Stats<'q> {
    aggs: &'q [Agg],
    by: &'q [GroupKey],
    groups: HashMap<Vec<String>, (Vec<FieldValue>, Vec<AggState>)>,
}

impl<'q> Stats<'q> {
    fn new(aggs: &'q [Agg], by: &'q [GroupKey]) -> Self {
        Stats {
            aggs,
            by,
            groups: HashMap::new(),
        }
    }

    fn add(&mut self, record: &dyn Record) {
        let mut key = Vec::with_capacity(self.by.len());
        let mut key_values = Vec::with_capacity(self.by.len());
        for group in self.by {
            // Like most SIEMs, records missing a group-by field are skipped.
            let Some(value) = record.get(group.field()) else {
                return;
            };
            let value = match group {
                GroupKey::Field(_) => value.into_owned(),
                GroupKey::Bucket { span, .. } => match bucket(&value, *span) {
                    Some(v) => v,
                    None => return,
                },
            };
            key.push(display_value(&value));
            key_values.push(value);
        }
        let aggs = self.aggs;
        let (_, states) = self.groups.entry(key).or_insert_with(|| {
            (
                key_values,
                aggs.iter().map(|a| AggState::new(a.func)).collect(),
            )
        });
        for (agg, state) in aggs.iter().zip(states.iter_mut()) {
            let value = agg.field.as_deref().and_then(|f| record.get(f));
            state.add(value.as_deref(), agg.field.is_some());
        }
    }

    fn finish(self) -> Stage<'static> {
        let groups = self
            .groups
            .into_iter()
            .map(|(key, (key_values, states))| {
                let results = states.into_iter().map(AggState::finish).collect();
                (key, key_values, results)
            })
            .collect();
        let table = stats_table(self.aggs, self.by, groups);
        Stage::Table {
            columns: table.columns,
            rows: table.rows,
        }
    }
}

/// One group of a `stats` result: its key strings (the display forms of the
/// group values), the group values, and one result per aggregate.
pub type StatsGroup = (Vec<String>, Vec<FieldValue>, Vec<Option<FieldValue>>);

/// Builds a `stats` table: columns are the `by` names then the aggregate
/// names; rows are sorted by key strings; with no `by` and no group, one row
/// holds every aggregate's empty result (`count` = 0). Backends answering
/// [`EventSource::aggregate`] use this to match the executor exactly.
pub fn stats_table(aggs: &[Agg], by: &[GroupKey], mut groups: Vec<StatsGroup>) -> StatsTable {
    let mut columns: Vec<String> = by.iter().map(|g| g.name().to_string()).collect();
    columns.extend(aggs.iter().map(|a| a.name.clone()));
    if groups.is_empty() && by.is_empty() {
        // `stats count` over nothing is one row of zeros, not no rows.
        let empty = aggs
            .iter()
            .map(|a| AggState::new(a.func).finish())
            .collect();
        groups.push((Vec::new(), Vec::new(), empty));
    }
    groups.sort_by(|a, b| a.0.cmp(&b.0));
    let rows = groups
        .into_iter()
        .map(|(_, key_values, results)| key_values.into_iter().map(Some).chain(results).collect())
        .collect();
    StatsTable { columns, rows }
}

#[cfg(test)]
#[cfg(feature = "jsonl")]
mod tests {
    use super::*;
    use crate::query::parse;
    use crate::store::EventStore;
    use crate::store::TimeRange;
    use crate::store::jsonl::JsonlStore;
    use crate::test_util::TempDir;
    use std::str::FromStr;
    use usiem::event::{Ip, Origin, RawData, Timestamp};

    /// Resolves `source.ip@hostname` from a fixed table.
    struct Hosts;

    impl VirtualFields for Hosts {
        fn resolve(&self, event: &Event, field: &str) -> Option<FieldValue> {
            let (base, attr) = field.split_once('@')?;
            if attr != "hostname" {
                return None;
            }
            match event.get_field(base)? {
                FieldValue::Ip(ip) if ip.to_string() == "10.0.0.1" => {
                    Some(FieldValue::from("dc01"))
                }
                FieldValue::Ip(ip) if ip.to_string() == "10.0.0.2" => {
                    Some(FieldValue::from("ws02"))
                }
                _ => None,
            }
        }
    }

    fn logon(secs: i64, user: &'static str, ip: &str, code: i64) -> Event {
        let mut e = Event::new(
            Timestamp::from_secs(1),
            Timestamp::from_secs(secs),
            Origin::File("Security.evtx".into()),
            RawData::from_text(format!("{secs}{user}{ip}{code}")),
        );
        e.add_field("user.name".into(), FieldValue::from(user));
        e.add_field(
            "source.ip".into(),
            FieldValue::Ip(Ip::from_str(ip).unwrap()),
        );
        e.add_field("event.code".into(), FieldValue::Int(code));
        e.add_field(
            "bytes".into(),
            FieldValue::Uint(u64::try_from(secs).unwrap() * 10),
        );
        e
    }

    fn store(tmp: &TempDir) -> JsonlStore {
        let mut store = JsonlStore::open(tmp.path()).unwrap();
        store
            .append(vec![
                logon(40, "bob", "10.0.0.2", 4625),
                logon(10, "alice", "10.0.0.1", 4624),
                logon(30, "bob", "10.0.0.1", 4624),
                logon(20, "alice", "10.0.0.9", 4624),
            ])
            .unwrap();
        store
    }

    fn run(store: &JsonlStore, q: &str) -> QueryResult {
        execute(store, &parse(q).unwrap(), &Hosts, &ExecOptions::default()).unwrap()
    }

    fn times(result: &QueryResult) -> Vec<i64> {
        match &result.rows {
            ResultRows::Events(events) => {
                events.iter().map(|e| e.original_time().as_secs()).collect()
            }
            other @ ResultRows::Table { .. } => panic!("{other:?}"),
        }
    }

    fn table(result: &QueryResult) -> (Vec<String>, Vec<Vec<String>>) {
        match &result.rows {
            ResultRows::Table { columns, rows } => (
                columns.clone(),
                rows.iter()
                    .map(|r| {
                        r.iter()
                            .map(|v| v.as_ref().map(display_value).unwrap_or_default())
                            .collect()
                    })
                    .collect(),
            ),
            other @ ResultRows::Events(_) => panic!("{other:?}"),
        }
    }

    #[test]
    fn plan_pushes_stored_fields_and_keeps_virtual_ones() {
        let q =
            parse("user.name:bob source.ip@hostname:dc01 earliest=2024-01-01 | head 5").unwrap();
        let p = plan(&q);
        assert_eq!(p.store.filter, Predicate::eq("user.name", "bob"));
        assert_eq!(p.residual, Predicate::eq("source.ip@hostname", "dc01"));
        assert_eq!(p.store.order, Order::TimeAsc);
        assert!(p.store.time.start.is_some());
        // A residual filter means the store can't apply the limit.
        assert_eq!(p.store.limit, None);

        let p = plan(&parse("user.name:bob | sort -@timestamp | head 5").unwrap());
        assert_eq!(p.store.order, Order::TimeDesc);
        assert_eq!(p.store.limit, Some(5));
        assert_eq!(p.commands, vec![Command::Head(5)]);

        let p = plan(&parse("* | stats count").unwrap());
        assert_eq!(p.store.order, Order::Storage);
        assert_eq!(p.store.time, TimeRange::default());
    }

    #[test]
    fn stream_projection_reads_only_up_to_stats() {
        let proj = |text: &str| {
            let plan = plan(&parse(text).unwrap());
            stream_projection(&plan.residual, &plan.commands)
        };
        let fields = |names: &[&str], raw, origin| {
            Some(Projection {
                fields: Some(names.iter().map(|n| (*n).to_string()).collect()),
                raw,
                origin,
            })
        };
        // Events reach the result: whole events.
        assert_eq!(proj("host:a"), None);
        assert_eq!(proj("* | fields host | sort -bytes"), None);
        assert_eq!(proj("* | where code>5 | head 3"), None);
        // Up to the first `stats`, in reading order; meta fields are free.
        assert_eq!(proj("* | stats count"), fields(&[], false, false));
        assert_eq!(
            proj(
                "* | where code>5 | sort -bytes, @timestamp | head 10 | dedup user.name | stats dc(src) by host, bucket(@arrival,1m) | sort -host"
            ),
            fields(&["code", "bytes", "user.name", "host", "src"], false, false)
        );
        assert_eq!(
            proj("* | where @id:x | stats count"),
            fields(&[], true, true)
        );
        assert_eq!(proj("* | stats count by @origin"), fields(&[], false, true));
        // A bare text term reads every field (but not the raw data).
        assert_eq!(
            proj("* | where admin | stats count by host"),
            Some(Projection {
                fields: None,
                raw: false,
                origin: false,
            })
        );
        // Virtual fields read unknown parts of the event.
        assert_eq!(proj("src@geo:ES | stats count"), None);
        assert_eq!(proj("* | stats count by src@geo"), None);
        assert_eq!(proj("* | sort src@geo | stats count"), None);
    }

    #[test]
    fn search_is_a_timeline_by_default() {
        let tmp = TempDir::new("exec-timeline");
        let s = store(&tmp);
        assert_eq!(times(&run(&s, "")), [10, 20, 30, 40]);
        assert_eq!(times(&run(&s, "user.name:bob")), [30, 40]);
        assert_eq!(
            times(&run(&s, "source.ip:10.0.0.0/30 NOT event.code:4625")),
            [10, 30]
        );
        assert_eq!(times(&run(&s, "* | sort -@timestamp | head 2")), [40, 30]);
        assert_eq!(times(&run(&s, "* | tail 1")), [40]);
        assert_eq!(times(&run(&s, "* | dedup user.name")), [10, 30]);
        assert_eq!(times(&run(&s, "* | sort -bytes")), [40, 30, 20, 10]);
    }

    #[test]
    fn virtual_fields_filter_and_group() {
        let tmp = TempDir::new("exec-virtual");
        let s = store(&tmp);
        assert_eq!(times(&run(&s, "source.ip@hostname:dc*")), [10, 30]);
        assert_eq!(times(&run(&s, "* | where source.ip@hostname:ws02")), [40]);
        let (columns, rows) = table(&run(&s, "* | stats count by source.ip@hostname"));
        assert_eq!(columns, ["source.ip@hostname", "count"]);
        // 10.0.0.9 has no hostname, so it is skipped.
        assert_eq!(rows, [["dc01", "2"], ["ws02", "1"]]);
    }

    #[test]
    fn stats_aggregations_then_table_commands() {
        let tmp = TempDir::new("exec-stats");
        let s = store(&tmp);
        let (columns, rows) = table(&run(
            &s,
            "* | stats count, dc(source.ip) as ips, min(bytes), max(bytes), sum(bytes), avg(bytes), values(event.code) by user.name | sort -sum(bytes)",
        ));
        assert_eq!(
            columns,
            [
                "user.name",
                "count",
                "ips",
                "min(bytes)",
                "max(bytes)",
                "sum(bytes)",
                "avg(bytes)",
                "values(event.code)"
            ]
        );
        assert_eq!(
            rows,
            [
                ["bob", "2", "2", "300", "400", "700", "350", "4624, 4625"],
                ["alice", "2", "2", "100", "200", "300", "150", "4624"],
            ]
        );
        let (_, rows) = table(&run(
            &s,
            "* | stats count by user.name | where count:>1 user.name:alice | fields count",
        ));
        assert_eq!(rows, [["2"]]);
        let (_, rows) = table(&run(&s, "user.name:nobody | stats count"));
        assert_eq!(rows, [["0"]]);
    }

    #[test]
    fn bucketed_stats() {
        let tmp = TempDir::new("exec-bucket");
        let s = store(&tmp);
        let (columns, rows) = table(&run(
            &s,
            "* | stats count by bucket(@timestamp,20s) | sort bucket(@timestamp,20s)",
        ));
        assert_eq!(columns, ["bucket(@timestamp,20s)", "count"]);
        // Times 10, 20, 30, 40 fall into buckets 0, 20, 20, 40.
        assert_eq!(
            rows,
            [
                ["1970-01-01T00:00:00Z", "1"],
                ["1970-01-01T00:00:20Z", "2"],
                ["1970-01-01T00:00:40Z", "1"]
            ]
        );
        let (_, rows) = table(&run(&s, "* | stats count by bucket(bytes,250)"));
        assert_eq!(rows, [["0", "2"], ["250", "2"]]);
    }

    #[test]
    fn truncation_and_cancellation() {
        let tmp = TempDir::new("exec-limits");
        let s = store(&tmp);
        let options = ExecOptions {
            max_rows: 3,
            ..Default::default()
        };
        let r = execute(&s, &parse("").unwrap(), &Hosts, &options).unwrap();
        assert_eq!(r.len(), 3);
        assert!(r.truncated);

        let options = ExecOptions {
            max_materialized: 2,
            ..Default::default()
        };
        let q = Query {
            commands: vec![Command::Sort(vec![SortKey {
                field: "bytes".into(),
                descending: false,
            }])],
            ..Default::default()
        };
        assert!(matches!(
            execute(&s, &q, &Hosts, &options),
            Err(ExecError::TooManyEvents(2))
        ));

        let options = ExecOptions {
            cancel: Some(Arc::new(AtomicBool::new(true))),
            ..Default::default()
        };
        assert!(matches!(
            execute(&s, &Query::default(), &Hosts, &options),
            Err(ExecError::Cancelled)
        ));
    }

    #[test]
    fn huge_tail_counts_do_not_preallocate() {
        let tmp = TempDir::new("exec-tail");
        let s = store(&tmp);
        // `with_capacity(n + 1)` overflowed or aborted on these.
        assert_eq!(
            times(&run(&s, "* | tail 18446744073709551615")),
            [10, 20, 30, 40]
        );
        assert_eq!(times(&run(&s, "* | tail 1000000000000")), [10, 20, 30, 40]);
    }

    #[test]
    fn time_buckets_near_the_minimum_do_not_overflow() {
        let t = FieldValue::Time(Timestamp::from_nanos(i64::MIN));
        assert_eq!(bucket(&t, Span::Nanos(3)), None);
        assert_eq!(
            bucket(&FieldValue::Time(Timestamp::from_nanos(-5)), Span::Nanos(3)),
            Some(FieldValue::Time(Timestamp::from_nanos(-6)))
        );
        assert_eq!(bucket(&t, Span::Nanos(1)), Some(t.clone()));
    }

    #[test]
    fn short_table_rows_read_as_missing_values() {
        let columns = vec!["a".to_string(), "b".to_string()];
        let values = vec![Some(FieldValue::Int(1))];
        let row = TableRow {
            columns: &columns,
            values: &values,
        };
        assert_eq!(row.get("a").as_deref(), Some(&FieldValue::Int(1)));
        assert_eq!(row.get("b"), None);
    }

    #[test]
    fn sorting_mixed_kinds_is_stable_and_total() {
        let tmp = TempDir::new("exec-mixed");
        let mut s = JsonlStore::open(tmp.path()).unwrap();
        let mut events = Vec::new();
        for i in 0..500 {
            let mut e = logon(i, "x", "10.0.0.1", 1);
            let v = match i % 4 {
                0 => FieldValue::Int(i),
                1 => FieldValue::from(format!("{}", 1000 - i)),
                2 => FieldValue::Float(2.5),
                _ => FieldValue::Ip(Ip::from_str("10.0.0.2").unwrap()),
            };
            e.add_field("v".into(), v);
            events.push(e);
        }
        s.append(events).unwrap();
        let r = run(&s, "* | sort v");
        assert_eq!(r.len(), 500);
    }
}
