//! The search language: a filter followed by pipe commands.
//!
//! ```text
//! artifact.name:"Windows::WinEvt::Security" event.code:(4624 OR 4625)
//!     source.ip:10.0.0.0/8 NOT user.name:SYSTEM earliest=2024-01-01
//!   | where source.ip@hostname:*dc*
//!   | stats count, dc(source.ip) as sources by user.name
//!   | sort -count
//!   | head 20
//! ```
//!
//! Filter terms:
//!
//! | syntax                     | meaning                                            |
//! |----------------------------|----------------------------------------------------|
//! | `field:value`              | equals (case-insensitive, numeric-aware)           |
//! | `field:*`                  | field exists                                       |
//! | `field:*cmd*`, `field:a?c` | glob                                               |
//! | `field:10.0.0.0/8`         | CIDR                                               |
//! | `field:(a OR b)`           | any of                                             |
//! | `field:>10`, `field<=x`    | comparison (numbers, times, IPs, text)             |
//! | `field:1..10`              | inclusive range                                    |
//! | `field!=value`             | not equal                                          |
//! | `word`, `"some words"`     | any string field contains it                       |
//! | `earliest=T` `latest=T`    | time range on the event time (`latest` exclusive)  |
//! | `AND`, `OR`, `NOT`, `( )`  | boolean logic; juxtaposition means AND             |
//!
//! Keywords are upper case, so `or` is an ordinary search word. Values with
//! spaces or a `:` (Windows paths, IPv6) need double quotes; inside quotes
//! only `\"` is an escape, so `"C:\Windows\*"` works as written.
//!
//! Field names may name a *virtual field* (`source.ip@hostname`): a value
//! computed at query time by a [`VirtualFields`] hook, never stored. Meta fields start
//! with `@`: `@timestamp`, `@arrival`, `@origin`, `@id`.
//!
//! Commands: `where <filter>`, `fields a, b` (alias `table`),
//! `sort -a +b`, `head [n]`, `tail [n]`, `dedup a b`,
//! `stats <agg> [as name], ... [by a, b]` with `count`, `count(f)`, `dc(f)`,
//! `min(f)`, `max(f)`, `sum(f)`, `avg(f)`, `values(f)`.
//!
//! The full reference, with matching rules and gotchas, is
//! [`docs/query-language.md`](https://github.com/u-siem/query/blob/main/docs/query-language.md).

pub mod exec;
pub mod parser;
pub mod stream;

use crate::store::{Predicate, TimeRange};

pub use exec::{
    ExecError, ExecOptions, NoVirtualFields, QueryResult, ResultRows, VirtualFields, execute,
};
pub use parser::{MAX_NESTING, ParseError, parse};
pub use stream::{StreamFilter, StreamFilterError};

/// A parsed query.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Query {
    /// The search before the first `|`, without `earliest=`/`latest=`.
    pub filter: Predicate,
    /// `earliest=` and `latest=`.
    pub time: TimeRange,
    /// The pipe commands, in order.
    pub commands: Vec<Command>,
}

/// A pipe command.
#[derive(Debug, Clone, PartialEq)]
pub enum Command {
    /// `where <filter>`: keeps the rows that match.
    Where(Predicate),
    /// Projection: which columns to show, in order.
    Fields(Vec<String>),
    /// `sort -a +b`: orders rows by these keys.
    Sort(Vec<SortKey>),
    /// `head n`: the first `n` rows.
    Head(usize),
    /// `tail n`: the last `n` rows.
    Tail(usize),
    /// `dedup a b`: the first row per distinct combination of values.
    Dedup(Vec<String>),
    /// `stats <aggs> by <keys>`: one row per group.
    Stats {
        /// Aggregates, one output column each.
        aggs: Vec<Agg>,
        /// Group keys; empty for a single overall row.
        by: Vec<GroupKey>,
    },
}

/// A `stats ... by` term.
#[derive(Debug, Clone, PartialEq)]
pub enum GroupKey {
    /// A field's value.
    Field(String),
    /// `bucket(field,span)`: the value floored to a multiple of `span`.
    Bucket {
        /// The bucketed field.
        field: String,
        /// Bucket width.
        span: Span,
        /// Column name: the term as written.
        name: String,
    },
}

impl GroupKey {
    /// The field the key reads.
    pub fn field(&self) -> &str {
        match self {
            GroupKey::Field(f) | GroupKey::Bucket { field: f, .. } => f,
        }
    }

    /// The output column name.
    pub fn name(&self) -> &str {
        match self {
            GroupKey::Field(f) => f,
            GroupKey::Bucket { name, .. } => name,
        }
    }
}

/// Bucket width: a duration for times (`30s`, `15m`, `1h`, `1d`), a plain
/// number for numbers.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Span {
    /// A duration, for time values.
    Nanos(i64),
    /// A width, for numeric values.
    Number(f64),
}

impl Span {
    /// Parses a positive number or duration; `None` otherwise.
    pub fn parse(text: &str) -> Option<Span> {
        if let Ok(n) = text.parse::<f64>() {
            return (n > 0.0 && n.is_finite()).then_some(Span::Number(n));
        }
        let nanos = parse_duration(text)?;
        (nanos > 0).then_some(Span::Nanos(nanos))
    }
}

/// Parses `30s`, `-15m`, `1h`, `2d` into nanoseconds, saturating at the
/// `i64` range.
pub fn parse_duration(text: &str) -> Option<i64> {
    let unit = text.chars().last()?;
    let count: i64 = text[..text.len() - unit.len_utf8()].parse().ok()?;
    let unit_nanos: i64 = match unit {
        's' => 1_000_000_000,
        'm' => 60 * 1_000_000_000,
        'h' => 3_600 * 1_000_000_000,
        'd' => 86_400 * 1_000_000_000,
        _ => return None,
    };
    Some(count.saturating_mul(unit_nanos))
}

/// One `sort` key.
#[derive(Debug, Clone, PartialEq)]
pub struct SortKey {
    /// The field or column sorted by.
    pub field: String,
    /// `-field`: largest first.
    pub descending: bool,
}

/// A `stats` aggregate function.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AggFunc {
    /// `count` (rows) or `count(f)` (rows with `f`).
    Count,
    /// `dc(f)`: distinct values.
    DistinctCount,
    /// `min(f)`, by [`compare_values`](crate::store::compare_values).
    Min,
    /// `max(f)`, by [`compare_values`](crate::store::compare_values).
    Max,
    /// `sum(f)` of numeric values.
    Sum,
    /// `avg(f)` of numeric values.
    Avg,
    /// `values(f)`: up to 100 distinct values, sorted.
    Values,
}

/// One `stats` aggregate.
#[derive(Debug, Clone, PartialEq)]
pub struct Agg {
    /// The function.
    pub func: AggFunc,
    /// `None` only for a bare `count`.
    pub field: Option<String>,
    /// Output column name.
    pub name: String,
}

/// Whether `field` names a virtual field (`base@attr`), as opposed to a
/// stored field or an `@meta` field.
pub fn is_virtual_field(field: &str) -> bool {
    field.find('@').is_some_and(|i| i > 0)
}

/// Plain-text syntax reference for the filter language and pipe commands.
/// Applications append their own sections (keys, screens).
pub const HELP: &str = r#"SEARCH                          (terms side by side mean AND)
  field:value                   equals; case-insensitive, numbers compare as numbers
  field:*                       field exists
  field:*cmd*   field:a?c       glob
  field:10.0.0.0/8              CIDR
  field:(a OR b OR c)           any of
  field:>10  field<=x  f:1..9   comparisons and inclusive range
  field!=value                  not equal
  word   "two words"            any text field contains it
  earliest=2024-01-01 latest="2024-01-02 12:00:00"     event-time range (UTC)
  AND  OR  NOT  ( )             upper case; lower-case 'or' is a plain word
  Quote values with spaces or ':' (paths, IPv6): file.path:"C:\Windows\*"
  Meta fields: @timestamp @arrival @origin @id
  Virtual fields: source.ip@hostname (computed at query time, never stored)

PIPES
  | where <filter>              filter again (works on virtual fields and stats output)
  | fields a, b   | table a b   choose columns
  | sort -count +user.name      sort (- descending)
  | head 20   | tail 20         first / last rows
  | dedup user.name             keep the first row per value
  | stats count, dc(f), min(f), max(f), sum(f), avg(f), values(f) [as name] by a, b
  Stats keys can bucket values: stats count by bucket(@timestamp,1h)"#;
