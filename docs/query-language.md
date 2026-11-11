# Query language reference

A query is a **filter** followed by zero or more **pipe commands**:

```text
process.name:sshd source.ip:10.0.0.0/8 NOT user.name:root earliest=-24h
  | stats count, dc(source.ip) as sources by user.name
  | sort -count
  | head 20
```

The filter, the text before the first `|`, selects events. Each command
after a `|` transforms the rows produced by the previous step. Newlines are
ordinary whitespace, so long queries can span lines.

This document describes the language as implemented in `src/query/` and
`src/store/predicate.rs`. A short plain-text version for help screens is
in [`query::HELP`](../src/query/mod.rs).

## Contents

1. [Filter terms](#1-filter-terms)
2. [Boolean logic](#2-boolean-logic)
3. [Values: quoting and how they are read](#3-values-quoting-and-how-they-are-read)
4. [Matching rules by type](#4-matching-rules-by-type)
5. [Time range: earliest and latest](#5-time-range-earliest-and-latest)
6. [Fields](#6-fields)
7. [Pipe commands](#7-pipe-commands)
8. [Using the language from Rust](#8-using-the-language-from-rust)
9. [Backends and performance](#9-backends-and-performance)
10. [Errors and limits](#10-errors-and-limits)
11. [Gotchas](#11-gotchas)
12. [Cookbook](#12-cookbook)

## 1. Filter terms

| Syntax | Meaning |
|---|---|
| `field:value` or `field=value` | Equals. Case-insensitive; numbers compare as numbers. |
| `field:*` | The field exists (has any value). |
| `field:*cmd*`, `field:a?c` | Glob: `*` matches any run of characters and `?` matches exactly one. |
| `field:10.0.0.0/8`, `field:2001:db8::/32` | CIDR: the value is an IP address in the network. |
| `field:(a OR b OR c)`, `field:(a b c)` | Any of the listed values. |
| `field>v`, `field>=v`, `field<v`, `field<=v` | Comparison. |
| `field:>v`, `field:>=v`, `field:<v`, `field:<=v` | The same comparison, written after `:`. |
| `field:1..9`, `field:1..`, `field:..9` | Inclusive range. Either end may be left open. |
| `field!=value` | Not `field:value`. Any right-hand side works: `f!=*`, `f!=(a OR b)`, `f!=10.0.0.0/8`, `f!=1..5`. |
| `field=~"re"` | A regular expression is found in the value. Case-**sensitive**, unlike everything else; `(?i)` turns case off. The pattern must be quoted. |
| `field!~"re"` | Not `field=~"re"`. |
| `word` | Some text field of the event contains `word`. |
| `"two words"` | Some text field contains the phrase. |
| `earliest=T`, `latest=T` | Time range on the event time (see [§5](#5-time-range-earliest-and-latest)). |

A field name is made of letters, digits and `_ . @ -`. A term is a field
term when one of the operators `=~ !~ >= <= != : = > <` follows the name
**immediately**. `user.name : bob`, with spaces, is three bare words.

A **bare word** is a substring search over the event's text values
([§4](#text-search)). `*` characters at the start or end of a bare word are
removed: `*powershell*` means `powershell`, and a lone `*` matches
everything. A `*` inside a bare word is a literal character, because bare
words are not globs.

## 2. Boolean logic

| Operator | Meaning |
|---|---|
| `a b` or `a AND b` | Both. |
| `a OR b` | Either. |
| `NOT a` | Not. |
| `( … )` | Grouping. |

- **Precedence**, from tightest to loosest: `NOT`, then `AND` (written or
  implied), then `OR`. So `a:1 OR b:2 c:3` means `a:1 OR (b:2 AND c:3)`.
- **Keywords are upper case.** Lower-case `and`, `or` and `not` are ordinary
  search words. A keyword must be followed by whitespace, `(` or the end of
  the query, so `NOT(a:1 OR b:2)` works.
- Repeated or leading `AND`s are ignored. A group with no term in it is an
  error: `()`, `a OR`, or a lone `AND` gives "expected a search term".
- **Nesting limit.** Parentheses and `NOT`s may nest at most
  `MAX_NESTING` = **64** levels deep. Sibling groups do not add up. The limit
  protects the parser and evaluator from stack overflow on untrusted input.

## 3. Values: quoting and how they are read

### Unquoted values

An unquoted value ends at whitespace, `(`, `)` or `"`. It may contain `:`,
so `source.ip:fe80::1` and `file.path:C:\Windows\*` parse as written. A
*bare word* cannot contain `:`, because the text before it would be read as
a field name.

### Quoted values

Use double quotes for values with spaces, parentheses or `|`:
`process.command_line:"cmd.exe /c whoami"`.

- The only escape is `\"`, for a literal quote.
- Every other backslash is literal, so Windows paths need no doubling:
  `"C:\Windows\System32\*"`.
- A `\` just before the closing quote stays literal when the quote is
  followed by whitespace, `)`, `|` or the end of the query. So
  `file.directory:"C:\Users\"` is the path `C:\Users\`.
- An unterminated quote is an error, reported at the opening quote.

### How a value after `field:` is classified

The parser tries these in order:

| Value | Becomes |
|---|---|
| unquoted `*` | exists |
| unquoted, contains `/`, and is a valid CIDR | CIDR |
| unquoted `lo..hi`, with at least one side present | inclusive range |
| contains `*` or `?`, **quoted or not** | glob |
| anything else | equals |

Quoting disables the first three rules, so `"10.0.0.0/8"` is a literal
string. It does **not** disable globs: `"*\temp\*"` is still a glob. Globs
have no escape, so you cannot search for a literal `*` or `?` with
`field:`; use a bare quoted phrase instead. The language has no regular
expressions.

### Value lists

`field:(v1 OR v2 v3)` matches when any value matches. `OR` between values
is optional. Each value is classified as in the table above, so lists may
mix equals, globs, CIDRs and ranges: `port:(22 80 8000..8100)`.

Inside a list, `AND` and `NOT` are not keywords. They are ordinary values.
Values that contain parentheses must be quoted. An empty list is an error.

## 4. Matching rules by type

Every value in a query is read as each type it could be: text, integer,
float, boolean (`true`/`false` in any case), IP address and time. The
stored value's type then decides which reading is compared.

### Equality (`field:value`)

| Stored value | Matches when |
|---|---|
| text | the strings are equal, ignoring case (Unicode lowercasing) |
| integer | equal as an integer, or as a float: `bytes:1024` matches `1024.0` |
| float | the float values are equal |
| boolean | same boolean |
| IP address | same address: `10.0.0.1` matches the IP but not `10.0.0.10` |
| time | **the same nanosecond**: `@timestamp:2024-01-01` matches only midnight; use a range instead |
| bytes, object | never |

**Arrays.** An array matches if **any** element matches. This holds for
every operator.

**Missing fields.** A field term on a missing field is false, so
`NOT user.name:root` also matches events that have no `user.name`. Use
`user.name:* NOT user.name:root` to require the field.

### Comparisons and ranges

- Integers and floats compare numerically, as floats.
- Times compare with absolute time literals: `@timestamp>=2024-01-01`.
  `@timestamp>-1h` parses, but `-1h` is not a time literal, so the term
  never matches. Use `earliest=-1h` ([§5](#5-time-range-earliest-and-latest)).
- IP addresses compare within a family. IPv4 sorts before IPv6.
- **Text compares as lower-cased text.** On a text field `"9" > "10"`, so
  store numbers as numbers if you want numeric ranges.
- Booleans, bytes and objects never match a comparison.

### Globs

Globs are case-insensitive and must match the **whole** value:
`process.name:power*` matches `PowerShell.exe`. On numbers, booleans, IPs
and times the glob is matched against the value's text form, so
`source.ip:10.0.*` matches the IP `10.0.3.7`. Bytes and objects never
match.

### Regular expressions

`field=~"re"` matches when the pattern is found **anywhere** in the value;
anchor with `^` and `$` to match the whole value. It is the one
case-sensitive test: `process.name=~"^power"` misses `PowerShell.exe`, and
`process.name=~"(?i)^power"` finds it. Like globs, numbers, booleans, IPs
and times are matched against their text form, and bytes and objects never
match. On an array, any element may match.

The syntax is that of the Rust `regex` crate (Perl-like classes, `\d`,
`\w`, `\s`, `(?i)`, `(?m)`, `(?s)`, named groups). Matching takes time
linear in the value whatever the pattern, so there are no look-around
assertions (`(?=…)`, `(?<!…)`) and no backreferences (`\1`): a pattern
using them is a syntax error. The pattern must be in double quotes, where
the only escape is `\"`, so backslashes reach the regex as written:
`message=~"user \w+ from \d+\.\d+"`.

On the evstore backend a regex is not answered by the index directly. The
store returns the events whose value contains one of the texts every match
must contain (`fail(ed|ure)` needs `failed` or `failure`), or every event
with the field when there is no such text, and the regex is checked on
those.

### CIDR

CIDR terms match IP values, and text values that parse as an IP address.
The prefix must be at most 32 for IPv4 and 128 for IPv6. Otherwise the
value is not a CIDR and is treated as equals or a glob. An address of the
other family never matches.

### Text search

A bare word or quoted phrase matches when it is a case-insensitive
substring of:

- any text value of the event's **stored fields**,
- including text inside arrays and objects, at any depth,
- and the text form of IP values.

It does **not** search numbers, times, booleans or bytes. It does not search
the meta fields (`@origin`, `@id`, ...), virtual fields, or the raw log
line. To find `4625` in a numeric `event.code`, write `event.code:4625`.

After `stats`, text search in `| where` searches every cell of the table.

### Sort order

`sort`, `min` and `max` order values as follows: numbers (NaN last), then
times, then IP addresses, then everything else as lower-cased text. Values
of different kinds are ordered by kind.

## 5. Time range: earliest and latest

`earliest=T` and `latest=T` restrict the event time (`@timestamp`) to
`[earliest, latest)`. `latest` is exclusive. Accepted forms of `T`, all in
UTC:

| Form | Example |
|---|---|
| now | `now` (any case) |
| relative, in the past | `-30s`, `-15m`, `-24h`, `-7d` |
| date (midnight UTC) | `2024-01-01` |
| date and time | `"2024-01-01 12:00:00"`, `2024-01-01T12:00:00.250` |
| RFC 3339 | `2024-01-01T12:00:00+02:00` |

- Relative times are computed when the query is parsed. There is no `+`
  form.
- Use `=`, not `:`. `earliest:-1h` is an ordinary field term on a field
  named `earliest`.
- The modifiers are only allowed before the first `|`. In `| where` they
  are an error.
- If one is given twice, the last one wins.
- Only `earliest=`/`latest=` accept relative times. Comparisons such as
  `@timestamp>=2024-01-01` take absolute times only, and
  `@timestamp>-1h` silently matches nothing.

Write the modifiers at the top level of the filter. See
[Gotchas](#11-gotchas) for what happens inside `OR` or `NOT`.

## 6. Fields

### Dotted paths

A field name is first looked up as a flat field. If there is no flat field
with that name, the longest dotted prefix that holds an object is used, and
lookup continues into it. So `winlog.event_data.TargetUserName` finds the
key `TargetUserName` inside an object field `winlog.event_data`.

### Meta fields

Names that start with `@` are meta fields, taken from the event envelope:

| Field | Value |
|---|---|
| `@timestamp` | the event's original time (time) |
| `@arrival` | when the event arrived (time) |
| `@origin` | where it came from (text) |
| `@id` | the event id (text) |

Any other `@name` has no value.

### Virtual fields

A name with `@` after the first character, such as `source.ip@hostname`,
is a **virtual field**. Its value is computed at query time by the
application through the [`VirtualFields`](../src/query/exec.rs) hook and is
never stored:

```rust
pub trait VirtualFields: Sync {
    fn resolve(&self, event: &Event, field: &str) -> Option<FieldValue>;
    fn suggest(&self, _event: &Event) -> Vec<(String, FieldValue)> { Vec::new() }
}
```

Which attributes exist depends on the application. With
`NoVirtualFields`, or in a `StreamFilter`, every virtual field is absent.
Field terms on an absent virtual field are false, and `NOT` turns them
true.

## 7. Pipe commands

Command names are lower case. Arguments are separated by spaces or commas.

| Command | Does |
|---|---|
| `where <filter>` | Filters again with the full filter syntax, except `earliest`/`latest`. It can test virtual fields, and after `stats` it filters table rows by column name. |
| `fields a, b`, alias `table a b` | On events, records which columns to display (`QueryResult::projection`); events keep all their fields. On a table, selects and reorders columns; an unknown column is empty. |
| `sort -a +b c` | Sorts. `-` means descending; `+` or nothing means ascending. Missing values sort last in both directions. The sort is stable. |
| `head [n]` | First `n` rows. The default is 10. |
| `tail [n]` | Last `n` rows. The default is 10. |
| `dedup a b` | Keeps the first row for each combination of values. A missing value counts as one of the combinations. |
| `stats …` | Aggregates (below). |

### `stats`

```text
stats <agg> [as name], <agg> [as name], ... [by key, key, ...]
```

| Aggregation | Result |
|---|---|
| `count`, `count()` | number of rows |
| `count(f)` | rows where `f` has a value |
| `dc(f)`, `distinct_count(f)` | number of distinct values of `f`, compared as text |
| `min(f)`, `max(f)` | smallest or largest value, using the sort order above; keeps the value's type |
| `sum(f)`, `avg(f)` | sum or mean of numeric values (text that parses as a number counts); empty if there are none |
| `values(f)` | up to **100** distinct values, sorted, as an array |

- **Column names.** By default a column is named after the aggregation as
  written, without spaces: `dc(source.ip)`. `as name` renames it.
- **Keys.** A key after `by` is a field name, or
  `bucket(field, span)`. The span is a duration (`30s`, `15m`, `1h`,
  `1d`) for time fields, or a positive number for numeric fields:
  `bucket(@timestamp, 1h)`, `bucket(bytes, 1000)`. Bucket values are floored.
- **Missing keys.** Rows that lack any `by` field are skipped. To count
  those rows, run `NOT f:* | stats count` as a separate query.
- **Arrays.** An array counts as **one** value, its elements joined by
  commas, for keys, `dc` and `values`.
- **Output.** The `by` columns come first, then the aggregations. Rows are
  sorted by key. With no `by` and no matching events, the result is a
  single row with `count = 0`.
- **Later commands.** After `stats`, later commands work on the table, and
  a second `stats` can aggregate it again.
- **Referring to a column.** A column whose name contains parentheses can be
  sorted (`sort -dc(source.ip)`), but cannot be named in `where`, because
  `(` is not a field-name character. Rename it with `as` first.

### Streaming and materializing commands

- `where`, `head`, `dedup` and `fields` stream.
- `sort` holds its input in memory, and on events it stops with an error
  after `max_materialized` events ([§8](#8-using-the-language-from-rust)).
  The exception is `sort … | head n` with `n` ≤ 10 000: it keeps only the
  best `n` events in a bounded buffer, with the same result as a stable
  sort, so it never hits that limit.
- `tail n` keeps the last `n` rows. When it comes first over a time-ordered
  stream, the store is read in reverse and stops after `n` events.
- `stats` turns the event stream into a table.

## 8. Using the language from Rust

```rust
use usiem_query::query::{ExecOptions, NoVirtualFields, ResultRows, execute, parse};
use usiem_query::store::jsonl::JsonlStore;

let store = JsonlStore::open("events".as_ref())?;
let query = parse("event.code:4625 earliest=-24h | stats count by source.ip | sort -count")?;
let result = execute(&store, &query, &NoVirtualFields, &ExecOptions::default())?;
match result.rows {
    ResultRows::Events(events) => { /* … */ }
    ResultRows::Table { columns, rows } => { /* rows: Vec<Vec<Option<FieldValue>>> */ }
}
```

- **`parse(text) -> Result<Query, ParseError>`.** A `Query` holds the filter
  (`Predicate`), the time range from `earliest`/`latest`, and the commands.
- **`ExecOptions`:**

  | Field | Default | Meaning |
  |---|---|---|
  | `max_rows` | 10 000 | rows kept; `QueryResult::truncated` is set when more existed |
  | `max_materialized` | 2 000 000 | events `sort` may hold in memory |
  | `cancel` | `None` | an `Arc<AtomicBool>` to stop the query from another thread |
  | `default_order` | `Order::TimeAsc` | event order when the query does not sort by time; set `TimeDesc` for newest first |

- **`QueryResult`** has `rows` (`Events` or `Table`), `projection` (from
  `fields`), `truncated` and `elapsed`.
- **`StreamFilter::parse(text)`** evaluates a filter, plus `| where` stages
  only, one event at a time. Use it for live tails and detection. Any other
  command is rejected with `NotStreamable`. `StreamFilter::from_predicate`
  wraps a predicate built in code.
- **Building filters in code.** `Predicate` and `FieldOp` are public.
  `FieldOp::ContainsAny` (multi-substring matching) exists only in code;
  the parser never produces it. `text::query_literal` quotes a value so it
  can be pasted into query text safely, and a `Predicate`'s `Display` renders
  it back as query syntax.

## 9. Backends and performance

The executor hands a `StoreQuery` (time range, filter, order, limit and
projection) to the backend:

- **Conjunct split.** The top-level `AND` terms are split. Terms that
  mention a virtual field anywhere stay in the executor. Everything else is
  sent to the backend.
- **Order and limit.** A leading `sort @timestamp` or `sort -@timestamp`
  becomes the backend order. If `head n` follows and nothing stays in the
  executor, `n` becomes the backend limit. A leading `tail n` reverses the
  backend order and, likewise, becomes its limit.
- **Projection.** When the events end up in a `stats` that the backend
  doesn't answer itself, they never reach the result. The executor then
  asks only for what the pipeline reads up to that `stats`:
  - the fields named in `where`, `sort`, `dedup` and in the `stats` keys
    and aggregations;
  - every field (but not the raw line) for a bare word in `where`;
  - the origin for `@origin`, and the raw data and origin for `@id`.

  A virtual field anywhere before the `stats` turns projection off, since
  its inputs are unknown. `fields` never projects: it only chooses the
  columns to show. A backend may ignore the hint (`JsonlStore` does) or
  return more than asked.
- **`JsonlStore`** checks every event in the time-overlapping segment files.
- **`EvstoreSource`** (feature `evstore`) translates the filter into an
  evstore filter. See [`src/store/evstore.rs`](../src/store/evstore.rs).
  - **Exact translation.** When the whole filter translates exactly, events
    are not re-checked. That is the case for equals, exists and value lists
    on plain fields; ranges on fields without IP values; globs on text-only
    fields; IPv4 CIDR on IP-only fields; and `AND`/`OR`/`NOT` of these.
    A plain field is one that is never stored as an array or object.
  - **Superset translation.** Otherwise the backend fetches a superset and
    re-checks each event in-process.
  - **Bare words** become a contains-search over every text value, which is
    a scan. A word made only of characters an IP address can contain
    (`443`, `10.0`, `db8`) also keeps every event with an IP field, since it
    may match an IP's text form, so it reads far more events.
  - **`@timestamp` terms** at the top level narrow the time range.
  - **Projection.** Only the columns of the requested fields are decoded,
    together with whatever the re-check needs, and the raw line is skipped
    unless `@id` is read. Past the store's field limit (`max_fields`), new
    names can't be listed, so whole events are read.
  - **`stats` pushdown.** `stats` runs inside evstore when all of these
    hold:
    - it is the first command;
    - the filter translates exactly;
    - every key is a single-typed field or `bucket(@timestamp, …)`;
    - every aggregation is `count`, `count(f)`, `sum`/`avg` of integers,
      or `min`/`max` of integers, times or booleans.

    `dc` and `values` are computed in the executor.

**Tips:**

- Prefer field terms to bare words.
- Always give a time range.
- Put `stats` straight after the filter, so the backend can answer it.
  When a `where`, `sort` or `dedup` must come first, the executor still
  reads only the fields the pipeline uses. A `stats` whose events read
  just a few fields is several times faster than one that needs whole
  events.
- Filter on virtual fields in `| where`, after a selective stored-field
  filter.

## 10. Errors and limits

- **`ParseError`** has `pos`, a **byte** offset into the query, and
  `message`. `Display` prints `message (at column pos+1)`. Errors in a
  command point at the command, except `where`, which points inside its
  filter. Typical messages:
  - unterminated quote
  - empty command after '|'
  - expected a search term
  - expected ')'
  - expected a value
  - empty value list
  - the query nests too deeply
  - earliest= is only allowed before the first '|'
  - "…" is not a time
  - unknown command
  - head expects a number
  - unknown aggregation
  - 'as' must follow an aggregation
  - "…" is not a span
- **`ExecError`** is `Store(StoreError)`, `Cancelled`, or
  `TooManyEvents(n)` (`sort` exceeded `max_materialized`; narrow the search
  or `stats` first).
- **Untrusted input.** Query text may come from untrusted users:
  - nesting is capped;
  - relative times and durations saturate instead of overflowing;
  - the parser is fuzzed.

  `head`/`tail` counts that don't fit in a `usize` are parse errors.

## 11. Gotchas

These describe current behaviour.

- **Quoted globs.** A quoted value with `*` or `?` is still a glob. There is
  no way to escape them in a field term.
- **Exact times.** `@timestamp:2024-01-01` matches only events at exactly
  midnight. Use `earliest=`/`latest=` or `@timestamp:2024-01-01..2024-01-02`.
- **`earliest`/`latest` under `OR` or `NOT`.** They are accepted anywhere in
  the filter and still set the query's time range, but the term itself
  becomes "match everything" at that position. So `a:1 OR earliest=-1h`
  matches every event in the time range, and `NOT earliest=-1h` matches
  nothing.
- **Relative times in comparisons.** `@timestamp>-1h` is not an error, but
  it matches nothing. Use `earliest=-1h`.
- **Missing fields and `NOT`.** `NOT field:x` is true for events without
  `field`.
- **Text comparisons.** On text fields `>`/`<` compare lower-cased strings,
  not numbers.
- **Text search coverage.** Text search skips numbers, times and meta
  fields.
- **`fields` on events.** It does not remove fields from events. It only
  sets the projection the application displays, and the backend still
  reads whole events.
- **Lower-case keywords.** `or`, `and`, `not` and `by` (outside `stats`)
  are plain words.

## 12. Cookbook

The `#` lines are captions for this listing. They are not query syntax.

```text
# Failed logons in the last day, by source address
event.code:4625 earliest=-24h | stats count by source.ip | sort -count | head 20

# SSH logins from outside the private ranges
process.name:sshd event.outcome:success NOT source.ip:(10.0.0.0/8 172.16.0.0/12 192.168.0.0/16)

# PowerShell with an encoded command, newest first
process.name:powershell.exe process.command_line:"*-enc*" | sort -@timestamp | head 50

# Anything under a Windows temp directory
file.path:"C:\Users\*\AppData\Local\Temp\*"

# High ports, excluding a range
destination.port>=1024 destination.port!=8000..8100

# Events per hour over a fixed window
earliest="2024-03-01 00:00:00" latest=2024-03-02 | stats count by bucket(@timestamp, 1h)

# Distinct users per host, keeping hosts with more than five
user.name:* | stats dc(user.name) as users, values(user.name) as names by host.name | where users>5

# Bytes sent per destination
network.bytes:* | stats sum(network.bytes) as bytes, avg(network.bytes) as mean by destination.ip | sort -bytes

# One row per user and source pair
event.code:4624 | dedup user.name source.ip | fields @timestamp, user.name, source.ip

# Free text, then narrow by a virtual field the application provides
mimikatz | where host.name@criticality:high
```
