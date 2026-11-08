# usiem-query

[![CI](https://github.com/u-siem/query/actions/workflows/ci.yml/badge.svg)](https://github.com/u-siem/query/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.89-blue)](Cargo.toml)

The search language, predicates and query executor over
[uSIEM](https://github.com/u-siem/usiem) events, kept in their own crate so
that every application built on uSIEM can share them.

```text
process.name:sshd source.ip:10.0.0.0/8 NOT user.name:root earliest=-24h
  | stats count, dc(source.ip) as sources by user.name
  | sort -count | head 20
```

## Using it

The crate is distributed from GitHub (it is not on crates.io yet). Pin a
release tag:

```toml
[dependencies]
usiem-query = { git = "https://github.com/u-siem/query", tag = "0.1.0" }
```

```rust
use usiem_query::query::{ExecOptions, NoVirtualFields, execute, parse};
use usiem_query::store::jsonl::JsonlStore;

let store = JsonlStore::open("events".as_ref())?;
let query = parse("user.name:bob | stats count by source.ip")?;
let result = execute(&store, &query, &NoVirtualFields, &ExecOptions::default())?;
println!("{} rows", result.len());
```

## What is in it

- `query`: the parser (`parse`), planner and executor (`execute`), and
  `StreamFilter` for evaluating a filter one event at a time (live tails,
  detection). The `VirtualFields` hook computes `field@attr` values at query
  time.
- `store`:
  - the `EventSource` trait (read side) and the `EventStore` trait (read and
    append);
  - `StoreQuery`, which a backend evaluates;
  - `Predicate`, the filter tree, with `Literal`, `Pattern`, `Cidr` and
    `Substrings`;
  - `FieldCatalog`, the fields a store has seen.
- `store::jsonl` (default feature `jsonl`): `JsonlStore`, a simple
  JSON-lines backend. It is also the oracle that other backends are tested
  against.
- `store::evstore` (feature `evstore`): `EvstoreSource`, the
  [usiem-evstore](https://github.com/u-siem/evstore) backend.
- `text`: value and time formatting for terminals.

The full syntax reference is in the `query` module docs and in `query::HELP`.

## Query text is untrusted input

The parser is written for text typed by people it does not trust: errors
carry a byte position, nesting of `(` and `NOT` is capped
(`query::MAX_NESTING`), and counts and durations saturate instead of
overflowing. The parser and the value parsers are fuzzed (see
[CONTRIBUTING.md](CONTRIBUTING.md)).

## Developing against a local uSIEM

`Cargo.toml` pins `usiem` to a commit on GitHub. To build against a sibling
checkout instead, override the source on the command line:

```sh
cargo test --config "patch.'https://github.com/u-siem/usiem'.usiem.path='../usiem'"
```

That rewrites `Cargo.lock`; do not commit the result.

## License

MIT, see [LICENSE](LICENSE).
