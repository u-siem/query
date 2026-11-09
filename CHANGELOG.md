# Changelog

All notable changes to this crate are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/). Release tags are the bare version,
with no prefix (`0.1.0`).

## [Unreleased]

### Changed

- `EvstoreSource::search`:
  - pushes `NOT` down when its operand translates exactly;
  - pushes bare terms that could be IP text (`443`, `10.0`, `db8`) as
    "contains in a string field, or has an IP field" instead of scanning
    every event;
  - skips the per-event re-check when the whole filter translates exactly;
  - parses each distinct `@origin` once per search.
- `benches/evstore.rs`: end-to-end benchmarks over the evstore backend
  (`cargo bench --features evstore`).
- `tail n` over a time-ordered result reads it newest-first and stops after
  `n` events (the store gets the limit when no virtual-field filter
  remains), instead of streaming everything.
- `sort … | head n` (n ≤ 10,000) keeps only the best `n` events in a
  bounded buffer, with the same result as a stable sort. It no longer
  fails with `TooManyEvents` when the stream exceeds `max_materialized`.
- `EvstoreSource` decodes plain top-level fields without building an
  object tree (about 20% less time per event in a raw search).


## [0.1.0]

First public release.

### Added

- The search language: field terms (equality, globs, CIDR, ranges,
  comparisons, value lists), bare text terms, `AND`/`OR`/`NOT`, and the
  `earliest=`/`latest=` time range, with `| where`, `fields`, `sort`,
  `head`, `tail`, `dedup` and `stats` (with `bucket()` group keys).
- `query::parse`, the planner and `query::execute`, over any
  `store::EventSource`, with virtual fields computed at query time.
- `query::StreamFilter`: a filter and `| where` stages evaluated per event.
- `store::Predicate` and its building blocks (`Literal`, `Pattern`, `Cidr`,
  `Substrings`), usable without the parser.
- Feature `jsonl` (default): `store::jsonl::JsonlStore`.
- Feature `evstore`: `store::evstore::EvstoreSource`, the usiem-evstore
  backend.

### Security

- Query nesting is capped at `query::MAX_NESTING` levels of `(` and `NOT`.

[Unreleased]: https://github.com/u-siem/query/compare/0.1.0...HEAD
[0.1.0]: https://github.com/u-siem/query/releases/tag/0.1.0
