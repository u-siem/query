# Contributing

Thanks for helping. Issues and pull requests are welcome.

## Before you open a pull request

CI runs all of these; running them first saves a round trip.

```sh
cargo fmt --all --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --no-default-features
cargo test --locked                      # default features (jsonl)
cargo test --locked --all-features
cargo deny check                         # https://github.com/EmbarkStudios/cargo-deny
```

The minimum supported Rust version is 1.89. CI tests it, along with Linux,
Windows and macOS.

## Local uSIEM and evstore checkouts

`usiem` and `usiem-evstore` are git dependencies pinned to commits. To try a
change in a sibling `../usiem` or `../usiem-evstore` checkout, override it for
one command:

```sh
cargo test --config "patch.'https://github.com/u-siem/usiem'.usiem.path='../usiem'"
cargo test --all-features \
  --config "patch.'https://github.com/u-siem/evstore'.usiem-evstore.path='../usiem-evstore'"
```

The override rewrites `Cargo.lock`. Never commit that lockfile: restore it
with `git checkout Cargo.lock`, and bump the pinned `rev` in `Cargo.toml` in
its own commit once the upstream change is on GitHub.

## Behaviour changes

Applications store queries that people wrote, so a change in what a query
means (what it matches, how `stats` groups, how `sort` orders) is a breaking
change even when no Rust signature changes. Say so in the pull request, and
add an entry under `Unreleased` in `CHANGELOG.md`.

`JsonlStore` is the reference: other backends must return exactly what it
returns for the same query, and their tests check that.

## Fuzzing

Query text comes from users, so the parser and the value parsers are fuzzed
with [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) (nightly):

```sh
cargo +nightly fuzz run query_parse
cargo +nightly fuzz run literals
```

CI runs each target daily and on pull requests that touch the query or
predicate code. A crash found by fuzzing belongs in a regular test once
fixed.

## Releases

Maintainers release by bumping `version` in `Cargo.toml`, moving the
`Unreleased` changelog entries under the new version, and pushing a tag that
is exactly the version, with no prefix: `git tag 0.2.0 && git push origin 0.2.0`.
The release workflow checks the tag, runs CI and creates the GitHub release
from the changelog. The crate is not published to crates.io.
