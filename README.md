# usiem-query

The search language, predicates and query executor over [uSIEM](../usiem) events, kept in their own crate so that every application built on uSIEM can share them.

```text
process.name:sshd source.ip:10.0.0.0/8 NOT user.name:root earliest=-24h
  | stats count, dc(source.ip) as sources by user.name
  | sort -count | head 20
```

- `query`: parser (`parse`), planner and executor (`execute`). The `VirtualFields` hook computes `field@attr` values at query time.
- `store`:
  - the `EventSource` trait (read side) and the `EventStore` trait (read and append);
  - `StoreQuery`, which a backend evaluates;
  - `Predicate`;
  - `FieldCatalog`.
- `store::jsonl` (default feature `jsonl`): `JsonlStore`, the interim JSON-lines backend. It is also the oracle that other backends are tested against.
- `text`: value and time formatting for terminals.

The full syntax reference is in `src/query/mod.rs` and in `query::HELP`.
