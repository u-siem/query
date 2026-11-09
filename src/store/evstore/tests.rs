//! Differential tests: `EvstoreSource` must return exactly what
//! `JsonlStore` returns, and give events back unchanged.

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    reason = "test data is generated from small counters"
)]

use super::*;
use crate::store::jsonl::JsonlStore;
use crate::store::{Pattern, Substrings, TimeRange};
use crate::test_util::TempDir;
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use usiem::event::JsonValue;

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    fn chance(&mut self, pct: u64) -> bool {
        self.below(100) < pct
    }
    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len() as u64) as usize]
    }
}

const T0: i64 = 1_700_000_000_000_000_000;
const SPAN: i64 = 1_000_000_000_000; // ~16 minutes in ns
const HOSTS: [&str; 6] = ["web01", "WEB02", "db01", "Nas", "Ärger", "fw-edge"];
const WORDS: [&str; 6] = ["login", "Logout", "failed", "sshd", "accepted", "drop"];

fn str_value(s: &str) -> FieldValue {
    FieldValue::Str(Text::from(s))
}

fn ip_value(rng: &mut Rng) -> FieldValue {
    if rng.chance(85) {
        let v4 = Ipv4Addr::new(
            10,
            rng.below(3) as u8,
            rng.below(4) as u8,
            rng.below(256) as u8,
        );
        FieldValue::Ip(Ip::from(IpAddr::V4(v4)))
    } else {
        let v6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, rng.below(16) as u16);
        FieldValue::Ip(Ip::from(IpAddr::V6(v6)))
    }
}

fn scalar_value(rng: &mut Rng) -> FieldValue {
    match rng.below(7) {
        0 => str_value(rng.pick::<&str>(&HOSTS)),
        1 => FieldValue::Int(rng.below(600) as i64 - 100),
        2 => FieldValue::Uint(rng.below(600)),
        3 => FieldValue::Float(*rng.pick(&[0.0, -0.0, 1.5, 443.0, -2.25])),
        4 => FieldValue::Bool(rng.chance(50)),
        5 => FieldValue::Time(Timestamp(T0 + rng.below(SPAN as u64) as i64)),
        _ => ip_value(rng),
    }
}

fn object(rng: &mut Rng, depth: u32) -> FieldValue {
    let mut map = HashMap::new();
    if rng.chance(80) {
        map.insert(
            Text::from("name"),
            str_value(rng.pick::<&str>(&["root", "Alice", "bob", "svc"])),
        );
    }
    if rng.chance(50) {
        map.insert(
            Text::from("id"),
            FieldValue::Int(rng.below(5) as i64 + 1000),
        );
    }
    if rng.chance(30) {
        map.insert(Text::from("groups"), array(rng, depth));
    }
    if depth > 0 && rng.chance(30) {
        map.insert(Text::from("sub"), object(rng, depth - 1));
    }
    FieldValue::Object(map)
}

fn array(rng: &mut Rng, depth: u32) -> FieldValue {
    let n = rng.below(4) as usize;
    FieldValue::Array(match rng.below(4) {
        0 => (0..n)
            .map(|_| str_value(rng.pick::<&str>(&WORDS)))
            .collect(),
        1 => (0..n)
            .map(|_| FieldValue::Int(rng.below(10) as i64))
            .collect(),
        2 => (0..n).map(|_| scalar_value(rng)).collect(),
        _ if depth > 0 => (0..n).map(|_| object(rng, depth - 1)).collect(),
        _ => Vec::new(),
    })
}

fn random_event(rng: &mut Rng, n: u64) -> Event {
    let origin = match rng.below(4) {
        0 => Origin::Hostname((*rng.pick(&HOSTS)).into()),
        1 => Origin::from(IpAddr::V4(Ipv4Addr::new(192, 168, 1, rng.below(4) as u8))),
        2 => Origin::File("/var/log/auth.log".into()),
        _ => Origin::Container {
            id: format!("c{}", rng.below(3)),
            name: rng.chance(50).then(|| "nginx".into()),
            image: None,
        },
    };
    let raw = if rng.chance(80) {
        RawData::from_text(format!("raw {n} {}", rng.pick(&WORDS)))
    } else {
        RawData::Json(JsonValue::object([
            ("n", JsonValue::number(n as f64)),
            ("w", JsonValue::string(*rng.pick(&WORDS))),
        ]))
    };
    let original = T0 + rng.below(SPAN as u64) as i64;
    let arrival = original + rng.below(5_000_000_000) as i64;
    let mut e = Event::new(Timestamp(arrival), Timestamp(original), origin, raw);
    let mut add = |name: &str, v: FieldValue| e.add_field(name.to_string(), v);
    if rng.chance(90) {
        add("host", str_value(rng.pick::<&str>(&HOSTS)));
    }
    if rng.chance(70) {
        let ip = if rng.chance(15) {
            str_value(&format!("10.0.0.{}", rng.below(8)))
        } else {
            ip_value(rng)
        };
        add("source.ip", ip);
    }
    if rng.chance(70) {
        add(
            "port",
            match rng.below(3) {
                0 => FieldValue::Int(rng.below(70_000) as i64),
                1 => FieldValue::Uint(rng.below(70_000)),
                _ => str_value(&format!("{}", rng.below(1000))),
            },
        );
    }
    if rng.chance(40) {
        add(
            "score",
            FieldValue::Float(*rng.pick(&[0.0, -0.0, 1.5, 99.9, -3.0])),
        );
    }
    if rng.chance(40) {
        add("ok", FieldValue::Bool(rng.chance(50)));
    }
    if rng.chance(60) {
        add("code", FieldValue::Int(rng.below(400) as i64 - 50));
    }
    if rng.chance(50) {
        add("bytes", FieldValue::Uint(rng.below(1 << 20)));
    }
    if rng.chance(30) {
        add(
            "when",
            FieldValue::Time(Timestamp(T0 + rng.below(SPAN as u64) as i64)),
        );
    }
    match rng.below(4) {
        0 => add("user", object(rng, 2)),
        1 => add("user.name", str_value(rng.pick::<&str>(&["root", "Alice"]))),
        2 => {
            add("user", object(rng, 1));
            add("user.name", str_value("flat-wins"));
        }
        _ => {}
    }
    if rng.chance(50) {
        add("tags", array(rng, 1));
    }
    if rng.chance(80) {
        let msg = format!(
            "{} from {} port {}",
            rng.pick(&WORDS),
            rng.pick(&HOSTS),
            rng.below(100)
        );
        add("message", str_value(&msg));
    }
    if rng.chance(10) {
        add("blob", FieldValue::Bytes(vec![rng.below(3) as u8; 2]));
    }
    if rng.chance(10) {
        add("empty", FieldValue::Object(HashMap::new()));
    }
    if rng.chance(5) {
        add("@weird", str_value("at-sign field"));
    }
    e
}

const PATHS: [&str; 18] = [
    "host",
    "source.ip",
    "source",
    "port",
    "score",
    "ok",
    "when",
    "user",
    "user.name",
    "user.id",
    "user.groups",
    "user.sub.name",
    "tags",
    "message",
    "blob",
    "empty",
    "missing",
    "@arrival",
];
const TOKENS: [&str; 22] = [
    "web01",
    "WEB01",
    "ärger",
    "443",
    "-0",
    "0",
    "1.5",
    "1000",
    "true",
    "false",
    "10.0.0.5",
    "10.1.2.3",
    "2001:db8::3",
    "2023-11-14",
    "2023-11-14 22:20:00",
    "root",
    "ALICE",
    "login",
    "flat-wins",
    "nas",
    "99.9",
    "-50",
];
const GLOBS: [&str; 8] = ["web*", "*0*", "?ar*", "*", "10.*", "1*", "*in", "true"];
const CIDRS: [&str; 5] = [
    "10.0.0.0/8",
    "10.1.0.0/16",
    "10.0.0.0/30",
    "2001:db8::/120",
    "0.0.0.0/0",
];
const TERMS: [&str; 6] = ["web", "10.0", "LOGIN", "root", "a", "db8"];

fn literal(rng: &mut Rng) -> Literal {
    Literal::new(rng.pick::<&str>(&TOKENS))
}

fn random_op(rng: &mut Rng) -> FieldOp {
    match rng.below(7) {
        0 => FieldOp::Exists,
        1 => FieldOp::Eq(literal(rng)),
        2 => FieldOp::In(vec![literal(rng), literal(rng)]),
        3 => FieldOp::Wildcard(Pattern::new(rng.pick::<&str>(&GLOBS))),
        4 => FieldOp::Range {
            lower: rng.chance(70).then(|| (literal(rng), rng.chance(50))),
            upper: rng.chance(70).then(|| (literal(rng), rng.chance(50))),
        },
        5 => FieldOp::Cidr(Cidr::parse(rng.pick::<&str>(&CIDRS)).unwrap()),
        _ => FieldOp::ContainsAny(Substrings::new([*rng.pick(&TERMS), *rng.pick(&TERMS)]).unwrap()),
    }
}

fn random_predicate(rng: &mut Rng, depth: u32) -> Predicate {
    if depth == 0 || rng.chance(45) {
        return match rng.below(10) {
            0 => Predicate::Text((*rng.pick(&TERMS)).into()),
            1 => {
                let t = Literal::new(&format!("{}", T0 + rng.below(SPAN as u64) as i64));
                // Times as literals: use RFC 3339 so `Literal::time` parses.
                let _ = t;
                let secs = (T0 + rng.below(SPAN as u64) as i64) / 1_000_000_000;
                let text = Timestamp::from_secs(secs).to_rfc3339();
                Predicate::field(
                    "@timestamp",
                    FieldOp::Range {
                        lower: Some((Literal::new(&text), rng.chance(50))),
                        upper: None,
                    },
                )
            }
            _ => Predicate::field(*rng.pick(&PATHS), random_op(rng)),
        };
    }
    match rng.below(3) {
        0 => Predicate::And(
            (0..=rng.below(3))
                .map(|_| random_predicate(rng, depth - 1))
                .collect(),
        ),
        1 => Predicate::Or(
            (0..=rng.below(3))
                .map(|_| random_predicate(rng, depth - 1))
                .collect(),
        ),
        _ => Predicate::Not(Box::new(random_predicate(rng, depth - 1))),
    }
}

fn small_opts() -> Options {
    Options {
        flush_bytes: 64 << 10,
        chunk_rows: 64,
        compaction_fanout: 2,
        ..Options::default()
    }
}

fn run_queries(
    rng: &mut Rng,
    jsonl: &JsonlStore,
    evs: &EvstoreSource,
    originals: &HashMap<u64, Event>,
    n: usize,
) {
    for i in 0..n {
        let filter = random_predicate(rng, 3);
        let time = if rng.chance(50) {
            TimeRange::default()
        } else {
            let a = T0 + rng.below(SPAN as u64) as i64;
            TimeRange {
                start: rng.chance(80).then_some(Timestamp(a)),
                end: Some(Timestamp(a + rng.below(SPAN as u64 / 2) as i64)),
            }
        };
        let order = *rng.pick(&[Order::Storage, Order::TimeAsc, Order::TimeDesc]);
        let limit = rng.chance(25).then(|| rng.below(20) as usize);
        let q = StoreQuery {
            time,
            filter,
            order,
            limit,
        };
        let want: Vec<Event> = jsonl.search(&q).unwrap().map(Result::unwrap).collect();
        let got: Vec<Event> = evs.search(&q).unwrap().map(Result::unwrap).collect();
        let ctx = || format!("query {i}: {q:?}");
        assert_eq!(got.len(), want.len(), "{}", ctx());
        for e in &got {
            let id = e.id().as_u64();
            assert_eq!(
                Some(e),
                originals.get(&id),
                "{}: event changed in storage",
                ctx()
            );
        }
        match (order, limit) {
            (Order::Storage, Some(_)) => {}
            (Order::Storage, None) => {
                let mut a: Vec<u64> = got.iter().map(|e| e.id().as_u64()).collect();
                let mut b: Vec<u64> = want.iter().map(|e| e.id().as_u64()).collect();
                a.sort_unstable();
                b.sort_unstable();
                assert_eq!(a, b, "{}", ctx());
            }
            _ => {
                let times = |v: &[Event]| v.iter().map(|e| e.original_time().0).collect::<Vec<_>>();
                assert_eq!(times(&got), times(&want), "{}", ctx());
                if limit.is_none() {
                    let mut a: Vec<u64> = got.iter().map(|e| e.id().as_u64()).collect();
                    let mut b: Vec<u64> = want.iter().map(|e| e.id().as_u64()).collect();
                    a.sort_unstable();
                    b.sort_unstable();
                    assert_eq!(a, b, "{}", ctx());
                }
            }
        }
    }
}

const STATS_FILTERS: [&str; 16] = [
    "*",
    "host:web01",
    "host:WEB02 ok:true",
    "code:>100",
    "code:50..300",
    "ok:false OR code:<0",
    "NOT host:db01",
    "message:*login*",
    "bytes:*",
    "source.ip:10.0.0.0/8",
    "port:443",
    "earliest=2023-11-14T22:20:00Z",
    "@timestamp>=2023-11-14T22:25:00Z code:*",
    "login",
    "user.name:root",
    "host:(nas OR fw-edge) code!=7",
];
const STATS_AGGS: [&str; 11] = [
    "count",
    "count(code)",
    "sum(bytes)",
    "avg(code)",
    "min(code)",
    "max(bytes)",
    "max(when)",
    "min(ok)",
    "sum(port)",
    "dc(host)",
    "count(user.name)",
];
const STATS_BY: [&str; 9] = [
    "",
    " by host",
    " by ok",
    " by code",
    " by host, ok",
    " by bucket(@timestamp,1m)",
    " by host, bucket(@timestamp,5m)",
    " by user.name",
    " by when",
];

/// Runs random `stats` pipelines through the executor on both stores and
/// returns how many evstore answered by aggregation.
///
/// Group fields whose values of different types share a display form
/// (`port` holds `5` and `"5"`) and float extremes (`-0.0` vs `0.0`) are
/// left out: the executor shows the first value it meets for those, so even
/// two streaming runs over different storage orders disagree.
fn run_stats(rng: &mut Rng, jsonl: &JsonlStore, evs: &EvstoreSource, n: usize) -> u64 {
    use crate::query::{ExecOptions, NoVirtualFields, ResultRows, execute, parse};
    let before = evs.pushdowns();
    for i in 0..n {
        let aggs: Vec<&str> = (0..=rng.below(3)).map(|_| *rng.pick(&STATS_AGGS)).collect();
        let mut text = format!(
            "{} | stats {}{}",
            rng.pick(&STATS_FILTERS),
            aggs.join(", "),
            rng.pick(&STATS_BY)
        );
        if rng.chance(30) {
            text.push_str(" | sort -count | head 5");
        }
        let query = parse(&text).unwrap_or_else(|e| panic!("{text}: {e:?}"));
        let opts = ExecOptions::default();
        let want = execute(jsonl, &query, &NoVirtualFields, &opts).unwrap();
        let got = execute(evs, &query, &NoVirtualFields, &opts).unwrap();
        let table = |r: ResultRows| match r {
            ResultRows::Table { columns, rows } => (columns, rows),
            ResultRows::Events(_) => panic!("stats gives a table"),
        };
        assert_eq!(table(got.rows), table(want.rows), "stats query {i}: {text}");
    }
    evs.pushdowns() - before
}

#[test]
fn round_trip_is_lossless() {
    let mut rng = Rng(42);
    for n in 0..2000 {
        let e = random_event(&mut rng, n);
        let back = decode(encode(&e).unwrap()).unwrap();
        assert_eq!(back, e);
        assert_eq!(back.id(), e.id());
    }
}

#[test]
fn candidate_names() {
    assert_eq!(candidates("host"), vec!["host"]);
    assert_eq!(
        candidates("a.b.c"),
        vec![
            "a.b.c".to_string(),
            "a\u{1f}b\u{1f}c".into(),
            "a.b\u{1f}c".into()
        ]
    );
}

#[test]
fn differential_against_jsonl() {
    let jdir = TempDir::new("diff-jsonl");
    let edir = TempDir::new("diff-evstore");
    let mut jsonl = JsonlStore::open(jdir.path()).unwrap();
    let mut evs = EvstoreSource::open_with(edir.path(), small_opts()).unwrap();
    let mut rng = Rng(0xd1ff);
    let mut originals = HashMap::new();
    for batch in 0..12u64 {
        let events: Vec<Event> = (0..250)
            .map(|i| random_event(&mut rng, batch * 1000 + i))
            .collect();
        for e in &events {
            originals.insert(e.id().as_u64(), e.clone());
        }
        jsonl.append(events.clone()).unwrap();
        evs.append(events).unwrap();
    }
    // A small tail that stays in the WAL buffer.
    let tail: Vec<Event> = (0..10)
        .map(|i| random_event(&mut rng, 99_000 + i))
        .collect();
    for e in &tail {
        originals.insert(e.id().as_u64(), e.clone());
    }
    jsonl.append(tail.clone()).unwrap();
    evs.append(tail).unwrap();
    assert_eq!(originals.len(), 3010, "event ids must be unique");
    assert!(
        evs.store().stats().segments >= 2,
        "{:?}",
        evs.store().stats()
    );
    assert!(evs.store().stats().buffered_rows > 0);
    assert_eq!(evs.len(), jsonl.len());
    assert_eq!(evs.field_catalog().fields, jsonl.field_catalog().fields);
    run_queries(&mut rng, &jsonl, &evs, &originals, 250);
    let pushed = run_stats(&mut rng, &jsonl, &evs, 120);
    assert!(
        pushed > 25,
        "only {pushed} of 120 stats queries were pushed down"
    );

    // Compaction, flush and reopen change nothing.
    let report = evs.maintain(Timestamp(T0)).unwrap();
    assert!(report.compactions > 0, "{report:?}");
    evs.seal().unwrap();
    jsonl.seal().unwrap();
    drop(evs);
    let evs = EvstoreSource::open_with(edir.path(), small_opts()).unwrap();
    assert!(
        !evs.catalog_rebuilt,
        "catalog should load from app metadata"
    );
    assert_eq!(evs.field_catalog().fields, jsonl.field_catalog().fields);
    run_queries(&mut rng, &jsonl, &evs, &originals, 100);
    assert!(run_stats(&mut rng, &jsonl, &evs, 60) > 12);
}

#[test]
fn differential_with_full_field_registry() {
    // Past the field cap, names land in the overflow field and the adapter
    // can no longer prove translations exact or rule out IP fields.
    let jdir = TempDir::new("diff-full-jsonl");
    let edir = TempDir::new("diff-full-evstore");
    let mut jsonl = JsonlStore::open(jdir.path()).unwrap();
    let opts = Options {
        max_fields: 8,
        ..small_opts()
    };
    let mut evs = EvstoreSource::open_with(edir.path(), opts).unwrap();
    let mut rng = Rng(0xf011);
    let mut originals = HashMap::new();
    for batch in 0..4u64 {
        let events: Vec<Event> = (0..200)
            .map(|i| random_event(&mut rng, batch * 1000 + i))
            .collect();
        for e in &events {
            originals.insert(e.id().as_u64(), e.clone());
        }
        jsonl.append(events.clone()).unwrap();
        evs.append(events).unwrap();
    }
    assert!(evs.store().fields().is_full());
    run_queries(&mut rng, &jsonl, &evs, &originals, 150);
}

#[test]
fn sync_makes_appends_durable() {
    let dir = TempDir::new("sync");
    let mut rng = Rng(11);
    {
        let mut evs = EvstoreSource::open(dir.path()).unwrap();
        let ack = evs
            .append((0..20).map(|i| random_event(&mut rng, i)).collect())
            .unwrap();
        assert_eq!(ack.appended, 20);
        evs.sync().unwrap();
        // Nothing pending: a second sync is a no-op.
        evs.sync().unwrap();
        // Dropped without seal or maintain: only the synced WAL remains.
    }
    let evs = EvstoreSource::open(dir.path()).unwrap();
    assert_eq!(evs.len(), 20);
}

#[test]
fn catalog_rebuilds_after_unflushed_appends() {
    let dir = TempDir::new("diff-catalog");
    let mut rng = Rng(7);
    let mut reference = FieldCatalog::with_inventory(&["host"]);
    {
        let mut evs = EvstoreSource::open(dir.path())
            .unwrap()
            .with_inventory_fields(&["host"])
            .unwrap();
        let events: Vec<Event> = (0..50).map(|i| random_event(&mut rng, i)).collect();
        for e in &events {
            reference.observe(e);
        }
        evs.append(events).unwrap();
        // Dropped without seal: the catalog was never saved.
    }
    let evs = EvstoreSource::open(dir.path())
        .unwrap()
        .with_inventory_fields(&["host"])
        .unwrap();
    assert!(evs.catalog_rebuilt);
    assert_eq!(evs.field_catalog().fields, reference.fields);
    assert_eq!(evs.field_catalog().values, reference.values);
}

#[test]
fn ip_mapping() {
    for text in [
        "10.1.2.3",
        "::1",
        "2001:db8::7",
        "255.255.255.255",
        "0.0.0.0",
    ] {
        let ip = Ip::from_str(text).unwrap();
        assert_eq!(u128_to_ip(ip_to_u128(&ip)), ip, "{text}");
    }
    let c = Cidr::parse("10.1.0.0/16").unwrap();
    let (lo, hi) = cidr_range(&c);
    assert_eq!(lo, ip_to_u128(&Ip::from_str("10.1.0.0").unwrap()));
    assert_eq!(hi, ip_to_u128(&Ip::from_str("10.1.255.255").unwrap()));
    let all = Cidr::parse("0.0.0.0/0").unwrap();
    let (lo, hi) = cidr_range(&all);
    assert!(lo <= ip_to_u128(&Ip::from_str("1.2.3.4").unwrap()));
    assert!(hi >= ip_to_u128(&Ip::from_str("255.0.0.1").unwrap()));
}
