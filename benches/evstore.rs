//! End-to-end query benchmarks over the evstore backend (std only,
//! `harness = false`): parse, plan, push down, decode and execute.
//!
//! `cargo bench --features evstore --bench evstore` prints the median time
//! of each query as a Markdown table.
//!
//! Environment: `QUERY_BENCH_SEGMENTS` (default 10), `QUERY_BENCH_ROWS`
//! events per segment (default 20,000), `QUERY_BENCH_RUNS` (default 5).

#![allow(
    missing_docs,
    clippy::cast_possible_wrap,
    clippy::cast_possible_truncation,
    clippy::print_stdout
)]

use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use usiem::event::field::Text;
use usiem::event::{FieldValue, Ip, Origin, RawData, Timestamp};
use usiem_query::Event;
use usiem_query::query::exec::{ExecOptions, NoVirtualFields, ResultRows, execute};
use usiem_query::query::parser::parse;
use usiem_query::store::EventStore;
use usiem_query::store::evstore::{EvstoreSource, Options, SyncPolicy};

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
}

fn env(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

const CODES: [i64; 8] = [4624, 4625, 4634, 4648, 4672, 4688, 4720, 5156];

fn event(rng: &mut Rng, ts: i64) -> Event {
    let host = format!("WEB{:02}", rng.below(50));
    let user = if rng.below(50) == 0 {
        "Admin".to_string()
    } else {
        format!("user{}", rng.below(200))
    };
    let ip = Ipv4Addr::new(10, 0, rng.below(256) as u8, rng.below(256) as u8);
    let port = rng.below(65_536);
    let raw = format!(
        "Failed password for {user} from {ip} port {port} ssh2 session={:016X}",
        rng.next()
    );
    let origin = Origin::Hostname(format!("collector{}", rng.below(4)));
    let mut e = Event::new(
        Timestamp(ts + 1_000_000),
        Timestamp(ts),
        origin,
        RawData::from_text(raw),
    );
    let s = |v: &str| FieldValue::Str(Text::from(v));
    e.add_field("host".into(), s(&host));
    e.add_field("user.name".into(), s(&user));
    e.add_field("source.ip".into(), FieldValue::Ip(Ip::from(IpAddr::V4(ip))));
    e.add_field("source.port".into(), FieldValue::Uint(port));
    e.add_field(
        "event.code".into(),
        FieldValue::Int(CODES[rng.below(CODES.len() as u64) as usize]),
    );
    e
}

fn median(mut samples: Vec<Duration>) -> Duration {
    samples.sort_unstable();
    samples[samples.len() / 2]
}

fn main() {
    let segments = env("QUERY_BENCH_SEGMENTS", 10);
    let rows = env("QUERY_BENCH_ROWS", 20_000);
    let runs = env("QUERY_BENCH_RUNS", 5);

    let dir = std::env::temp_dir().join(format!("usiem-query-bench-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let opts = Options {
        sync: SyncPolicy::Interval(Duration::from_secs(3600)),
        flush_bytes: usize::MAX,
        ..Options::default()
    };
    let mut store = EvstoreSource::open_with(&dir, opts).expect("open store");
    let mut rng = Rng(0x0e2e);
    let mut ts = 1_700_000_000_000_000_000i64;
    let build = Instant::now();
    for _ in 0..segments {
        let batch: Vec<Event> = (0..rows)
            .map(|_| {
                ts += 1_000_000 + rng.below(1_000_000) as i64;
                event(&mut rng, ts)
            })
            .collect();
        store.append(batch).expect("append");
        store.seal().expect("seal");
    }
    eprintln!(
        "built {segments} segments x {rows} events in {:.1?}",
        build.elapsed()
    );

    let queries = [
        "host:web07",
        "host:web07 | head 100",
        "host:web07 | tail 100",
        "admin",
        "443",
        "user.name:*adm*",
        "source.ip:10.0.7.0/24",
        "host:web07 NOT user.name:admin",
        "NOT host:web07 | head 100",
        "host:web07 | sort -event.code | head 10",
        "host:web07 | stats count by user.name",
        "event.code:* | stats count by event.code",
        "admin | stats count by host",
    ];
    let options = ExecOptions {
        max_rows: 1_000_000,
        ..ExecOptions::default()
    };
    println!("| query | median | rows |");
    println!("|---|---:|---:|");
    for text in queries {
        let query = parse(text).expect("query parses");
        let run = || {
            let result = execute(&store, &query, &NoVirtualFields, &options).expect("execute");
            match &result.rows {
                ResultRows::Events(e) => e.len(),
                ResultRows::Table { rows, .. } => rows.len(),
            }
        };
        let mut n = run(); // warm-up
        let mut samples = Vec::with_capacity(runs);
        for _ in 0..runs {
            let t = Instant::now();
            n = black_box(run());
            samples.push(t.elapsed());
        }
        println!("| `{text}` | {:.2?} | {n} |", median(samples));
    }

    drop(store);
    let _ = std::fs::remove_dir_all(&dir);
}
