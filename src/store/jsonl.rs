//! Interim [`EventStore`](super::EventStore): JSON-lines segment files and full scans.
//!
//! ```text
//! store/meta.json        segment list (event count + min/max original_time) and field catalog
//! store/seg-000001.jsonl one serialized uSIEM event per line
//! ```
//!
//! Segments roll over every [`SEGMENT_EVENTS`] events. A search skips segments
//! whose time bounds miss the query's range and scans the rest line by line.
//! It is slow next to usiem-evstore, but simple and dependency-free, and it
//! doubles as the oracle that evstore results are checked against.

use super::{
    AppendAck, EventIter, EventSource, EventStore, FieldCatalog, Order, StoreError, StoreQuery,
};
use crate::Event;
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use usiem::event::Timestamp;

/// Events per segment file.
pub const SEGMENT_EVENTS: u64 = 200_000;

const META_FILE: &str = "meta.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SegmentMeta {
    file: String,
    events: u64,
    min_time: i64,
    max_time: i64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Meta {
    segments: Vec<SegmentMeta>,
    catalog: FieldCatalog,
}

pub struct JsonlStore {
    dir: PathBuf,
    meta: Meta,
    writer: Option<BufWriter<File>>,
}

impl JsonlStore {
    /// Opens (or initialises) the store in `dir`.
    pub fn open(dir: &Path) -> Result<JsonlStore, StoreError> {
        fs::create_dir_all(dir)?;
        let meta_path = dir.join(META_FILE);
        let meta = if meta_path.is_file() {
            serde_json::from_slice(&fs::read(&meta_path)?).map_err(|e| StoreError::Corrupt {
                location: meta_path.display().to_string(),
                reason: e.to_string(),
            })?
        } else {
            Meta::default()
        };
        Ok(JsonlStore {
            dir: dir.to_path_buf(),
            meta,
            writer: None,
        })
    }

    /// Counts the values of `fields` in the field catalog from now on (see
    /// [`FieldCatalog::inventory`]).
    pub fn with_inventory_fields(mut self, fields: &[&str]) -> JsonlStore {
        self.meta.catalog.inventory_fields = fields.iter().map(|f| f.to_string()).collect();
        self
    }

    fn write_meta(&self) -> Result<(), StoreError> {
        let tmp = self.dir.join("meta.json.tmp");
        let bytes =
            serde_json::to_vec(&self.meta).map_err(|e| StoreError::Encode(e.to_string()))?;
        fs::write(&tmp, bytes)?;
        fs::rename(tmp, self.dir.join(META_FILE))?;
        Ok(())
    }

    /// Returns the segment to append to, starting a new one when the last is full.
    fn current_segment(&mut self) -> Result<usize, StoreError> {
        let needs_new = self
            .meta
            .segments
            .last()
            .is_none_or(|s| s.events >= SEGMENT_EVENTS);
        if needs_new {
            if let Some(mut w) = self.writer.take() {
                w.flush()?;
            }
            let file = format!("seg-{:06}.jsonl", self.meta.segments.len() + 1);
            self.meta.segments.push(SegmentMeta {
                file,
                events: 0,
                min_time: i64::MAX,
                max_time: i64::MIN,
            });
        }
        let index = self.meta.segments.len() - 1;
        if self.writer.is_none() {
            let path = self.dir.join(&self.meta.segments[index].file);
            let file = OpenOptions::new().create(true).append(true).open(path)?;
            self.writer = Some(BufWriter::new(file));
        }
        Ok(index)
    }

    fn scan(&self, query: &StoreQuery) -> EventIter<'_> {
        let time = query.time;
        let filter = query.filter.clone();
        let segments: Vec<SegmentMeta> = self
            .meta
            .segments
            .iter()
            .filter(|s| {
                s.events > 0
                    && time.overlaps(
                        Timestamp::from_nanos(s.min_time),
                        Timestamp::from_nanos(s.max_time),
                    )
            })
            .cloned()
            .collect();
        let dir = self.dir.clone();
        Box::new(
            segments
                .into_iter()
                .flat_map(move |segment| SegmentReader::open(&dir, &segment))
                .filter(move |item| match item {
                    Ok(event) => time.contains(event.original_time()) && filter.matches(event),
                    Err(_) => true,
                }),
        )
    }
}

impl EventStore for JsonlStore {
    fn append(&mut self, batch: Vec<Event>) -> Result<AppendAck, StoreError> {
        let appended = batch.len();
        let mut line = Vec::with_capacity(1024);
        for event in &batch {
            let index = self.current_segment()?;
            line.clear();
            serde_json::to_writer(&mut line, event)
                .map_err(|e| StoreError::Encode(e.to_string()))?;
            line.push(b'\n');
            let writer = self
                .writer
                .as_mut()
                .expect("current_segment opens the writer");
            writer.write_all(&line)?;

            let t = event.original_time().as_nanos();
            let segment = &mut self.meta.segments[index];
            segment.events += 1;
            segment.min_time = segment.min_time.min(t);
            segment.max_time = segment.max_time.max(t);
            self.meta.catalog.observe(event);
        }
        if let Some(w) = self.writer.as_mut() {
            w.flush()?;
        }
        self.write_meta()?;
        Ok(AppendAck {
            appended,
            total: self.len(),
        })
    }

    fn seal(&mut self) -> Result<(), StoreError> {
        if let Some(mut w) = self.writer.take() {
            w.flush()?;
            w.get_ref().sync_all()?;
        }
        self.write_meta()
    }
}

impl EventSource for JsonlStore {
    fn search(&self, query: &StoreQuery) -> Result<EventIter<'_>, StoreError> {
        let matches = self.scan(query);
        let limit = query.limit.unwrap_or(usize::MAX);
        let descending = match query.order {
            Order::Storage => return Ok(Box::new(matches.take(limit))),
            Order::TimeAsc => false,
            Order::TimeDesc => true,
        };
        // Sorting needs every match in memory; a backend with time-sorted
        // segments (evstore) can merge instead.
        let mut events = matches.collect::<Result<Vec<_>, _>>()?;
        events.sort_by_key(|e| e.original_time());
        if descending {
            events.reverse();
        }
        events.truncate(limit);
        Ok(Box::new(events.into_iter().map(Ok)))
    }

    fn field_catalog(&self) -> &FieldCatalog {
        &self.meta.catalog
    }

    fn len(&self) -> u64 {
        self.meta.segments.iter().map(|s| s.events).sum()
    }
}

impl Drop for JsonlStore {
    fn drop(&mut self) {
        if let Some(w) = self.writer.as_mut() {
            let _ = w.flush();
        }
    }
}

/// Lazily reads one segment; an open error becomes the first item.
struct SegmentReader {
    name: String,
    lines: Option<std::io::Lines<BufReader<File>>>,
    line_no: usize,
    pending_error: Option<StoreError>,
}

impl SegmentReader {
    fn open(dir: &Path, segment: &SegmentMeta) -> SegmentReader {
        let (lines, pending_error) = match File::open(dir.join(&segment.file)) {
            Ok(f) => (Some(BufReader::new(f).lines()), None),
            Err(e) => (None, Some(StoreError::Io(e))),
        };
        SegmentReader {
            name: segment.file.clone(),
            lines,
            line_no: 0,
            pending_error,
        }
    }
}

impl Iterator for SegmentReader {
    type Item = Result<Event, StoreError>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(e) = self.pending_error.take() {
            return Some(Err(e));
        }
        loop {
            let line = match self.lines.as_mut()?.next()? {
                Ok(line) => line,
                Err(e) => return Some(Err(StoreError::Io(e))),
            };
            self.line_no += 1;
            if line.trim().is_empty() {
                continue;
            }
            return Some(
                serde_json::from_str(&line).map_err(|e| StoreError::Corrupt {
                    location: format!("{}:{}", self.name, self.line_no),
                    reason: e.to_string(),
                }),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{Predicate, TimeRange};
    use crate::test_util::TempDir;
    use usiem::event::{FieldValue, Origin, RawData};

    fn event(secs: i64, user: &'static str) -> Event {
        let mut e = Event::new(
            Timestamp::from_secs(1_000),
            Timestamp::from_secs(secs),
            Origin::File("Security.evtx".into()),
            RawData::from_text(format!("{secs} {user}")),
        );
        e.add_field("user.name".into(), FieldValue::from(user));
        e.add_field("event.code".into(), FieldValue::Int(4624));
        e
    }

    fn collect(store: &JsonlStore, q: &StoreQuery) -> Vec<(i64, String)> {
        store
            .search(q)
            .unwrap()
            .map(|e| {
                let e = e.unwrap();
                (
                    e.original_time().as_secs(),
                    e.get_field("user.name").unwrap().to_string(),
                )
            })
            .collect()
    }

    #[test]
    fn append_search_and_reopen() {
        let tmp = TempDir::new("jsonl");
        {
            let mut store = JsonlStore::open(tmp.path()).unwrap();
            let ack = store
                .append(vec![
                    event(30, "carol"),
                    event(10, "alice"),
                    event(20, "bob"),
                ])
                .unwrap();
            assert_eq!(
                ack,
                AppendAck {
                    appended: 3,
                    total: 3
                }
            );
            store.seal().unwrap();
        }
        let store = JsonlStore::open(tmp.path()).unwrap();
        assert_eq!(store.len(), 3);
        assert_eq!(store.field_catalog().fields["user.name"].count, 3);

        let all = collect(&store, &StoreQuery::default());
        assert_eq!(all.len(), 3);

        let q = StoreQuery {
            time: TimeRange {
                start: Some(Timestamp::from_secs(15)),
                end: None,
            },
            order: Order::TimeAsc,
            ..Default::default()
        };
        assert_eq!(
            collect(&store, &q),
            [(20, "bob".into()), (30, "carol".into())]
        );

        let q = StoreQuery {
            filter: Predicate::eq("user.name", "ALICE"),
            ..Default::default()
        };
        assert_eq!(collect(&store, &q), [(10, "alice".into())]);

        let q = StoreQuery {
            order: Order::TimeDesc,
            limit: Some(1),
            ..Default::default()
        };
        assert_eq!(collect(&store, &q), [(30, "carol".into())]);
    }

    #[test]
    fn appends_after_reopen_and_skips_segments_by_time() {
        let tmp = TempDir::new("jsonl-reopen");
        {
            let mut store = JsonlStore::open(tmp.path()).unwrap();
            store.append(vec![event(10, "alice")]).unwrap();
        }
        let mut store = JsonlStore::open(tmp.path()).unwrap();
        store.append(vec![event(20, "bob")]).unwrap();
        assert_eq!(store.len(), 2);
        assert_eq!(collect(&store, &StoreQuery::default()).len(), 2);

        // A range entirely outside the segment's bounds reads nothing.
        let q = StoreQuery {
            time: TimeRange {
                start: Some(Timestamp::from_secs(100)),
                end: None,
            },
            ..Default::default()
        };
        assert!(collect(&store, &q).is_empty());
    }

    #[test]
    fn reports_corrupt_lines() {
        let tmp = TempDir::new("jsonl-corrupt");
        let mut store = JsonlStore::open(tmp.path()).unwrap();
        store.append(vec![event(10, "alice")]).unwrap();
        store.seal().unwrap();
        let seg = tmp.path().join("seg-000001.jsonl");
        let mut f = OpenOptions::new().append(true).open(seg).unwrap();
        writeln!(f, "{{not json").unwrap();
        drop(f);
        let results: Vec<_> = store.search(&StoreQuery::default()).unwrap().collect();
        assert!(results[0].is_ok());
        assert!(
            matches!(&results[1], Err(StoreError::Corrupt { location, .. }) if location == "seg-000001.jsonl:2")
        );
    }
}
