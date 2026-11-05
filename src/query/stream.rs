//! Queries evaluated one event at a time, as events stream past (live tail,
//! detection rules).

use super::{Command, is_virtual_field, parse};
use crate::Event;
use crate::store::{Predicate, TimeRange};
use std::fmt;

/// The part of a query that can judge one event on its own: the filter and
/// any `| where` stages. Commands that need the whole result (`stats`,
/// `sort`, `head`, ...) are rejected.
#[derive(Debug, Clone, PartialEq)]
pub struct StreamFilter {
    filter: Predicate,
    time: TimeRange,
    wheres: Vec<Predicate>,
}

/// Why a query can't be a [`StreamFilter`].
#[derive(Debug, Clone, PartialEq)]
pub enum StreamFilterError {
    /// The query does not parse.
    Parse(String),
    /// It uses a command other than `where`.
    NotStreamable,
}

impl fmt::Display for StreamFilterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StreamFilterError::Parse(e) => f.write_str(e),
            StreamFilterError::NotStreamable => {
                f.write_str("only a filter and | where can be evaluated per event")
            }
        }
    }
}

impl std::error::Error for StreamFilterError {}

impl StreamFilter {
    pub fn parse(text: &str) -> Result<StreamFilter, StreamFilterError> {
        let query = parse(text).map_err(|e| StreamFilterError::Parse(e.to_string()))?;
        let mut wheres = Vec::new();
        for command in query.commands {
            match command {
                Command::Where(predicate) => wheres.push(predicate),
                _ => return Err(StreamFilterError::NotStreamable),
            }
        }
        Ok(StreamFilter {
            filter: query.filter,
            time: query.time,
            wheres,
        })
    }

    /// A filter built in code rather than parsed (e.g. compiled from a
    /// Sigma rule): no time range, no `| where` stages.
    pub fn from_predicate(filter: Predicate) -> StreamFilter {
        StreamFilter {
            filter,
            time: TimeRange::default(),
            wheres: Vec::new(),
        }
    }

    /// The main filter (without `| where` stages).
    pub fn predicate(&self) -> &Predicate {
        &self.filter
    }

    /// Matches everything.
    pub fn all() -> StreamFilter {
        StreamFilter {
            filter: Predicate::True,
            time: TimeRange::default(),
            wheres: Vec::new(),
        }
    }

    /// Every field the filter reads, in order of appearance (with repeats).
    pub fn fields(&self) -> Vec<&str> {
        let mut out = Vec::new();
        self.filter.visit_fields(&mut |f| out.push(f));
        for w in &self.wheres {
            w.visit_fields(&mut |f| out.push(f));
        }
        out
    }

    /// The first virtual field (`base@attr`) used, if any. Those need a
    /// [`VirtualFields`](super::VirtualFields) hook, which per-event
    /// evaluation does not have.
    pub fn virtual_field(&self) -> Option<&str> {
        self.fields().into_iter().find(|f| is_virtual_field(f))
    }

    /// Plain [`Predicate::matches`]: virtual fields resolve to nothing.
    pub fn matches(&self, event: &Event) -> bool {
        self.time.contains(event.original_time())
            && self.filter.matches(event)
            && self.wheres.iter().all(|w| w.matches(event))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use usiem::event::{Origin, RawEvent, Timestamp};

    fn event(fields: &[(&str, &str)]) -> Event {
        let mut raw = RawEvent::new(String::new(), Timestamp::now(), Origin::from_hostname("t"));
        for (k, v) in fields {
            raw.insert_field(*k, v.to_string());
        }
        raw.into_event()
    }

    #[test]
    fn filter_and_where() {
        let f = StreamFilter::parse("host.name:web* | where host.name:web01").unwrap();
        assert!(f.matches(&event(&[("host.name", "web01")])));
        assert!(!f.matches(&event(&[("host.name", "web02")])));
        assert!(StreamFilter::all().matches(&event(&[])));
    }

    #[test]
    fn predicates_render_back_to_queries() {
        for q in [
            "a:1",
            "a:* b:x*",
            "a:(x OR y)",
            "NOT a:1",
            "(a:1 OR b:2) c:3",
            "ip:10.0.0.0/8",
            "n:>5",
            "n<=5",
            "n:1..9",
            "msg:\"two words\" \"say \\\"hi\\\"\"",
            "path:\"C:\\Windows\\*\"",
        ] {
            let parsed = StreamFilter::parse(q).unwrap();
            let text = parsed.predicate().to_string();
            let again = StreamFilter::parse(&text).unwrap_or_else(|e| panic!("{q} -> {text}: {e}"));
            assert_eq!(again.predicate(), parsed.predicate(), "{q} -> {text}");
            let built = StreamFilter::from_predicate(parsed.predicate().clone());
            assert!(
                built.matches(&event(&[("a", "1"), ("c", "3")]))
                    == parsed.matches(&event(&[("a", "1"), ("c", "3")]))
            );
        }
    }

    #[test]
    fn rejects_whole_result_commands() {
        for q in ["* | stats count", "* | head 5", "* | sort -a"] {
            assert_eq!(
                StreamFilter::parse(q),
                Err(StreamFilterError::NotStreamable),
                "{q}"
            );
        }
        assert!(matches!(
            StreamFilter::parse("host.name:("),
            Err(StreamFilterError::Parse(_))
        ));
    }

    #[test]
    fn finds_virtual_fields() {
        let f = StreamFilter::parse("a:1 | where source.ip@intel:*").unwrap();
        assert_eq!(f.virtual_field(), Some("source.ip@intel"));
        assert_eq!(f.fields(), vec!["a", "source.ip@intel"]);
        assert_eq!(
            StreamFilter::parse("a:1 @timestamp>1")
                .unwrap()
                .virtual_field(),
            None
        );
    }
}
