//! Filter predicates over events.
//!
//! Matching is forgiving on purpose, like most SIEM search bars: string
//! comparisons ignore case (Windows artifacts are case-insensitive almost
//! everywhere), literals compare numerically against numeric fields, and an
//! array field matches when any element matches.

use crate::Event;
use std::borrow::Cow;
use std::net::IpAddr;
use std::str::FromStr;
use usiem::event::{FieldValue, Ip, Timestamp};

/// A boolean filter. `Default` is [`Predicate::True`] (match everything).
#[derive(Debug, Clone, Default, PartialEq)]
pub enum Predicate {
    #[default]
    True,
    And(Vec<Predicate>),
    Or(Vec<Predicate>),
    Not(Box<Predicate>),
    Field {
        field: String,
        op: Box<FieldOp>,
    },
    /// Bare search term: any string field contains it (case-insensitive).
    Text(String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum FieldOp {
    Exists,
    Eq(Literal),
    In(Vec<Literal>),
    /// `*` / `?` glob, case-insensitive.
    Wildcard(Pattern),
    Range {
        lower: Option<(Literal, bool)>,
        upper: Option<(Literal, bool)>,
    },
    Cidr(Cidr),
}

impl Predicate {
    pub fn field(field: impl Into<String>, op: FieldOp) -> Predicate {
        Predicate::Field {
            field: field.into(),
            op: Box::new(op),
        }
    }

    pub fn eq(field: impl Into<String>, value: &str) -> Predicate {
        Predicate::field(field, FieldOp::Eq(Literal::new(value)))
    }

    /// Evaluates against anything field-addressable: a stored event, an
    /// event plus its virtual fields, or a `stats` output row.
    pub fn matches<R: Record + ?Sized>(&self, record: &R) -> bool {
        match self {
            Predicate::True => true,
            Predicate::And(all) => all.iter().all(|p| p.matches(record)),
            Predicate::Or(any) => any.iter().any(|p| p.matches(record)),
            Predicate::Not(p) => !p.matches(record),
            Predicate::Field { field, op } => match record.get(field) {
                Some(value) => op.matches(&value),
                None => false,
            },
            Predicate::Text(term) => {
                let term = term.to_lowercase();
                let mut found = false;
                record.for_each_value(&mut |v| found = found || contains_text(v, &term));
                found
            }
        }
    }

    /// Calls `f` with every field name the predicate references.
    pub fn visit_fields<'a>(&'a self, f: &mut dyn FnMut(&'a str)) {
        match self {
            Predicate::True | Predicate::Text(_) => {}
            Predicate::And(ps) | Predicate::Or(ps) => ps.iter().for_each(|p| p.visit_fields(f)),
            Predicate::Not(p) => p.visit_fields(f),
            Predicate::Field { field, .. } => f(field),
        }
    }
}

/// Something predicates can be evaluated against.
pub trait Record {
    fn get(&self, field: &str) -> Option<Cow<'_, FieldValue>>;
    /// Visits every value, for bare-term text search.
    fn for_each_value(&self, f: &mut dyn FnMut(&FieldValue));
}

impl Record for Event {
    fn get(&self, field: &str) -> Option<Cow<'_, FieldValue>> {
        lookup(self, field)
    }

    fn for_each_value(&self, f: &mut dyn FnMut(&FieldValue)) {
        self.fields().values().for_each(f)
    }
}

impl FieldOp {
    pub fn matches(&self, value: &FieldValue) -> bool {
        if let FieldValue::Array(items) = value {
            return items.iter().any(|item| self.matches(item));
        }
        match self {
            FieldOp::Exists => true,
            FieldOp::Eq(lit) => lit.equals(value),
            FieldOp::In(lits) => lits.iter().any(|lit| lit.equals(value)),
            FieldOp::Wildcard(pattern) => match value {
                FieldValue::Str(s) => pattern.matches(s),
                FieldValue::Object(_) | FieldValue::Bytes(_) => false,
                other => pattern.matches(&other.to_string()),
            },
            FieldOp::Range { lower, upper } => {
                let above = lower.as_ref().is_none_or(|(lit, inclusive)| {
                    lit.compare(value)
                        .is_some_and(|o| o.is_lt() || (*inclusive && o.is_eq()))
                });
                let below = upper.as_ref().is_none_or(|(lit, inclusive)| {
                    lit.compare(value)
                        .is_some_and(|o| o.is_gt() || (*inclusive && o.is_eq()))
                });
                above && below
            }
            FieldOp::Cidr(cidr) => match value {
                FieldValue::Ip(ip) => cidr.contains(ip),
                FieldValue::Str(s) => Ip::from_str(s).is_ok_and(|ip| cidr.contains(&ip)),
                _ => false,
            },
        }
    }
}

/// Resolves a field path on an event.
///
/// Besides stored fields this understands the meta fields `@timestamp`
/// (original time), `@arrival`, `@origin` and `@id`, and dotted paths into
/// `Object` values when no flat field has that exact name.
pub fn lookup<'a>(event: &'a Event, path: &str) -> Option<Cow<'a, FieldValue>> {
    if let Some(meta) = path.strip_prefix('@') {
        return match meta {
            "timestamp" => Some(Cow::Owned(FieldValue::Time(event.original_time()))),
            "arrival" => Some(Cow::Owned(FieldValue::Time(event.arrival_time()))),
            "origin" => Some(Cow::Owned(FieldValue::from(event.origin().to_string()))),
            "id" => Some(Cow::Owned(FieldValue::from(event.id().to_string()))),
            _ => None,
        };
    }
    if let Some(value) = event.get_field(path) {
        return Some(Cow::Borrowed(value));
    }
    // Longest flat prefix that holds an object, then descend.
    let mut split = path.len();
    while let Some(dot) = path[..split].rfind('.') {
        if let Some(FieldValue::Object(_)) = event.get_field(&path[..dot]) {
            let mut current = event.get_field(&path[..dot])?;
            for part in path[dot + 1..].split('.') {
                match current {
                    FieldValue::Object(map) => current = map.get(part)?,
                    _ => return None,
                }
            }
            return Some(Cow::Borrowed(current));
        }
        split = dot;
    }
    None
}

/// Total order for sorting mixed values: numbers numerically, times
/// chronologically, IPs by address, everything else as case-insensitive text.
pub fn compare_values(a: &FieldValue, b: &FieldValue) -> std::cmp::Ordering {
    use FieldValue::*;
    use std::cmp::Ordering;
    let number = |v: &FieldValue| match v {
        Int(i) => Some(*i as f64),
        Uint(u) => Some(*u as f64),
        Float(f) => Some(*f),
        _ => None,
    };
    if let (Some(x), Some(y)) = (number(a), number(b)) {
        return x.partial_cmp(&y).unwrap_or(Ordering::Equal);
    }
    match (a, b) {
        (Time(x), Time(y)) => x.cmp(y),
        (Ip(x), Ip(y)) => ip_key(x).cmp(&ip_key(y)),
        _ => a
            .to_string()
            .to_lowercase()
            .cmp(&b.to_string().to_lowercase()),
    }
}

fn contains_text(value: &FieldValue, lower_term: &str) -> bool {
    match value {
        FieldValue::Str(s) => s.to_lowercase().contains(lower_term),
        FieldValue::Array(items) => items.iter().any(|v| contains_text(v, lower_term)),
        FieldValue::Object(map) => map.values().any(|v| contains_text(v, lower_term)),
        FieldValue::Ip(ip) => ip.to_string().contains(lower_term),
        _ => false,
    }
}

/// A literal from a query, pre-parsed into every type it could compare as.
#[derive(Debug, Clone, PartialEq)]
pub struct Literal {
    pub text: String,
    pub(crate) lower: String,
    pub(crate) int: Option<i128>,
    pub(crate) float: Option<f64>,
    pub(crate) boolean: Option<bool>,
    pub(crate) ip: Option<Ip>,
    pub(crate) time: Option<Timestamp>,
}

impl Literal {
    pub fn new(text: &str) -> Literal {
        let float = text.parse::<f64>().ok().filter(|f| f.is_finite());
        Literal {
            text: text.to_string(),
            lower: text.to_lowercase(),
            int: text.parse::<i128>().ok(),
            float,
            boolean: match text.to_ascii_lowercase().as_str() {
                "true" => Some(true),
                "false" => Some(false),
                _ => None,
            },
            ip: Ip::from_str(text).ok(),
            time: parse_time(text),
        }
    }

    pub fn as_time(&self) -> Option<Timestamp> {
        self.time
    }

    fn equals(&self, value: &FieldValue) -> bool {
        match value {
            FieldValue::Str(s) => eq_ignore_case(s, &self.text, &self.lower),
            FieldValue::Int(i) => self.int == Some(*i as i128) || self.float == Some(*i as f64),
            FieldValue::Uint(u) => self.int == Some(*u as i128) || self.float == Some(*u as f64),
            FieldValue::Float(f) => self.float == Some(*f),
            FieldValue::Bool(b) => self.boolean == Some(*b),
            FieldValue::Ip(ip) => self.ip == Some(*ip),
            FieldValue::Time(t) => self.time == Some(*t),
            FieldValue::Bytes(_) | FieldValue::Object(_) | FieldValue::Array(_) => false,
        }
    }

    /// `self.cmp(value)`, flipped: how the literal orders against the value.
    /// `Some(Less)` means literal < value.
    fn compare(&self, value: &FieldValue) -> Option<std::cmp::Ordering> {
        match value {
            FieldValue::Int(i) => self.float?.partial_cmp(&(*i as f64)),
            FieldValue::Uint(u) => self.float?.partial_cmp(&(*u as f64)),
            FieldValue::Float(f) => self.float?.partial_cmp(f),
            FieldValue::Time(t) => Some(self.time?.cmp(t)),
            FieldValue::Ip(ip) => Some(ip_key(&self.ip?).cmp(&ip_key(ip))),
            FieldValue::Str(s) => Some(self.lower.as_str().cmp(s.to_lowercase().as_str())),
            _ => None,
        }
    }
}

fn ip_key(ip: &Ip) -> (u8, u128) {
    match ip.as_ip_addr() {
        IpAddr::V4(v4) => (4, u32::from(v4) as u128),
        IpAddr::V6(v6) => (6, u128::from(v6)),
    }
}

fn eq_ignore_case(value: &str, text: &str, lower: &str) -> bool {
    if value.is_ascii() && text.is_ascii() {
        value.eq_ignore_ascii_case(text)
    } else {
        value.to_lowercase() == lower
    }
}

/// Parses the time formats a query can contain: RFC 3339,
/// `YYYY-MM-DD`, `YYYY-MM-DD hh:mm:ss[.fff]` (UTC).
pub fn parse_time(text: &str) -> Option<Timestamp> {
    let bytes = text.as_bytes();
    if bytes.len() < 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return None;
    }
    if let Ok(t) = Timestamp::from_rfc3339(text) {
        return Some(t);
    }
    let candidate = if text.len() == 10 {
        format!("{text}T00:00:00Z")
    } else {
        let mut s = text.replacen(' ', "T", 1);
        if !s.ends_with('Z') {
            s.push('Z');
        }
        s
    };
    Timestamp::from_rfc3339(&candidate).ok()
}

/// A case-insensitive glob with `*` (any run) and `?` (one char).
#[derive(Debug, Clone, PartialEq)]
pub struct Pattern {
    source: String,
    chars: Vec<char>,
}

impl Pattern {
    pub fn new(glob: &str) -> Pattern {
        Pattern {
            source: glob.to_string(),
            chars: glob.to_lowercase().chars().collect(),
        }
    }

    pub fn as_str(&self) -> &str {
        &self.source
    }

    pub fn has_wildcards(text: &str) -> bool {
        text.contains(['*', '?'])
    }

    pub fn matches(&self, text: &str) -> bool {
        let text: Vec<char> = text.to_lowercase().chars().collect();
        let p = &self.chars;
        // Iterative glob matching with single-star backtracking.
        let (mut t, mut i) = (0usize, 0usize);
        let mut star: Option<(usize, usize)> = None;
        while t < text.len() {
            if i < p.len() && (p[i] == '?' || p[i] == text[t]) {
                i += 1;
                t += 1;
            } else if i < p.len() && p[i] == '*' {
                star = Some((i, t));
                i += 1;
            } else if let Some((si, st)) = star {
                i = si + 1;
                t = st + 1;
                star = Some((si, st + 1));
            } else {
                return false;
            }
        }
        p[i..].iter().all(|c| *c == '*')
    }
}

/// An IPv4 or IPv6 network in CIDR notation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    pub(crate) addr: IpAddr,
    pub(crate) prefix: u8,
}

impl Cidr {
    pub fn parse(text: &str) -> Option<Cidr> {
        let (addr, prefix) = text.split_once('/')?;
        let addr = IpAddr::from_str(addr).ok()?;
        let prefix: u8 = prefix.parse().ok()?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        (prefix <= max).then_some(Cidr { addr, prefix })
    }

    pub fn contains(&self, ip: &Ip) -> bool {
        match (self.addr, ip.as_ip_addr()) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = u32::MAX.checked_shl(32 - self.prefix as u32).unwrap_or(0);
                u32::from(net) & mask == u32::from(ip) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = u128::MAX.checked_shl(128 - self.prefix as u32).unwrap_or(0);
                u128::from(net) & mask == u128::from(ip) & mask
            }
            _ => false,
        }
    }
}

impl std::fmt::Display for Cidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use usiem::event::{Origin, RawData};

    fn event(fields: &[(&str, FieldValue)]) -> Event {
        let mut e = Event::new(
            Timestamp::from_secs(100),
            Timestamp::from_secs(50),
            Origin::Collector("test".into()),
            RawData::from_text(""),
        );
        for (k, v) in fields {
            e.add_field(k.to_string(), v.clone());
        }
        e
    }

    #[test]
    fn eq_is_case_insensitive_and_numeric_aware() {
        let e = event(&[
            ("user.name", FieldValue::from("Administrator")),
            ("event.code", FieldValue::Int(4624)),
            (
                "source.ip",
                FieldValue::Ip(Ip::from_str("10.1.2.3").unwrap()),
            ),
        ]);
        assert!(Predicate::eq("user.name", "administrator").matches(&e));
        assert!(Predicate::eq("event.code", "4624").matches(&e));
        assert!(!Predicate::eq("event.code", "4625").matches(&e));
        assert!(Predicate::eq("source.ip", "10.1.2.3").matches(&e));
        assert!(!Predicate::eq("missing", "x").matches(&e));
    }

    #[test]
    fn wildcard_cidr_range_and_text() {
        let e = event(&[
            (
                "process.executable",
                FieldValue::from(r"C:\Windows\System32\cmd.exe"),
            ),
            (
                "source.ip",
                FieldValue::Ip(Ip::from_str("10.1.2.3").unwrap()),
            ),
            ("file.size", FieldValue::Uint(2048)),
        ]);
        let glob =
            |g: &str| Predicate::field("process.executable", FieldOp::Wildcard(Pattern::new(g)));
        assert!(glob(r"*\cmd.exe").matches(&e));
        assert!(glob(r"c:\windows\*").matches(&e));
        assert!(!glob(r"*\powershell.exe").matches(&e));

        let cidr = |c: &str| Predicate::field("source.ip", FieldOp::Cidr(Cidr::parse(c).unwrap()));
        assert!(cidr("10.0.0.0/8").matches(&e));
        assert!(!cidr("192.168.0.0/16").matches(&e));

        let range = Predicate::field(
            "file.size",
            FieldOp::Range {
                lower: Some((Literal::new("1024"), false)),
                upper: Some((Literal::new("2048"), true)),
            },
        );
        assert!(range.matches(&e));

        assert!(Predicate::Text("SYSTEM32".into()).matches(&e));
        assert!(!Predicate::Text("mimikatz".into()).matches(&e));
    }

    #[test]
    fn arrays_match_any_element_and_objects_by_path() {
        let mut obj = HashMap::new();
        obj.insert("TargetUserName".into(), FieldValue::from("bob"));
        let e = event(&[
            (
                "tags",
                FieldValue::Array(vec![FieldValue::from("a"), FieldValue::from("lateral")]),
            ),
            ("winlog.event_data", FieldValue::Object(obj)),
        ]);
        assert!(Predicate::eq("tags", "LATERAL").matches(&e));
        assert!(Predicate::eq("winlog.event_data.TargetUserName", "bob").matches(&e));
    }

    #[test]
    fn meta_fields_and_boolean_logic() {
        let e = event(&[("a", FieldValue::from("x"))]);
        let p = Predicate::And(vec![
            Predicate::eq("a", "x"),
            Predicate::Not(Box::new(Predicate::eq("a", "y"))),
            Predicate::field(
                "@timestamp",
                FieldOp::Range {
                    lower: Some((Literal::new("1970-01-01"), true)),
                    upper: None,
                },
            ),
        ]);
        assert!(p.matches(&e));
        assert!(!Predicate::Or(vec![]).matches(&e));
    }

    #[test]
    fn glob_edge_cases() {
        assert!(Pattern::new("*").matches(""));
        assert!(Pattern::new("a*b*c").matches("aXXbYYc"));
        assert!(!Pattern::new("a*b*c").matches("aXXbYY"));
        assert!(Pattern::new("?b").matches("ab"));
        assert!(Pattern::new("**x").matches("abcx"));
    }

    #[test]
    fn parses_query_times() {
        assert_eq!(parse_time("1970-01-02"), Some(Timestamp::from_secs(86400)));
        assert_eq!(
            parse_time("1970-01-01 00:01:00"),
            Some(Timestamp::from_secs(60))
        );
        assert_eq!(parse_time("4624"), None);
    }
}
