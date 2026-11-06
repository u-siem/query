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
    /// Contains any of several substrings, case-insensitive: what
    /// `f:*a* OR f:*b* OR ...` means, in one pass over the value. Built in
    /// code (detection rules); the query parser never produces it.
    ContainsAny(Substrings),
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

/// Renders the predicate in query syntax. Best effort, for display (a rule
/// compiled from another format shows what it became): simple predicates
/// parse back to themselves, but a value ending in `\` or a range with one
/// exclusive bound may not.
impl std::fmt::Display for Predicate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fn grouped(p: &Predicate, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match p {
                Predicate::And(ps) | Predicate::Or(ps) if ps.len() > 1 => write!(f, "({p})"),
                _ => write!(f, "{p}"),
            }
        }
        fn joined(
            ps: &[Predicate],
            sep: &str,
            f: &mut std::fmt::Formatter<'_>,
        ) -> std::fmt::Result {
            for (i, p) in ps.iter().enumerate() {
                if i > 0 {
                    f.write_str(sep)?;
                }
                grouped(p, f)?;
            }
            Ok(())
        }
        match self {
            Predicate::True => f.write_str("*"),
            Predicate::And(ps) if ps.is_empty() => f.write_str("*"),
            Predicate::Or(ps) if ps.is_empty() => f.write_str("NOT *"),
            Predicate::And(ps) => joined(ps, " AND ", f),
            Predicate::Or(ps) => joined(ps, " OR ", f),
            Predicate::Not(p) => {
                f.write_str("NOT ")?;
                grouped(p, f)
            }
            Predicate::Text(term) => f.write_str(&quote(term)),
            Predicate::Field { field, op } => match op.as_ref() {
                FieldOp::Exists => write!(f, "{field}:*"),
                FieldOp::Eq(lit) => write!(f, "{field}:{}", quote(&lit.text)),
                FieldOp::In(lits) => {
                    write!(f, "{field}:(")?;
                    for (i, lit) in lits.iter().enumerate() {
                        if i > 0 {
                            f.write_str(" OR ")?;
                        }
                        f.write_str(&quote(&lit.text))?;
                    }
                    f.write_str(")")
                }
                FieldOp::Wildcard(p) => write!(f, "{field}:{}", quote(p.as_str())),
                FieldOp::Cidr(c) => write!(f, "{field}:{c}"),
                FieldOp::ContainsAny(subs) => {
                    let items: Vec<String> = subs
                        .needles()
                        .iter()
                        .map(|n| format!("{field}:{}", quote(&format!("*{n}*"))))
                        .collect();
                    match items.len() {
                        0 => f.write_str("NOT *"),
                        1 => f.write_str(&items[0]),
                        _ => write!(f, "({})", items.join(" OR ")),
                    }
                }
                FieldOp::Range { lower, upper } => match (lower, upper) {
                    (Some((lo, true)), Some((hi, true))) => {
                        write!(f, "{field}:{}..{}", quote(&lo.text), quote(&hi.text))
                    }
                    _ => {
                        let mut parts = Vec::new();
                        if let Some((lo, inc)) = lower {
                            let op = if *inc { ">=" } else { ">" };
                            parts.push(format!("{field}{op}{}", quote(&lo.text)));
                        }
                        if let Some((hi, inc)) = upper {
                            let op = if *inc { "<=" } else { "<" };
                            parts.push(format!("{field}{op}{}", quote(&hi.text)));
                        }
                        f.write_str(&parts.join(" AND "))
                    }
                },
            },
        }
    }
}

/// A value as query text: quoted when it holds spaces or syntax.
fn quote(text: &str) -> String {
    let plain = !text.is_empty()
        && !matches!(text, "AND" | "OR" | "NOT")
        && !text.contains(|c: char| {
            c.is_whitespace() || matches!(c, ':' | '(' | ')' | '"' | '<' | '>' | '=' | '!')
        });
    if plain {
        text.to_string()
    } else {
        format!("\"{}\"", text.replace('"', "\\\""))
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
            FieldOp::ContainsAny(subs) => match value {
                FieldValue::Str(s) => subs.matches(s),
                FieldValue::Object(_) | FieldValue::Bytes(_) => false,
                other => subs.matches(&other.to_string()),
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

/// An event read through [`lookup`], minus its slow path: a dotted name
/// that isn't a flat field probes every dotted prefix for an `Object`,
/// which costs several hash lookups per missing field. Events without any
/// `Object` value (most parsed logs) can skip that. Whether there is one is
/// found out on the first miss, once.
pub struct FlatLookup<'a> {
    event: &'a Event,
    nested: std::cell::Cell<Option<bool>>,
}

impl<'a> FlatLookup<'a> {
    pub fn new(event: &'a Event) -> FlatLookup<'a> {
        FlatLookup {
            event,
            nested: std::cell::Cell::new(None),
        }
    }

    pub fn event(&self) -> &'a Event {
        self.event
    }

    fn nested(&self) -> bool {
        match self.nested.get() {
            Some(nested) => nested,
            None => {
                let nested = self
                    .event
                    .fields()
                    .values()
                    .any(|v| matches!(v, FieldValue::Object(_)));
                self.nested.set(Some(nested));
                nested
            }
        }
    }
}

impl Record for FlatLookup<'_> {
    fn get(&self, field: &str) -> Option<Cow<'_, FieldValue>> {
        if field.starts_with('@') {
            return lookup(self.event, field);
        }
        match self.event.get_field(field) {
            Some(value) => Some(Cow::Borrowed(value)),
            None if self.nested() => lookup(self.event, field),
            None => None,
        }
    }

    fn for_each_value(&self, f: &mut dyn FnMut(&FieldValue)) {
        self.event.for_each_value(f)
    }
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

    /// Lowercased text, the form text equality compares against.
    pub fn lower(&self) -> &str {
        &self.lower
    }

    /// The literal reads only as text (not as a number, boolean, address or
    /// time), so it can equal only string values: case-insensitively, as
    /// [`Literal::lower`].
    pub fn is_text_only(&self) -> bool {
        self.int.is_none()
            && self.float.is_none()
            && self.boolean.is_none()
            && self.ip.is_none()
            && self.time.is_none()
    }

    /// The integer this literal equals, when it reads as text or as that
    /// integer and nothing else (no boolean, address or time reading), and
    /// the integer is exact as a float (|n| < 2^53). Such a literal equals a
    /// string value whose lowercase is [`Literal::lower`], or a number value
    /// equal to `n`, and nothing else.
    pub fn exact_int(&self) -> Option<i64> {
        const EXACT: i128 = 1 << 53;
        let n = self.int?;
        let exact = n.abs() < EXACT
            && self.float == Some(n as f64)
            && self.boolean.is_none()
            && self.ip.is_none()
            && self.time.is_none();
        exact.then_some(n as i64)
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
    /// The lowercased glob as bytes, when it is ASCII: ASCII text then
    /// matches without lowercasing or allocating (detection rules run
    /// hundreds of these per event).
    ascii: Option<Vec<u8>>,
}

impl Pattern {
    pub fn new(glob: &str) -> Pattern {
        Pattern {
            source: glob.to_string(),
            chars: glob.to_lowercase().chars().collect(),
            ascii: glob
                .is_ascii()
                .then(|| glob.to_ascii_lowercase().into_bytes()),
        }
    }

    pub fn as_str(&self) -> &str {
        &self.source
    }

    pub fn has_wildcards(text: &str) -> bool {
        text.contains(['*', '?'])
    }

    pub fn matches(&self, text: &str) -> bool {
        if let Some(p) = &self.ascii
            && text.is_ascii()
        {
            return glob_ascii(p, text.as_bytes());
        }
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

/// A set of substrings searched case-insensitively in one pass
/// (Aho-Corasick), for [`FieldOp::ContainsAny`].
#[derive(Clone)]
pub struct Substrings {
    /// As given.
    needles: Vec<String>,
    automaton: aho_corasick::AhoCorasick,
    /// Every needle is ASCII: ASCII text is searched as is.
    ascii: bool,
}

impl Substrings {
    /// `Err` only when the set is too large for the automaton.
    pub fn new<S: AsRef<str>>(needles: impl IntoIterator<Item = S>) -> Result<Substrings, String> {
        let needles: Vec<String> = needles
            .into_iter()
            .map(|n| n.as_ref().to_string())
            .collect();
        let ascii = needles.iter().all(|n| n.is_ascii());
        // ASCII needles match case-insensitively as they are; others are
        // lowercased and searched in lowercased text.
        let lowered: Vec<String> = needles.iter().map(|n| n.to_lowercase()).collect();
        let automaton = aho_corasick::AhoCorasick::builder()
            .ascii_case_insensitive(ascii)
            .build(&lowered)
            .map_err(|e| e.to_string())?;
        Ok(Substrings {
            needles,
            automaton,
            ascii,
        })
    }

    pub fn needles(&self) -> &[String] {
        &self.needles
    }

    /// Same answer as `Pattern::new("*n*").matches(text)` for any needle.
    pub fn matches(&self, text: &str) -> bool {
        if self.ascii && text.is_ascii() {
            self.automaton.is_match(text)
        } else {
            self.automaton.is_match(&text.to_lowercase())
        }
    }
}

impl PartialEq for Substrings {
    fn eq(&self, other: &Self) -> bool {
        self.needles == other.needles
    }
}

impl std::fmt::Debug for Substrings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Substrings").field(&self.needles).finish()
    }
}

/// [`Pattern::matches`] on ASCII: `p` is lowercased, `text` is not.
fn glob_ascii(p: &[u8], text: &[u8]) -> bool {
    // Fast paths for the shapes rules use most: `*lit*`, `lit*`, `*lit`.
    let inner = |s: &[u8]| !s.contains(&b'*') && !s.contains(&b'?');
    match p {
        [b'*', mid @ .., b'*'] if inner(mid) => return contains_ascii(text, mid),
        [b'*', tail @ ..] if inner(tail) => {
            return text.len() >= tail.len()
                && text[text.len() - tail.len()..].eq_ignore_ascii_case(tail);
        }
        [head @ .., b'*'] if inner(head) => {
            return text.len() >= head.len() && text[..head.len()].eq_ignore_ascii_case(head);
        }
        _ => {}
    }
    let (mut t, mut i) = (0usize, 0usize);
    let mut star: Option<(usize, usize)> = None;
    while t < text.len() {
        if i < p.len() && (p[i] == b'?' || p[i] == text[t].to_ascii_lowercase()) {
            i += 1;
            t += 1;
        } else if i < p.len() && p[i] == b'*' {
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
    p[i..].iter().all(|c| *c == b'*')
}

/// Case-insensitive substring search; `needle` is lowercased.
fn contains_ascii(haystack: &[u8], needle: &[u8]) -> bool {
    let Some((&first, rest)) = needle.split_first() else {
        return true;
    };
    if haystack.len() < needle.len() {
        return false;
    }
    let upper = first.to_ascii_uppercase();
    let last_start = haystack.len() - needle.len();
    let mut i = 0;
    while i <= last_start {
        // Skip to the next byte equal to `first` in either case.
        match haystack[i..=last_start]
            .iter()
            .position(|&b| b == first || b == upper)
        {
            None => return false,
            Some(off) => i += off,
        }
        if haystack[i + 1..i + needle.len()].eq_ignore_ascii_case(rest) {
            return true;
        }
        i += 1;
    }
    false
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
    fn ascii_glob_agrees_with_the_general_one() {
        let patterns = [
            "*",
            "**",
            "",
            "a",
            "A*",
            "*a",
            "*ab*",
            "*AB*",
            "a*b",
            "a?c",
            "*a?c*",
            "?",
            "??",
            "*x*y*",
            "*/bin/sh*",
            "*-s*",
            "abc",
            "*bc",
            "ab*",
            "*aab*",
        ];
        let texts = [
            "",
            "a",
            "A",
            "ab",
            "AB",
            "abc",
            "xaabz",
            "aac",
            "x/BIN/sh -i",
            "--s",
            "xy",
            "yx",
            "x y",
            "ba",
            "aaab",
        ];
        for p in patterns {
            let pat = Pattern::new(p);
            let general = Pattern {
                ascii: None,
                ..pat.clone()
            };
            for t in texts {
                assert_eq!(pat.matches(t), general.matches(t), "{p:?} on {t:?}");
            }
        }
        // Substrings agree with `*n*` globs.
        let needles = ["ab", "-S", "/bin/sh", "x y", ""];
        for set in [&needles[..1], &needles[1..4], &needles[4..]] {
            let subs = Substrings::new(set).unwrap();
            for t in texts.iter().chain(&["CAFÉ -s", "é/BIN/SH"]) {
                let any = set
                    .iter()
                    .any(|n| Pattern::new(&format!("*{n}*")).matches(t));
                assert_eq!(subs.matches(t), any, "{set:?} on {t:?}");
            }
        }
        let accents = Substrings::new(["É"]).unwrap();
        assert!(accents.matches("café") && accents.matches("CAFÉ") && !accents.matches("cafe"));
        // Non-ASCII text takes the general path.
        assert!(Pattern::new("*É*").matches("cafÉ"));
        assert!(Pattern::new("*é*").matches("CAFÉ"));
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
