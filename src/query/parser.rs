//! Recursive-descent parser for the search language (see [`super`]).

use super::{Agg, AggFunc, Command, GroupKey, Query, SortKey, Span};
use crate::store::predicate::parse_time;
use crate::store::{Cidr, FieldOp, Literal, Pattern, Predicate, Regex, TimeRange};
use std::fmt;
use usiem::event::Timestamp;

/// A syntax error. `pos` is a byte offset into the query text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    /// Byte offset of the problem in the query text.
    pub pos: usize,
    /// What is wrong, for people.
    pub message: String,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (at column {})", self.message, self.pos + 1)
    }
}

impl std::error::Error for ParseError {}

type Result<T> = std::result::Result<T, ParseError>;

/// How deeply parentheses and `NOT`s may nest. The parser, the evaluator and
/// `Drop` all recurse over the predicate tree, so untrusted query text must
/// not be able to grow it deep enough to overflow the stack.
pub const MAX_NESTING: usize = 64;

/// `now`, or a duration before now: `-15m`, `-24h`, `-7d`.
fn relative_time(text: &str) -> Option<Timestamp> {
    let now = Timestamp::now();
    if text.eq_ignore_ascii_case("now") {
        return Some(now);
    }
    let ago = super::parse_duration(text.strip_prefix('-')?)?;
    (ago >= 0).then(|| Timestamp(now.as_nanos().saturating_sub(ago)))
}

/// Parses a query: a filter, then `|`-separated commands.
///
/// # Errors
///
/// A [`ParseError`] pointing at the first problem: a syntax error, an
/// unknown command or aggregation, a bad time or span, or nesting deeper
/// than [`MAX_NESTING`].
pub fn parse(input: &str) -> Result<Query> {
    let segments = split_pipes(input)?;
    let (search_start, search) = segments[0];
    let mut filter = FilterParser::new(search, search_start, true);
    let predicate = filter.parse_all()?;
    let mut query = Query {
        filter: predicate,
        time: filter.time,
        commands: Vec::new(),
    };
    for &(start, text) in &segments[1..] {
        query.commands.push(parse_command(text, start)?);
    }
    Ok(query)
}

/// Splits on `|` outside quotes. Returns `(offset, text)` per segment.
fn split_pipes(input: &str) -> Result<Vec<(usize, &str)>> {
    let mut segments = Vec::new();
    let mut start = 0;
    let mut in_quotes = false;
    let mut escaped = false;
    for (i, c) in input.char_indices() {
        match c {
            _ if escaped => escaped = false,
            '\\' if in_quotes && is_escaped_quote(&input[i + 1..]) => escaped = true,
            '"' => in_quotes = !in_quotes,
            '|' if !in_quotes => {
                segments.push((start, &input[start..i]));
                start = i + 1;
            }
            _ => {}
        }
    }
    if in_quotes {
        return Err(ParseError {
            pos: input.len(),
            message: "unterminated quote".into(),
        });
    }
    segments.push((start, &input[start..]));
    for &(offset, text) in &segments[1..] {
        if text.trim().is_empty() {
            return Err(ParseError {
                pos: offset,
                message: "empty command after '|'".into(),
            });
        }
    }
    Ok(segments)
}

/// Whether a backslash followed by `after` escapes a quote. `\"` closes the
/// string instead when the quote ends the value (end of input, whitespace,
/// `)` or `|` next), so Windows paths like `"C:\Users\"` work as written.
fn is_escaped_quote(after: &str) -> bool {
    let mut chars = after.chars();
    chars.next() == Some('"')
        && chars
            .next()
            .is_some_and(|c| !(c.is_whitespace() || c == ')' || c == '|'))
}

fn is_field_char(c: char) -> bool {
    c.is_alphanumeric() || matches!(c, '_' | '.' | '@' | '-')
}

/// Ends an unquoted value.
fn is_value_end(c: char) -> bool {
    c.is_whitespace() || matches!(c, '(' | ')' | '"')
}

struct FilterParser<'a> {
    text: &'a str,
    pos: usize,
    base: usize,
    /// `earliest=`/`latest=` are only allowed in the leading search.
    allow_time: bool,
    time: TimeRange,
    /// Open parentheses and `NOT`s around the current position.
    depth: usize,
}

impl<'a> FilterParser<'a> {
    fn new(text: &'a str, base: usize, allow_time: bool) -> Self {
        FilterParser {
            text,
            pos: 0,
            base,
            allow_time,
            time: TimeRange::default(),
            depth: 0,
        }
    }

    fn error<T>(&self, message: impl Into<String>) -> Result<T> {
        Err(ParseError {
            pos: self.base + self.pos,
            message: message.into(),
        })
    }

    /// Enters one more level of nesting.
    fn nest(&mut self) -> Result<()> {
        if self.depth >= MAX_NESTING {
            return self.error(format!(
                "the query nests too deeply (more than {MAX_NESTING} levels of '(' and NOT)"
            ));
        }
        self.depth += 1;
        Ok(())
    }

    fn rest(&self) -> &'a str {
        &self.text[self.pos..]
    }

    fn peek(&self) -> Option<char> {
        self.rest().chars().next()
    }

    fn skip_ws(&mut self) {
        let trimmed = self.rest().trim_start();
        self.pos = self.text.len() - trimmed.len();
    }

    fn eat(&mut self, s: &str) -> bool {
        if self.rest().starts_with(s) {
            self.pos += s.len();
            true
        } else {
            false
        }
    }

    /// Eats an upper-case keyword followed by a delimiter.
    fn eat_keyword(&mut self, keyword: &str) -> bool {
        self.skip_ws();
        let rest = self.rest();
        if rest.starts_with(keyword)
            && rest[keyword.len()..]
                .chars()
                .next()
                .is_none_or(|c| c.is_whitespace() || c == '(')
        {
            self.pos += keyword.len();
            true
        } else {
            false
        }
    }

    fn parse_all(&mut self) -> Result<Predicate> {
        self.skip_ws();
        if self.rest().is_empty() {
            return Ok(Predicate::True);
        }
        let predicate = self.parse_or()?;
        self.skip_ws();
        if !self.rest().is_empty() {
            return self.error(format!("unexpected {:?}", self.peek().unwrap_or(' ')));
        }
        Ok(predicate)
    }

    fn parse_or(&mut self) -> Result<Predicate> {
        let mut items = vec![self.parse_and()?];
        while self.eat_keyword("OR") {
            items.push(self.parse_and()?);
        }
        Ok(if items.len() == 1 {
            items.swap_remove(0)
        } else {
            Predicate::Or(items)
        })
    }

    fn parse_and(&mut self) -> Result<Predicate> {
        let mut items = Vec::new();
        let mut saw_term = false;
        loop {
            self.skip_ws();
            match self.peek() {
                None | Some(')') => break,
                _ => {}
            }
            let checkpoint = self.pos;
            if self.eat_keyword("OR") {
                self.pos = checkpoint;
                break;
            }
            if self.eat_keyword("AND") {
                continue;
            }
            saw_term = true;
            match self.parse_unary()? {
                Predicate::True => {}
                p => items.push(p),
            }
        }
        if !saw_term {
            return self.error("expected a search term");
        }
        Ok(match items.len() {
            0 => Predicate::True,
            1 => items.swap_remove(0),
            _ => Predicate::And(items),
        })
    }

    fn parse_unary(&mut self) -> Result<Predicate> {
        if self.eat_keyword("NOT") {
            self.nest()?;
            let inner = self.parse_unary()?;
            self.depth -= 1;
            return Ok(Predicate::Not(Box::new(inner)));
        }
        self.parse_primary()
    }

    fn parse_primary(&mut self) -> Result<Predicate> {
        self.skip_ws();
        if self.eat("(") {
            self.nest()?;
            let inner = self.parse_or()?;
            self.skip_ws();
            if !self.eat(")") {
                return self.error("expected ')'");
            }
            self.depth -= 1;
            return Ok(inner);
        }
        if self.peek() == Some('"') {
            let text = self.quoted()?;
            return Ok(Predicate::Text(text));
        }
        let start = self.pos;
        let name_len = self
            .rest()
            .find(|c: char| !is_field_char(c))
            .unwrap_or(self.rest().len());
        let name = &self.rest()[..name_len];
        let after = &self.rest()[name_len..];
        if !name.is_empty() {
            let operator = ["=~", "!~", ">=", "<=", "!=", ":", "=", ">", "<"]
                .into_iter()
                .find(|op| after.starts_with(op));
            if let Some(op) = operator {
                let name = name.to_string();
                self.pos += name_len + op.len();
                return self.field_term(name, op, start);
            }
        }
        // A bare search word.
        let len = self.rest().find(is_value_end).unwrap_or(self.rest().len());
        if len == 0 {
            return self.error(format!("unexpected {:?}", self.peek().unwrap_or(' ')));
        }
        let word = self.rest()[..len].trim_matches('*').to_string();
        self.pos += len;
        Ok(if word.is_empty() {
            Predicate::True
        } else {
            Predicate::Text(word)
        })
    }

    fn field_term(&mut self, field: String, op: &str, start: usize) -> Result<Predicate> {
        if op == "=" && (field == "earliest" || field == "latest") {
            if !self.allow_time {
                self.pos = start;
                return self.error(format!("{field}= is only allowed before the first '|'"));
            }
            let value_pos = self.pos;
            let (value, _) = self.value()?;
            let Some(time) = parse_time(&value).or_else(|| relative_time(&value)) else {
                self.pos = value_pos;
                return self.error(format!(
                    "{value:?} is not a time (use -24h, now, YYYY-MM-DD, 'YYYY-MM-DD hh:mm:ss' or RFC 3339)"
                ));
            };
            if field == "earliest" {
                self.time.start = Some(time);
            } else {
                self.time.end = Some(time);
            }
            return Ok(Predicate::True);
        }
        match op {
            "=~" | "!~" => {
                let value_pos = self.pos;
                if self.peek() != Some('"') {
                    return self.error(format!(
                        "a regex after {op} must be quoted: {field}{op}\"...\""
                    ));
                }
                let pattern = self.quoted()?;
                let re = match Regex::new(&pattern) {
                    Ok(re) => re,
                    Err(e) => {
                        self.pos = value_pos;
                        return self.error(format!("bad regex: {e}"));
                    }
                };
                let test = Predicate::field(field, FieldOp::Regex(re));
                Ok(if op == "!~" {
                    Predicate::Not(Box::new(test))
                } else {
                    test
                })
            }
            ":" | "=" => self.match_expr(field),
            "!=" => {
                let eq = self.match_expr(field)?;
                Ok(Predicate::Not(Box::new(eq)))
            }
            _ => {
                let (value, _) = self.value()?;
                Ok(comparison(field, op, &value))
            }
        }
    }

    /// What follows `field:`.
    fn match_expr(&mut self, field: String) -> Result<Predicate> {
        for op in [">=", "<=", ">", "<"] {
            if self.eat(op) {
                let (value, _) = self.value()?;
                return Ok(comparison(field, op, &value));
            }
        }
        if self.eat("(") {
            let mut ops = Vec::new();
            loop {
                self.skip_ws();
                if self.eat(")") {
                    break;
                }
                if self.peek().is_none() {
                    return self.error("expected ')'");
                }
                if self.eat_keyword("OR") {
                    continue;
                }
                let (value, quoted) = self.value()?;
                ops.push(value_op(&value, quoted));
            }
            if ops.is_empty() {
                return self.error("empty value list");
            }
            if ops.iter().all(|op| matches!(op, FieldOp::Eq(_))) {
                let literals = ops
                    .into_iter()
                    .map(|op| match op {
                        FieldOp::Eq(lit) => lit,
                        _ => unreachable!(),
                    })
                    .collect();
                return Ok(Predicate::field(field, FieldOp::In(literals)));
            }
            return Ok(Predicate::Or(
                ops.into_iter()
                    .map(|op| Predicate::field(field.clone(), op))
                    .collect(),
            ));
        }
        let (value, quoted) = self.value()?;
        Ok(Predicate::field(field, value_op(&value, quoted)))
    }

    /// A quoted or bare value. Returns the text and whether it was quoted.
    fn value(&mut self) -> Result<(String, bool)> {
        if self.peek() == Some('"') {
            return Ok((self.quoted()?, true));
        }
        let len = self.rest().find(is_value_end).unwrap_or(self.rest().len());
        if len == 0 {
            return self.error("expected a value");
        }
        let value = self.rest()[..len].to_string();
        self.pos += len;
        Ok((value, false))
    }

    fn quoted(&mut self) -> Result<String> {
        debug_assert_eq!(self.peek(), Some('"'));
        let open = self.pos;
        self.pos += 1;
        let mut out = String::new();
        let mut chars = self.rest().char_indices();
        while let Some((i, c)) = chars.next() {
            match c {
                '"' => {
                    self.pos += i + 1;
                    return Ok(out);
                }
                '\\' if is_escaped_quote(&self.rest()[i + 1..]) => {
                    out.push('"');
                    chars.next();
                }
                c => out.push(c),
            }
        }
        self.pos = open;
        self.error("unterminated quote")
    }
}

fn comparison(field: String, op: &str, value: &str) -> Predicate {
    let literal = Literal::new(value);
    let (lower, upper) = match op {
        ">" => (Some((literal, false)), None),
        ">=" => (Some((literal, true)), None),
        "<" => (None, Some((literal, false))),
        _ => (None, Some((literal, true))),
    };
    Predicate::field(field, FieldOp::Range { lower, upper })
}

/// Interprets a value after `field:`.
fn value_op(value: &str, quoted: bool) -> FieldOp {
    if !quoted {
        if value == "*" {
            return FieldOp::Exists;
        }
        if let Some(cidr) = value.contains('/').then(|| Cidr::parse(value)).flatten() {
            return FieldOp::Cidr(cidr);
        }
        if let Some((low, high)) = value.split_once("..")
            && !(low.is_empty() && high.is_empty())
        {
            let bound = |s: &str| (!s.is_empty()).then(|| (Literal::new(s), true));
            return FieldOp::Range {
                lower: bound(low),
                upper: bound(high),
            };
        }
    }
    if Pattern::has_wildcards(value) {
        FieldOp::Wildcard(Pattern::new(value))
    } else {
        FieldOp::Eq(Literal::new(value))
    }
}

/// Splits a command's arguments on whitespace and commas, honouring quotes.
fn words(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut depth = 0usize;
    for c in text.chars() {
        match c {
            '"' => in_quotes = !in_quotes,
            '(' if !in_quotes => {
                depth += 1;
                current.push(c);
            }
            ')' if !in_quotes => {
                depth = depth.saturating_sub(1);
                current.push(c);
            }
            c if !in_quotes && depth == 0 && (c.is_whitespace() || c == ',') => {
                if !current.is_empty() {
                    out.push(std::mem::take(&mut current));
                }
            }
            // `bucket(@timestamp, 1h)` is one word.
            c if !in_quotes && depth > 0 && c.is_whitespace() => {}
            c => current.push(c),
        }
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}

fn parse_command(text: &str, offset: usize) -> Result<Command> {
    let leading = text.len() - text.trim_start().len();
    let trimmed = text.trim();
    let (name, args) = trimmed
        .split_once(char::is_whitespace)
        .unwrap_or((trimmed, ""));
    let args_offset = offset + leading + name.len() + (trimmed.len() - name.len() - args.len());
    let err = |message: String| ParseError {
        pos: offset + leading,
        message,
    };
    let count = |default: usize| -> Result<usize> {
        match args.trim() {
            "" => Ok(default),
            n => n
                .parse()
                .map_err(|_| err(format!("{name} expects a number, got {n:?}"))),
        }
    };
    let field_list = || -> Result<Vec<String>> {
        let fields = words(args);
        if fields.is_empty() {
            Err(err(format!("{name} expects field names")))
        } else {
            Ok(fields)
        }
    };
    match name {
        "where" => {
            let mut parser = FilterParser::new(args, args_offset, false);
            if args.trim().is_empty() {
                return Err(err("where expects a filter".into()));
            }
            Ok(Command::Where(parser.parse_all()?))
        }
        "fields" | "table" => Ok(Command::Fields(field_list()?)),
        "dedup" => Ok(Command::Dedup(field_list()?)),
        "head" => Ok(Command::Head(count(10)?)),
        "tail" => Ok(Command::Tail(count(10)?)),
        "sort" => Ok(Command::Sort(
            field_list()?
                .into_iter()
                .map(|w| match w.strip_prefix('-') {
                    Some(field) => SortKey {
                        field: field.to_string(),
                        descending: true,
                    },
                    None => SortKey {
                        field: w.trim_start_matches('+').to_string(),
                        descending: false,
                    },
                })
                .collect(),
        )),
        "stats" => parse_stats(args).map_err(err),
        other => Err(err(format!(
            "unknown command {other:?} (expected where, fields, table, sort, head, tail, dedup or stats)"
        ))),
    }
}

fn parse_stats(args: &str) -> std::result::Result<Command, String> {
    let words = words(args);
    let (agg_words, by) = match words.iter().position(|w| w == "by") {
        Some(i) => (
            &words[..i],
            words[i + 1..]
                .iter()
                .map(|w| parse_group_key(w))
                .collect::<std::result::Result<Vec<_>, _>>()?,
        ),
        None => (&words[..], Vec::new()),
    };
    if agg_words.is_empty() {
        return Err(
            "stats expects at least one aggregation, e.g. 'stats count by user.name'".into(),
        );
    }
    if words.last().is_some_and(|w| w == "by") {
        return Err("stats ... by expects field names".into());
    }
    let mut aggs: Vec<Agg> = Vec::new();
    let mut iter = agg_words.iter().peekable();
    while let Some(word) = iter.next() {
        if word == "as" {
            let alias = iter.next().ok_or("'as' expects a name")?;
            let last = aggs.last_mut().ok_or("'as' must follow an aggregation")?;
            last.name.clone_from(alias);
            continue;
        }
        aggs.push(parse_agg(word)?);
    }
    Ok(Command::Stats { aggs, by })
}

fn parse_group_key(word: &str) -> std::result::Result<GroupKey, String> {
    let Some(inner) = word.strip_prefix("bucket(") else {
        return Ok(GroupKey::Field(word.to_string()));
    };
    let usage = || format!("{word:?}: expected bucket(field,span), e.g. bucket(@timestamp,1h)");
    let inner = inner.strip_suffix(')').ok_or_else(usage)?;
    let (field, span) = inner.split_once(',').ok_or_else(usage)?;
    let span = Span::parse(span.trim())
        .ok_or_else(|| format!("{span:?} is not a span (use 30s, 15m, 1h, 1d or a number)"))?;
    Ok(GroupKey::Bucket {
        field: field.trim().to_string(),
        span,
        name: word.to_string(),
    })
}

fn parse_agg(word: &str) -> std::result::Result<Agg, String> {
    let (func_name, field) = match word.split_once('(') {
        Some((f, rest)) => {
            let field = rest
                .strip_suffix(')')
                .ok_or_else(|| format!("missing ')' in {word:?}"))?;
            (f, Some(field.to_string()).filter(|f| !f.is_empty()))
        }
        None => (word, None),
    };
    let func = match func_name {
        "count" => AggFunc::Count,
        "dc" | "distinct_count" => AggFunc::DistinctCount,
        "min" => AggFunc::Min,
        "max" => AggFunc::Max,
        "sum" => AggFunc::Sum,
        "avg" => AggFunc::Avg,
        "values" => AggFunc::Values,
        other => {
            return Err(format!(
                "unknown aggregation {other:?} (expected count, dc, min, max, sum, avg or values)"
            ));
        }
    };
    if func != AggFunc::Count && field.is_none() {
        return Err(format!(
            "{func_name} needs a field, e.g. {func_name}(user.name)"
        ));
    }
    Ok(Agg {
        func,
        name: word.to_string(),
        field,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use usiem::event::Timestamp;

    fn eq(field: &str, value: &str) -> Predicate {
        Predicate::eq(field, value)
    }

    #[test]
    fn empty_query_matches_everything() {
        assert_eq!(parse("").unwrap(), Query::default());
        assert_eq!(parse("   ").unwrap().filter, Predicate::True);
    }

    #[test]
    fn field_terms_and_implicit_and() {
        let q =
            parse(r#"user.name:bob event.code:4624 file.path:"C:\Program Files\x.exe""#).unwrap();
        assert_eq!(
            q.filter,
            Predicate::And(vec![
                eq("user.name", "bob"),
                eq("event.code", "4624"),
                eq("file.path", r"C:\Program Files\x.exe"),
            ])
        );
    }

    #[test]
    fn boolean_precedence_and_grouping() {
        let q = parse("a:1 OR b:2 c:3").unwrap();
        assert_eq!(
            q.filter,
            Predicate::Or(vec![
                eq("a", "1"),
                Predicate::And(vec![eq("b", "2"), eq("c", "3")])
            ])
        );
        let q = parse("(a:1 OR b:2) AND NOT c:3").unwrap();
        assert_eq!(
            q.filter,
            Predicate::And(vec![
                Predicate::Or(vec![eq("a", "1"), eq("b", "2")]),
                Predicate::Not(Box::new(eq("c", "3"))),
            ])
        );
        // Lower-case "or" is a search word, not a keyword.
        assert_eq!(
            parse("a:1 or").unwrap().filter,
            Predicate::And(vec![eq("a", "1"), Predicate::Text("or".into())])
        );
    }

    #[test]
    fn value_kinds() {
        let op = |q: &str| match parse(q).unwrap().filter {
            Predicate::Field { op, .. } => *op,
            other => panic!("{other:?}"),
        };
        assert_eq!(op("f:*"), FieldOp::Exists);
        assert!(matches!(op("f:*cmd*"), FieldOp::Wildcard(_)));
        assert!(matches!(op(r#"f:"*\temp\*""#), FieldOp::Wildcard(_)));
        assert!(matches!(op("f:10.0.0.0/8"), FieldOp::Cidr(_)));
        assert!(matches!(op(r#"f:"10.0.0.0/8""#), FieldOp::Eq(_)));
        assert!(matches!(op("f:(1 OR 2 3)"), FieldOp::In(ref v) if v.len() == 3));
        assert!(matches!(
            op("f:1..5"),
            FieldOp::Range {
                lower: Some(_),
                upper: Some(_)
            }
        ));
        assert!(matches!(
            op("f:>5"),
            FieldOp::Range {
                lower: Some((_, false)),
                upper: None
            }
        ));
        assert!(matches!(
            op("f<=5"),
            FieldOp::Range {
                lower: None,
                upper: Some((_, true))
            }
        ));
        assert!(matches!(parse("f!=5").unwrap().filter, Predicate::Not(_)));
        assert!(matches!(
            parse("f:(a* OR b)").unwrap().filter,
            Predicate::Or(ref v) if v.len() == 2
        ));
    }

    #[test]
    fn bare_words_and_virtual_fields() {
        assert_eq!(
            parse(r#"mimikatz "lsass dump""#).unwrap().filter,
            Predicate::And(vec![
                Predicate::Text("mimikatz".into()),
                Predicate::Text("lsass dump".into())
            ])
        );
        assert_eq!(
            parse("source.ip@hostname:dc01").unwrap().filter,
            eq("source.ip@hostname", "dc01")
        );
        assert_eq!(
            parse("@timestamp:*").unwrap().filter,
            Predicate::field("@timestamp", FieldOp::Exists)
        );
    }

    #[test]
    fn time_range() {
        let q = parse("earliest=2024-01-01 latest=\"2024-01-02 12:00:00\" user.name:bob").unwrap();
        assert_eq!(
            q.time.start,
            Timestamp::from_rfc3339("2024-01-01T00:00:00Z").ok()
        );
        assert_eq!(
            q.time.end,
            Timestamp::from_rfc3339("2024-01-02T12:00:00Z").ok()
        );
        assert_eq!(q.filter, eq("user.name", "bob"));
        assert_eq!(
            parse("earliest=2024-01-01").unwrap().filter,
            Predicate::True
        );
        let q = parse("earliest=-1h latest=now").unwrap();
        let (start, end) = (
            q.time.start.unwrap().as_nanos(),
            q.time.end.unwrap().as_nanos(),
        );
        let hour = 3_600_000_000_000;
        assert!((hour..hour + 1_000_000_000).contains(&(end - start)));
        let err = parse("earliest=yesterday").unwrap_err();
        assert_eq!(err.pos, 9);
        assert!(parse("* | where earliest=2024-01-01").is_err());
    }

    #[test]
    fn commands() {
        let q = parse(
            "event.code:4624 | where source.ip@hostname:*dc* | stats count, dc(source.ip) as sources by user.name, host.name | sort -count +user.name | head 5 | tail | fields user.name, count | dedup user.name",
        )
        .unwrap();
        assert_eq!(q.commands.len(), 7);
        assert_eq!(
            q.commands[0],
            Command::Where(Predicate::field(
                "source.ip@hostname",
                FieldOp::Wildcard(Pattern::new("*dc*"))
            ))
        );
        assert_eq!(
            q.commands[1],
            Command::Stats {
                aggs: vec![
                    Agg {
                        func: AggFunc::Count,
                        field: None,
                        name: "count".into()
                    },
                    Agg {
                        func: AggFunc::DistinctCount,
                        field: Some("source.ip".into()),
                        name: "sources".into()
                    },
                ],
                by: vec![
                    GroupKey::Field("user.name".into()),
                    GroupKey::Field("host.name".into())
                ],
            }
        );
        assert_eq!(
            q.commands[2],
            Command::Sort(vec![
                SortKey {
                    field: "count".into(),
                    descending: true
                },
                SortKey {
                    field: "user.name".into(),
                    descending: false
                },
            ])
        );
        assert_eq!(q.commands[3], Command::Head(5));
        assert_eq!(q.commands[4], Command::Tail(10));
        assert_eq!(
            q.commands[5],
            Command::Fields(vec!["user.name".into(), "count".into()])
        );
        assert_eq!(q.commands[6], Command::Dedup(vec!["user.name".into()]));
    }

    #[test]
    fn bucket_group_keys_keep_commas_inside_parentheses() {
        let q = parse("* | stats count by bucket(@timestamp, 1h), artifact.host").unwrap();
        assert_eq!(
            q.commands[0],
            Command::Stats {
                aggs: vec![Agg {
                    func: AggFunc::Count,
                    field: None,
                    name: "count".into()
                }],
                by: vec![
                    GroupKey::Bucket {
                        field: "@timestamp".into(),
                        span: Span::Nanos(3_600_000_000_000),
                        name: "bucket(@timestamp,1h)".into()
                    },
                    GroupKey::Field("artifact.host".into()),
                ],
            }
        );
        assert!(parse("* | stats count by bucket(@timestamp,1y)").is_err());
        assert!(parse("* | stats count by bucket(@timestamp)").is_err());
        assert_eq!(Span::parse("10"), Some(Span::Number(10.0)));
        assert_eq!(Span::parse("0m"), None);
    }

    #[test]
    fn trailing_backslash_before_closing_quote() {
        let q = parse(r#"file.path:"C:\Users\" user.name:bob | head 1"#).unwrap();
        assert_eq!(
            q.filter,
            Predicate::And(vec![eq("file.path", r"C:\Users\"), eq("user.name", "bob")])
        );
        assert_eq!(q.commands, vec![Command::Head(1)]);
        assert_eq!(
            parse(r#"a:"say \"hi\"""#).unwrap().filter,
            eq("a", r#"say "hi""#)
        );
    }

    #[test]
    fn pipes_inside_quotes_are_values() {
        let q = parse(r#"process.command_line:"a | b" | head 1"#).unwrap();
        assert_eq!(q.filter, eq("process.command_line", "a | b"));
        assert_eq!(q.commands, vec![Command::Head(1)]);
    }

    #[test]
    fn errors_point_at_the_problem() {
        let e = parse("a:1 | bogus x").unwrap_err();
        assert_eq!(e.pos, 6);
        assert!(e.message.contains("unknown command"));
        assert_eq!(parse("(a:1").unwrap_err().message, "expected ')'");
        assert_eq!(parse("a:\"open").unwrap_err().message, "unterminated quote");
        assert!(parse("a:1 |").is_err());
        assert!(parse("* | stats").is_err());
        assert!(parse("* | stats avg").is_err());
        assert!(parse("* | stats count by").is_err());
        assert!(parse("* | head x").is_err());
        assert!(parse("a:1 )").is_err());
    }

    #[test]
    fn deep_nesting_is_an_error_not_a_stack_overflow() {
        for open in ["(", "NOT ", "a:1 OR (", "NOT ("] {
            let deep = open.repeat(100_000);
            let e = parse(&deep).unwrap_err();
            assert!(e.message.contains("nests too deeply"), "{open:?}: {e}");
            let e = parse(&format!("* | where {deep}")).unwrap_err();
            assert!(e.message.contains("nests too deeply"), "{open:?}: {e}");
        }
        // Up to the limit is fine, and the depth resets between groups.
        let ok = format!("{}a:1{}", "(".repeat(MAX_NESTING), ")".repeat(MAX_NESTING));
        assert_eq!(parse(&ok).unwrap().filter, eq("a", "1"));
        let siblings = "(a:1) ".repeat(MAX_NESTING * 4);
        assert!(parse(&siblings).is_ok());
        let nots = format!("{}a:1", "NOT ".repeat(MAX_NESTING));
        assert!(parse(&nots).is_ok());
        assert!(parse(&format!("NOT {nots}")).is_err());
    }

    #[test]
    fn odd_text_and_huge_numbers_do_not_panic() {
        for q in [
            "é",
            "a:é",
            "😀:😀",
            r#"a:"é\"""#,
            "a\u{3000}:b",
            "* |\u{3000}head",
            "* | head 99999999999999999999999",
            "* | tail 18446744073709551615",
            "* | stats count by bucket(@timestamp,99999999999d)",
            "* | stats count by bucket(f,1e-300)",
            "f:170141183460469231731687303715884105728",
            "f:-170141183460469231731687303715884105728",
            "f:1..",
            "f:..",
            "f:/",
            "f:1.2.3.4/999",
            "f:\"::\"/129",
            "f:é/8",
            "\"",
            r#"\""#,
            "(",
            ")",
            "|",
            "a:(",
            r#"a:("x""#,
            "NOT",
            "AND OR",
            "earliest=-é",
            "earliest=-5é",
        ] {
            let _ = parse(q);
        }
    }

    #[test]
    fn huge_relative_times_saturate() {
        let q = parse("earliest=-99999999999d latest=-9223372036854775807d").unwrap();
        assert!(q.time.start.is_some() && q.time.end.is_some());
        assert!(parse("earliest=--5d").is_err());
        assert!(parse("earliest=-d").is_err());
    }
}
