//! Arbitrary text through the value parsers a query uses: literals, times,
//! durations, spans, CIDR networks and globs. None of them may panic.

#![no_main]

use libfuzzer_sys::fuzz_target;
use usiem_query::query::{Span, parse_duration};
use usiem_query::store::predicate::parse_time;
use usiem_query::store::{Cidr, Literal, Pattern, Substrings};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let literal = Literal::new(text);
    let _ = literal.exact_int();
    let _ = literal.is_text_only();
    let _ = parse_time(text);
    let _ = parse_duration(text);
    let _ = Span::parse(text);
    if let Some(cidr) = Cidr::parse(text) {
        let _ = cidr.to_string();
    }
    // The first line is a glob, the rest the text it is matched against.
    let (glob, subject) = text.split_once('\n').unwrap_or((text, text));
    let _ = Pattern::new(glob).matches(subject);
    if !Pattern::has_wildcards(glob)
        && let Ok(subs) = Substrings::new([glob])
    {
        // `*n*` and a one-needle substring search agree.
        assert_eq!(
            Pattern::new(&format!("*{glob}*")).matches(subject),
            subs.matches(subject)
        );
    }
});
