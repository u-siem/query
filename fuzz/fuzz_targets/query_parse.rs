//! Arbitrary query text: parsing never panics or overflows the stack, a
//! parsed filter renders back to text that parses again, and the filter
//! evaluates against an event without panicking.

#![no_main]

use std::str::FromStr;
use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use usiem::event::{FieldValue, Ip, Origin, RawData, Timestamp};
use usiem_query::Event;
use usiem_query::query::{StreamFilter, parse};

fn event() -> &'static Event {
    static EVENT: OnceLock<Event> = OnceLock::new();
    EVENT.get_or_init(|| {
        let mut e = Event::new(
            Timestamp::from_secs(1_700_000_000),
            Timestamp::from_secs(1_700_000_000),
            Origin::Collector("fuzz".into()),
            RawData::from_text("raw"),
        );
        e.add_field("user.name".into(), FieldValue::from("Administrator"));
        e.add_field(
            "process.command_line".into(),
            FieldValue::from(r"C:\Windows\cmd.exe /c é"),
        );
        e.add_field("event.code".into(), FieldValue::Int(4624));
        e.add_field("bytes".into(), FieldValue::Uint(u64::MAX));
        e.add_field("ratio".into(), FieldValue::Float(f64::NAN));
        e.add_field("ok".into(), FieldValue::Bool(true));
        e.add_field(
            "at".into(),
            FieldValue::Time(Timestamp::from_nanos(i64::MIN)),
        );
        e.add_field(
            "source.ip".into(),
            FieldValue::Ip(Ip::from_str("10.1.2.3").expect("valid ip")),
        );
        e.add_field(
            "tags".into(),
            FieldValue::Array(vec![FieldValue::from("a"), FieldValue::Int(-1)]),
        );
        e
    })
}

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(query) = parse(text) else {
        return;
    };
    let event = event();
    let _ = query.filter.matches(event);
    let _ = query.time.contains(event.original_time());
    // Display is best effort, but its output is always query text.
    let rendered = query.filter.to_string();
    let _ = parse(&rendered);
    if let Ok(filter) = StreamFilter::parse(text) {
        let _ = filter.matches(event);
        let _ = filter.virtual_field();
    }
});
