//! Times, sizes and status lines as the mockups show them, in the user's local time.

use chrono::{DateTime, Datelike, Local, TimeZone};
use pnesecrets_core::history::{Entry, Status};
use pnesecrets_core::time::{DAY, HOUR, MINUTE, Millis};

fn at<Tz: TimeZone>(tz: &Tz, t: Millis) -> DateTime<Tz> {
    tz.timestamp_millis_opt(t).single().unwrap_or_else(|| {
        tz.timestamp_millis_opt(0)
            .single()
            .expect("epoch is representable")
    })
}

fn days_between<Tz: TimeZone>(tz: &Tz, from: Millis, to: Millis) -> i64 {
    let (a, b) = (at(tz, from).date_naive(), at(tz, to).date_naive());
    (b - a).num_days()
}

pub fn clock_in<Tz: TimeZone>(tz: &Tz, t: Millis) -> String
where
    Tz::Offset: std::fmt::Display,
{
    at(tz, t).format("%H:%M").to_string()
}

/// Sidebar right column: 10:42 / Yesterday / Mon / Oct 17.
pub fn list_time_in<Tz: TimeZone>(tz: &Tz, now: Millis, t: Millis) -> String
where
    Tz::Offset: std::fmt::Display,
{
    match days_between(tz, t, now) {
        0 => clock_in(tz, t),
        1 => "Yesterday".into(),
        2..=6 => at(tz, t).format("%a").to_string(),
        _ => at(tz, t).format("%b %-d").to_string(),
    }
}

/// Timeline: Today 10:42 / Tomorrow 10:42 / Yesterday 14:05 / Mon 18:30 / Oct 17 18:30.
pub fn day_time_in<Tz: TimeZone>(tz: &Tz, now: Millis, t: Millis) -> String
where
    Tz::Offset: std::fmt::Display,
{
    let clock = clock_in(tz, t);
    let day = match days_between(tz, now, t) {
        0 => "Today".to_string(),
        1 => "Tomorrow".into(),
        -1 => "Yesterday".into(),
        -6..=-2 | 2..=6 => at(tz, t).format("%a").to_string(),
        _ if at(tz, t).year() == at(tz, now).year() => at(tz, t).format("%b %-d").to_string(),
        _ => at(tz, t).format("%b %-d %Y").to_string(),
    };
    format!("{day} {clock}")
}

/// "Read · 14:05" today, "Read · Mon 18:30" otherwise.
pub fn short_moment_in<Tz: TimeZone>(tz: &Tz, now: Millis, t: Millis) -> String
where
    Tz::Offset: std::fmt::Display,
{
    if days_between(tz, t, now) == 0 {
        clock_in(tz, t)
    } else {
        day_time_in(tz, now, t)
    }
}

pub fn clock(t: Millis) -> String {
    clock_in(&Local, t)
}
pub fn list_time(now: Millis, t: Millis) -> String {
    list_time_in(&Local, now, t)
}
pub fn day_time(now: Millis, t: Millis) -> String {
    day_time_in(&Local, now, t)
}
pub fn short_moment(now: Millis, t: Millis) -> String {
    short_moment_in(&Local, now, t)
}

/// "23 h left", "12 min left", "2 d left".
pub fn left(ms: Millis) -> String {
    let ms = ms.max(0);
    if ms >= 2 * DAY {
        format!("{} d left", ms / DAY)
    } else if ms >= HOUR {
        format!("{} h left", ms / HOUR)
    } else {
        format!("{} min left", (ms / MINUTE).max(1))
    }
}

/// "in 23 h 12 min".
pub fn expires_in(ms: Millis) -> String {
    let ms = ms.max(0);
    let (d, h, m) = (ms / DAY, ms % DAY / HOUR, ms % HOUR / MINUTE);
    if d > 0 {
        format!("in {d} d {h} h")
    } else if h > 0 {
        format!("in {h} h {m} min")
    } else {
        format!("in {} min", m.max(1))
    }
}

pub fn ago(ms: Millis) -> String {
    if ms < MINUTE {
        "just now".into()
    } else if ms < HOUR {
        format!("{} min ago", ms / MINUTE)
    } else {
        format!("{} h ago", ms / HOUR)
    }
}

pub fn ttl_long(ttl: u32) -> &'static str {
    match ttl {
        3600 => "1 hour",
        604800 => "7 days",
        _ => "24 hours",
    }
}

pub fn ttl_short(ttl: u32) -> &'static str {
    match ttl {
        3600 => "1 h",
        604800 => "7 d",
        _ => "24 h",
    }
}

pub fn size(n: u64) -> String {
    pnesecrets_core::sdrop::ops::human_size(n as usize)
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Tone {
    Waiting,
    Read,
    Muted,
    Revoked,
}

/// The status line of a history entry (sidebar) and its tone.
pub fn status_line(e: &Entry, now: Millis) -> (String, Tone) {
    match e.status {
        Status::Waiting if !e.tracked => ("Not tracked".into(), Tone::Muted),
        Status::Waiting => (
            format!("Waiting · {}", left(e.expires_at - now)),
            Tone::Waiting,
        ),
        Status::Read => (
            match e.consumed_at {
                Some(t) => format!("Read · {}", short_moment(now, t)),
                None => "Read".into(),
            },
            Tone::Read,
        ),
        Status::Revoked => ("Revoked".into(), Tone::Revoked),
        Status::NotFound => ("Not found".into(), Tone::Muted),
        Status::ExpiredUnknown => ("Expired · unknown".into(), Tone::Muted),
    }
}

/// The pill in the A2 header.
pub fn status_pill(e: &Entry) -> (&'static str, Tone) {
    match e.status {
        Status::Waiting if !e.tracked => ("Not tracked", Tone::Muted),
        Status::Waiting => ("Waiting to be opened", Tone::Waiting),
        Status::Read => ("Read", Tone::Read),
        Status::Revoked => ("Revoked", Tone::Revoked),
        Status::NotFound => ("Not found", Tone::Muted),
        Status::ExpiredUnknown => ("Expired · read status unknown", Tone::Muted),
    }
}

pub fn untitled(e: &Entry) -> String {
    if e.label.is_empty() {
        format!("Untitled · {}", clock(e.created_at))
    } else {
        e.label.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::FixedOffset;

    // 2026-10-22 10:42 at UTC+3 (a Thursday).
    const NOW: Millis = 1_792_654_920_000;

    fn tz() -> FixedOffset {
        FixedOffset::east_opt(3 * 3600).unwrap()
    }

    #[test]
    fn list_and_day_times() {
        let tz = tz();
        assert_eq!(clock_in(&tz, NOW), "10:42");
        assert_eq!(list_time_in(&tz, NOW, NOW - HOUR), "09:42");
        assert_eq!(list_time_in(&tz, NOW, NOW - DAY), "Yesterday");
        assert_eq!(list_time_in(&tz, NOW, NOW - 3 * DAY), "Mon");
        assert_eq!(list_time_in(&tz, NOW, NOW - 5 * DAY), "Sat");
        assert_eq!(list_time_in(&tz, NOW, NOW - 7 * DAY), "Oct 15");
        assert_eq!(day_time_in(&tz, NOW, NOW), "Today 10:42");
        assert_eq!(day_time_in(&tz, NOW, NOW + DAY), "Tomorrow 10:42");
        assert_eq!(day_time_in(&tz, NOW, NOW - DAY), "Yesterday 10:42");
        assert_eq!(day_time_in(&tz, NOW, NOW + 3 * DAY), "Sun 10:42");
        assert_eq!(short_moment_in(&tz, NOW, NOW - 3 * HOUR), "07:42");
        assert_eq!(short_moment_in(&tz, NOW, NOW - 3 * DAY), "Mon 10:42");
    }

    #[test]
    fn durations() {
        assert_eq!(left(23 * HOUR + 59 * MINUTE), "23 h left");
        assert_eq!(left(30 * MINUTE), "30 min left");
        assert_eq!(left(10), "1 min left");
        assert_eq!(left(6 * DAY + HOUR), "6 d left");
        assert_eq!(expires_in(23 * HOUR + 12 * MINUTE), "in 23 h 12 min");
        assert_eq!(expires_in(3 * DAY + 2 * HOUR), "in 3 d 2 h");
        assert_eq!(ago(30_000), "just now");
        assert_eq!(ago(MINUTE), "1 min ago");
    }
}
