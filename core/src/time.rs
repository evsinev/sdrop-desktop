//! Time as milliseconds since the Unix epoch (UTC), the server's ISO 8601 form
//! (`2026-10-22T12:00:00.000Z`, FORMAT.md 6) and an injectable clock for tests.

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

/// Milliseconds since 1970-01-01T00:00:00Z.
pub type Millis = i64;

pub const SECOND: Millis = 1000;
pub const MINUTE: Millis = 60 * SECOND;
pub const HOUR: Millis = 60 * MINUTE;
pub const DAY: Millis = 24 * HOUR;

pub trait Clock: Send + Sync {
    fn now(&self) -> Millis;
}

pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Millis {
        let d = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        d.as_millis() as Millis
    }
}

/// A clock the test moves by hand.
#[derive(Clone, Default)]
pub struct ManualClock(Arc<AtomicI64>);

impl ManualClock {
    pub fn at(t: Millis) -> ManualClock {
        ManualClock(Arc::new(AtomicI64::new(t)))
    }
    pub fn set(&self, t: Millis) {
        self.0.store(t, Ordering::SeqCst);
    }
    pub fn advance(&self, d: Millis) {
        self.0.fetch_add(d, Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now(&self) -> Millis {
        self.0.load(Ordering::SeqCst)
    }
}

/// Days since the epoch for a proleptic Gregorian date (H. Hinnant's days_from_civil).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

/// Exactly `YYYY-MM-DDTHH:MM:SS.mmmZ`, the form the service sends; anything else is None.
pub fn parse_iso(s: &str) -> Option<Millis> {
    let b = s.as_bytes();
    if b.len() != 24
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || b[19] != b'.'
        || b[23] != b'Z'
    {
        return None;
    }
    let num = |r: std::ops::Range<usize>| -> Option<i64> {
        let part = &s[r];
        part.bytes()
            .all(|c| c.is_ascii_digit())
            .then(|| part.parse().ok())
            .flatten()
    };
    let (y, mo, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (h, mi, sec, ms) = (num(11..13)?, num(14..16)?, num(17..19)?, num(20..23)?);
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let month_days = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if !(1..=12).contains(&mo) || d < 1 || d > month_days[(mo - 1) as usize] {
        return None;
    }
    if h > 23 || mi > 59 || sec > 59 {
        return None;
    }
    Some((((days_from_civil(y, mo, d) * 24 + h) * 60 + mi) * 60 + sec) * 1000 + ms)
}

pub fn format_iso(t: Millis) -> String {
    let (days, ms) = (t.div_euclid(DAY), t.rem_euclid(DAY));
    let (y, m, d) = civil_from_days(days);
    let (h, mi, s, milli) = (
        ms / HOUR,
        ms % HOUR / MINUTE,
        ms % MINUTE / SECOND,
        ms % SECOND,
    );
    format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}.{milli:03}Z")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_known_points() {
        assert_eq!(parse_iso("1970-01-01T00:00:00.000Z"), Some(0));
        let t = parse_iso("2026-10-22T12:00:00.000Z").unwrap();
        assert_eq!(t, 1_792_670_400_000);
        assert_eq!(format_iso(t), "2026-10-22T12:00:00.000Z");
        let leap = parse_iso("2028-02-29T23:59:59.999Z").unwrap();
        assert_eq!(format_iso(leap), "2028-02-29T23:59:59.999Z");
        for t in [0, 1, 951_782_400_000, 4_102_444_799_999] {
            assert_eq!(parse_iso(&format_iso(t)), Some(t));
        }
    }

    #[test]
    fn other_forms_are_rejected() {
        for bad in [
            "",
            "2026-10-22T12:00:00Z",
            "2026-10-22T12:00:00.000+00:00",
            "2026-10-22 12:00:00.000Z",
            "2026-13-01T00:00:00.000Z",
            "2026-02-29T00:00:00.000Z",
            "2026-10-22T24:00:00.000Z",
            "2026-10-22T12:60:00.000Z",
            "+026-10-22T12:00:00.000Z",
            "2026-10-22T12:00:00.0a0Z",
        ] {
            assert_eq!(parse_iso(bad), None, "{bad}");
        }
    }
}
