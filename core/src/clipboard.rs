//! Clipboard service (SPEC 5): every copy of a link or a secret goes through it. It clears the
//! clipboard after a timeout only while the clipboard still holds our value: by the OS change
//! counter where there is one (macOS, Windows), else by comparing the text (Linux, accepted race).

use crate::time::{Millis, SECOND};
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

pub const LINK_TIMEOUT: Millis = 60 * SECOND;
pub const SECRET_TIMEOUT: Millis = 30 * SECOND;
/// A failed clear (the clipboard busy) is tried again after this.
pub const RETRY: Millis = SECOND;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClipError;

impl std::fmt::Display for ClipError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the clipboard is not available")
    }
}

/// The platform clipboard. Implementations mark writes as concealed / excluded from history.
pub trait ClipboardBackend: Send {
    fn write_concealed(&mut self, text: &str) -> Result<(), ClipError>;
    /// Ok(None): the clipboard holds no text. Err: it could not be read (busy, no access).
    fn read_text(&mut self) -> Result<Option<Zeroizing<String>>, ClipError>;
    fn clear(&mut self) -> Result<(), ClipError>;
    /// Bumped by every write from any process; None where the OS has no such counter.
    fn change_count(&mut self) -> Option<i64>;
}

/// What was copied: a recipient link (of a history entry, if any) or a revealed secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CopyKind {
    Link { entry: Option<String> },
    Secret,
}

/// Our value left the clipboard: cleared by us, or replaced by someone else (then left alone).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Released {
    pub kind: CopyKind,
    pub at: Millis,
    /// True: we cleared it. False: the clipboard already held something else.
    pub cleared: bool,
}

struct Held {
    kind: CopyKind,
    value: Zeroizing<String>,
    count: Option<i64>,
    clear_at: Millis,
}

pub struct ClipboardService {
    backend: Box<dyn ClipboardBackend>,
    held: Option<Held>,
}

impl ClipboardService {
    pub fn new(backend: Box<dyn ClipboardBackend>) -> ClipboardService {
        ClipboardService {
            backend,
            held: None,
        }
    }

    /// Copies and schedules the clear. A value of ours still on the clipboard is replaced by this
    /// one: it is reported as released (not cleared by us, but gone).
    pub fn copy(
        &mut self,
        text: Zeroizing<String>,
        kind: CopyKind,
        now: Millis,
    ) -> Result<Option<Released>, ClipError> {
        let timeout = match kind {
            CopyKind::Link { .. } => LINK_TIMEOUT,
            CopyKind::Secret => SECRET_TIMEOUT,
        };
        self.backend.write_concealed(&text)?;
        let count = self.backend.change_count();
        let previous = self.held.replace(Held {
            kind,
            value: text,
            count,
            clear_at: now + timeout,
        });
        Ok(previous.map(|h| Released {
            kind: h.kind,
            at: now,
            cleared: false,
        }))
    }

    /// When `tick` must run next (None: nothing held).
    pub fn deadline(&self) -> Option<Millis> {
        self.held.as_ref().map(|h| h.clear_at)
    }

    pub fn holds(&self) -> Option<&CopyKind> {
        self.held.as_ref().map(|h| &h.kind)
    }

    pub fn tick(&mut self, now: Millis) -> Option<Released> {
        if self.held.as_ref().is_some_and(|h| now >= h.clear_at) {
            self.release(now)
        } else {
            None
        }
    }

    /// Clear now if still ours (exit, window closed). If the clear fails, our value stays held
    /// and the clear is tried again from `tick` after RETRY: a failure never drops the timer.
    pub fn release(&mut self, now: Millis) -> Option<Released> {
        let h = self.held.take()?;
        let ours = match self.still_ours(&h) {
            Ok(ours) => ours,
            // Could not check (the clipboard could not be read): keep it and try again.
            Err(ClipError) => {
                self.held = Some(Held {
                    clear_at: now + RETRY,
                    ..h
                });
                return None;
            }
        };
        if !ours {
            return Some(Released {
                kind: h.kind,
                at: now,
                cleared: false,
            });
        }
        if self.backend.clear().is_err() {
            self.held = Some(Held {
                clear_at: now + RETRY,
                ..h
            });
            return None;
        }
        Some(Released {
            kind: h.kind,
            at: now,
            cleared: true,
        })
    }

    /// Ok(false) only when the clipboard surely holds something else (or nothing).
    fn still_ours(&mut self, h: &Held) -> Result<bool, ClipError> {
        match (h.count, self.backend.change_count()) {
            (Some(then), Some(now)) => Ok(then == now),
            _ => Ok(self
                .backend
                .read_text()?
                .is_some_and(|t| t.as_str() == h.value.as_str())),
        }
    }

    /// Paste from clipboard (A1): the text, without clearing it (it is the user's own copy).
    pub fn read_text(&mut self) -> Option<Zeroizing<String>> {
        self.backend.read_text().ok().flatten()
    }

    /// Quick drop (SPEC 7): takes text from the clipboard and clears it if nobody wrote between
    /// the read and the clear. Returns the text and whether the clipboard was cleared.
    pub fn take_text(&mut self) -> Option<(Zeroizing<String>, bool)> {
        let before = self.backend.change_count();
        let text = self.backend.read_text().ok()??;
        if text.is_empty() {
            return None;
        }
        let unchanged = match (before, self.backend.change_count()) {
            (Some(a), Some(b)) => a == b,
            _ => self
                .backend
                .read_text()
                .ok()
                .flatten()
                .is_some_and(|t| t.as_str() == text.as_str()),
        };
        let cleared = unchanged && self.backend.clear().is_ok();
        // Whatever of ours was there is gone now.
        if cleared {
            self.held = None;
        }
        Some((text, cleared))
    }
}

/// Clipboard for tests: a shared value with a change counter, and writes "from another app".
#[derive(Clone, Default)]
pub struct FakeClipboard {
    inner: Arc<Mutex<FakeInner>>,
}

#[derive(Default)]
struct FakeInner {
    value: Option<String>,
    count: i64,
    has_counter: bool,
    fail: bool,
    concealed: bool,
}

impl FakeClipboard {
    /// With an OS change counter (macOS, Windows) or without (Linux).
    pub fn new(has_counter: bool) -> FakeClipboard {
        let f = FakeClipboard::default();
        f.inner.lock().unwrap().has_counter = has_counter;
        f
    }
    pub fn value(&self) -> Option<String> {
        self.inner.lock().unwrap().value.clone()
    }
    pub fn concealed(&self) -> bool {
        self.inner.lock().unwrap().concealed
    }
    /// Another application copies something.
    pub fn external_write(&self, text: &str) {
        let mut i = self.inner.lock().unwrap();
        i.value = Some(text.to_owned());
        i.count += 1;
        i.concealed = false;
    }
    pub fn set_fail(&self, fail: bool) {
        self.inner.lock().unwrap().fail = fail;
    }
}

impl ClipboardBackend for FakeClipboard {
    fn write_concealed(&mut self, text: &str) -> Result<(), ClipError> {
        let mut i = self.inner.lock().unwrap();
        if i.fail {
            return Err(ClipError);
        }
        i.value = Some(text.to_owned());
        i.count += 1;
        i.concealed = true;
        Ok(())
    }
    fn read_text(&mut self) -> Result<Option<Zeroizing<String>>, ClipError> {
        let i = self.inner.lock().unwrap();
        if i.fail {
            return Err(ClipError);
        }
        Ok(i.value.clone().map(Zeroizing::new))
    }
    fn clear(&mut self) -> Result<(), ClipError> {
        let mut i = self.inner.lock().unwrap();
        if i.fail {
            return Err(ClipError);
        }
        i.value = None;
        i.count += 1;
        Ok(())
    }
    fn change_count(&mut self) -> Option<i64> {
        let i = self.inner.lock().unwrap();
        i.has_counter.then_some(i.count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn z(s: &str) -> Zeroizing<String> {
        Zeroizing::new(s.to_owned())
    }

    fn link() -> CopyKind {
        CopyKind::Link {
            entry: Some("e1".into()),
        }
    }

    #[test]
    fn clears_after_timeout_only_if_still_ours() {
        for counter in [true, false] {
            let fake = FakeClipboard::new(counter);
            let mut s = ClipboardService::new(Box::new(fake.clone()));
            s.copy(z("https://x/s/1#k"), link(), 0).unwrap();
            assert!(fake.concealed());
            assert_eq!(s.deadline(), Some(LINK_TIMEOUT));
            assert_eq!(s.tick(LINK_TIMEOUT - 1), None);
            assert_eq!(fake.value().as_deref(), Some("https://x/s/1#k"));
            let r = s.tick(LINK_TIMEOUT).unwrap();
            assert!(r.cleared, "counter={counter}");
            assert_eq!(fake.value(), None);
            assert_eq!(s.deadline(), None);

            // Someone else copied meanwhile: their value stays.
            s.copy(z("secret text"), CopyKind::Secret, 0).unwrap();
            assert_eq!(s.deadline(), Some(SECRET_TIMEOUT));
            fake.external_write("theirs");
            let r = s.tick(SECRET_TIMEOUT).unwrap();
            assert!(!r.cleared, "counter={counter}");
            assert_eq!(fake.value().as_deref(), Some("theirs"));
        }
    }

    #[test]
    fn counter_catches_the_same_text_written_again_by_another_app() {
        // With a counter a rewrite of the same text by someone else is not ours any more.
        let fake = FakeClipboard::new(true);
        let mut s = ClipboardService::new(Box::new(fake.clone()));
        s.copy(z("same"), CopyKind::Secret, 0).unwrap();
        fake.external_write("same");
        assert!(!s.release(1).unwrap().cleared);
        assert_eq!(fake.value().as_deref(), Some("same"));
    }

    #[test]
    fn new_copy_replaces_and_reports_the_old_one() {
        let fake = FakeClipboard::new(true);
        let mut s = ClipboardService::new(Box::new(fake.clone()));
        assert_eq!(s.copy(z("a"), link(), 0).unwrap(), None);
        let r = s.copy(z("b"), CopyKind::Secret, 5).unwrap().unwrap();
        assert_eq!(r.kind, link());
        assert!(!r.cleared);
        assert_eq!(s.holds(), Some(&CopyKind::Secret));
        assert!(s.release(6).unwrap().cleared);
        assert_eq!(s.release(7), None);
    }

    #[test]
    fn failing_clipboard() {
        let fake = FakeClipboard::new(true);
        let mut s = ClipboardService::new(Box::new(fake.clone()));
        fake.set_fail(true);
        assert_eq!(s.copy(z("a"), link(), 0), Err(ClipError));
        assert_eq!(s.deadline(), None);
        fake.set_fail(false);
        s.copy(z("a"), link(), 0).unwrap();
        // The clipboard is busy at the deadline: the value stays held and is cleared later.
        fake.set_fail(true);
        assert_eq!(s.tick(LINK_TIMEOUT), None);
        assert_eq!(s.deadline(), Some(LINK_TIMEOUT + RETRY));
        assert_eq!(fake.value().as_deref(), Some("a"));
        assert_eq!(
            s.release(LINK_TIMEOUT + 1),
            None,
            "quit while busy: still held"
        );
        fake.set_fail(false);
        let r = s.tick(LINK_TIMEOUT + 1 + RETRY).unwrap();
        assert!(r.cleared);
        assert_eq!(fake.value(), None);
        assert_eq!(s.deadline(), None);
    }

    #[test]
    fn unreadable_clipboard_without_a_counter_keeps_the_timer() {
        // Linux: no counter, the text is compared; a failed read is "unknown", not "not ours".
        let fake = FakeClipboard::new(false);
        let mut s = ClipboardService::new(Box::new(fake.clone()));
        s.copy(z("secret"), CopyKind::Secret, 0).unwrap();
        fake.set_fail(true);
        assert_eq!(s.tick(SECRET_TIMEOUT), None);
        assert_eq!(s.deadline(), Some(SECRET_TIMEOUT + RETRY));
        assert_eq!(
            s.release(SECRET_TIMEOUT + 1),
            None,
            "quit while unreadable: still held"
        );
        fake.set_fail(false);
        assert!(s.tick(SECRET_TIMEOUT + 1 + RETRY).unwrap().cleared);
        assert_eq!(fake.value(), None);
    }

    #[test]
    fn take_text_for_quick_drop() {
        let fake = FakeClipboard::new(true);
        let mut s = ClipboardService::new(Box::new(fake.clone()));
        assert_eq!(s.take_text(), None);
        fake.external_write("");
        assert_eq!(s.take_text(), None);
        fake.external_write("pa$$word");
        let (t, cleared) = s.take_text().unwrap();
        assert_eq!(t.as_str(), "pa$$word");
        assert!(cleared);
        assert_eq!(fake.value(), None);
    }
}
