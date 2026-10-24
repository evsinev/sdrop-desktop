//! A received secret (SPEC 8): one session per opened link, owned by the application, not by a
//! window. The link is parsed before any request; consume happens at most once per session; the
//! envelope is kept for passphrase retries; the secret is destroyed only when the user confirms.

use crate::service::ApiError;
use crate::time::Millis;
use sdrop::api::{Origin, parse_recipient_link};
use sdrop::format::{self, FormatError, Key, Secret};
use zeroize::Zeroizing;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Gone {
    /// 404: not found, already read, revoked or expired.
    NotFound,
    /// The envelope fails the format checks, or the key does not open it: nothing is shown.
    Damaged,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Phase {
    /// Parsed; nothing requested yet. `error` may tell why the last attempt did not go through.
    Ready,
    Consuming,
    /// The envelope is here and needs the passphrase (no `~p`, or none entered yet).
    NeedPassphrase,
    /// The passphrase did not open the envelope; it is kept for another try.
    WrongPassphrase,
    Revealed,
    Gone(Gone),
    /// The connection broke during consume: the secret may already be destroyed.
    Unknown,
    Destroyed,
}

/// What closing the window of this session does (SPEC 8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnClose {
    /// Nothing worth keeping: close and drop the session.
    Drop,
    /// Consume in flight: close the window, keep the session; the result opens it again.
    KeepInBackground,
    /// The secret is here and not all saved to files: ask, Cancel is the default.
    Confirm,
}

pub struct ReceivedFile {
    /// From the sender: shown, suggested in the save dialog, never used as a path by itself.
    pub name: Zeroizing<String>,
    pub data: Zeroizing<Vec<u8>>,
    pub saved: bool,
}

pub struct Received {
    pub text: Zeroizing<String>,
    pub text_saved: bool,
    pub files: Vec<ReceivedFile>,
}

impl Received {
    fn from_secret(s: Secret) -> Received {
        let file = |(name, data): (Zeroizing<String>, Zeroizing<Vec<u8>>)| ReceivedFile {
            name,
            data,
            saved: false,
        };
        match s {
            Secret::Text(text) => Received {
                text,
                text_saved: false,
                files: Vec::new(),
            },
            Secret::File { name, data } => Received {
                text: Zeroizing::new(String::new()),
                text_saved: false,
                files: vec![file((name, data))],
            },
            Secret::Bundle { text, files } => Received {
                text,
                text_saved: false,
                files: files.into_iter().map(file).collect(),
            },
        }
    }

    /// Everything that can be saved to a file was (Copy does not count, SPEC 8).
    pub fn all_saved(&self) -> bool {
        (self.text.is_empty() || self.text_saved) && self.files.iter().all(|f| f.saved)
    }
}

pub struct Receipt {
    id: String,
    key: Key,
    hint: bool,
    host: String,
    phase: Phase,
    envelope: Option<Zeroizing<Vec<u8>>>,
    received: Option<Received>,
    opened_at: Option<Millis>,
    error: Option<ApiError>,
}

impl Receipt {
    /// Parses against the trusted origin; a broken or foreign link makes no request.
    pub fn open(origin: &Origin, url: &str) -> Result<Receipt, ApiError> {
        let link = parse_recipient_link(origin, url.trim())
            .map_err(|_| ApiError::Format(FormatError::BadLink))?;
        Ok(Receipt {
            id: link.id,
            key: link.key,
            hint: link.passphrase_hint,
            host: origin
                .as_str()
                .split_once("://")
                .map_or("", |(_, h)| h)
                .to_owned(),
            phase: Phase::Ready,
            envelope: None,
            received: None,
            opened_at: None,
            error: None,
        })
    }

    pub fn phase(&self) -> &Phase {
        &self.phase
    }

    /// The link says `~p`: ask for the passphrase before Reveal.
    pub fn passphrase_hint(&self) -> bool {
        self.hint
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn error(&self) -> Option<&ApiError> {
        self.error.as_ref()
    }

    pub fn received(&self) -> Option<&Received> {
        self.received.as_ref()
    }

    pub fn opened_at(&self) -> Option<Millis> {
        self.opened_at
    }

    /// Reveal pressed: the server id to consume, once. Any later call returns None.
    pub fn begin(&mut self) -> Option<String> {
        if self.phase != Phase::Ready {
            return None;
        }
        self.phase = Phase::Consuming;
        self.error = None;
        Some(self.id.clone())
    }

    /// After `Unknown`, the user may try again explicitly (it may answer 404).
    pub fn retry_after_unknown(&mut self) -> bool {
        if self.phase != Phase::Unknown {
            return false;
        }
        self.phase = Phase::Ready;
        true
    }

    /// The consume answer. `passphrase`: entered before Reveal (with `~p`), or None.
    /// Slow with a passphrase (PBKDF2): call off the UI thread.
    pub fn consumed(
        &mut self,
        result: Result<Zeroizing<Vec<u8>>, ApiError>,
        passphrase: Option<&str>,
        now: Millis,
    ) {
        if self.phase != Phase::Consuming {
            return;
        }
        match result {
            Ok(envelope) => {
                self.opened_at = Some(now);
                self.envelope = Some(envelope);
                self.decrypt(passphrase.filter(|p| !p.is_empty()));
            }
            Err(ApiError::NotFound) => self.phase = Phase::Gone(Gone::NotFound),
            // Refused before the service consumed anything: safe to try again.
            Err(e @ (ApiError::SignInRequired | ApiError::Denied | ApiError::TooManyRequests)) => {
                self.phase = Phase::Ready;
                self.error = Some(e);
            }
            // The request may have reached the service: say so, never retry silently.
            Err(_) => self.phase = Phase::Unknown,
        }
    }

    /// Another passphrase for the kept envelope; an empty one is not an attempt.
    pub fn try_passphrase(&mut self, passphrase: &str) {
        if !matches!(self.phase, Phase::NeedPassphrase | Phase::WrongPassphrase)
            || passphrase.is_empty()
        {
            return;
        }
        self.decrypt(Some(passphrase));
    }

    fn decrypt(&mut self, passphrase: Option<&str>) {
        let Some(env) = self.envelope.as_ref() else {
            return;
        };
        match format::decrypt(env, &self.key, passphrase) {
            Ok(secret) => {
                self.received = Some(Received::from_secret(secret));
                self.envelope = None;
                self.phase = Phase::Revealed;
            }
            Err(FormatError::NeedPassphrase) => self.phase = Phase::NeedPassphrase,
            // With a passphrase it may be a typo: keep the envelope. Without one, the key itself
            // does not open it: nothing to try.
            Err(FormatError::DecryptFailed) if passphrase.is_some() => {
                self.phase = Phase::WrongPassphrase
            }
            Err(_) => {
                self.envelope = None;
                self.phase = Phase::Gone(Gone::Damaged);
            }
        }
    }

    pub fn mark_text_saved(&mut self) {
        if let Some(r) = self.received.as_mut() {
            r.text_saved = true;
        }
    }

    pub fn mark_file_saved(&mut self, index: usize) {
        if let Some(f) = self.received.as_mut().and_then(|r| r.files.get_mut(index)) {
            f.saved = true;
        }
    }

    pub fn on_close(&self) -> OnClose {
        match &self.phase {
            Phase::Consuming => OnClose::KeepInBackground,
            Phase::NeedPassphrase | Phase::WrongPassphrase => OnClose::Confirm,
            Phase::Revealed if !self.received.as_ref().is_some_and(Received::all_saved) => {
                OnClose::Confirm
            }
            _ => OnClose::Drop,
        }
    }

    /// Holds something that quitting would lose (SPEC 8, quit coordinator).
    pub fn blocks_quit(&self) -> bool {
        self.on_close() != OnClose::Drop
    }

    /// The user confirmed: wipe the envelope and the secret.
    pub fn destroy(&mut self) {
        self.envelope = None;
        self.received = None;
        self.phase = Phase::Destroyed;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake::{FakeApi, ORIGIN};
    use crate::service::SecretsApi;
    use crate::time::{HOUR, ManualClock};
    use sdrop::format::Content;

    const T0: Millis = 1_792_670_400_000;

    fn origin() -> Origin {
        Origin::parse(ORIGIN).unwrap()
    }

    fn make(api: &mut FakeApi, content: &Content, passphrase: Option<&str>) -> String {
        api.create(content, passphrase, 3600)
            .unwrap()
            .recipient
            .to_string()
    }

    fn reveal(api: &mut FakeApi, r: &mut Receipt, passphrase: Option<&str>) {
        let id = r.begin().unwrap();
        let res = api.consume(&id);
        r.consumed(res, passphrase, T0);
    }

    #[test]
    fn broken_and_foreign_links_make_no_request() {
        let api = FakeApi::new(ManualClock::at(T0));
        let id = "a".repeat(64);
        let key = "A".repeat(43);
        for bad in [
            String::new(),
            format!("{ORIGIN}/s/{id}"),
            format!("{ORIGIN}/s/{id}#short"),
            format!("{ORIGIN}/o/{id}#{key}"),
            format!("https://evil.example.com/s/{id}#{key}"),
            format!("{ORIGIN}/s/{}#{key}", "A".repeat(64)),
        ] {
            assert!(Receipt::open(&origin(), &bad).is_err(), "{bad}");
        }
        assert!(Receipt::open(&origin(), &format!("  {ORIGIN}/s/{id}#{key}\n")).is_ok());
        assert_eq!(api.calls("consume"), 0);
    }

    #[test]
    fn text_and_files_revealed_once() {
        let mut api = FakeApi::new(ManualClock::at(T0));
        let link = make(
            &mut api,
            &Content::Bundle {
                text: "DB_HOST=stage",
                files: vec![("stage-ca.pem", b"cert")],
            },
            None,
        );
        let mut r = Receipt::open(&origin(), &link).unwrap();
        assert_eq!(
            api.calls("consume"),
            0,
            "opening the window requests nothing"
        );
        assert_eq!(r.on_close(), OnClose::Drop);
        reveal(&mut api, &mut r, None);
        assert_eq!(r.phase(), &Phase::Revealed);
        assert_eq!(r.begin(), None, "a second Reveal does not consume again");
        let got = r.received().unwrap();
        assert_eq!(got.text.as_str(), "DB_HOST=stage");
        assert_eq!(got.files[0].name.as_str(), "stage-ca.pem");
        assert_eq!(got.files[0].data.as_slice(), b"cert");
        assert_eq!(api.calls("consume"), 1);
        assert_eq!(r.opened_at(), Some(T0));
        // Copy is not saving: closing asks until text and files are saved.
        assert_eq!(r.on_close(), OnClose::Confirm);
        r.mark_text_saved();
        assert_eq!(r.on_close(), OnClose::Confirm);
        r.mark_file_saved(0);
        assert_eq!(r.on_close(), OnClose::Drop);
        r.destroy();
        assert!(r.received().is_none());
    }

    #[test]
    fn passphrase_after_consume_retries_locally() {
        let mut api = FakeApi::new(ManualClock::at(T0));
        let link = make(&mut api, &Content::Text("secret"), Some("tame-otter"));
        // The ~p hint lost on the way: the envelope flag decides.
        let link = link.trim_end_matches("~p").to_owned();
        let mut r = Receipt::open(&origin(), &link).unwrap();
        assert!(!r.passphrase_hint());
        reveal(&mut api, &mut r, None);
        assert_eq!(r.phase(), &Phase::NeedPassphrase);
        assert_eq!(r.on_close(), OnClose::Confirm);
        assert!(r.blocks_quit());
        r.try_passphrase("");
        assert_eq!(r.phase(), &Phase::NeedPassphrase, "empty is not an attempt");
        r.try_passphrase("wrong");
        assert_eq!(r.phase(), &Phase::WrongPassphrase);
        r.try_passphrase("tame-otter");
        assert_eq!(r.phase(), &Phase::Revealed);
        assert_eq!(r.received().unwrap().text.as_str(), "secret");
        assert_eq!(api.calls("consume"), 1);
    }

    #[test]
    fn passphrase_before_reveal_with_hint() {
        let mut api = FakeApi::new(ManualClock::at(T0));
        let link = make(&mut api, &Content::Text("s"), Some("pw"));
        let mut r = Receipt::open(&origin(), &link).unwrap();
        assert!(r.passphrase_hint());
        reveal(&mut api, &mut r, Some("typo"));
        assert_eq!(r.phase(), &Phase::WrongPassphrase);
        r.try_passphrase("pw");
        assert_eq!(r.phase(), &Phase::Revealed);
    }

    #[test]
    fn not_found_damaged_unknown_and_refused() {
        let clock = ManualClock::at(T0);
        let mut api = FakeApi::new(clock.clone());
        let link = make(&mut api, &Content::Text("s"), None);
        let mut first = Receipt::open(&origin(), &link).unwrap();
        reveal(&mut api, &mut first, None);
        let mut second = Receipt::open(&origin(), &link).unwrap();
        reveal(&mut api, &mut second, None);
        assert_eq!(second.phase(), &Phase::Gone(Gone::NotFound));
        assert_eq!(second.on_close(), OnClose::Drop);

        // A wrong key without a passphrase: damaged, nothing to retry.
        let link = make(&mut api, &Content::Text("s"), None);
        let (head, _) = link.split_once('#').unwrap();
        let other = format!("{head}#{}", format::encode_base64url(&[9u8; 32]));
        let mut r = Receipt::open(&origin(), &other).unwrap();
        reveal(&mut api, &mut r, None);
        assert_eq!(r.phase(), &Phase::Gone(Gone::Damaged));

        // The answer is lost: unknown, never retried by itself.
        let link = make(&mut api, &Content::Text("s"), None);
        let mut r = Receipt::open(&origin(), &link).unwrap();
        api.lose_next_answer("consume");
        reveal(&mut api, &mut r, None);
        assert_eq!(r.phase(), &Phase::Unknown);
        assert_eq!(r.begin(), None);
        assert!(r.retry_after_unknown());
        reveal(&mut api, &mut r, None);
        assert_eq!(r.phase(), &Phase::Gone(Gone::NotFound));

        // Sign-in needed: nothing consumed, Reveal works again after it.
        let link = make(&mut api, &Content::Text("s"), None);
        let mut r = Receipt::open(&origin(), &link).unwrap();
        api.fail_next("consume", ApiError::SignInRequired);
        reveal(&mut api, &mut r, None);
        assert_eq!(r.phase(), &Phase::Ready);
        assert_eq!(r.error(), Some(&ApiError::SignInRequired));
        reveal(&mut api, &mut r, None);
        assert_eq!(r.phase(), &Phase::Revealed);

        // Expired on the server.
        let link = make(&mut api, &Content::Text("s"), None);
        clock.advance(2 * HOUR);
        let mut r = Receipt::open(&origin(), &link).unwrap();
        reveal(&mut api, &mut r, None);
        assert_eq!(r.phase(), &Phase::Gone(Gone::NotFound));
    }

    #[test]
    fn closing_during_consume_keeps_the_session() {
        let mut api = FakeApi::new(ManualClock::at(T0));
        let link = make(
            &mut api,
            &Content::File {
                name: "k",
                data: b"x",
            },
            None,
        );
        let mut r = Receipt::open(&origin(), &link).unwrap();
        let id = r.begin().unwrap();
        assert_eq!(r.on_close(), OnClose::KeepInBackground);
        assert!(r.blocks_quit());
        // The window is closed; the answer comes later and is not lost.
        let res = api.consume(&id);
        r.consumed(res, None, T0);
        assert_eq!(r.phase(), &Phase::Revealed);
        assert_eq!(r.received().unwrap().files.len(), 1);
        assert!(r.received().unwrap().text.is_empty());
        assert_eq!(r.on_close(), OnClose::Confirm);
    }
}
