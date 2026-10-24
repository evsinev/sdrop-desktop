//! The engine thread: owns the history (`Sent`) and the creates, so that nothing the UI thread
//! does (or waits on) can stall a disk write or a vault call, and nothing here waits on the UI.
//! The clipboard has its own thread (`clipthread`): a slow vault never delays its timers.
//! The UI sends `Cmd`s (and `ClipCmd`s) and gets `Event`s with snapshots. Network calls run on
//! their own threads and come back as commands.

use std::collections::BTreeMap;
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, channel};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use zeroize::Zeroizing;

use crate::clipboard::{ClipError, ClipboardService, CopyKind, Released};
use crate::clipthread::{self, ClipCmd, ClipNote};
use crate::history::Index;
use crate::quit::{CreateOp, CreatePhase};
use crate::sent::{Check, Draft, Effect, RevokeError, Sent, ServerCreated, create_on_server};
use crate::service::{ApiError, RevokeReply, SecretsApi, StatusReply};
use crate::time::{Clock, Millis};

pub type Api = Arc<Mutex<dyn SecretsApi>>;

/// Opens the history on the engine thread (loading and crash recovery read the vault, which may
/// block). Ok(moved): Some(path) when a damaged file was set aside.
pub type OpenHistory = Box<
    dyn FnOnce() -> Result<(Sent, Option<std::path::PathBuf>), crate::history::HistoryError> + Send,
>;

#[allow(clippy::large_enum_variant)]
pub enum Cmd {
    Create {
        op: u64,
        draft: Draft,
    },
    /// Retry the local steps of a create the service accepted.
    RetryLocal {
        op: u64,
    },
    /// Esc / leaving the screen: drop it if nothing would be lost, else keep it detached.
    DropCreate {
        op: u64,
    },
    /// After an unknown outcome, the user wants to create a new one (the form is kept).
    CreateAgain {
        op: u64,
    },
    /// From the clipboard thread: a link copied, a value released.
    Clip(ClipNote),
    Focus(bool),
    Woke,
    Revoke {
        id: String,
    },
    /// The recipient link for A2 (from the vault, off the UI thread).
    LoadLink {
        id: String,
    },
    ForgetSessionLink {
        id: String,
    },
    FetchLimit,
    /// A sign-in finished: read the Access token again.
    ResetCredentials,
    /// Publish once more and answer `done` (the UI waits for it before quitting).
    Shutdown {
        done: Sender<()>,
    },
    CreateAnswered {
        op: u64,
        result: Result<ServerCreated, ApiError>,
    },
    StatusAnswered {
        id: String,
        result: Result<StatusReply, ApiError>,
    },
    /// A queued check was not sent: the expiry came first.
    StatusSkipped {
        id: String,
    },
    StatusRoundDone,
    RevokeAnswered {
        id: String,
        result: Result<RevokeReply, ApiError>,
    },
    LimitAnswered(Result<usize, ApiError>),
}

#[derive(Clone)]
pub struct CreateView {
    pub op: u64,
    pub phase: CreatePhase,
    pub detached: bool,
    pub error: Option<ApiError>,
    /// The link while the local steps are missing (shown with Copy and Retry).
    pub recipient: Option<Zeroizing<String>>,
}

#[derive(Clone)]
pub struct Snapshot {
    pub index: Index,
    pub creates: Vec<CreateView>,
    pub limit: Option<usize>,
    pub vault_ok: bool,
}

pub enum Event {
    Snapshot(Box<Snapshot>),
    Created {
        op: u64,
        entry: String,
    },
    Notify {
        id: String,
        label: String,
        consumed_at: Millis,
    },
    Notice(String),
    Link {
        id: String,
        link: Option<Zeroizing<String>>,
    },
    ClipboardText {
        tag: u64,
        text: Option<Zeroizing<String>>,
        cleared: bool,
    },
    /// A create the engine could not start (no history or service): it never reached the service.
    CreateRejected {
        op: u64,
        reason: String,
    },
    /// The history was opened (or not): `error` disables creating, `moved` tells the user a
    /// damaged file was set aside.
    History {
        error: Option<String>,
        moved: bool,
    },
    /// What the clipboard thread holds and until when.
    Clip {
        holds: Option<CopyKind>,
        deadline: Option<Millis>,
    },
}

pub struct Engine {
    sent: Option<Sent>,
    clip: Sender<ClipCmd>,
    api: Option<Api>,
    clock: Arc<dyn Clock>,
    creates: BTreeMap<u64, CreateOp>,
    focused: bool,
    checking: bool,
    limit: Option<usize>,
    vault_ok: bool,
    tx: Sender<Cmd>,
    events: Sender<Event>,
    dirty: bool,
    /// The history revision last published.
    published: u64,
}

/// Starts the engine and clipboard threads. Returns the engine commands, the clipboard commands
/// and the event receiver.
pub fn start(
    open: Option<OpenHistory>,
    clip: ClipboardService,
    api: Option<Api>,
    clock: Arc<dyn Clock>,
) -> (Sender<Cmd>, Sender<ClipCmd>, Receiver<Event>) {
    let (tx, rx) = channel::<Cmd>();
    let (etx, erx) = channel::<Event>();
    let (to_engine, to_ui) = (tx.clone(), etx.clone());
    let clip = clipthread::start(clip, clock.clone(), move |note| match note {
        ClipNote::State { holds, deadline } => {
            let _ = to_ui.send(Event::Clip { holds, deadline });
        }
        ClipNote::Text { tag, text, cleared } => {
            let _ = to_ui.send(Event::ClipboardText { tag, text, cleared });
        }
        ClipNote::CopyFailed => {
            let _ = to_ui.send(Event::Notice(
                "Could not copy: the clipboard is not available.".into(),
            ));
        }
        n @ (ClipNote::LinkCopied { .. } | ClipNote::Released(_)) => {
            let _ = to_engine.send(Cmd::Clip(n));
        }
    });
    let mut e = Engine {
        sent: None,
        clip: clip.clone(),
        api,
        clock,
        creates: BTreeMap::new(),
        focused: true,
        checking: false,
        limit: None,
        // Checked on the engine thread (a vault call may block): assumed fine until then.
        vault_ok: true,
        tx: tx.clone(),
        events: etx,
        dirty: true,
        published: 0,
    };
    std::thread::Builder::new()
        .name("pnesecrets-engine".into())
        .spawn(move || {
            e.open(open);
            e.run(rx)
        })
        .expect("engine thread");
    (tx, clip, erx)
}

impl Engine {
    fn now(&self) -> Millis {
        self.clock.now()
    }

    fn open(&mut self, open: Option<OpenHistory>) {
        let Some(open) = open else { return };
        match open() {
            Ok((sent, moved)) => {
                self.vault_ok = sent.vault_works();
                self.sent = Some(sent);
                self.emit(Event::History {
                    error: None,
                    moved: moved.is_some(),
                });
            }
            Err(e) => self.emit(Event::History {
                error: Some(e.to_string()),
                moved: false,
            }),
        }
    }

    fn run(&mut self, rx: Receiver<Cmd>) {
        loop {
            match rx.recv_timeout(Duration::from_millis(250)) {
                Ok(Cmd::Shutdown { done }) => {
                    self.publish();
                    let _ = done.send(());
                }
                Ok(cmd) => self.handle(cmd),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => return,
            }
            self.tick();
            // Any write to the history (expiry, purge, a status) reaches the UI.
            if self.sent.as_ref().map_or(0, Sent::revision) != self.published {
                self.dirty = true;
            }
            if self.dirty {
                self.publish();
            }
        }
    }

    fn emit(&self, e: Event) {
        let _ = self.events.send(e);
    }

    fn publish(&mut self) {
        self.dirty = false;
        self.published = self.sent.as_ref().map_or(0, Sent::revision);
        let snap = Snapshot {
            index: self
                .sent
                .as_ref()
                .map(|s| s.index().clone())
                .unwrap_or_default(),
            creates: self
                .creates
                .iter()
                .map(|(op, c)| CreateView {
                    op: *op,
                    phase: c.phase(),
                    detached: c.detached(),
                    error: c.error().cloned(),
                    recipient: c
                        .created()
                        .filter(|_| c.phase() == CreatePhase::NotSavedLocally)
                        .map(|sc| sc.recipient.clone()),
                })
                .collect(),
            limit: self.limit,
            vault_ok: self.vault_ok,
        };
        self.emit(Event::Snapshot(Box::new(snap)));
    }

    fn released(&mut self, r: Released) {
        if let Some(s) = self.sent.as_mut() {
            s.clipboard_released(&r);
        }
        self.dirty = true;
    }

    fn effects(&mut self, effects: Vec<Effect>) {
        for e in effects {
            let Effect::Notify {
                id,
                label,
                consumed_at,
            } = e;
            self.emit(Event::Notify {
                id,
                label,
                consumed_at,
            });
            self.dirty = true;
        }
    }

    fn handle(&mut self, cmd: Cmd) {
        let now = self.now();
        self.dirty = true;
        match cmd {
            Cmd::Create { op, draft } => self.create(op, draft),
            Cmd::CreateAnswered { op, result } => {
                if let Some(c) = self.creates.get_mut(&op) {
                    c.answered(result);
                }
                self.finish(op);
            }
            Cmd::RetryLocal { op } => self.finish(op),
            Cmd::DropCreate { op } => {
                if self.creates.get_mut(&op).is_none_or(|c| c.cancel()) {
                    self.creates.remove(&op);
                }
            }
            Cmd::CreateAgain { op } => {
                self.creates.remove(&op);
            }
            Cmd::Clip(ClipNote::LinkCopied { entry, at }) => {
                if let Some(s) = self.sent.as_mut() {
                    s.link_copied(&entry, at);
                }
            }
            Cmd::Clip(ClipNote::Released(r)) => self.released(r),
            Cmd::Clip(_) => {}
            Cmd::Focus(f) => self.focused = f,
            Cmd::Woke => {
                if let Some(s) = self.sent.as_mut() {
                    s.woke();
                }
            }
            Cmd::Revoke { id } => self.revoke(id),
            Cmd::RevokeAnswered { id, result } => {
                let Some(s) = self.sent.as_mut() else { return };
                let (r, effects) = s.apply_revoke(&id, result, now);
                self.effects(effects);
                if let Err(e) = r {
                    self.emit(Event::Notice(match e {
                        RevokeError::Api(e) => format!("Revoke failed: {e}"),
                        _ => {
                            "Revoke: the result could not be saved yet; it is kept and saved later."
                                .into()
                        }
                    }));
                }
            }
            Cmd::LoadLink { id } => {
                let link = self.sent.as_ref().and_then(|s| s.recipient_link(&id, now));
                self.emit(Event::Link { id, link });
            }
            Cmd::ForgetSessionLink { id } => {
                if let Some(s) = self.sent.as_mut() {
                    s.forget_session_link(&id);
                }
            }
            Cmd::FetchLimit => self.fetch_limit(),
            Cmd::ResetCredentials => {
                if let Some(api) = &self.api {
                    api.lock().unwrap().reset_credentials();
                }
                self.fetch_limit();
            }
            Cmd::LimitAnswered(r) => {
                if let Ok(n) = r {
                    self.limit = Some(n);
                }
            }
            Cmd::StatusAnswered { id, result } => {
                let effects = self
                    .sent
                    .as_mut()
                    .map(|s| s.apply_status(&id, result, now))
                    .unwrap_or_default();
                self.effects(effects);
            }
            Cmd::StatusSkipped { id } => {
                if let Some(s) = self.sent.as_mut() {
                    s.check_skipped(&id);
                }
            }
            Cmd::StatusRoundDone => self.checking = false,
            Cmd::Shutdown { .. } => {}
        }
    }

    fn create(&mut self, op: u64, draft: Draft) {
        let (Some(api), true) = (self.api.clone(), self.sent.is_some()) else {
            // Every accepted op gets an outcome: this one never reached the service.
            self.emit(Event::CreateRejected {
                op,
                reason: "Creating is not available: the history could not be opened.".into(),
            });
            return;
        };
        let mut c = CreateOp::new();
        if !c.start() || self.creates.contains_key(&op) {
            return;
        }
        self.creates.insert(op, c);
        let tx = self.tx.clone();
        let clock = self.clock.clone();
        std::thread::spawn(move || {
            let result = {
                let mut a = api.lock().unwrap();
                create_on_server(&mut *a, &draft, clock.now())
            };
            drop(draft);
            let _ = tx.send(Cmd::CreateAnswered { op, result });
        });
    }

    fn finish(&mut self, op: u64) {
        let now = self.now();
        let (Some(c), Some(sent)) = (self.creates.get_mut(&op), self.sent.as_mut()) else {
            return;
        };
        if c.phase() != CreatePhase::NotSavedLocally {
            return;
        }
        let Some(sc) = c.created_mut() else { return };
        let clip = self.clip.clone();
        // The link goes to the clipboard thread; a stuck clipboard is a failed step, retried.
        let copy = move |text: Zeroizing<String>, kind: CopyKind| {
            let (reply, wait) = channel();
            clip.send(ClipCmd::Copy {
                text,
                kind,
                reply: Some(reply),
            })
            .map_err(|_| ClipError)?;
            wait.recv_timeout(Duration::from_secs(3))
                .map_err(|_| ClipError)?
        };
        if let Ok(released) = sent.finish(sc, copy, now) {
            let entry = sc.local_id.clone();
            let tracked = sent.entry(&entry).is_some_and(|e| e.tracked);
            c.local_done();
            self.creates.remove(&op);
            if let Some(r) = released {
                self.released(r);
            }
            if !tracked {
                self.vault_ok = false;
            }
            self.emit(Event::Created { op, entry });
        }
    }

    fn revoke(&mut self, id: String) {
        let now = self.now();
        let (Some(api), Some(s)) = (self.api.clone(), self.sent.as_mut()) else {
            return;
        };
        let Ok(owner) = s.revoke_target(&id, now) else {
            self.emit(Event::Notice(
                "This secret can no longer be revoked.".into(),
            ));
            return;
        };
        let tx = self.tx.clone();
        std::thread::spawn(move || {
            let result = api.lock().unwrap().revoke(&owner);
            let _ = tx.send(Cmd::RevokeAnswered { id, result });
        });
    }

    fn fetch_limit(&mut self) {
        let (None, Some(api)) = (self.limit, self.api.clone()) else {
            return;
        };
        let tx = self.tx.clone();
        std::thread::spawn(move || {
            let r = api.lock().unwrap().limit();
            let _ = tx.send(Cmd::LimitAnswered(r));
        });
    }

    /// Timers: kept answers, expiry, the purge, and one status round at a time.
    fn tick(&mut self) {
        let now = self.now();
        let Some(sent) = self.sent.as_mut() else {
            return;
        };
        let effects = sent.tick(now);
        let checks: Vec<Check> = if self.checking {
            Vec::new()
        } else {
            sent.due_checks(now, self.focused)
        };
        self.effects(effects);
        let Some(api) = self.api.clone() else { return };
        if checks.is_empty() {
            return;
        }
        self.checking = true;
        self.dirty = true;
        let tx = self.tx.clone();
        // Every Check ends in StatusAnswered or StatusSkipped (sdrop's agent times out after
        // 60 s). Its expiry is checked right before sending: earlier ones may have taken long.
        std::thread::spawn(move || {
            for c in checks {
                let result = api.lock().unwrap().status_until(&c.owner, c.expires_at);
                let _ = tx.send(match result {
                    // Never sent (the expiry came first, also before a retry after Access).
                    Err(ApiError::TooLate) => Cmd::StatusSkipped { id: c.id },
                    result => Cmd::StatusAnswered { id: c.id, result },
                });
            }
            let _ = tx.send(Cmd::StatusRoundDone);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clipboard::FakeClipboard;
    use crate::fake::{FakeApi, ORIGIN};
    use crate::history::HistoryStore;
    use crate::time::ManualClock;
    use crate::vault::MemVault;
    use sdrop::api::Origin;

    fn wait<T>(rx: &Receiver<Event>, mut f: impl FnMut(&Event) -> Option<T>) -> T {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            let e = rx.recv_timeout(left).expect("event in time");
            if let Some(t) = f(&e) {
                return t;
            }
        }
    }

    #[test]
    fn create_runs_off_the_caller_and_reports() {
        let dir = std::env::temp_dir().join(format!(
            "pnesecrets-engine-{}",
            crate::history::new_local_id()
        ));
        let clock = ManualClock::at(1_792_670_400_000);
        let api = FakeApi::new(clock.clone());
        let vault = MemVault::default();
        let fake_clip = FakeClipboard::new(true);
        let (d, v, c) = (dir.clone(), vault.clone(), clock.clone());
        let open: OpenHistory = Box::new(move || {
            Sent::open(
                HistoryStore::new(&d),
                Box::new(v),
                Origin::parse(ORIGIN).unwrap(),
                c.now(),
            )
        });
        let api_dyn: Api = Arc::new(Mutex::new(api.clone()));
        let (tx, clip_tx, rx) = start(
            Some(open),
            ClipboardService::new(Box::new(fake_clip.clone())),
            Some(api_dyn),
            Arc::new(clock.clone()),
        );
        tx.send(Cmd::Create {
            op: 7,
            draft: Draft {
                text: Zeroizing::new("pw".into()),
                files: vec![],
                passphrase: None,
                ttl: 3600,
                label: "x".into(),
                notify: true,
            },
        })
        .unwrap();
        let entry = wait(&rx, |e| match e {
            Event::Created { op: 7, entry } => Some(entry.clone()),
            _ => None,
        });
        assert!(fake_clip.value().unwrap().contains("/s/"));
        assert_eq!(vault.ids(), vec![entry.clone()]);
        assert_eq!(api.calls("create"), 1);
        tx.send(Cmd::LoadLink { id: entry.clone() }).unwrap();
        let link = wait(&rx, |e| match e {
            Event::Link { id, link } if *id == entry => Some(link.clone()),
            _ => None,
        });
        assert_eq!(
            link.as_deref().map(|s| s.as_str()),
            fake_clip.value().as_deref()
        );
        // The clipboard thread clears our value on shutdown.
        let (done_tx, done_rx) = channel();
        clip_tx.send(ClipCmd::Shutdown { done: done_tx }).unwrap();
        done_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(fake_clip.value(), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_stuck_vault_does_not_delay_the_clipboard_timer() {
        // Once armed, the vault blocks every call until released and says when it was entered.
        struct SlowVault {
            armed: Arc<std::sync::atomic::AtomicBool>,
            gate: Arc<Mutex<()>>,
            entered: Mutex<Sender<()>>,
        }
        impl SlowVault {
            fn wait(&self) {
                if self.armed.load(std::sync::atomic::Ordering::SeqCst) {
                    let _ = self.entered.lock().unwrap().send(());
                    let _g = self.gate.lock().unwrap();
                }
            }
        }
        impl crate::vault::Vault for SlowVault {
            fn put(
                &self,
                _: &str,
                _: &crate::vault::Links,
            ) -> Result<(), crate::vault::VaultError> {
                self.wait();
                Ok(())
            }
            fn get(
                &self,
                _: &str,
            ) -> Result<Option<crate::vault::Links>, crate::vault::VaultError> {
                self.wait();
                Ok(None)
            }
            fn delete(&self, _: &str) -> Result<(), crate::vault::VaultError> {
                self.wait();
                Ok(())
            }
        }
        let dir = std::env::temp_dir().join(format!(
            "pnesecrets-engine-{}",
            crate::history::new_local_id()
        ));
        let clock = ManualClock::at(1_792_670_400_000);
        // A waiting secret: the engine polls it, which reads the vault.
        let mut index = crate::history::Index::new();
        index.entries.push(crate::history::Entry {
            id: "0123456789abcdef0123456789abcdef".into(),
            label: String::new(),
            created_at: clock.now(),
            expires_at: clock.now() + crate::time::DAY,
            ttl: 86400,
            status: crate::history::Status::Waiting,
            status_at: clock.now(),
            checked_at: None,
            stored_seen_at: None,
            notified_at: None,
            vault: crate::history::VaultState::Present,
            tracked: true,
            passphrase: false,
            notify: true,
            text_lines: Some(1),
            files: vec![],
            link_copied_at: None,
            clipboard_cleared_at: None,
            consumed_at: None,
            consumed_by: None,
            revoked_at: None,
            server: "secrets.example.com".into(),
        });
        HistoryStore::new(&dir).save(&index).unwrap();
        let armed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let gate = Arc::new(Mutex::new(()));
        let (entered_tx, entered) = channel();
        let (d, c) = (dir.clone(), clock.clone());
        let slow = SlowVault {
            armed: armed.clone(),
            gate: gate.clone(),
            entered: Mutex::new(entered_tx),
        };
        let open: OpenHistory = Box::new(move || {
            Sent::open(
                HistoryStore::new(&d),
                Box::new(slow),
                Origin::parse(ORIGIN).unwrap(),
                c.now(),
            )
        });
        let fake_clip = FakeClipboard::new(true);
        let api: Api = Arc::new(Mutex::new(FakeApi::new(clock.clone())));
        // Armed and closed before the engine starts: its first poll hangs in the vault.
        let held = gate.lock().unwrap();
        armed.store(true, std::sync::atomic::Ordering::SeqCst);
        let (_tx, clip_tx, _rx) = start(
            Some(open),
            ClipboardService::new(Box::new(fake_clip.clone())),
            Some(api),
            Arc::new(clock.clone()),
        );
        entered
            .recv_timeout(Duration::from_secs(5))
            .expect("the engine is inside the vault");
        clip_tx
            .send(ClipCmd::Copy {
                text: Zeroizing::new("secret".into()),
                kind: CopyKind::Secret,
                reply: None,
            })
            .unwrap();
        let until = std::time::Instant::now() + Duration::from_secs(3);
        while fake_clip.value().is_none() && std::time::Instant::now() < until {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(fake_clip.value().as_deref(), Some("secret"));
        clock.advance(crate::clipboard::SECRET_TIMEOUT);
        let until = std::time::Instant::now() + Duration::from_secs(3);
        while fake_clip.value().is_some() && std::time::Instant::now() < until {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(
            fake_clip.value(),
            None,
            "cleared while the engine hangs in the vault"
        );
        armed.store(false, std::sync::atomic::Ordering::SeqCst);
        drop(held);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn expiry_without_polling_still_reaches_the_ui() {
        // An untracked waiting secret: no status requests, no notification; only the expiry.
        let dir = std::env::temp_dir().join(format!(
            "pnesecrets-engine-{}",
            crate::history::new_local_id()
        ));
        let clock = ManualClock::at(1_792_670_400_000);
        let mut index = crate::history::Index::new();
        index.entries.push(crate::history::Entry {
            id: "0123456789abcdef0123456789abcdef".into(),
            label: String::new(),
            created_at: clock.now(),
            expires_at: clock.now() + crate::time::HOUR,
            ttl: 3600,
            status: crate::history::Status::Waiting,
            status_at: clock.now(),
            checked_at: None,
            stored_seen_at: None,
            notified_at: None,
            vault: crate::history::VaultState::None,
            tracked: false,
            passphrase: false,
            notify: true,
            text_lines: Some(1),
            files: vec![],
            link_copied_at: None,
            clipboard_cleared_at: None,
            consumed_at: None,
            consumed_by: None,
            revoked_at: None,
            server: "secrets.example.com".into(),
        });
        HistoryStore::new(&dir).save(&index).unwrap();
        let (d, c) = (dir.clone(), clock.clone());
        let open: OpenHistory = Box::new(move || {
            Sent::open(
                HistoryStore::new(&d),
                Box::new(MemVault::default()),
                Origin::parse(ORIGIN).unwrap(),
                c.now(),
            )
        });
        let (_tx, _clip, rx) = start(
            Some(open),
            ClipboardService::new(Box::new(FakeClipboard::new(true))),
            None,
            Arc::new(clock.clone()),
        );
        wait(&rx, |e| match e {
            Event::Snapshot(s) if s.index.entries.len() == 1 => Some(()),
            _ => None,
        });
        clock.advance(crate::time::HOUR);
        wait(&rx, |e| match e {
            Event::Snapshot(s)
                if s.index.entries[0].status == crate::history::Status::ExpiredUnknown =>
            {
                Some(())
            }
            _ => None,
        });
        let _ = std::fs::remove_dir_all(&dir);
    }
}
