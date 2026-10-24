//! The UI side of the application: a snapshot of the engine thread (history, creates, clipboard)
//! plus the received-secret sessions. Nothing here touches the disk, the vault or the network on
//! the UI thread: the engine owns those, receipts consume and decrypt on the background executor.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use gpui_kit::*;
use pnesecrets_core::clipboard::{ClipboardService, CopyKind};
use pnesecrets_core::clipthread::ClipCmd;
use pnesecrets_core::engine::{self, Cmd, CreateView, Event, Snapshot};
use pnesecrets_core::history::{Entry, HistoryStore};
use pnesecrets_core::quit::{Blocker, CreatePhase};
use pnesecrets_core::receive::{OnClose, Receipt};
use pnesecrets_core::sdrop::api::Origin;
use pnesecrets_core::sent::{Draft, Sent};
use pnesecrets_core::service::{ApiError, SecretsApi, Service};
use pnesecrets_core::time::{Clock, Millis, SystemClock};
use pnesecrets_core::vault::KeyringVault;
use zeroize::Zeroizing;

use crate::platform;

pub fn now() -> Millis {
    SystemClock.now()
}

/// What the main window shows on the right.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Screen {
    New,
    Status(String),
    /// A create whose local steps failed (link, Copy, Retry) or whose outcome is unknown.
    Create(u64),
}

/// Settings carried to A1 by "Send again" (the secret itself is never kept).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Preset {
    pub ttl: u32,
    pub passphrase: bool,
}

#[derive(Clone)]
pub enum ModelEvent {
    /// A create finished: its form clears itself right away.
    Created { op: u64 },
    /// A create failed before reaching the service (the form shows the error, keeps its fields).
    CreateFailed {
        op: u64,
        error: String,
        sign_in: bool,
    },
    /// A received secret changed (its window re-renders or reopens).
    Receipt(u64),
    /// A create from quick drop needs the main window (partial success, unknown outcome).
    ShowMain,
    /// Text read from the clipboard for a request tagged `tag`.
    ClipboardText {
        tag: u64,
        text: Option<Zeroizing<String>>,
        cleared: bool,
    },
}

/// A received secret; `None` while a background step (consume, PBKDF2) holds it.
pub struct ReceiptSlot {
    pub receipt: Option<Receipt>,
    pub window: Option<AnyWindowHandle>,
}

pub struct AppModel {
    pub origin: Option<Origin>,
    pub origin_error: Option<String>,
    pub history_error: Option<String>,
    pub history_note: Option<String>,
    /// The engine opened the history (creating waits for it).
    pub history_ready: bool,
    tx: Sender<Cmd>,
    clip: Sender<ClipCmd>,
    events: Receiver<Event>,
    /// What the clipboard thread holds (for "Copied · clears in N s").
    pub clip_holds: Option<CopyKind>,
    pub clip_deadline: Option<Millis>,
    receive_service: Option<Arc<Mutex<Service>>>,
    pub snap: Snapshot,
    pub links: HashMap<String, Option<Zeroizing<String>>>,
    pub screen: Screen,
    pub receipts: BTreeMap<u64, ReceiptSlot>,
    pub quick_drop_input: bool,
    /// A notice for the main window and when it came (kept here: the window may be closed).
    pub notice: Option<(String, Millis)>,
    /// Creates sent to the engine, not yet in a snapshot.
    pending: BTreeSet<u64>,
    /// Creates started from the main window (their outcome screens show there).
    ours: BTreeSet<u64>,
    /// Creates from quick drop with their lifetime (a notification tells they are done).
    quick: HashMap<u64, u32>,
    next_id: u64,
    last_refresh: Millis,
}

impl EventEmitter<ModelEvent> for AppModel {}

pub struct ModelGlobal(pub Entity<AppModel>);
impl Global for ModelGlobal {}

pub fn model(cx: &App) -> Entity<AppModel> {
    cx.global::<ModelGlobal>().0.clone()
}

/// The app data directory (SPEC 4); `PNESECRETS_DATA_DIR` overrides it (tests, portable use).
pub fn data_dir() -> Option<PathBuf> {
    if let Some(d) = std::env::var_os("PNESECRETS_DATA_DIR").filter(|v| !v.is_empty()) {
        return Some(PathBuf::from(d));
    }
    let home = std::env::var_os("HOME").map(PathBuf::from);
    if cfg!(target_os = "macos") {
        Some(home?.join("Library/Application Support/com.payneteasy.secrets"))
    } else if cfg!(target_os = "windows") {
        Some(
            PathBuf::from(std::env::var_os("APPDATA")?)
                .join("Payneteasy")
                .join("Secrets"),
        )
    } else {
        let base = std::env::var_os("XDG_DATA_HOME")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .or_else(|| home.map(|h| h.join(".local/share")))?;
        Some(base.join("pnesecrets"))
    }
}

/// The OS vault; dev and e2e builds (`test-loopback`) may use another service name so they never
/// touch real items.
fn vault() -> KeyringVault {
    if cfg!(feature = "test-loopback")
        && let Ok(name) = std::env::var("PNESECRETS_VAULT_SERVICE")
    {
        return KeyringVault::with_service(&name);
    }
    KeyringVault::new()
}

fn empty_snapshot() -> Snapshot {
    Snapshot {
        index: Default::default(),
        creates: Vec::new(),
        limit: None,
        vault_ok: true,
    }
}

impl AppModel {
    /// `history`: false when the instance lock could not be taken: then the history is never
    /// opened for writing (another process might own it).
    pub fn new(history: bool) -> AppModel {
        let now = now();
        let (origin, origin_error) = match pnesecrets_core::origin() {
            Ok(o) => (Some(o), None),
            Err(e) => (None, Some(e.to_string())),
        };
        let clip = ClipboardService::new(match platform::SystemClipboard::new() {
            Some(c) => Box::new(c),
            None => Box::new(platform::NoClipboard),
        });
        let mut history_error = None;
        let history_note = None;
        let mut open: Option<engine::OpenHistory> = None;
        if !history {
            history_error = Some(
                "The app data folder could not be locked, so the history is off (another copy may be running). Check the folder's permissions and restart."
                    .into(),
            );
        } else if let Some(origin) = origin.clone() {
            match data_dir() {
                None => history_error = Some("No folder for the history on this system.".into()),
                // Opened on the engine thread (the vault may block); the result comes as an event.
                Some(dir) => {
                    open = Some(Box::new(move || {
                        Sent::open(HistoryStore::new(dir), Box::new(vault()), origin, now)
                    }))
                }
            }
        }
        let api: Option<engine::Api> = origin.clone().map(|o| {
            let s: Arc<Mutex<dyn SecretsApi>> = Arc::new(Mutex::new(Service::new(o)));
            s
        });
        let (tx, clip, events) = engine::start(open, clip, api, Arc::new(SystemClock));
        let _ = tx.send(Cmd::FetchLimit);
        AppModel {
            receive_service: origin
                .clone()
                .map(|o| Arc::new(Mutex::new(Service::new(o)))),
            origin,
            origin_error,
            history_error,
            history_note,
            history_ready: false,
            tx,
            clip,
            events,
            clip_holds: None,
            clip_deadline: None,
            snap: empty_snapshot(),
            links: HashMap::new(),
            screen: Screen::New,
            receipts: BTreeMap::new(),
            quick_drop_input: false,
            notice: None,
            pending: BTreeSet::new(),
            ours: BTreeSet::new(),
            quick: HashMap::new(),
            next_id: 1,
            last_refresh: 0,
        }
    }

    pub fn host(&self) -> String {
        self.origin
            .as_ref()
            .and_then(|o| o.as_str().split_once("://").map(|(_, h)| h.to_owned()))
            .unwrap_or_default()
    }

    fn id(&mut self) -> u64 {
        self.next_id += 1;
        self.next_id
    }

    fn send(&self, c: Cmd) {
        let _ = self.tx.send(c);
    }

    pub fn entry(&self, id: &str) -> Option<&Entry> {
        self.snap.index.get(id)
    }

    pub fn create_view(&self, op: u64) -> Option<&CreateView> {
        self.snap.creates.iter().find(|c| c.op == op)
    }

    /// Why Create is off, for the forms.
    pub fn cannot_create(&self) -> String {
        self.origin_error
            .clone()
            .or_else(|| self.history_error.clone())
            .unwrap_or_else(|| "The history is still loading; try again in a moment.".into())
    }

    pub fn can_create(&self) -> bool {
        self.origin.is_some() && self.history_error.is_none() && self.history_ready
    }

    /// Switches the right side; leaving A2 of an untracked secret drops its link (SPEC 4).
    pub fn set_screen(&mut self, s: Screen, cx: &mut Context<Self>) {
        if let Screen::Status(old) = &self.screen
            && Screen::Status(old.clone()) != s
        {
            if self.entry(old).is_some_and(|e| !e.tracked) {
                self.send(Cmd::ForgetSessionLink { id: old.clone() });
            }
            self.links.remove(old);
        }
        if let Screen::Status(id) = &s {
            self.send(Cmd::LoadLink { id: id.clone() });
        }
        if let Screen::Create(old) = self.screen
            && s != Screen::Create(old)
        {
            self.send(Cmd::DropCreate { op: old });
        }
        self.screen = s;
        self.sync_hold();
        cx.notify();
    }

    /// Drains engine events (called every 100 ms from the app loop).
    pub fn drain(&mut self, cx: &mut Context<Self>) {
        let mut changed = false;
        while let Ok(e) = self.events.try_recv() {
            changed = true;
            match e {
                Event::Snapshot(s) => {
                    self.snap = *s;
                    for c in &self.snap.creates {
                        self.pending.remove(&c.op);
                    }
                    // A cached recipient link lives only while the secret can be opened.
                    let now = now();
                    let stale: Vec<String> = self
                        .links
                        .keys()
                        .filter(|id| {
                            self.snap.index.get(id).is_none_or(|e| {
                                e.status != pnesecrets_core::history::Status::Waiting
                                    || now >= e.expires_at
                            })
                        })
                        .cloned()
                        .collect();
                    for id in stale {
                        self.links.remove(&id);
                        self.send(Cmd::ForgetSessionLink { id });
                    }
                    let shown: Vec<(u64, CreatePhase, Option<ApiError>)> = self
                        .snap
                        .creates
                        .iter()
                        .filter(|c| self.ours.contains(&c.op) || self.quick.contains_key(&c.op))
                        .map(|c| (c.op, c.phase, c.error.clone()))
                        .collect();
                    for (op, phase, error) in shown {
                        match phase {
                            CreatePhase::NotSavedLocally | CreatePhase::Unknown => {
                                // From quick drop: the main window takes it over (Copy, Retry).
                                if self.quick.remove(&op).is_some() {
                                    self.ours.insert(op);
                                    cx.emit(ModelEvent::ShowMain);
                                }
                                if self.screen != Screen::Create(op) {
                                    self.set_screen(Screen::Create(op), cx);
                                }
                            }
                            CreatePhase::Failed => {
                                self.ours.remove(&op);
                                if self.quick.remove(&op).is_some() {
                                    // The panel shows it if still open; the main window opens
                                    // with it too (the panel may be gone after Esc).
                                    self.set_notice(format!(
                                        "Quick drop: {}",
                                        error.as_ref().map(|e| e.to_string()).unwrap_or_default()
                                    ));
                                    cx.emit(ModelEvent::ShowMain);
                                }
                                self.send(Cmd::DropCreate { op });
                                cx.emit(ModelEvent::CreateFailed {
                                    op,
                                    sign_in: error == Some(ApiError::SignInRequired),
                                    error: error.map(|e| e.to_string()).unwrap_or_default(),
                                });
                            }
                            _ => {}
                        }
                    }
                }
                Event::Created { op, entry } => {
                    self.pending.remove(&op);
                    let from_main = self.ours.remove(&op);
                    if let Some(ttl) = self.quick.remove(&op) {
                        let _ = platform::notify(
                            "link-copied",
                            "Link copied",
                            &format!(
                                "Opens once, deleted in {} if unread. The clipboard clears in 60 s.",
                                crate::fmt::ttl_short(ttl)
                            ),
                        );
                    }
                    cx.emit(ModelEvent::Created { op });
                    if from_main {
                        self.set_screen(Screen::Status(entry), cx);
                    }
                }
                Event::Notify {
                    id,
                    label,
                    consumed_at,
                } => {
                    let title = if label.is_empty() {
                        "A secret was read".to_string()
                    } else {
                        format!("{label} was read")
                    };
                    let _ = platform::notify(&id, &title, &crate::fmt::clock(consumed_at));
                }
                Event::Notice(n) => self.set_notice(n),
                Event::Link { id, link } => {
                    if self.screen == Screen::Status(id.clone()) {
                        self.links.insert(id, link);
                    }
                }
                Event::ClipboardText { tag, text, cleared } => {
                    cx.emit(ModelEvent::ClipboardText { tag, text, cleared })
                }
                Event::CreateRejected { op, reason } => {
                    self.pending.remove(&op);
                    self.ours.remove(&op);
                    self.quick.remove(&op);
                    cx.emit(ModelEvent::CreateFailed {
                        op,
                        error: reason,
                        sign_in: false,
                    });
                }
                Event::History { error, moved } => {
                    self.history_ready = error.is_none();
                    if let Some(e) = error {
                        self.history_error = Some(format!(
                            "{e}. Creating secrets is off until it can be read; fix the file's permissions and restart."
                        ));
                    }
                    if moved {
                        self.history_note = Some(
                            "The history file was damaged and has been set aside; the history starts empty."
                                .into(),
                        );
                    }
                }
                Event::Clip { holds, deadline } => {
                    self.clip_holds = holds;
                    self.clip_deadline = deadline;
                }
            }
        }
        let now = now();
        if changed || now - self.last_refresh > 15_000 {
            self.last_refresh = now;
            self.sync_hold();
            cx.notify();
        }
    }

    // ---- create (A1, C) ----

    /// Starts a create in the engine; the draft moves there and is wiped after use.
    pub fn create(&mut self, draft: Draft, from_main: bool, cx: &mut Context<Self>) -> Option<u64> {
        if !self.can_create() {
            return None;
        }
        let op = self.id();
        self.pending.insert(op);
        if from_main {
            self.ours.insert(op);
        } else {
            self.quick.insert(op, draft.ttl);
        }
        self.send(Cmd::Create { op, draft });
        self.sync_hold();
        cx.notify();
        Some(op)
    }

    pub fn retry_local(&mut self, op: u64) {
        self.send(Cmd::RetryLocal { op });
    }

    pub fn create_again(&mut self, op: u64, cx: &mut Context<Self>) {
        self.ours.remove(&op);
        self.send(Cmd::CreateAgain { op });
        self.set_screen(Screen::New, cx);
    }

    pub fn creating(&self, op: u64) -> bool {
        self.pending.contains(&op)
            || self
                .create_view(op)
                .is_some_and(|c| c.phase == CreatePhase::Sending)
    }

    // ---- clipboard ----

    pub fn copy(&mut self, text: Zeroizing<String>, kind: CopyKind) {
        let _ = self.clip.send(ClipCmd::Copy {
            text,
            kind,
            reply: None,
        });
    }

    pub fn read_clipboard(&mut self) -> u64 {
        let tag = self.id();
        let _ = self.clip.send(ClipCmd::Read { tag });
        tag
    }

    pub fn take_clipboard(&mut self) -> u64 {
        let tag = self.id();
        let _ = self.clip.send(ClipCmd::Take { tag });
        tag
    }

    /// The main window closed: drop what A2 showed (an untracked link lives only while shown).
    pub fn main_closed(&mut self, cx: &mut Context<Self>) {
        if matches!(self.screen, Screen::Status(_)) {
            self.set_screen(Screen::New, cx);
        }
    }

    pub fn set_focus(&self, focused: bool) {
        self.send(Cmd::Focus(focused));
    }

    pub fn revoke(&mut self, entry: &str) {
        self.send(Cmd::Revoke {
            id: entry.to_owned(),
        });
    }

    /// Cloudflare Access login through `cloudflared` (SPEC 9): it opens the system browser; only
    /// the service address goes on its command line. Then both clients read the token again.
    pub fn sign_in(&mut self, cx: &mut Context<Self>) {
        let Some(origin) = self.origin.as_ref().map(|o| o.as_str().to_owned()) else {
            return;
        };
        let receive = self.receive_service.clone();
        let tx = self.tx.clone();
        cx.spawn(async move |this, cx| {
            // All of it off the UI thread: the receive client's lock may be held by a consume.
            let ok = cx
                .background_executor()
                .spawn(async move {
                    let ok = std::process::Command::new("cloudflared")
                        .args(["access", "login", &origin])
                        .stdin(std::process::Stdio::null())
                        .stdout(std::process::Stdio::null())
                        .stderr(std::process::Stdio::null())
                        .status()
                        .map(|s| s.success());
                    if let Some(r) = receive {
                        r.lock().unwrap().reset_credentials();
                    }
                    let _ = tx.send(Cmd::ResetCredentials);
                    ok
                })
                .await;
            let _ = this.update(cx, |m, cx| {
                cx.notify();
                m.set_notice(match ok {
                    Ok(true) => "Signed in. Try again.".into(),
                    Ok(false) => "Sign in did not finish.".into(),
                    Err(_) => "cloudflared is not installed: install it, or set SDROP_ACCESS_TOKEN, and restart.".into(),
                });
            });
        })
        .detach();
    }

    pub fn set_notice(&mut self, n: String) {
        self.notice = Some((n, now()));
    }

    // ---- received (D) ----

    pub fn open_link(&mut self, url: &str) -> Result<u64, ApiError> {
        let origin = self.origin.as_ref().ok_or(ApiError::Format(
            pnesecrets_core::sdrop::format::FormatError::BadLink,
        ))?;
        let r = Receipt::open(origin, url)?;
        let id = self.id();
        self.receipts.insert(
            id,
            ReceiptSlot {
                receipt: Some(r),
                window: None,
            },
        );
        Ok(id)
    }

    /// Reveal pressed: consume once, decrypt off the UI thread, put the receipt back.
    pub fn reveal(
        &mut self,
        id: u64,
        passphrase: Option<Zeroizing<String>>,
        cx: &mut Context<Self>,
    ) {
        let Some(service) = self.receive_service.clone() else {
            return;
        };
        let Some(slot) = self.receipts.get_mut(&id) else {
            return;
        };
        let Some(mut receipt) = slot.receipt.take() else {
            return;
        };
        let Some(server_id) = receipt.begin() else {
            slot.receipt = Some(receipt);
            return;
        };
        self.sync_hold();
        cx.notify();
        cx.spawn(async move |this, cx| {
            let receipt = cx
                .background_executor()
                .spawn(async move {
                    let r = service.lock().unwrap().consume(&server_id);
                    receipt.consumed(r, passphrase.as_ref().map(|p| p.as_str()), now());
                    receipt
                })
                .await;
            let _ = this.update(cx, |m, cx| m.put_receipt(id, receipt, cx));
        })
        .detach();
    }

    pub fn try_passphrase(
        &mut self,
        id: u64,
        passphrase: Zeroizing<String>,
        cx: &mut Context<Self>,
    ) {
        let Some(slot) = self.receipts.get_mut(&id) else {
            return;
        };
        let Some(mut receipt) = slot.receipt.take() else {
            return;
        };
        cx.notify();
        cx.spawn(async move |this, cx| {
            let receipt = cx
                .background_executor()
                .spawn(async move {
                    receipt.try_passphrase(&passphrase);
                    receipt
                })
                .await;
            let _ = this.update(cx, |m, cx| m.put_receipt(id, receipt, cx));
        })
        .detach();
    }

    fn put_receipt(&mut self, id: u64, receipt: Receipt, cx: &mut Context<Self>) {
        if let Some(slot) = self.receipts.get_mut(&id) {
            slot.receipt = Some(receipt);
        }
        self.sync_hold();
        cx.emit(ModelEvent::Receipt(id));
        cx.notify();
    }

    pub fn retry_unknown(&mut self, id: u64, cx: &mut Context<Self>) {
        if let Some(r) = self.receipts.get_mut(&id).and_then(|s| s.receipt.as_mut()) {
            r.retry_after_unknown();
        }
        cx.notify();
    }

    pub fn receipt_on_close(&self, id: u64) -> OnClose {
        match self.receipts.get(&id) {
            Some(ReceiptSlot { receipt: None, .. }) => OnClose::KeepInBackground,
            Some(ReceiptSlot {
                receipt: Some(r), ..
            }) => r.on_close(),
            None => OnClose::Drop,
        }
    }

    pub fn destroy_receipt(&mut self, id: u64, cx: &mut Context<Self>) {
        if let Some(mut slot) = self.receipts.remove(&id)
            && let Some(r) = slot.receipt.as_mut()
        {
            r.destroy();
        }
        // A copy of the revealed text may still be on the clipboard: clear it now if ours.
        let _ = self.clip.send(ClipCmd::ReleaseSecret);
        self.sync_hold();
        cx.notify();
    }

    // ---- quit ----

    pub fn blockers(&self) -> Vec<Blocker> {
        let mut b = Vec::new();
        let held = self
            .receipts
            .values()
            .filter(|s| s.receipt.as_ref().is_none_or(Receipt::blocks_quit))
            .count();
        if held > 0 {
            b.push(Blocker::Received(held));
        }
        if !self.pending.is_empty()
            || self
                .snap
                .creates
                .iter()
                .any(|c| c.phase == CreatePhase::Sending)
        {
            b.push(Blocker::Creating);
        }
        if self
            .snap
            .creates
            .iter()
            .any(|c| c.phase == CreatePhase::NotSavedLocally)
        {
            b.push(Blocker::NotSavedLocally);
        }
        if self.quick_drop_input {
            b.push(Blocker::QuickDropInput);
        }
        b
    }

    /// Keeps the native Quit guard (Dock, app menu) in step with what quitting would lose.
    pub fn sync_hold(&self) {
        platform::HOLD.store(
            !self.blockers().is_empty(),
            std::sync::atomic::Ordering::SeqCst,
        );
    }

    /// Before the process ends: wipe received secrets and let the engine clear our clipboard
    /// value (waits up to a second).
    pub fn shutdown(&mut self) {
        for slot in self.receipts.values_mut() {
            if let Some(r) = slot.receipt.as_mut() {
                r.destroy();
            }
        }
        self.receipts.clear();
        // The clipboard thread is independent of the vault and the disk: it answers fast.
        let (done, wait) = std::sync::mpsc::channel();
        let _ = self.clip.send(ClipCmd::Shutdown { done });
        let _ = wait.recv_timeout(Duration::from_secs(2));
    }
}

pub fn blocker_text(b: &[Blocker]) -> String {
    let mut parts = Vec::new();
    for x in b {
        parts.push(match x {
            Blocker::Received(1) => "a received secret that is not saved".to_string(),
            Blocker::Received(n) => format!("{n} received secrets that are not saved"),
            Blocker::Creating => "a secret being created".into(),
            Blocker::NotSavedLocally => "a created link not saved on this computer".into(),
            Blocker::QuickDropInput => "text in quick drop".into(),
        });
    }
    parts.join(", ")
}
