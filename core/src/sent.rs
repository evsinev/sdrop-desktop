//! Sent secrets (SPEC 4, 6): create with the local steps after the server answered, status
//! polling, revoke, crash recovery and the 30-day purge. Network calls run outside this state:
//! `create_on_server`, `due_checks` + `SecretsApi::status` + `apply_status`, `revoke_target` +
//! `SecretsApi::revoke` + `apply_revoke`. Everything here is local and fast.

use crate::clipboard::{ClipError, CopyKind, Released};
use crate::history::{Entry, FileMeta, HistoryError, HistoryStore, Index, Status, VaultState};
use crate::service::{ApiError, RevokeReply, SecretsApi, State, StatusReply};
use crate::time::{HOUR, MINUTE, Millis, SECOND};
use crate::vault::{Links, Vault, VaultError};
use sdrop::api::{Origin, OwnerLink, parse_owner_link};
use sdrop::format::{self, Content};
use std::collections::{HashMap, HashSet};
use zeroize::Zeroizing;

pub const POLL_FOCUSED: Millis = MINUTE;
pub const POLL_BACKGROUND: Millis = 5 * MINUTE;
/// The last check before expiry (SPEC 6): the service forgets everything at `expiresAt`.
pub const FINAL_CHECK: Millis = 90 * SECOND;
const VAULT_RETRY: Millis = HOUR;
/// An account name no entry uses (local ids are hex): a read tells whether the vault works.
const VAULT_PROBE: &str = "probe";
/// A pending vault write that could not be checked (keyring locked) is checked again after this.
const RECOVER_RETRY: Millis = MINUTE;
/// After a failed index write, local maintenance pauses this long (no loop on a full disk).
pub const DISK_RETRY: Millis = MINUTE;

/// What the user entered in A1 or C. Wiped on drop.
pub struct Draft {
    pub text: Zeroizing<String>,
    pub files: Vec<DraftFile>,
    pub passphrase: Option<Zeroizing<String>>,
    pub ttl: u32,
    pub label: String,
    pub notify: bool,
}

pub struct DraftFile {
    /// Already the base name through `sdrop::format::sanitize_file_name`.
    pub name: Zeroizing<String>,
    pub data: Zeroizing<Vec<u8>>,
}

impl Draft {
    pub fn content(&self) -> Content<'_> {
        format::compose(
            &self.text,
            self.files
                .iter()
                .map(|f| (f.name.as_str(), f.data.as_slice()))
                .collect(),
        )
    }

    /// Plaintext size before padding, to show against the limit before encrypting.
    pub fn plaintext_len(&self) -> usize {
        let files: Vec<(&str, usize)> = self
            .files
            .iter()
            .map(|f| (f.name.as_str(), f.data.len()))
            .collect();
        format::plaintext_len(&self.text, &files)
    }
}

/// The label as the index accepts it: control characters become spaces, trimmed, bounded.
pub fn clean_label(label: &str) -> String {
    let s: String = label
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    s.trim().chars().take(crate::history::MAX_LABEL).collect()
}

/// The links of entries that left Waiting or stopped being tracked must go from the vault.
fn needs_vault_delete(e: &Entry) -> bool {
    e.vault != VaultState::None && (e.status != Status::Waiting || !e.tracked)
}

fn text_lines(text: &str) -> Option<u32> {
    (!text.is_empty()).then(|| text.lines().count().max(1) as u32)
}

/// The service accepted the secret; the local steps may still be missing (SPEC 6, A1).
pub struct ServerCreated {
    pub local_id: String,
    pub recipient: Zeroizing<String>,
    owner: Zeroizing<String>,
    entry: Entry,
    index_started: bool,
    vault_done: bool,
    index_done: bool,
    copied: bool,
}

impl ServerCreated {
    /// True once every local step is done.
    pub fn complete(&self) -> bool {
        self.index_done && self.copied
    }
}

/// Which local step failed after the service created the secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalFailure {
    /// The history file could not be written: the link exists only on this screen.
    Index,
    /// The vault failed (not "unavailable", which means "not tracked").
    Vault,
    Clipboard,
}

/// Encrypt and upload (no local state touched). The draft stays with the caller.
pub fn create_on_server(
    api: &mut dyn SecretsApi,
    draft: &Draft,
    now: Millis,
) -> Result<ServerCreated, ApiError> {
    if let Some(p) = &draft.passphrase
        && p.is_empty()
    {
        return Err(ApiError::Format(format::FormatError::EmptyPassphrase));
    }
    let created = api.create(
        &draft.content(),
        draft.passphrase.as_ref().map(|p| p.as_str()),
        draft.ttl,
    )?;
    let host = api
        .origin()
        .as_str()
        .split_once("://")
        .map_or("", |(_, h)| h)
        .to_owned();
    let local_id = crate::history::new_local_id();
    let entry = Entry {
        id: local_id.clone(),
        label: clean_label(&draft.label),
        created_at: now,
        expires_at: created.expires_at.max(now),
        ttl: draft.ttl,
        status: Status::Waiting,
        status_at: now,
        checked_at: None,
        stored_seen_at: None,
        notified_at: None,
        vault: VaultState::Pending,
        tracked: true,
        passphrase: draft.passphrase.is_some(),
        notify: draft.notify,
        text_lines: text_lines(&draft.text),
        files: draft
            .files
            .iter()
            .map(|f| FileMeta {
                name: f.name.to_string(),
                size: f.data.len() as u64,
            })
            .collect(),
        link_copied_at: None,
        clipboard_cleared_at: None,
        consumed_at: None,
        consumed_by: None,
        revoked_at: None,
        server: host,
    };
    Ok(ServerCreated {
        local_id,
        recipient: created.recipient,
        owner: created.owner,
        entry,
        index_started: false,
        vault_done: false,
        index_done: false,
        copied: false,
    })
}

/// A terminal answer not yet written to the index: kept and written again, never asked again.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Terminal {
    Read {
        consumed_at: Millis,
        consumed_by: Option<String>,
        /// Learned from Revoke (409): the user is looking at it, no notification.
        quiet: bool,
    },
    Revoked,
    NotFound,
    ExpiredUnknown,
}

impl Terminal {
    /// Read and Revoked are confirmed by the service; NotFound and ExpiredUnknown only say it no
    /// longer knows. A weaker answer never replaces a stronger one.
    fn strength(&self) -> u8 {
        match self {
            Terminal::Read { .. } | Terminal::Revoked => 2,
            Terminal::NotFound | Terminal::ExpiredUnknown => 1,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    /// Show "<label> was read · <time>"; already committed as notified.
    Notify {
        id: String,
        label: String,
        consumed_at: Millis,
    },
}

/// A status request to make: the owner link from the vault.
pub struct Check {
    pub id: String,
    pub owner: OwnerLink,
    /// Not to be sent at or after this (the service no longer knows then).
    pub expires_at: Millis,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevokeError {
    /// Not tracked or no longer waiting.
    NotAvailable,
    Vault(VaultError),
    Api(ApiError),
    /// The answer came but could not be written; it is kept and written later.
    NotSaved,
}

pub struct Sent {
    store: HistoryStore,
    index: Index,
    vault: Box<dyn Vault>,
    origin: Origin,
    /// Untracked secrets: the recipient link for this session only.
    session_links: HashMap<String, Zeroizing<String>>,
    pending: HashMap<String, Terminal>,
    in_flight: HashSet<String>,
    last_attempt: HashMap<String, Millis>,
    vault_retry_at: HashMap<String, Millis>,
    /// A write failed since the last tick; the tick turns it into `disk_retry_at`.
    disk_failed: bool,
    disk_retry_at: Millis,
    /// Bumped by every successful write (the engine publishes when it changes).
    revision: u64,
}

impl Sent {
    /// Loads the index and runs the crash recovery of vault items. A damaged index (not our
    /// format) is moved aside and reported; the history starts empty. An index that cannot be
    /// read at all (permissions, I/O), or a damaged one that cannot be moved aside, is an error:
    /// no `Sent` exists then, so nothing can overwrite the file (SPEC 4).
    pub fn open(
        store: HistoryStore,
        vault: Box<dyn Vault>,
        origin: Origin,
        now: Millis,
    ) -> Result<(Sent, Option<std::path::PathBuf>), HistoryError> {
        let (index, moved) = match store.load() {
            Ok(i) => (i, None),
            Err(HistoryError::Damaged(_)) => {
                let to = store.quarantine(now).map_err(HistoryError::Io)?;
                (Index::new(), Some(to))
            }
            Err(e) => return Err(e),
        };
        let mut s = Sent {
            store,
            index,
            vault,
            origin,
            session_links: HashMap::new(),
            pending: HashMap::new(),
            in_flight: HashSet::new(),
            last_attempt: HashMap::new(),
            vault_retry_at: HashMap::new(),
            disk_failed: false,
            disk_retry_at: 0,
            revision: 0,
        };
        s.recover(now);
        Ok((s, moved))
    }

    pub fn index(&self) -> &Index {
        &self.index
    }

    pub fn entry(&self, id: &str) -> Option<&Entry> {
        self.index.get(id)
    }

    /// Writes a changed copy; memory follows the disk only on success.
    fn commit(&mut self, f: impl FnOnce(&mut Index)) -> std::io::Result<()> {
        let mut next = self.index.clone();
        f(&mut next);
        if let Err(e) = self.store.save(&next) {
            self.disk_failed = true;
            return Err(e);
        }
        self.index = next;
        self.revision += 1;
        Ok(())
    }

    pub fn revision(&self) -> u64 {
        self.revision
    }

    /// A check that was not sent (its expiry came while it waited in the queue).
    pub fn check_skipped(&mut self, id: &str) {
        self.in_flight.remove(id);
    }

    fn set(&mut self, id: &str, f: impl FnOnce(&mut Entry)) -> std::io::Result<()> {
        let id = id.to_owned();
        self.commit(|i| {
            if let Some(e) = i.get_mut(&id) {
                f(e);
            }
        })
    }

    /// After a crash: a pending vault write is either there (keep it) or not (untracked); items of
    /// entries that left Waiting are deleted.
    fn recover(&mut self, now: Millis) {
        let ids: Vec<(String, VaultState, Status, bool, bool)> = self
            .index
            .entries
            .iter()
            .map(|e| {
                (
                    e.id.clone(),
                    e.vault,
                    e.status,
                    e.tracked,
                    needs_vault_delete(e),
                )
            })
            .collect();
        for (id, vault, status, tracked, delete) in ids {
            match vault {
                VaultState::Pending => self.recover_pending(&id, status, tracked, now),
                VaultState::Present if delete => self.delete_vault(&id),
                _ => {}
            }
        }
    }

    /// A vault write of unknown outcome: present → tracked on; absent → untracked. If the vault
    /// cannot be read or the result cannot be written, it is tried again after RECOVER_RETRY.
    fn recover_pending(&mut self, id: &str, status: Status, tracked: bool, now: Millis) {
        let done = match self.vault.get(id) {
            Ok(Some(_)) if status == Status::Waiting && tracked => {
                self.set(id, |e| e.vault = VaultState::Present).is_ok()
            }
            Ok(Some(_)) => {
                self.delete_vault(id);
                self.index
                    .get(id)
                    .is_some_and(|e| e.vault == VaultState::None)
            }
            Ok(None) => self
                .set(id, |e| {
                    e.vault = VaultState::None;
                    e.tracked = false;
                })
                .is_ok(),
            Err(_) => false,
        };
        if done {
            self.vault_retry_at.remove(id);
        } else {
            self.vault_retry_at
                .insert(id.to_owned(), now + RECOVER_RETRY);
        }
    }

    /// Deletes the item; the retry mark goes only once `vault = None` is on disk.
    fn delete_vault(&mut self, id: &str) {
        if self.vault.delete(id).is_ok() && self.set(id, |e| e.vault = VaultState::None).is_ok() {
            self.vault_retry_at.remove(id);
        }
    }

    /// The local steps after the service created the secret, in the order that never leaves a
    /// vault item without its entry: entry (vault pending) → vault → entry (final) → clipboard.
    /// Call again after a failure: only the missing steps run.
    /// `copy` puts the link on the clipboard (the clipboard service, maybe on its own thread).
    pub fn finish(
        &mut self,
        sc: &mut ServerCreated,
        copy: impl FnOnce(Zeroizing<String>, CopyKind) -> Result<Option<Released>, ClipError>,
        now: Millis,
    ) -> Result<Option<Released>, LocalFailure> {
        if !sc.index_started {
            let entry = sc.entry.clone();
            self.commit(|i| {
                i.remove(&entry.id);
                i.entries.push(entry);
            })
            .map_err(|_| LocalFailure::Index)?;
            sc.index_started = true;
        }
        if !sc.vault_done {
            // A Retry may come late: the entry may have left Waiting meanwhile (tick wrote
            // Expired, the vault item was cleaned up). Then there is nothing to track: no write.
            let live = self
                .index
                .get(&sc.local_id)
                .is_some_and(|e| e.status == Status::Waiting && now < e.expires_at);
            if !live {
                sc.entry.vault = VaultState::None;
                sc.vault_done = true;
                sc.index_done = true;
            }
        }
        if !sc.vault_done {
            // The intent to write stays on disk until the write is confirmed (SPEC 4).
            if self.index.get(&sc.local_id).map(|e| e.vault) != Some(VaultState::Pending) {
                let id = sc.local_id.clone();
                self.set(&id, |e| {
                    e.vault = VaultState::Pending;
                    e.tracked = true;
                })
                .map_err(|_| LocalFailure::Index)?;
            }
            let links = Links {
                recipient: sc.recipient.clone(),
                owner: sc.owner.clone(),
            };
            match self.vault.put(&sc.local_id, &links) {
                Ok(()) => sc.entry.vault = VaultState::Present,
                Err(VaultError::Unavailable) => {
                    sc.entry.vault = VaultState::None;
                    sc.entry.tracked = false;
                    self.session_links
                        .insert(sc.local_id.clone(), sc.recipient.clone());
                }
                Err(_) => return Err(LocalFailure::Vault),
            }
            sc.vault_done = true;
        }
        if !sc.index_done {
            let id = sc.local_id.clone();
            let waiting = self
                .index
                .get(&id)
                .is_some_and(|e| e.status == Status::Waiting);
            if waiting {
                // Only the vault fields: whatever else happened to the entry meanwhile stays.
                let (vault, tracked) = (sc.entry.vault, sc.entry.tracked);
                self.set(&id, |e| {
                    e.vault = vault;
                    e.tracked = tracked;
                })
                .map_err(|_| LocalFailure::Index)?;
            } else {
                // Finished meanwhile (expired, cleaned up): the links just written must go; the
                // entry keeps Pending until the delete succeeds.
                self.delete_vault(&id);
            }
            sc.index_done = true;
        }
        let mut released = None;
        if !sc.copied {
            released = copy(
                sc.recipient.clone(),
                CopyKind::Link {
                    entry: Some(sc.local_id.clone()),
                },
            )
            .map_err(|ClipError| LocalFailure::Clipboard)?;
            sc.copied = true;
            let _ = self.set(&sc.local_id, |e| e.link_copied_at = Some(now));
        }
        if let Some(r) = &released {
            self.clipboard_released(r);
        }
        Ok(released)
    }

    /// The recipient link to show in A2: from the vault, or this session's memory when untracked.
    /// Only while the secret can still be opened: Waiting and before its expiry.
    pub fn recipient_link(&self, id: &str, now: Millis) -> Option<Zeroizing<String>> {
        let e = self.index.get(id)?;
        if e.status != Status::Waiting || now >= e.expires_at {
            return None;
        }
        if let Some(l) = self.session_links.get(id) {
            return Some(l.clone());
        }
        if e.vault != VaultState::Present {
            return None;
        }
        self.vault.get(id).ok().flatten().map(|l| l.recipient)
    }

    /// Whether the OS vault answers at all (the sidebar footer, the warning at Create).
    pub fn vault_works(&self) -> bool {
        !matches!(self.vault.get(VAULT_PROBE), Err(VaultError::Unavailable))
    }

    /// Leaving A2 of an untracked secret drops its link (SPEC 4).
    pub fn forget_session_link(&mut self, id: &str) {
        self.session_links.remove(id);
    }

    pub fn link_copied(&mut self, id: &str, now: Millis) {
        let _ = self.set(id, |e| e.link_copied_at = Some(now));
    }

    /// A copied link left the clipboard: the time goes to the timeline (SPEC 6, A2).
    pub fn clipboard_released(&mut self, r: &Released) {
        if let CopyKind::Link { entry: Some(id) } = &r.kind {
            let at = r.at;
            let _ = self.set(id, |e| e.clipboard_cleared_at = Some(at));
        }
    }

    fn pollable(&self, e: &Entry, now: Millis) -> bool {
        e.status == Status::Waiting
            && e.tracked
            && e.vault == VaultState::Present
            && now < e.expires_at
            && !self.pending.contains_key(&e.id)
            && !self.in_flight.contains(&e.id)
    }

    fn is_due(&self, e: &Entry, now: Millis, focused: bool) -> bool {
        let interval = if focused {
            POLL_FOCUSED
        } else {
            POLL_BACKGROUND
        };
        let final_at = e.expires_at - FINAL_CHECK;
        match self.last_attempt.get(&e.id) {
            None => true,
            Some(&last) => now - last >= interval || (now >= final_at && last < final_at),
        }
    }

    /// Status requests due now; each is in flight until `apply_status`.
    pub fn due_checks(&mut self, now: Millis, focused: bool) -> Vec<Check> {
        let due: Vec<String> = self
            .index
            .entries
            .iter()
            .filter(|e| self.pollable(e, now) && self.is_due(e, now, focused))
            .map(|e| e.id.clone())
            .collect();
        let mut checks = Vec::new();
        for id in due {
            // Every branch counts as an attempt: a failing vault or disk waits for the interval.
            self.last_attempt.insert(id.clone(), now);
            match self.vault.get(&id) {
                Ok(Some(links)) => match parse_owner_link(&self.origin, &links.owner) {
                    Ok(owner) => {
                        self.in_flight.insert(id.clone());
                        let expires_at = self.index.get(&id).map_or(now, |e| e.expires_at);
                        checks.push(Check {
                            id,
                            owner,
                            expires_at,
                        });
                    }
                    Err(_) => self.lose_tracking(&id),
                },
                // The item is gone (removed by hand): nothing to ask with.
                Ok(None) => self.lose_tracking(&id),
                Err(_) => {}
            }
        }
        checks
    }

    /// Stops tracking; the vault item is marked gone only after its delete succeeded, else the
    /// delete is retried (tick, next start) until it does.
    fn lose_tracking(&mut self, id: &str) {
        let _ = self.set(id, |e| e.tracked = false);
        self.delete_vault(id);
    }

    /// When the next poll or local transition is due (to schedule a timer).
    pub fn next_wake(&self, now: Millis, focused: bool) -> Option<Millis> {
        let interval = if focused {
            POLL_FOCUSED
        } else {
            POLL_BACKGROUND
        };
        let mut next: Option<Millis> = None;
        let mut take = |t: Millis| next = Some(next.map_or(t, |n| n.min(t)));
        // Local maintenance waits out a failed write; polling keeps its own interval.
        let disk = self.disk_retry_at;
        if !self.pending.is_empty() {
            take((now + SECOND).max(disk));
        }
        for e in &self.index.entries {
            // A request in flight decides the outcome; its answer reschedules (no wake loop).
            if e.status == Status::Waiting && !self.in_flight.contains(&e.id) {
                take(e.expires_at.max(disk));
            }
            let retry = self.vault_retry_at.get(&e.id).copied();
            if needs_vault_delete(e) || (e.vault == VaultState::Pending && retry.is_some()) {
                take(retry.unwrap_or(now).max(disk));
            }
            let purge_at = e.created_at + crate::history::KEEP;
            take(retry.map_or(purge_at, |r| r.max(purge_at)).max(disk));
            if self.pollable(e, now) {
                let last = self.last_attempt.get(&e.id).copied();
                let final_at = e.expires_at - FINAL_CHECK;
                match last {
                    None => take(now),
                    Some(l) => {
                        take(l + interval);
                        if l < final_at {
                            take(final_at);
                        }
                    }
                }
            }
        }
        next.map(|t| t.max(now))
    }

    /// The machine woke up: check every waiting secret now (SPEC 6).
    pub fn woke(&mut self) {
        self.last_attempt.clear();
    }

    pub fn apply_status(
        &mut self,
        id: &str,
        result: Result<StatusReply, ApiError>,
        now: Millis,
    ) -> Vec<Effect> {
        self.in_flight.remove(id);
        let Some(expires_at) = self.index.get(id).map(|e| e.expires_at) else {
            return Vec::new();
        };
        let terminal = match result {
            Ok(s) => match s.state {
                State::Stored => {
                    // A late "stored" (asked before a revoke or a read was seen) changes nothing.
                    if self.pending.contains_key(id)
                        || self
                            .index
                            .get(id)
                            .is_some_and(|e| e.status != Status::Waiting)
                    {
                        return Vec::new();
                    }
                    let _ = self.set(id, |e| {
                        e.checked_at = Some(now);
                        e.stored_seen_at = Some(now);
                    });
                    return Vec::new();
                }
                State::Consumed => Terminal::Read {
                    consumed_at: s.consumed_at.unwrap_or(now),
                    consumed_by: s.consumed_by,
                    quiet: false,
                },
                State::Revoked => Terminal::Revoked,
            },
            Err(ApiError::NotFound) if now < expires_at => Terminal::NotFound,
            Err(ApiError::NotFound) => Terminal::ExpiredUnknown,
            // Network, sign-in, unexpected: try again on the next tick, quietly.
            Err(_) => return Vec::new(),
        };
        self.offer(id, terminal);
        self.commit_pending(now)
    }

    /// Keeps a terminal answer unless the entry already has one at least as strong: on disk
    /// (any status but Waiting) or kept in memory. Answers may arrive in any order (a status
    /// asked before a revoke, answered after expiry).
    fn offer(&mut self, id: &str, t: Terminal) {
        let Some(e) = self.index.get(id) else {
            return;
        };
        // A written NotFound / ExpiredUnknown may still become Read or Revoked (a revoke answer
        // delivered late); a written Read or Revoked stays.
        let written = match e.status {
            Status::Waiting => 0,
            Status::NotFound | Status::ExpiredUnknown => 1,
            Status::Read | Status::Revoked => 2,
        };
        if written >= t.strength() {
            return;
        }
        if self
            .pending
            .get(id)
            .is_some_and(|old| old.strength() >= t.strength())
        {
            return;
        }
        self.pending.insert(id.to_owned(), t);
    }

    /// Writes kept terminal answers; the notification is returned only after its write.
    fn commit_pending(&mut self, now: Millis) -> Vec<Effect> {
        let mut effects = Vec::new();
        let ids: Vec<String> = self.pending.keys().cloned().collect();
        for id in ids {
            let t = self.pending[&id].clone();
            let Some(e) = self.index.get(&id) else {
                self.pending.remove(&id);
                continue;
            };
            let notify = matches!(t, Terminal::Read { quiet: false, .. })
                && e.notify
                && e.notified_at.is_none();
            let label = e.label.clone();
            let written = self.set(&id, |e| {
                e.status_at = now;
                e.checked_at = Some(now);
                match &t {
                    Terminal::Read {
                        consumed_at,
                        consumed_by,
                        ..
                    } => {
                        e.status = Status::Read;
                        e.consumed_at = Some(*consumed_at);
                        e.consumed_by = consumed_by.clone();
                    }
                    Terminal::Revoked => {
                        e.status = Status::Revoked;
                        e.revoked_at.get_or_insert(now);
                    }
                    Terminal::NotFound => e.status = Status::NotFound,
                    Terminal::ExpiredUnknown => {
                        e.status = Status::ExpiredUnknown;
                        e.status_at = e.expires_at;
                    }
                }
                if notify {
                    e.notified_at = Some(now);
                }
            });
            if written.is_err() {
                continue;
            }
            self.pending.remove(&id);
            if let Terminal::Read { consumed_at, .. } = t
                && notify
            {
                effects.push(Effect::Notify {
                    id: id.clone(),
                    label,
                    consumed_at,
                });
            }
            self.delete_vault(&id);
        }
        effects
    }

    /// Local work of a tick: kept answers, expiry, vault deletes left over, the 30-day purge.
    pub fn tick(&mut self, now: Millis) -> Vec<Effect> {
        if now < self.disk_retry_at {
            return Vec::new();
        }
        let effects = self.maintain(now);
        if std::mem::take(&mut self.disk_failed) {
            self.disk_retry_at = now + DISK_RETRY;
        }
        effects
    }

    fn maintain(&mut self, now: Millis) -> Vec<Effect> {
        let mut effects = self.commit_pending(now);
        let expired: Vec<String> = self
            .index
            .entries
            .iter()
            .filter(|e| {
                e.status == Status::Waiting
                    && now >= e.expires_at
                    && !self.pending.contains_key(&e.id)
                    && !self.in_flight.contains(&e.id)
            })
            .map(|e| e.id.clone())
            .collect();
        for id in expired {
            self.pending.insert(id, Terminal::ExpiredUnknown);
        }
        effects.extend(self.commit_pending(now));
        let unsure: Vec<(String, Status, bool)> = self
            .index
            .entries
            .iter()
            .filter(|e| e.vault == VaultState::Pending && self.vault_retry_at.contains_key(&e.id))
            .filter(|e| self.vault_retry_at.get(&e.id).is_none_or(|&t| now >= t))
            .map(|e| (e.id.clone(), e.status, e.tracked))
            .collect();
        for (id, status, tracked) in unsure {
            self.recover_pending(&id, status, tracked, now);
        }
        let leftover: Vec<String> = self
            .index
            .entries
            .iter()
            .filter(|e| needs_vault_delete(e))
            .filter(|e| self.vault_retry_at.get(&e.id).is_none_or(|&t| now >= t))
            .map(|e| e.id.clone())
            .collect();
        for id in leftover {
            self.vault_retry_at.insert(id.clone(), now + VAULT_RETRY);
            self.delete_vault(&id);
        }
        self.purge(now);
        effects
    }

    /// Entries older than 30 days: the vault item first, the entry only after (SPEC 4).
    fn purge(&mut self, now: Millis) {
        for id in self.index.expired_ids(now) {
            if self.vault_retry_at.get(&id).is_some_and(|&t| now < t) {
                continue;
            }
            let vault = self.index.get(&id).map(|e| e.vault);
            if vault != Some(VaultState::None) && self.vault.delete(&id).is_err() {
                self.vault_retry_at.insert(id, now + VAULT_RETRY);
                continue;
            }
            if self.commit(|i| i.remove(&id)).is_err() {
                self.vault_retry_at.insert(id, now + VAULT_RETRY);
                continue;
            }
            self.vault_retry_at.remove(&id);
            self.session_links.remove(&id);
            self.last_attempt.remove(&id);
        }
    }

    /// The owner link for Revoke (SPEC 6, A2).
    pub fn revoke_target(&mut self, id: &str, now: Millis) -> Result<OwnerLink, RevokeError> {
        let e = self.index.get(id).ok_or(RevokeError::NotAvailable)?;
        if e.status != Status::Waiting
            || !e.tracked
            || e.vault != VaultState::Present
            || now >= e.expires_at
            || self.pending.contains_key(id)
        {
            return Err(RevokeError::NotAvailable);
        }
        let links = self
            .vault
            .get(id)
            .map_err(RevokeError::Vault)?
            .ok_or(RevokeError::NotAvailable)?;
        parse_owner_link(&self.origin, &links.owner).map_err(|_| RevokeError::NotAvailable)
    }

    pub fn apply_revoke(
        &mut self,
        id: &str,
        result: Result<RevokeReply, ApiError>,
        now: Millis,
    ) -> (Result<(), RevokeError>, Vec<Effect>) {
        let terminal = match result {
            Ok(RevokeReply::Revoked) => Terminal::Revoked,
            Ok(RevokeReply::AlreadyRead(s)) => Terminal::Read {
                consumed_at: s.consumed_at.unwrap_or(now),
                consumed_by: s.consumed_by,
                quiet: true,
            },
            Err(ApiError::NotFound) => {
                let expires_at = self.index.get(id).map_or(now, |e| e.expires_at);
                if now < expires_at {
                    Terminal::NotFound
                } else {
                    Terminal::ExpiredUnknown
                }
            }
            Err(e) => return (Err(RevokeError::Api(e)), Vec::new()),
        };
        self.offer(id, terminal);
        // Other kept answers may be written now too: their notifications are returned.
        let effects = self.commit_pending(now);
        let r = if self.pending.contains_key(id) {
            Err(RevokeError::NotSaved)
        } else {
            Ok(())
        };
        (r, effects)
    }
}

#[cfg(test)]
#[path = "sent_tests.rs"]
mod tests;
