//! SPEC 12 items 1, 3, 4, 5, 8 on `Sent`: local steps after create, crash recovery, polling,
//! notifications, revoke, purge. Every check has a counterpart that fails without the property.

use super::*;
use crate::clipboard::{ClipboardService, FakeClipboard};
use crate::fake::{FakeApi, ORIGIN};
use crate::history::KEEP;
use crate::service::SecretsApi;
use crate::time::{Clock, DAY, ManualClock};
use crate::vault::MemVault;
use std::path::PathBuf;
use std::sync::atomic::Ordering;

const T0: Millis = 1_792_670_400_000;
const CANARY: &str = "canary-Xq7vR2m9LpTz4eW8";

struct World {
    dir: PathBuf,
    clock: ManualClock,
    api: FakeApi,
    vault: MemVault,
    fake_clip: FakeClipboard,
    clip: ClipboardService,
    sent: Sent,
    fail: std::sync::Arc<std::sync::atomic::AtomicBool>,
    saves: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl Drop for World {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn world() -> World {
    let dir = std::env::temp_dir().join(format!(
        "pnesecrets-sent-{}",
        crate::history::new_local_id()
    ));
    let clock = ManualClock::at(T0);
    let api = FakeApi::new(clock.clone());
    let vault = MemVault::default();
    let fake_clip = FakeClipboard::new(true);
    let clip = ClipboardService::new(Box::new(fake_clip.clone()));
    let store = HistoryStore::new(&dir);
    let fail = store.fail_switch();
    let saves = store.attempts();
    let (sent, moved) = Sent::open(
        store,
        Box::new(vault.clone()),
        Origin::parse(ORIGIN).unwrap(),
        T0,
    )
    .unwrap();
    assert!(moved.is_none());
    World {
        dir,
        clock,
        api,
        vault,
        fake_clip,
        clip,
        sent,
        fail,
        saves,
    }
}

impl World {
    fn now(&self) -> Millis {
        self.clock.now()
    }

    /// Reopen from disk, as after a crash or restart.
    fn reopen(&mut self) {
        let store = HistoryStore::new(&self.dir);
        self.fail = store.fail_switch();
        self.saves = store.attempts();
        let (sent, moved) = Sent::open(
            store,
            Box::new(self.vault.clone()),
            Origin::parse(ORIGIN).unwrap(),
            self.now(),
        )
        .unwrap();
        assert!(moved.is_none());
        self.sent = sent;
    }

    fn create(&mut self, notify: bool) -> ServerCreated {
        let d = draft(notify);
        let now = self.now();
        create_on_server(&mut self.api, &d, now).unwrap()
    }

    fn created(&mut self, notify: bool) -> String {
        let mut sc = self.create(notify);
        let now = self.now();
        self.sent
            .finish(&mut sc, |t, k| self.clip.copy(t, k, now), now)
            .unwrap();
        assert!(sc.complete());
        sc.local_id.clone()
    }

    /// One poll round: due checks, the requests, the answers.
    fn poll(&mut self, focused: bool) -> (usize, Vec<Effect>) {
        let now = self.now();
        let checks = self.sent.due_checks(now, focused);
        let n = checks.len();
        let mut effects = Vec::new();
        for c in checks {
            let r = self.api.status(&c.owner);
            effects.extend(self.sent.apply_status(&c.id, r, now));
        }
        effects.extend(self.sent.tick(now));
        (n, effects)
    }

    fn server_id(&self, local: &str) -> String {
        let links = self.vault.get(local).unwrap().unwrap();
        parse_owner_link(&Origin::parse(ORIGIN).unwrap(), &links.owner)
            .unwrap()
            .id
    }

    fn status(&self, id: &str) -> Status {
        self.sent.entry(id).unwrap().status
    }

    fn index_file(&self) -> String {
        std::fs::read_to_string(self.dir.join(crate::history::FILE_NAME)).unwrap_or_default()
    }
}

fn draft(notify: bool) -> Draft {
    Draft {
        text: Zeroizing::new(format!("DB_PASSWORD={CANARY}\nline2\nline3")),
        files: vec![DraftFile {
            name: Zeroizing::new("stage-ca.pem".into()),
            data: Zeroizing::new(b"-----BEGIN CERT-----".to_vec()),
        }],
        passphrase: None,
        ttl: 86400,
        label: "Staging DB password".into(),
        notify,
    }
}

#[test]
fn create_keeps_links_out_of_the_index() {
    let mut w = world();
    let id = w.created(true);
    let e = w.sent.entry(&id).unwrap().clone();
    assert_eq!(e.status, Status::Waiting);
    assert_eq!(e.vault, VaultState::Present);
    assert_eq!(e.text_lines, Some(3));
    assert_eq!(e.files[0].name, "stage-ca.pem");
    assert_eq!(e.link_copied_at, Some(T0));
    assert_eq!(e.server, "secrets.example.com");
    let links = w.vault.get(&id).unwrap().unwrap();
    assert_eq!(
        w.fake_clip.value().as_deref(),
        Some(links.recipient.as_str())
    );
    // Nothing secret in the index file: text, recipient link, key, owner link, token, server id.
    let file = w.index_file();
    assert!(
        file.contains("Staging DB password"),
        "the check reads the real file"
    );
    let key = links.recipient.split_once('#').unwrap().1;
    let token = links.owner.split_once('#').unwrap().1;
    let server_id = w.server_id(&id);
    for needle in [
        CANARY,
        links.recipient.as_str(),
        key,
        links.owner.as_str(),
        token,
        &server_id,
    ] {
        assert!(!file.contains(needle), "index leaks {needle}");
    }
    assert_eq!(w.api.calls("create"), 1);
}

#[test]
fn index_failure_before_vault_leaves_no_vault_item_and_retry_does_not_post_again() {
    let mut w = world();
    let mut sc = w.create(true);
    w.fail.store(true, Ordering::SeqCst);
    let now = w.now();
    assert_eq!(
        w.sent.finish(&mut sc, |t, k| w.clip.copy(t, k, now), now),
        Err(LocalFailure::Index)
    );
    assert!(w.vault.ids().is_empty(), "no vault item without its entry");
    assert!(!sc.complete());
    // The link is still there to show and copy by hand.
    assert!(sc.recipient.contains("/s/"));
    w.fail.store(false, Ordering::SeqCst);
    w.sent
        .finish(&mut sc, |t, k| w.clip.copy(t, k, now), now)
        .unwrap();
    assert!(sc.complete());
    assert_eq!(w.api.calls("create"), 1);
    assert_eq!(w.vault.ids(), vec![sc.local_id.clone()]);
}

#[test]
fn vault_and_clipboard_failures_retry_only_the_missing_steps() {
    let mut w = world();
    let mut sc = w.create(true);
    let now = w.now();
    w.vault.fail_put(Some(VaultError::Other));
    assert_eq!(
        w.sent.finish(&mut sc, |t, k| w.clip.copy(t, k, now), now),
        Err(LocalFailure::Vault)
    );
    assert_eq!(
        w.sent.entry(&sc.local_id).unwrap().vault,
        VaultState::Pending
    );
    w.vault.fail_put(None);
    w.fake_clip.set_fail(true);
    assert_eq!(
        w.sent.finish(&mut sc, |t, k| w.clip.copy(t, k, now), now),
        Err(LocalFailure::Clipboard)
    );
    assert_eq!(
        w.sent.entry(&sc.local_id).unwrap().vault,
        VaultState::Present
    );
    w.fake_clip.set_fail(false);
    w.sent
        .finish(&mut sc, |t, k| w.clip.copy(t, k, now), now)
        .unwrap();
    assert!(sc.complete());
    assert!(w.fake_clip.value().is_some());
    assert_eq!(w.api.calls("create"), 1);
}

#[test]
fn crash_between_steps_never_leaves_a_vault_item_without_its_entry() {
    // Crash after the vault write, before the final entry: the item is kept, tracking goes on.
    let mut w = world();
    let sc = w.create(true);
    let now = w.now();
    let real_index = w.sent.index().clone();
    // Simulate: first entry written, vault written, then the process dies.
    w.sent.commit(|i| i.entries.push(sc.entry.clone())).unwrap();
    w.vault
        .put(
            &sc.local_id,
            &Links {
                recipient: sc.recipient.clone(),
                owner: sc.owner.clone(),
            },
        )
        .unwrap();
    let _ = real_index;
    w.reopen();
    assert_eq!(
        w.sent.entry(&sc.local_id).unwrap().vault,
        VaultState::Present
    );
    assert!(w.sent.entry(&sc.local_id).unwrap().tracked);
    assert_eq!(w.poll(true).0, 1, "recovered entry is polled");

    // Crash after the first entry, before the vault write: untracked, nothing to delete.
    let mut w = world();
    let mut sc2 = w.create(true);
    w.vault.fail_put(Some(VaultError::Other));
    assert_eq!(
        w.sent.finish(&mut sc2, |t, k| w.clip.copy(t, k, now), now),
        Err(LocalFailure::Vault)
    );
    w.vault.fail_put(None);
    w.reopen();
    let e = w.sent.entry(&sc2.local_id).unwrap();
    assert_eq!((e.vault, e.tracked), (VaultState::None, false));
    assert!(w.vault.ids().is_empty());
    assert_eq!(w.poll(true).0, 0);
    drop(sc);
}

#[test]
fn unavailable_vault_creates_untracked_with_a_session_link() {
    let mut w = world();
    w.vault.fail_put(Some(VaultError::Unavailable));
    let id = w.created(true);
    let e = w.sent.entry(&id).unwrap().clone();
    assert_eq!((e.tracked, e.vault), (false, VaultState::None));
    assert!(w.sent.recipient_link(&id, w.now()).is_some());
    w.sent.forget_session_link(&id);
    assert!(w.sent.recipient_link(&id, w.now()).is_none());
    assert_eq!(
        w.poll(true).0,
        0,
        "no status requests without the owner link"
    );
    assert_eq!(
        w.sent.revoke_target(&id, w.now()).err(),
        Some(RevokeError::NotAvailable)
    );
    w.reopen();
    assert!(w.sent.recipient_link(&id, w.now()).is_none());
}

#[test]
fn polling_intervals_and_one_notification() {
    let mut w = world();
    let id = w.created(true);
    assert_eq!(w.poll(true).0, 1, "first check right away");
    assert_eq!(w.poll(true).0, 0);
    w.clock.advance(POLL_FOCUSED - 1);
    assert_eq!(w.poll(true).0, 0);
    w.clock.advance(1);
    assert_eq!(w.poll(true).0, 1);
    // In the background: every 5 minutes.
    w.clock.advance(POLL_FOCUSED);
    assert_eq!(w.poll(false).0, 0);
    w.clock.advance(POLL_BACKGROUND - POLL_FOCUSED);
    assert_eq!(w.poll(false).0, 1);
    assert_eq!(w.sent.entry(&id).unwrap().stored_seen_at, Some(w.now()));

    w.api.set_reader(Some("reader@example.com"));
    assert!(w.api.recipient_consumes(&w.server_id(&id)));
    w.clock.advance(POLL_FOCUSED);
    let (n, effects) = w.poll(true);
    assert_eq!(n, 1);
    assert_eq!(
        effects,
        vec![Effect::Notify {
            id: id.clone(),
            label: "Staging DB password".into(),
            consumed_at: w.now() - POLL_FOCUSED
        }]
    );
    let e = w.sent.entry(&id).unwrap();
    assert_eq!(e.status, Status::Read);
    assert_eq!(e.consumed_by.as_deref(), Some("reader@example.com"));
    assert!(w.vault.ids().is_empty(), "vault item deleted after Read");
    let calls = w.api.calls("status");
    for _ in 0..3 {
        w.clock.advance(POLL_FOCUSED);
        let (n, effects) = w.poll(true);
        assert_eq!((n, effects.len()), (0, 0));
    }
    assert_eq!(w.api.calls("status"), calls);
    w.reopen();
    assert_eq!(
        w.poll(true),
        (0, vec![]),
        "no second notification after restart"
    );
}

#[test]
fn no_notification_when_disabled() {
    let mut w = world();
    let id = w.created(false);
    w.poll(true);
    w.api.recipient_consumes(&w.server_id(&id));
    w.clock.advance(POLL_FOCUSED);
    let (_, effects) = w.poll(true);
    assert!(effects.is_empty());
    assert_eq!(w.status(&id), Status::Read);
}

#[test]
fn read_kept_through_a_failed_write_and_expiry_without_asking_again() {
    let mut w = world();
    let id = w.created(true);
    w.poll(true);
    w.api.recipient_consumes(&w.server_id(&id));
    // Just before expiry the answer comes, but the index cannot be written.
    w.clock
        .set(w.sent.entry(&id).unwrap().expires_at - 10 * SECOND);
    w.fail.store(true, Ordering::SeqCst);
    let (n, effects) = w.poll(true);
    assert_eq!(n, 1);
    assert!(effects.is_empty(), "no notification before the write");
    assert_eq!(w.status(&id), Status::Waiting);
    // Past expiry: the service would say 404 now; the kept answer is written instead.
    w.clock.advance(MINUTE);
    w.fail.store(false, Ordering::SeqCst);
    let calls = w.api.calls("status");
    let (n, effects) = w.poll(true);
    assert_eq!(n, 0);
    assert_eq!(w.api.calls("status"), calls, "no new status request");
    assert_eq!(effects.len(), 1);
    assert_eq!(w.status(&id), Status::Read);
    assert_eq!(w.poll(true).1.len(), 0);
}

#[test]
fn expiry_is_unknown_even_after_a_late_stored() {
    let mut w = world();
    let id = w.created(true);
    let expires = w.sent.entry(&id).unwrap().expires_at;
    w.poll(false);
    // Background polling: the final check comes at expiresAt - 90 s even inside the interval.
    w.clock
        .set(expires - FINAL_CHECK - POLL_BACKGROUND + MINUTE);
    assert_eq!(w.poll(false).0, 1);
    w.clock.set(expires - FINAL_CHECK - 1);
    assert_eq!(w.poll(false).0, 0);
    w.clock.set(expires - FINAL_CHECK);
    assert_eq!(w.poll(false).0, 1);
    assert_eq!(
        w.sent.entry(&id).unwrap().stored_seen_at,
        Some(expires - FINAL_CHECK)
    );
    // Read 10 s before expiry, after the last check.
    w.clock.set(expires - 10 * SECOND);
    w.api.recipient_consumes(&w.server_id(&id));
    w.clock.set(expires);
    let calls = w.api.calls("status");
    assert_eq!(w.poll(false).0, 0, "no request at or after expiry");
    assert_eq!(w.api.calls("status"), calls);
    assert_eq!(w.status(&id), Status::ExpiredUnknown);
    assert!(w.vault.ids().is_empty());
}

#[test]
fn sleep_through_expiry_and_not_found_before() {
    let mut w = world();
    let a = w.created(true);
    w.poll(true);
    // 404 before expiry: gone on the server for another reason.
    w.api.fail_next("status", ApiError::NotFound);
    w.clock.advance(POLL_FOCUSED);
    w.poll(true);
    assert_eq!(w.status(&a), Status::NotFound);
    assert!(w.vault.ids().is_empty());
    // Revoked elsewhere: the service says so.
    let b = w.created(true);
    let owner = parse_owner_link(
        &Origin::parse(ORIGIN).unwrap(),
        &w.vault.get(&b).unwrap().unwrap().owner,
    )
    .unwrap();
    w.api.revoke(&owner).unwrap();
    w.poll(true);
    assert_eq!(w.status(&b), Status::Revoked);
    // Slept through expiry: nothing is asked, the outcome is unknown.
    let c = w.created(true);
    w.clock.advance(2 * DAY);
    let calls = w.api.calls("status");
    assert_eq!(w.poll(true).0, 0);
    assert_eq!(w.api.calls("status"), calls);
    assert_eq!(w.status(&c), Status::ExpiredUnknown);
}

#[test]
fn network_errors_are_quiet_and_retried() {
    let mut w = world();
    let id = w.created(true);
    w.api.fail_next("status", ApiError::Network);
    assert_eq!(w.poll(true).0, 1);
    assert_eq!(w.status(&id), Status::Waiting);
    w.clock.advance(POLL_FOCUSED);
    assert_eq!(w.poll(true).0, 1);
    assert_eq!(w.sent.entry(&id).unwrap().checked_at, Some(w.now()));
}

#[test]
fn woke_checks_right_away() {
    let mut w = world();
    w.created(true);
    w.poll(false);
    w.clock.advance(MINUTE);
    assert_eq!(w.poll(false).0, 0);
    w.sent.woke();
    assert_eq!(w.poll(false).0, 1);
}

#[test]
fn revoke_and_already_read() {
    let mut w = world();
    let a = w.created(true);
    let owner = w.sent.revoke_target(&a, w.now()).unwrap();
    let r = w.api.revoke(&owner);
    assert!(w.sent.apply_revoke(&a, r, w.now()).0.is_ok());
    assert_eq!(w.status(&a), Status::Revoked);
    assert!(w.vault.get(&a).unwrap().is_none());
    assert_eq!(
        w.sent.revoke_target(&a, w.now()).err(),
        Some(RevokeError::NotAvailable)
    );
    assert!(w.sent.recipient_link(&a, w.now()).is_none());

    let b = w.created(true);
    w.api.set_reader(Some("x@example.com"));
    w.api.recipient_consumes(&w.server_id(&b));
    let owner = w.sent.revoke_target(&b, w.now()).unwrap();
    let r = w.api.revoke(&owner);
    assert!(matches!(r, Ok(RevokeReply::AlreadyRead(_))));
    let (ok, effects) = w.sent.apply_revoke(&b, r, w.now());
    assert!(ok.is_ok());
    assert!(effects.is_empty(), "409 from revoke is not a notification");
    let e = w.sent.entry(&b).unwrap();
    assert_eq!(e.status, Status::Read);
    assert_eq!(e.consumed_by.as_deref(), Some("x@example.com"));
    assert!(
        w.poll(true).1.is_empty(),
        "no notification for what revoke just showed"
    );

    let c = w.created(true);
    let owner = w.sent.revoke_target(&c, w.now()).unwrap();
    assert!(
        w.sent
            .apply_revoke(&c, Err(ApiError::Network), w.now())
            .0
            .is_err()
    );
    assert_eq!(w.status(&c), Status::Waiting);
    drop(owner);
}

#[test]
fn purge_deletes_the_vault_item_before_the_entry() {
    let mut w = world();
    let id = w.created(true);
    w.clock.advance(KEEP);
    w.vault.fail_delete(Some(VaultError::Other));
    w.poll(false);
    assert!(
        w.sent.entry(&id).is_some(),
        "entry kept while its vault item is there"
    );
    assert_eq!(w.vault.ids(), vec![id.clone()]);
    w.vault.fail_delete(None);
    w.clock.advance(HOUR);
    w.poll(false);
    assert!(w.sent.entry(&id).is_none());
    assert!(w.vault.ids().is_empty());
}

#[test]
fn vault_item_removed_by_hand_stops_tracking() {
    let mut w = world();
    let id = w.created(true);
    w.vault.delete(&id).unwrap();
    assert_eq!(w.poll(true).0, 0);
    let e = w.sent.entry(&id).unwrap();
    assert_eq!((e.tracked, e.vault), (false, VaultState::None));
}

#[test]
fn leftover_vault_items_of_finished_entries_are_deleted_on_open() {
    let mut w = world();
    let id = w.created(true);
    w.poll(true);
    w.api.recipient_consumes(&w.server_id(&id));
    w.vault.fail_delete(Some(VaultError::Other));
    w.clock.advance(POLL_FOCUSED);
    w.poll(true);
    assert_eq!(w.status(&id), Status::Read);
    assert_eq!(w.vault.ids(), vec![id.clone()]);
    w.vault.fail_delete(None);
    w.reopen();
    assert!(w.vault.ids().is_empty());
    assert_eq!(w.sent.entry(&id).unwrap().vault, VaultState::None);
}

#[test]
fn clipboard_release_goes_to_the_timeline() {
    let mut w = world();
    let id = w.created(true);
    let r = w
        .clip
        .tick(w.now() + crate::clipboard::LINK_TIMEOUT)
        .unwrap();
    assert!(r.cleared);
    w.sent.clipboard_released(&r);
    assert_eq!(
        w.sent.entry(&id).unwrap().clipboard_cleared_at,
        Some(T0 + crate::clipboard::LINK_TIMEOUT)
    );
}

#[test]
fn damaged_index_is_moved_aside_not_treated_as_empty() {
    let w = world();
    std::fs::create_dir_all(&w.dir).unwrap();
    std::fs::write(w.dir.join(crate::history::FILE_NAME), b"{broken").unwrap();
    let (sent, moved) = Sent::open(
        HistoryStore::new(&w.dir),
        Box::new(w.vault.clone()),
        Origin::parse(ORIGIN).unwrap(),
        T0,
    )
    .unwrap();
    assert!(sent.index().entries.is_empty());
    let moved = moved.unwrap();
    assert_eq!(std::fs::read(&moved).unwrap(), b"{broken");
    assert!(!w.dir.join(crate::history::FILE_NAME).exists());
}

#[test]
fn unreadable_index_is_an_error_and_stays_in_place() {
    let mut w = world();
    let id = w.created(true);
    let file = w.dir.join(crate::history::FILE_NAME);
    let good = std::fs::read(&file).unwrap();
    // A read error that is not "damaged": the path is a directory now.
    std::fs::rename(&file, w.dir.join("kept")).unwrap();
    std::fs::create_dir(&file).unwrap();
    let r = Sent::open(
        HistoryStore::new(&w.dir),
        Box::new(w.vault.clone()),
        Origin::parse(ORIGIN).unwrap(),
        T0,
    );
    assert!(matches!(r, Err(HistoryError::Io(_))));
    assert!(file.is_dir(), "nothing moved or replaced");
    let names: Vec<String> = std::fs::read_dir(&w.dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert!(!names.iter().any(|n| n.contains("damaged")), "{names:?}");
    // Put it back: the history and its vault item are intact.
    std::fs::remove_dir(&file).unwrap();
    std::fs::write(&file, good).unwrap();
    w.reopen();
    assert!(w.sent.entry(&id).is_some());
    assert_eq!(w.vault.ids(), vec![id]);
}

#[cfg(unix)]
#[test]
fn damaged_index_that_cannot_be_moved_is_an_error() {
    use std::os::unix::fs::PermissionsExt;
    let w = world();
    std::fs::create_dir_all(&w.dir).unwrap();
    std::fs::write(w.dir.join(crate::history::FILE_NAME), b"{broken").unwrap();
    std::fs::set_permissions(&w.dir, std::fs::Permissions::from_mode(0o500)).unwrap();
    let r = Sent::open(
        HistoryStore::new(&w.dir),
        Box::new(w.vault.clone()),
        Origin::parse(ORIGIN).unwrap(),
        T0,
    );
    std::fs::set_permissions(&w.dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(matches!(r, Err(HistoryError::Io(_))));
    assert_eq!(
        std::fs::read(w.dir.join(crate::history::FILE_NAME)).unwrap(),
        b"{broken"
    );
}

#[test]
fn not_found_answered_after_expiry_is_unknown_not_read() {
    // The request leaves a second before expiry; the 404 comes back after it.
    let mut w = world();
    let id = w.created(true);
    let expires = w.sent.entry(&id).unwrap().expires_at;
    w.clock.set(expires - SECOND);
    let checks = w.sent.due_checks(w.now(), true);
    assert_eq!(checks.len(), 1);
    w.clock.set(expires + SECOND);
    let effects = w
        .sent
        .apply_status(&checks[0].id, Err(ApiError::NotFound), w.now());
    assert!(effects.is_empty());
    assert_eq!(w.status(&id), Status::ExpiredUnknown);
}

#[test]
fn a_late_answer_never_downgrades_a_confirmed_read() {
    for disk_fails in [false, true] {
        let mut w = world();
        let id = w.created(true);
        let expires = w.sent.entry(&id).unwrap().expires_at;
        // A status request leaves just before expiry and hangs.
        w.clock.set(expires - 30 * SECOND);
        let checks = w.sent.due_checks(w.now(), true);
        assert_eq!(checks.len(), 1);
        // Meanwhile the recipient opens it and Revoke answers 409 with the read.
        w.api.set_reader(Some("r@example.com"));
        w.api.recipient_consumes(&w.server_id(&id));
        let owner = w.sent.revoke_target(&id, w.now()).unwrap();
        let r = w.api.revoke(&owner);
        w.fail.store(disk_fails, Ordering::SeqCst);
        let (saved, _) = w.sent.apply_revoke(&id, r, w.now());
        assert_eq!(saved.is_err(), disk_fails);
        // The hung request comes back after expiry with 404, then a stale "stored".
        w.clock.set(expires + SECOND);
        w.sent
            .apply_status(&checks[0].id, Err(ApiError::NotFound), w.now());
        w.sent.apply_status(
            &checks[0].id,
            Ok(StatusReply {
                state: State::Stored,
                created_at: T0,
                expires_at: expires,
                consumed_at: None,
                consumed_by: None,
            }),
            w.now(),
        );
        w.fail.store(false, Ordering::SeqCst);
        w.sent.tick(w.now());
        let e = w.sent.entry(&id).unwrap();
        assert_eq!(e.status, Status::Read, "disk_fails={disk_fails}");
        assert_eq!(e.consumed_by.as_deref(), Some("r@example.com"));
    }
}

#[test]
fn a_late_confirmed_revoke_upgrades_a_written_unknown() {
    let mut w = world();
    let id = w.created(true);
    let expires = w.sent.entry(&id).unwrap().expires_at;
    w.clock.set(expires - SECOND);
    let owner = w.sent.revoke_target(&id, w.now()).unwrap();
    let r = w.api.revoke(&owner);
    // The answer is delivered after expiry, when tick already wrote "unknown".
    w.clock.set(expires + SECOND);
    w.sent.tick(w.now());
    assert_eq!(w.status(&id), Status::ExpiredUnknown);
    assert!(w.sent.apply_revoke(&id, r, w.now()).0.is_ok());
    assert_eq!(w.status(&id), Status::Revoked);

    // Same with 409: Read, and no notification (the user is looking at the revoke result).
    let id = w.created(true);
    let expires = w.sent.entry(&id).unwrap().expires_at;
    w.api.recipient_consumes(&w.server_id(&id));
    w.clock.set(expires - SECOND);
    let owner = w.sent.revoke_target(&id, w.now()).unwrap();
    let r = w.api.revoke(&owner);
    w.clock.set(expires + SECOND);
    assert!(w.sent.tick(w.now()).is_empty());
    let (ok, effects) = w.sent.apply_revoke(&id, r, w.now());
    assert!(ok.is_ok());
    assert!(
        effects.is_empty(),
        "no notification for a read learned from revoke"
    );
    assert_eq!(w.status(&id), Status::Read);
    assert!(w.sent.tick(w.now()).is_empty());
    assert!(w.poll(true).1.is_empty());
}

#[test]
fn losing_tracking_keeps_the_vault_item_until_it_is_deleted() {
    let mut w = world();
    let id = w.created(true);
    // The owner link no longer parses against the origin (e.g. SDROP_ORIGIN changed).
    w.vault
        .put(
            &id,
            &Links {
                recipient: Zeroizing::new("https://other.example/s/x#y".into()),
                owner: Zeroizing::new("https://other.example/o/x#y".into()),
            },
        )
        .unwrap();
    w.vault.fail_delete(Some(VaultError::Other));
    assert_eq!(w.poll(true).0, 0);
    let e = w.sent.entry(&id).unwrap();
    assert!(!e.tracked);
    assert_eq!(
        e.vault,
        VaultState::Present,
        "not marked gone while it is there"
    );
    w.vault.fail_delete(None);
    w.reopen();
    assert!(w.vault.ids().is_empty());
    assert_eq!(w.sent.entry(&id).unwrap().vault, VaultState::None);
}

#[test]
fn a_label_with_control_characters_never_damages_the_index() {
    let mut w = world();
    let mut d = draft(true);
    d.label = "DB\tprod\n".into();
    let now = w.now();
    let mut sc = create_on_server(&mut w.api, &d, now).unwrap();
    w.sent
        .finish(&mut sc, |t, k| w.clip.copy(t, k, now), now)
        .unwrap();
    assert_eq!(w.sent.entry(&sc.local_id).unwrap().label, "DB prod");
    w.reopen();
    assert!(w.sent.entry(&sc.local_id).is_some());
    // And save itself refuses an index that parse would reject.
    let mut bad = w.sent.index().clone();
    bad.entries[0].label = "a\u{7}b".into();
    assert!(HistoryStore::new(&w.dir).save(&bad).is_err());
    w.reopen();
    assert_eq!(w.sent.index().entries[0].label, "DB prod");
}

#[test]
fn next_wake_schedules_vault_retries_and_the_purge() {
    let mut w = world();
    let id = w.created(true);
    w.poll(true);
    w.api.recipient_consumes(&w.server_id(&id));
    w.vault.fail_delete(Some(VaultError::Other));
    w.clock.advance(POLL_FOCUSED);
    w.poll(true);
    assert_eq!(w.status(&id), Status::Read);
    assert_eq!(w.vault.ids(), vec![id.clone()]);
    // Driven only by next_wake, as the app's timer would be.
    w.vault.fail_delete(None);
    let wake = w
        .sent
        .next_wake(w.now(), false)
        .expect("a retry is scheduled");
    assert!(wake > w.now() && wake <= w.now() + HOUR);
    w.clock.set(wake);
    w.sent.tick(w.now());
    assert!(w.vault.ids().is_empty());
    // Nothing waiting, nothing to delete: the next wake is the purge.
    let wake = w.sent.next_wake(w.now(), false).unwrap();
    assert_eq!(wake, T0 + KEEP);
    w.clock.set(wake);
    w.sent.tick(w.now());
    assert!(w.sent.entry(&id).is_none());
    assert_eq!(w.sent.next_wake(w.now(), false), None);
}

#[test]
fn a_revoke_returns_notifications_of_other_kept_answers() {
    let mut w = world();
    let a = w.created(true);
    let b = w.created(true);
    w.poll(true);
    w.api.recipient_consumes(&w.server_id(&a));
    // a's Read arrives while the disk refuses: kept, not notified yet.
    w.fail.store(true, Ordering::SeqCst);
    w.clock.advance(POLL_FOCUSED);
    let now = w.now();
    for c in w.sent.due_checks(now, true) {
        if c.id == a {
            let r = w.api.status(&c.owner);
            assert!(w.sent.apply_status(&c.id, r, now).is_empty());
        } else {
            w.sent.apply_status(&c.id, Err(ApiError::Network), now);
        }
    }
    w.fail.store(false, Ordering::SeqCst);
    // Revoking b writes a's kept answer too: a's notification must come out here.
    let owner = w.sent.revoke_target(&b, w.now()).unwrap();
    let r = w.api.revoke(&owner);
    let (ok, effects) = w.sent.apply_revoke(&b, r, w.now());
    assert!(ok.is_ok());
    assert_eq!(effects.len(), 1);
    assert!(matches!(&effects[0], Effect::Notify { id, .. } if *id == a));
    assert_eq!(w.status(&a), Status::Read);
    assert_eq!(w.status(&b), Status::Revoked);
}

#[test]
fn a_late_retry_after_expiry_writes_nothing_to_the_vault() {
    let mut w = world();
    let mut sc = w.create(true);
    let now = w.now();
    w.vault.fail_put(Some(VaultError::Other));
    assert_eq!(
        w.sent.finish(&mut sc, |t, k| w.clip.copy(t, k, now), now),
        Err(LocalFailure::Vault)
    );
    w.vault.fail_put(None);
    // The user leaves the Retry screen open past the expiry; tick closes the entry.
    w.clock.advance(2 * DAY);
    w.sent.tick(w.now());
    assert_eq!(w.status(&sc.local_id), Status::ExpiredUnknown);
    let now = w.now();
    w.sent
        .finish(&mut sc, |t, k| w.clip.copy(t, k, now), now)
        .unwrap();
    assert!(
        w.vault.ids().is_empty(),
        "no links written for a finished entry"
    );
    let e = w.sent.entry(&sc.local_id).unwrap();
    assert_eq!(
        e.status,
        Status::ExpiredUnknown,
        "the retry does not reset the status"
    );
    assert_eq!(e.vault, VaultState::None);
}

#[test]
fn a_retry_after_recovery_marked_it_untracked_writes_the_intent_again() {
    let mut w = world();
    let mut sc = w.create(true);
    let now = w.now();
    w.vault.fail_put(Some(VaultError::Other));
    assert_eq!(
        w.sent.finish(&mut sc, |t, k| w.clip.copy(t, k, now), now),
        Err(LocalFailure::Vault)
    );
    w.vault.fail_put(None);
    // A restart in between: recovery finds no item and marks the entry untracked.
    let id = sc.local_id.clone();
    let index_before = std::fs::read(w.dir.join(crate::history::FILE_NAME)).unwrap();
    w.reopen();
    assert_eq!(w.sent.entry(&id).unwrap().vault, VaultState::None);
    // The Retry must put Pending on disk before writing the vault: fail that write.
    w.fail.store(true, Ordering::SeqCst);
    assert_eq!(
        w.sent.finish(&mut sc, |t, k| w.clip.copy(t, k, now), now),
        Err(LocalFailure::Index)
    );
    assert!(
        w.vault.ids().is_empty(),
        "no vault write without the intent on disk"
    );
    w.fail.store(false, Ordering::SeqCst);
    w.sent
        .finish(&mut sc, |t, k| w.clip.copy(t, k, now), now)
        .unwrap();
    let e = w.sent.entry(&id).unwrap();
    assert_eq!((e.vault, e.tracked), (VaultState::Present, true));
    drop(index_before);
}

#[test]
fn a_failing_purge_backs_off() {
    let mut w = world();
    let id = w.created(true);
    w.clock.set(T0 + KEEP);
    w.vault.fail_delete(Some(VaultError::Unavailable));
    w.sent.tick(w.now());
    let calls = w.vault.delete_calls();
    assert!(w.sent.entry(&id).is_some());
    let wake = w.sent.next_wake(w.now(), false).unwrap();
    assert!(wake >= w.now() + HOUR, "no busy loop: next try in an hour");
    w.clock.advance(MINUTE);
    w.sent.tick(w.now());
    assert_eq!(w.vault.delete_calls(), calls, "not retried before its time");
    w.vault.fail_delete(None);
    w.clock.set(wake);
    w.sent.tick(w.now());
    assert!(w.sent.entry(&id).is_none());
}

#[test]
fn a_locked_vault_at_start_is_recovered_later() {
    let mut w = world();
    let mut sc = w.create(true);
    let now = w.now();
    // Crash after the vault write, before Present was written.
    w.sent.commit(|i| i.entries.push(sc.entry.clone())).unwrap();
    w.vault
        .put(
            &sc.local_id,
            &Links {
                recipient: sc.recipient.clone(),
                owner: sc.owner.clone(),
            },
        )
        .unwrap();
    w.vault.fail_get(Some(VaultError::Unavailable));
    w.reopen();
    let id = sc.local_id.clone();
    assert_eq!(w.sent.entry(&id).unwrap().vault, VaultState::Pending);
    let wake = w.sent.next_wake(w.now(), true).unwrap();
    assert!(wake <= now + MINUTE);
    w.vault.fail_get(None);
    w.clock.set(wake);
    assert_eq!(
        w.poll(true).0,
        0,
        "recovered in this tick, polled from the next"
    );
    assert_eq!(w.sent.entry(&id).unwrap().vault, VaultState::Present);
    assert_eq!(w.poll(true).0, 1);
    sc.local_id.clear();
}

#[test]
fn a_retry_of_the_final_write_after_expiry_keeps_the_entry_closed() {
    let mut w = world();
    let now = w.now();
    let fail = w.fail.clone();
    // Entry (pending) and vault written, then the final entry write fails.
    let mut sc = w.create(true);
    let id2 = sc.local_id.clone();
    w.sent
        .commit(|i| {
            let mut e = sc.entry.clone();
            e.vault = VaultState::Pending;
            i.entries.push(e);
        })
        .unwrap();
    sc.index_started = true;
    w.vault
        .put(
            &id2,
            &Links {
                recipient: sc.recipient.clone(),
                owner: sc.owner.clone(),
            },
        )
        .unwrap();
    sc.vault_done = true;
    sc.entry.vault = VaultState::Present;
    fail.store(true, Ordering::SeqCst);
    assert_eq!(
        w.sent.finish(&mut sc, |t, k| w.clip.copy(t, k, now), now),
        Err(LocalFailure::Index)
    );
    fail.store(false, Ordering::SeqCst);
    // Past expiry, tick closes it and cleans the vault item up.
    w.clock.advance(2 * DAY);
    w.sent.tick(w.now());
    assert_eq!(w.status(&id2), Status::ExpiredUnknown);
    // The Retry finishes without reopening the entry or claiming a vault item.
    let now = w.now();
    w.sent
        .finish(&mut sc, |t, k| w.clip.copy(t, k, now), now)
        .unwrap();
    let e = w.sent.entry(&id2).unwrap();
    assert_eq!(e.status, Status::ExpiredUnknown);
    assert_eq!(e.vault, VaultState::None);
    assert!(!w.vault.ids().contains(&id2));
    assert_eq!(w.poll(true).0, 0);
}

#[test]
fn a_failing_disk_pauses_maintenance_instead_of_looping() {
    // An old entry past its TTL and the 30 days, the disk refuses writes.
    let mut w = world();
    let id = w.created(true);
    w.clock.set(T0 + KEEP + DAY);
    w.fail.store(true, Ordering::SeqCst);
    w.sent.tick(w.now());
    assert_eq!(w.status(&id), Status::Waiting, "nothing could be written");
    let wake = w.sent.next_wake(w.now(), false).unwrap();
    assert!(
        wake >= w.now() + DISK_RETRY,
        "no immediate wake while the disk fails"
    );
    let saves = w.saves.load(Ordering::SeqCst);
    w.clock.advance(SECOND);
    w.sent.tick(w.now());
    assert_eq!(
        w.saves.load(Ordering::SeqCst),
        saves,
        "no writes before the pause ends"
    );
    w.fail.store(false, Ordering::SeqCst);
    w.clock.set(wake);
    w.sent.tick(w.now());
    assert!(
        w.sent.entry(&id).is_none(),
        "closed and purged once the disk is back"
    );
    assert!(w.vault.ids().is_empty());
}

#[test]
fn a_vault_delete_that_cannot_be_recorded_keeps_its_pause() {
    let mut w = world();
    let id = w.created(true);
    w.poll(true);
    w.api.recipient_consumes(&w.server_id(&id));
    w.vault.fail_delete(Some(VaultError::Other));
    w.clock.advance(POLL_FOCUSED);
    w.poll(true);
    assert_eq!(w.status(&id), Status::Read);
    // At the retry the vault works, the disk does not.
    let retry = w.sent.next_wake(w.now(), false).unwrap();
    w.vault.fail_delete(None);
    w.fail.store(true, Ordering::SeqCst);
    w.clock.set(retry);
    w.sent.tick(w.now());
    assert!(w.vault.ids().is_empty(), "the item itself is gone");
    assert_eq!(
        w.sent.entry(&id).unwrap().vault,
        VaultState::Present,
        "not recorded"
    );
    let wake = w.sent.next_wake(w.now(), false).unwrap();
    assert!(wake > w.now(), "no busy loop");
    let deletes = w.vault.delete_calls();
    w.clock.advance(SECOND);
    w.sent.tick(w.now());
    assert_eq!(w.vault.delete_calls(), deletes);
    w.fail.store(false, Ordering::SeqCst);
    w.clock.set(wake.max(w.now() + DISK_RETRY));
    w.sent.tick(w.now());
    assert_eq!(w.sent.entry(&id).unwrap().vault, VaultState::None);
}

#[test]
fn losing_tracking_on_a_failing_disk_waits_for_the_poll_interval() {
    let mut w = world();
    let id = w.created(true);
    w.vault.delete(&id).unwrap();
    w.fail.store(true, Ordering::SeqCst);
    // The app loop: due_checks → tick → sleep until next_wake.
    let mut wakes = Vec::new();
    for _ in 0..5 {
        let now = w.now();
        assert!(w.sent.due_checks(now, true).is_empty());
        w.sent.tick(now);
        let wake = w.sent.next_wake(now, true).unwrap();
        assert!(wake > now, "no busy loop");
        wakes.push(wake - now);
        w.clock.set(wake);
    }
    assert!(wakes.iter().all(|&d| d >= SECOND), "{wakes:?}");
    let saves = w.saves.load(Ordering::SeqCst);
    assert!(saves < 20, "a handful of writes, not a loop: {saves}");
    w.fail.store(false, Ordering::SeqCst);
    w.clock.advance(POLL_FOCUSED);
    w.sent.due_checks(w.now(), true);
    assert!(!w.sent.entry(&id).unwrap().tracked);
}

#[test]
fn a_request_in_flight_at_expiry_does_not_spin_the_scheduler() {
    let mut w = world();
    let id = w.created(true);
    let expires = w.sent.entry(&id).unwrap().expires_at;
    w.clock.set(expires - 5 * SECOND);
    let checks = w.sent.due_checks(w.now(), true);
    assert_eq!(checks.len(), 1);
    w.api.recipient_consumes(&w.server_id(&id));
    let answer = w.api.status(&checks[0].owner);
    // The answer is late: the loop goes on past expiry.
    w.clock.set(expires + SECOND);
    for _ in 0..3 {
        let now = w.now();
        assert!(w.sent.due_checks(now, true).is_empty());
        w.sent.tick(now);
        assert_eq!(
            w.status(&id),
            Status::Waiting,
            "the request in flight decides"
        );
        if let Some(wake) = w.sent.next_wake(now, true) {
            assert!(wake > now, "no busy loop while the request is out");
        }
        w.clock.advance(SECOND);
    }
    let effects = w.sent.apply_status(&checks[0].id, answer, w.now());
    assert_eq!(effects.len(), 1);
    assert_eq!(w.status(&id), Status::Read);
}

#[test]
fn session_link_ends_with_the_secret() {
    let mut w = world();
    w.vault.fail_put(Some(VaultError::Unavailable));
    let id = w.created(true);
    assert!(w.sent.recipient_link(&id, w.now()).is_some());
    w.clock.advance(2 * DAY);
    assert!(
        w.sent.recipient_link(&id, w.now()).is_none(),
        "not after expiry"
    );
    w.vault.fail_get(Some(VaultError::Unavailable));
    assert!(!w.sent.vault_works());
    w.vault.fail_get(None);
    assert!(w.sent.vault_works());
}
