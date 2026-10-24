//! Local history index (SPEC 4): metadata of sent secrets in one JSON file in the app data
//! directory. Never the text, the key, the links, the server id or tokens: those live only in the
//! OS vault. Parsed strictly: an unknown field, a wrong type or a value out of range rejects the
//! whole file instead of being dropped silently.

use crate::time::{DAY, Millis};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};

pub const FILE_NAME: &str = "history.json";
pub const VERSION: u32 = 1;
/// Entries older than this are removed (SPEC 4).
pub const KEEP: Millis = 30 * DAY;
pub const MAX_LABEL: usize = 200;
const MAX_CONSUMED_BY: usize = 254;
const MAX_FILE_SIZE: u64 = 1 << 20;

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Waiting,
    Read,
    Revoked,
    /// 404 before `expiresAt`.
    NotFound,
    /// Past `expiresAt` without a confirmed terminal answer: the service no longer knows.
    ExpiredUnknown,
}

/// Whether the OS vault holds this entry's links (the vault cannot be listed, SPEC 4).
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VaultState {
    /// Nothing in the vault (never written, deleted, or the vault is unavailable).
    None,
    /// About to be written: after a crash the item may or may not exist, so it is deleted.
    Pending,
    Present,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FileMeta {
    pub name: String,
    pub size: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Entry {
    /// Local id: 32 lowercase hex characters, also the vault account name.
    pub id: String,
    /// Local only, may be empty.
    pub label: String,
    pub created_at: Millis,
    pub expires_at: Millis,
    pub ttl: u32,
    pub status: Status,
    pub status_at: Millis,
    /// Last successful status request.
    pub checked_at: Option<Millis>,
    /// Last status answer `stored`.
    pub stored_seen_at: Option<Millis>,
    /// The read notification was committed (shown at most once).
    pub notified_at: Option<Millis>,
    pub vault: VaultState,
    /// False: created without the vault, no status, revoke or notification (SPEC 4).
    pub tracked: bool,
    pub passphrase: bool,
    pub notify: bool,
    /// Line count of the text, None when the secret has no text.
    pub text_lines: Option<u32>,
    pub files: Vec<FileMeta>,
    pub link_copied_at: Option<Millis>,
    pub clipboard_cleared_at: Option<Millis>,
    pub consumed_at: Option<Millis>,
    pub consumed_by: Option<String>,
    pub revoked_at: Option<Millis>,
    /// Host of the service origin.
    pub server: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct Index {
    pub version: u32,
    pub entries: Vec<Entry>,
}

#[derive(Debug)]
pub enum HistoryError {
    Io(std::io::Error),
    /// Not our format; the reason names the rule, never a value from the file.
    Damaged(&'static str),
}

impl std::fmt::Display for HistoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HistoryError::Io(e) => write!(f, "history file: {}", e.kind()),
            HistoryError::Damaged(why) => write!(f, "history file is damaged: {why}"),
        }
    }
}

pub fn is_local_id(s: &str) -> bool {
    s.len() == 32 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

pub fn new_local_id() -> String {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).expect("system random number generator is unavailable");
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn valid_host(s: &str) -> bool {
    let host = match s.rsplit_once(':') {
        Some((h, p)) if !p.is_empty() && p.len() <= 5 && p.bytes().all(|b| b.is_ascii_digit()) => h,
        _ => s,
    };
    !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && l.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

impl Entry {
    fn check(&self) -> Result<(), &'static str> {
        if !is_local_id(&self.id) {
            return Err("entry id");
        }
        if self.label.chars().count() > MAX_LABEL || self.label.chars().any(char::is_control) {
            return Err("label");
        }
        if ![3600, 86400, 604800].contains(&self.ttl) {
            return Err("ttl");
        }
        if self.expires_at < self.created_at {
            return Err("expiry before creation");
        }
        if self.files.len() > sdrop::format::MAX_FILES
            || self.files.iter().any(|f| {
                !sdrop::format::valid_file_name(&f.name) || f.size == 0 || f.size > MAX_FILE_SIZE
            })
        {
            return Err("files");
        }
        if self.text_lines.is_none() && self.files.is_empty() {
            return Err("empty content");
        }
        if let Some(by) = &self.consumed_by
            && (by.is_empty()
                || by.chars().count() > MAX_CONSUMED_BY
                || by.chars().any(char::is_control))
        {
            return Err("consumed by");
        }
        if !valid_host(&self.server) {
            return Err("server");
        }
        Ok(())
    }
}

impl Index {
    pub fn new() -> Index {
        Index {
            version: VERSION,
            entries: Vec::new(),
        }
    }

    pub fn parse(bytes: &[u8]) -> Result<Index, HistoryError> {
        let index: Index = serde_json::from_slice(bytes)
            .map_err(|_| HistoryError::Damaged("not the index format"))?;
        index.validate().map_err(HistoryError::Damaged)?;
        Ok(index)
    }

    /// The rules `parse` enforces; `save` checks them too, so the app never writes an index it
    /// would reject on the next start.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.version != VERSION {
            return Err("version");
        }
        let mut seen = std::collections::HashSet::new();
        for e in &self.entries {
            e.check()?;
            if !seen.insert(e.id.as_str()) {
                return Err("duplicate entry id");
            }
        }
        Ok(())
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec_pretty(self).expect("index serializes")
    }

    pub fn get(&self, id: &str) -> Option<&Entry> {
        self.entries.iter().find(|e| e.id == id)
    }

    pub fn get_mut(&mut self, id: &str) -> Option<&mut Entry> {
        self.entries.iter_mut().find(|e| e.id == id)
    }

    /// Newest first, as the sidebar shows them.
    pub fn sorted(&self) -> Vec<&Entry> {
        let mut v: Vec<&Entry> = self.entries.iter().collect();
        v.sort_by(|a, b| b.created_at.cmp(&a.created_at).then(a.id.cmp(&b.id)));
        v
    }

    /// Case-insensitive label search.
    pub fn search(&self, query: &str) -> Vec<&Entry> {
        let q = query.trim().to_lowercase();
        self.sorted()
            .into_iter()
            .filter(|e| q.is_empty() || e.label.to_lowercase().contains(&q))
            .collect()
    }

    /// Entries older than 30 days (SPEC 4). The caller deletes their vault item first and only then
    /// removes them, so no vault item is left without its entry.
    pub fn expired_ids(&self, now: Millis) -> Vec<String> {
        self.entries
            .iter()
            .filter(|e| now - e.created_at >= KEEP)
            .map(|e| e.id.clone())
            .collect()
    }

    pub fn remove(&mut self, id: &str) {
        self.entries.retain(|e| e.id != id);
    }
}

/// The index file in the app data directory, written atomically (temp file + rename), private to
/// the user on Unix (directory 0700, file 0600).
pub struct HistoryStore {
    dir: PathBuf,
    /// Tests: make every save fail (disk full, read-only directory).
    fail_writes: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// Tests: how many saves were tried.
    attempts: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl HistoryStore {
    pub fn new(dir: impl Into<PathBuf>) -> HistoryStore {
        HistoryStore {
            dir: dir.into(),
            fail_writes: Default::default(),
            attempts: Default::default(),
        }
    }

    /// Tests: a counter of save attempts.
    #[cfg(any(test, feature = "test-loopback"))]
    pub fn attempts(&self) -> std::sync::Arc<std::sync::atomic::AtomicUsize> {
        self.attempts.clone()
    }

    /// Tests: a switch that makes saves fail.
    #[cfg(any(test, feature = "test-loopback"))]
    pub fn fail_switch(&self) -> std::sync::Arc<std::sync::atomic::AtomicBool> {
        self.fail_writes.clone()
    }

    pub fn path(&self) -> PathBuf {
        self.dir.join(FILE_NAME)
    }

    /// A missing file is an empty history; a damaged one is an error (never treated as empty).
    pub fn load(&self) -> Result<Index, HistoryError> {
        match std::fs::read(self.path()) {
            Ok(b) => Index::parse(&b),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Index::new()),
            Err(e) => Err(HistoryError::Io(e)),
        }
    }

    /// Moves a damaged file aside (kept for the user, never parsed again) and returns its new name.
    pub fn quarantine(&self, now: Millis) -> std::io::Result<PathBuf> {
        let to = self.dir.join(format!("{FILE_NAME}.damaged-{now}"));
        std::fs::rename(self.path(), &to)?;
        Ok(to)
    }

    pub fn save(&self, index: &Index) -> std::io::Result<()> {
        self.attempts
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if self.fail_writes.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(std::io::Error::other("writes disabled"));
        }
        index.validate().map_err(std::io::Error::other)?;
        create_private_dir(&self.dir)?;
        let tmp = self.dir.join(format!("{FILE_NAME}.tmp-{}", new_local_id()));
        let result = (|| {
            let mut f = create_private_file(&tmp)?;
            f.write_all(&index.to_bytes())?;
            f.sync_all()?;
            drop(f);
            std::fs::rename(&tmp, self.path())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        result
    }
}

fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    let mut b = std::fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(dir)
}

fn create_private_file(path: &Path) -> std::io::Result<std::fs::File> {
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o.open(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::time::HOUR;

    pub fn entry(id: &str, created_at: Millis) -> Entry {
        Entry {
            id: id.to_owned(),
            label: "Staging DB password".into(),
            created_at,
            expires_at: created_at + 24 * HOUR,
            ttl: 86400,
            status: Status::Waiting,
            status_at: created_at,
            checked_at: None,
            stored_seen_at: None,
            notified_at: None,
            vault: VaultState::Present,
            tracked: true,
            passphrase: false,
            notify: true,
            text_lines: Some(3),
            files: vec![FileMeta {
                name: "stage-ca.pem".into(),
                size: 2048,
            }],
            link_copied_at: None,
            clipboard_cleared_at: None,
            consumed_at: None,
            consumed_by: None,
            revoked_at: None,
            server: "secrets.example.com".into(),
        }
    }

    fn id(n: u8) -> String {
        format!("{n:032x}")
    }

    fn with(f: impl FnOnce(&mut Entry)) -> Vec<u8> {
        let mut e = entry(&id(1), 1000);
        f(&mut e);
        Index {
            version: VERSION,
            entries: vec![e],
        }
        .to_bytes()
    }

    #[test]
    fn round_trip() {
        let mut i = Index::new();
        i.entries.push(entry(&id(1), 1000));
        i.entries.push(entry(&id(2), 2000));
        assert_eq!(Index::parse(&i.to_bytes()).unwrap(), i);
        assert!(is_local_id(&new_local_id()));
        assert_ne!(new_local_id(), new_local_id());
    }

    #[test]
    fn strict_parse_rejects() {
        let good = String::from_utf8(with(|_| {})).unwrap();
        // An extra field anywhere: a link or a token could hide in it.
        for (from, to) in [
            ("\"label\":", "\"link\": \"x\", \"label\":"),
            ("\"name\":", "\"ownerToken\": \"x\", \"name\":"),
            ("\"version\":", "\"extra\": 1, \"version\":"),
        ] {
            let bad = good.replacen(from, to, 1);
            assert!(Index::parse(bad.as_bytes()).is_err(), "{to}");
        }
        assert!(
            Index::parse(
                good.replace("\"ttl\": 86400", "\"ttl\": \"86400\"")
                    .as_bytes()
            )
            .is_err()
        );
        assert!(Index::parse(good.replace("\"version\": 1", "\"version\": 2").as_bytes()).is_err());
        assert!(Index::parse(b"").is_err());
        assert!(Index::parse(good.as_bytes()).is_ok());

        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("id", with(|e| e.id = "XYZ".into())),
            ("label", with(|e| e.label = "a\nb".into())),
            ("label long", with(|e| e.label = "x".repeat(MAX_LABEL + 1))),
            ("ttl", with(|e| e.ttl = 60)),
            ("expiry", with(|e| e.expires_at = e.created_at - 1)),
            ("file name", with(|e| e.files[0].name = "../etc".into())),
            ("file size", with(|e| e.files[0].size = 0)),
            (
                "files",
                with(|e| {
                    e.files = vec![
                        FileMeta {
                            name: "a".into(),
                            size: 1
                        };
                        21
                    ];
                }),
            ),
            (
                "empty",
                with(|e| {
                    e.text_lines = None;
                    e.files.clear();
                }),
            ),
            ("server", with(|e| e.server = "https://x".into())),
            ("consumed by", with(|e| e.consumed_by = Some(String::new()))),
        ];
        for (name, bytes) in cases {
            assert!(Index::parse(&bytes).is_err(), "{name}");
        }
        let mut dup = Index::new();
        dup.entries = vec![entry(&id(1), 1), entry(&id(1), 2)];
        assert!(Index::parse(&dup.to_bytes()).is_err());
    }

    #[test]
    fn search_sort_and_expiry() {
        let mut i = Index::new();
        let mut a = entry(&id(1), 1000);
        a.label = "Hetzner API token".into();
        i.entries.push(a);
        i.entries.push(entry(&id(2), 5000));
        assert_eq!(i.sorted()[0].id, id(2));
        assert_eq!(i.search("hetzner").len(), 1);
        assert_eq!(i.search("  ").len(), 2);
        assert_eq!(i.expired_ids(1000 + KEEP - 1), Vec::<String>::new());
        assert_eq!(i.expired_ids(1000 + KEEP), vec![id(1)]);
    }

    #[test]
    fn store_atomic_private_and_damaged_is_not_empty() {
        let dir = std::env::temp_dir().join(format!("pnesecrets-test-{}", new_local_id()));
        let store = HistoryStore::new(dir.join("data"));
        assert_eq!(store.load().unwrap(), Index::new());
        let mut i = Index::new();
        i.entries.push(entry(&id(7), 1000));
        store.save(&i).unwrap();
        assert_eq!(store.load().unwrap(), i);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&store.path()), 0o600);
            assert_eq!(mode(&dir.join("data")), 0o700);
        }
        // No temp files left behind.
        let names: Vec<_> = std::fs::read_dir(dir.join("data"))
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from(FILE_NAME)]);
        std::fs::write(store.path(), b"{not json").unwrap();
        assert!(matches!(store.load(), Err(HistoryError::Damaged(_))));
        let moved = store.quarantine(42).unwrap();
        assert!(moved.exists());
        assert_eq!(store.load().unwrap(), Index::new());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
