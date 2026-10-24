//! OS vault (SPEC 4): the recipient and sender links of each tracked secret, one item per local
//! history id in Keychain / Credential Manager / Secret Service. The item is two lines,
//! `recipient\nowner`: links contain no line breaks, and no JSON parser makes copies of the key.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

pub const SERVICE: &str = "com.payneteasy.secrets";

/// The links of one sent secret.
pub struct Links {
    /// `origin/s/<id>#<K_url>[~p]`.
    pub recipient: Zeroizing<String>,
    /// `origin/o/<id>#<ownerToken>`.
    pub owner: Zeroizing<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultError {
    /// No vault on this system or access refused: create without tracking (SPEC 4).
    Unavailable,
    /// The item is not in our format.
    Damaged,
    Other,
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            VaultError::Unavailable => "the system keyring is not available",
            VaultError::Damaged => "the saved links are damaged",
            VaultError::Other => "the system keyring failed",
        })
    }
}

pub trait Vault: Send + Sync {
    fn put(&self, id: &str, links: &Links) -> Result<(), VaultError>;
    /// None: no item for this id.
    fn get(&self, id: &str) -> Result<Option<Links>, VaultError>;
    /// Deleting a missing item is fine.
    fn delete(&self, id: &str) -> Result<(), VaultError>;
}

fn encode(links: &Links) -> Zeroizing<String> {
    let mut s = Zeroizing::new(String::with_capacity(
        links.recipient.len() + 1 + links.owner.len(),
    ));
    s.push_str(&links.recipient);
    s.push('\n');
    s.push_str(&links.owner);
    s
}

fn decode(s: &str) -> Result<Links, VaultError> {
    let (r, o) = s.split_once('\n').ok_or(VaultError::Damaged)?;
    if r.is_empty() || o.is_empty() || o.contains('\n') {
        return Err(VaultError::Damaged);
    }
    let copy = |p: &str| {
        let mut z = Zeroizing::new(String::with_capacity(p.len()));
        z.push_str(p);
        z
    };
    Ok(Links {
        recipient: copy(r),
        owner: copy(o),
    })
}

/// The system vault through the `keyring` crate.
pub struct KeyringVault {
    service: String,
}

impl KeyringVault {
    pub fn new() -> KeyringVault {
        KeyringVault::with_service(SERVICE)
    }

    /// Another service name (the probe and manual tests keep apart from real data).
    pub fn with_service(service: &str) -> KeyringVault {
        KeyringVault {
            service: service.to_owned(),
        }
    }

    fn entry(&self, id: &str) -> Result<keyring::Entry, VaultError> {
        keyring::Entry::new(&self.service, id).map_err(map_err)
    }
}

impl Default for KeyringVault {
    fn default() -> Self {
        KeyringVault::new()
    }
}

fn map_err(e: keyring::Error) -> VaultError {
    match e {
        keyring::Error::NoStorageAccess(_) | keyring::Error::PlatformFailure(_) => {
            VaultError::Unavailable
        }
        keyring::Error::BadEncoding(_) => VaultError::Damaged,
        _ => VaultError::Other,
    }
}

impl Vault for KeyringVault {
    fn put(&self, id: &str, links: &Links) -> Result<(), VaultError> {
        self.entry(id)?
            .set_password(&encode(links))
            .map_err(map_err)
    }

    fn get(&self, id: &str) -> Result<Option<Links>, VaultError> {
        match self.entry(id)?.get_password() {
            Ok(s) => decode(&Zeroizing::new(s)).map(Some),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(map_err(e)),
        }
    }

    fn delete(&self, id: &str) -> Result<(), VaultError> {
        match self.entry(id)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(map_err(e)),
        }
    }
}

/// In-memory vault for tests, with switches to make each operation fail.
#[derive(Clone, Default)]
pub struct MemVault {
    inner: Arc<Mutex<MemInner>>,
}

#[derive(Default)]
struct MemInner {
    items: HashMap<String, Zeroizing<String>>,
    fail_put: Option<VaultError>,
    fail_get: Option<VaultError>,
    fail_delete: Option<VaultError>,
    delete_calls: usize,
}

impl MemVault {
    pub fn fail_put(&self, e: Option<VaultError>) {
        self.inner.lock().unwrap().fail_put = e;
    }
    pub fn fail_get(&self, e: Option<VaultError>) {
        self.inner.lock().unwrap().fail_get = e;
    }
    pub fn fail_delete(&self, e: Option<VaultError>) {
        self.inner.lock().unwrap().fail_delete = e;
    }
    pub fn delete_calls(&self) -> usize {
        self.inner.lock().unwrap().delete_calls
    }
    pub fn ids(&self) -> Vec<String> {
        let mut v: Vec<String> = self.inner.lock().unwrap().items.keys().cloned().collect();
        v.sort();
        v
    }
    /// Raw item, for tests that check what was stored.
    pub fn raw(&self, id: &str) -> Option<String> {
        self.inner
            .lock()
            .unwrap()
            .items
            .get(id)
            .map(|s| s.to_string())
    }
}

impl Vault for MemVault {
    fn put(&self, id: &str, links: &Links) -> Result<(), VaultError> {
        let mut i = self.inner.lock().unwrap();
        if let Some(e) = i.fail_put.clone() {
            return Err(e);
        }
        i.items.insert(id.to_owned(), encode(links));
        Ok(())
    }

    fn get(&self, id: &str) -> Result<Option<Links>, VaultError> {
        let i = self.inner.lock().unwrap();
        if let Some(e) = i.fail_get.clone() {
            return Err(e);
        }
        i.items.get(id).map(|s| decode(s)).transpose()
    }

    fn delete(&self, id: &str) -> Result<(), VaultError> {
        let mut i = self.inner.lock().unwrap();
        i.delete_calls += 1;
        if let Some(e) = i.fail_delete.clone() {
            return Err(e);
        }
        i.items.remove(id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn links() -> Links {
        Links {
            recipient: Zeroizing::new("https://s.example/s/ab#key~p".into()),
            owner: Zeroizing::new("https://s.example/o/ab#token".into()),
        }
    }

    #[test]
    fn encode_decode() {
        let l = decode(&encode(&links())).unwrap();
        assert_eq!(l.recipient.as_str(), "https://s.example/s/ab#key~p");
        assert_eq!(l.owner.as_str(), "https://s.example/o/ab#token");
        for bad in ["", "only-one-line", "\nowner", "recipient\n", "a\nb\nc"] {
            assert!(decode(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn mem_vault_and_failures() {
        let v = MemVault::default();
        v.put("a", &links()).unwrap();
        assert!(v.get("a").unwrap().is_some());
        assert!(v.get("b").unwrap().is_none());
        v.delete("b").unwrap();
        v.fail_delete(Some(VaultError::Other));
        assert_eq!(v.delete("a"), Err(VaultError::Other));
        assert_eq!(v.ids(), vec!["a".to_string()]);
        v.fail_delete(None);
        v.delete("a").unwrap();
        assert!(v.ids().is_empty());
    }
}
