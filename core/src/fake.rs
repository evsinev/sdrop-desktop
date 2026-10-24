//! In-memory service for tests (`test` builds and the `test-loopback` feature): the API semantics
//! of FORMAT.md 6 with real envelopes, a shared clock, call counters and injected failures.

use crate::service::{ApiError, Created, RevokeReply, SecretsApi, State, StatusReply};
use crate::time::{Clock, ManualClock, Millis};
use sdrop::api::{Origin, OwnerLink};
use sdrop::format::{self, Content};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

pub const ORIGIN: &str = "https://secrets.example.com";

#[derive(Clone)]
struct Record {
    envelope: Option<Vec<u8>>,
    token: String,
    state: State,
    created_at: Millis,
    expires_at: Millis,
    consumed_at: Option<Millis>,
    consumed_by: Option<String>,
}

#[derive(Default)]
struct Inner {
    records: HashMap<String, Record>,
    calls: HashMap<&'static str, usize>,
    failures: HashMap<&'static str, VecDeque<ApiError>>,
    /// The request reaches the service, then the answer is lost (unknown outcome).
    lose_answer: HashMap<&'static str, usize>,
    limit: usize,
    consumed_by: Option<String>,
}

#[derive(Clone)]
pub struct FakeApi {
    origin: Origin,
    clock: ManualClock,
    inner: Arc<Mutex<Inner>>,
}

fn random_hex(n: usize) -> String {
    let mut b = vec![0u8; n];
    getrandom::fill(&mut b).unwrap();
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn status_of(r: &Record) -> StatusReply {
    StatusReply {
        state: r.state,
        created_at: r.created_at,
        expires_at: r.expires_at,
        consumed_at: r.consumed_at,
        consumed_by: r.consumed_by.clone(),
    }
}

impl FakeApi {
    pub fn new(clock: ManualClock) -> FakeApi {
        let inner = Inner {
            limit: 262144,
            ..Default::default()
        };
        FakeApi {
            origin: Origin::parse(ORIGIN).unwrap(),
            clock,
            inner: Arc::new(Mutex::new(inner)),
        }
    }

    pub fn calls(&self, op: &'static str) -> usize {
        *self.inner.lock().unwrap().calls.get(op).unwrap_or(&0)
    }

    /// The next call of `op` fails with `e` before reaching the service.
    pub fn fail_next(&self, op: &'static str, e: ApiError) {
        self.inner
            .lock()
            .unwrap()
            .failures
            .entry(op)
            .or_default()
            .push_back(e);
    }

    /// The next call of `op` takes effect on the service, but the client sees a broken connection.
    pub fn lose_next_answer(&self, op: &'static str) {
        *self
            .inner
            .lock()
            .unwrap()
            .lose_answer
            .entry(op)
            .or_default() += 1;
    }

    /// Someone opens the secret (as the web page or sdrop would).
    pub fn recipient_consumes(&self, id: &str) -> bool {
        let now = self.clock.now();
        let mut i = self.inner.lock().unwrap();
        let by = i.consumed_by.clone();
        match i.records.get_mut(id) {
            Some(r) if r.state == State::Stored && now < r.expires_at => {
                r.state = State::Consumed;
                r.envelope = None;
                r.consumed_at = Some(now);
                r.consumed_by = by;
                true
            }
            _ => false,
        }
    }

    /// A service with login reports the reader.
    pub fn set_reader(&self, email: Option<&str>) {
        self.inner.lock().unwrap().consumed_by = email.map(str::to_owned);
    }

    pub fn set_limit(&self, n: usize) {
        self.inner.lock().unwrap().limit = n;
    }

    pub fn ids(&self) -> Vec<String> {
        self.inner.lock().unwrap().records.keys().cloned().collect()
    }

    /// Stores an envelope made elsewhere (a link "from the web page") and returns its id.
    pub fn store(&self, envelope: Vec<u8>, ttl: Millis) -> String {
        let now = self.clock.now();
        let id = random_hex(32);
        self.inner.lock().unwrap().records.insert(
            id.clone(),
            Record {
                envelope: Some(envelope),
                token: format::encode_base64url(&[7u8; 32]),
                state: State::Stored,
                created_at: now,
                expires_at: now + ttl,
                consumed_at: None,
                consumed_by: None,
            },
        );
        id
    }

    fn enter(&self, op: &'static str) -> Result<(), ApiError> {
        let mut i = self.inner.lock().unwrap();
        *i.calls.entry(op).or_default() += 1;
        match i.failures.get_mut(op).and_then(VecDeque::pop_front) {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    fn leave<T>(&self, op: &'static str, r: Result<T, ApiError>) -> Result<T, ApiError> {
        let mut i = self.inner.lock().unwrap();
        match i.lose_answer.get_mut(op) {
            Some(n) if *n > 0 => {
                *n -= 1;
                Err(ApiError::Network)
            }
            _ => r,
        }
    }

    /// A live record for `id` (the service forgets everything at expiry).
    fn live(&self, i: &Inner, id: &str, token: Option<&str>) -> Option<Record> {
        let r = i.records.get(id)?;
        if self.clock.now() >= r.expires_at || token.is_some_and(|t| t != r.token) {
            return None;
        }
        Some(r.clone())
    }
}

impl SecretsApi for FakeApi {
    fn origin(&self) -> &Origin {
        &self.origin
    }

    fn limit(&mut self) -> Result<usize, ApiError> {
        self.enter("limit")?;
        let n = self.inner.lock().unwrap().limit;
        self.leave("limit", Ok(n))
    }

    fn create(
        &mut self,
        content: &Content,
        passphrase: Option<&str>,
        ttl: u32,
    ) -> Result<Created, ApiError> {
        self.enter("create")?;
        let limit = self.inner.lock().unwrap().limit;
        let (envelope, k_url) =
            format::encrypt(content, passphrase, limit).map_err(|e| match e {
                format::FormatError::TooLarge => ApiError::TooLarge { limit: Some(limit) },
                e => ApiError::Format(e),
            })?;
        let now = self.clock.now();
        let id = random_hex(32);
        let token = format::encode_base64url(&{
            let mut t = [0u8; 32];
            getrandom::fill(&mut t).unwrap();
            t
        });
        let expires_at = now + ttl as Millis * 1000;
        self.inner.lock().unwrap().records.insert(
            id.clone(),
            Record {
                envelope: Some(envelope),
                token: token.clone(),
                state: State::Stored,
                created_at: now,
                expires_at,
                consumed_at: None,
                consumed_by: None,
            },
        );
        let mut recipient = Zeroizing::new(format!("{ORIGIN}/s/{id}#"));
        format::push_key(&mut recipient, &k_url);
        if passphrase.is_some() {
            recipient.push_str(format::PASSPHRASE_SUFFIX);
        }
        let owner = Zeroizing::new(format!("{ORIGIN}/o/{id}#{token}"));
        self.leave(
            "create",
            Ok(Created {
                recipient,
                owner,
                expires_at,
            }),
        )
    }

    fn consume(&mut self, id: &str) -> Result<Zeroizing<Vec<u8>>, ApiError> {
        self.enter("consume")?;
        let now = self.clock.now();
        let r = {
            let mut i = self.inner.lock().unwrap();
            let by = i.consumed_by.clone();
            match self.live(&i, id, None) {
                Some(r) if r.state == State::Stored => {
                    let rec = i.records.get_mut(id).unwrap();
                    rec.state = State::Consumed;
                    rec.consumed_at = Some(now);
                    rec.consumed_by = by;
                    Ok(Zeroizing::new(rec.envelope.take().unwrap()))
                }
                _ => Err(ApiError::NotFound),
            }
        };
        self.leave("consume", r)
    }

    fn status_until(
        &mut self,
        owner: &OwnerLink,
        not_after: Millis,
    ) -> Result<StatusReply, ApiError> {
        if self.clock.now() >= not_after {
            return Err(ApiError::TooLate);
        }
        self.status(owner)
    }

    fn status(&mut self, owner: &OwnerLink) -> Result<StatusReply, ApiError> {
        self.enter("status")?;
        let r = {
            let i = self.inner.lock().unwrap();
            self.live(&i, &owner.id, Some(&owner.token))
                .map(|r| status_of(&r))
                .ok_or(ApiError::NotFound)
        };
        self.leave("status", r)
    }

    fn revoke(&mut self, owner: &OwnerLink) -> Result<RevokeReply, ApiError> {
        self.enter("revoke")?;
        let r = {
            let mut i = self.inner.lock().unwrap();
            match self.live(&i, &owner.id, Some(&owner.token)) {
                None => Err(ApiError::NotFound),
                Some(r) if r.state == State::Consumed => {
                    Ok(RevokeReply::AlreadyRead(status_of(&r)))
                }
                Some(_) => {
                    let rec = i.records.get_mut(&owner.id).unwrap();
                    rec.state = State::Revoked;
                    rec.envelope = None;
                    Ok(RevokeReply::Revoked)
                }
            }
        };
        self.leave("revoke", r)
    }
}
