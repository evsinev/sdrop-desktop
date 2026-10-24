//! The service API (FORMAT.md 6) with typed errors: the UI decides by kind (not found, unknown
//! outcome, sign-in needed), never by message text. Built on sdrop's request, Access and format
//! code: one trusted origin, no redirects, the link parsed before any request.

use crate::time::{Clock, Millis, parse_iso};
use sdrop::access::{self, Credentials};
use sdrop::api::{self, CliError, Origin, OwnerLink};
use sdrop::format::{self, Content, FormatError};
use serde_json::Value;
use zeroize::Zeroizing;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiError {
    /// 404: not found, already read, revoked, expired (indistinguishable by design).
    NotFound,
    /// The connection broke: whether the request took effect is unknown.
    Network,
    /// Cloudflare Access wants a login and there is no token (SPEC 9).
    SignInRequired,
    /// Above the service limit (local check or 413).
    TooLarge { limit: Option<usize> },
    /// 429.
    TooManyRequests,
    /// 401 / 403: the service login does not allow this.
    Denied,
    /// Any other status or a malformed answer.
    Unexpected,
    /// Not sent: its deadline (the secret's expiry) passed before the request could go out.
    TooLate,
    /// The service said 201 Created, but the answer cannot be read: the secret exists and its
    /// link is lost. Never a reason to create again silently.
    CreatedUnreadable,
    /// The secret cannot be encoded or decoded (empty text, bad file name, damaged, ...).
    Format(FormatError),
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApiError::NotFound => f.write_str(
                "Not found, already read, revoked or expired. If you did not open it yourself, tell the sender.",
            ),
            ApiError::Network => f.write_str(
                "The connection broke. The result is unknown: the request may have reached the service.",
            ),
            ApiError::SignInRequired => f.write_str("Sign in is required."),
            ApiError::TooLarge { limit: Some(n) } => write!(
                f,
                "The secret is larger than the service limit of {}.",
                sdrop::ops::human_size(*n)
            ),
            ApiError::TooLarge { limit: None } => {
                f.write_str("The secret is larger than the service limit.")
            }
            ApiError::TooManyRequests => {
                f.write_str("Too many secrets created. Wait a minute and try again.")
            }
            ApiError::Denied => f.write_str("The service does not allow this for your account."),
            ApiError::Unexpected => f.write_str("The service returned an unexpected answer."),
            ApiError::TooLate => f.write_str("Not sent: too late."),
            ApiError::CreatedUnreadable => f.write_str(
                "The service created the secret but its answer could not be read: the link is lost. It is deleted when it expires.",
            ),
            ApiError::Format(e) => write!(f, "{}", CliError::from(*e)),
        }
    }
}

impl From<FormatError> for ApiError {
    fn from(e: FormatError) -> Self {
        match e {
            FormatError::TooLarge => ApiError::TooLarge { limit: None },
            e => ApiError::Format(e),
        }
    }
}

fn from_cli(e: CliError) -> ApiError {
    match e {
        CliError::Network(_) => ApiError::Network,
        CliError::Redirect(_) => ApiError::SignInRequired,
        CliError::Msg(_) => ApiError::Unexpected,
    }
}

/// A created secret: the links (wiped buffers), the server id and the expiry.
pub struct Created {
    pub recipient: Zeroizing<String>,
    pub owner: Zeroizing<String>,
    pub expires_at: Millis,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Stored,
    Consumed,
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusReply {
    pub state: State,
    pub created_at: Millis,
    pub expires_at: Millis,
    pub consumed_at: Option<Millis>,
    pub consumed_by: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevokeReply {
    Revoked,
    AlreadyRead(StatusReply),
}

/// What the app needs from the service; `Service` is the real one, tests use fakes.
pub trait SecretsApi: Send {
    /// Origin of the service (links are built and checked against it).
    fn origin(&self) -> &Origin;
    fn limit(&mut self) -> Result<usize, ApiError>;
    fn create(
        &mut self,
        content: &Content,
        passphrase: Option<&str>,
        ttl: u32,
    ) -> Result<Created, ApiError>;
    /// Fetch the envelope; the service deletes it in the same request.
    fn consume(&mut self, id: &str) -> Result<Zeroizing<Vec<u8>>, ApiError>;
    fn status(&mut self, owner: &OwnerLink) -> Result<StatusReply, ApiError>;
    /// Status, but never sent (also not as a retry after an Access login) at or after
    /// `not_after`: then `TooLate`.
    fn status_until(
        &mut self,
        owner: &OwnerLink,
        not_after: Millis,
    ) -> Result<StatusReply, ApiError> {
        let _ = not_after;
        self.status(owner)
    }
    fn revoke(&mut self, owner: &OwnerLink) -> Result<RevokeReply, ApiError>;
    /// After a sign-in: read the Access token again on the next request.
    fn reset_credentials(&mut self) {}
}

pub struct Service {
    /// Requests are not sent at or after this (status before an expiry).
    not_after: Option<Millis>,
    origin: Origin,
    agent: ureq::Agent,
    creds: Option<Credentials>,
    creds_read: bool,
    limit: Option<usize>,
}

fn json(body: &[u8]) -> Result<Value, ApiError> {
    serde_json::from_slice(body).map_err(|_| ApiError::Unexpected)
}

fn field<'a>(v: &'a Value, name: &str) -> Result<&'a str, ApiError> {
    v.get(name)
        .and_then(Value::as_str)
        .ok_or(ApiError::Unexpected)
}

fn time(v: &Value, name: &str) -> Result<Millis, ApiError> {
    parse_iso(field(v, name)?).ok_or(ApiError::Unexpected)
}

fn opt_time(v: &Value, name: &str) -> Result<Option<Millis>, ApiError> {
    match v.get(name) {
        None => Ok(None),
        Some(_) => time(v, name).map(Some),
    }
}

/// The reader's email from a service with login: printable, bounded, or the answer is rejected.
fn consumed_by(v: &Value) -> Result<Option<String>, ApiError> {
    match v.get("consumedBy") {
        None => Ok(None),
        Some(Value::String(s))
            if !s.is_empty() && s.chars().count() <= 254 && !s.chars().any(char::is_control) =>
        {
            Ok(Some(s.clone()))
        }
        Some(_) => Err(ApiError::Unexpected),
    }
}

pub fn parse_status(body: &[u8]) -> Result<StatusReply, ApiError> {
    let v = json(body)?;
    let state = match field(&v, "state")? {
        "stored" => State::Stored,
        "consumed" => State::Consumed,
        "revoked" => State::Revoked,
        _ => return Err(ApiError::Unexpected),
    };
    let reply = StatusReply {
        state,
        created_at: time(&v, "createdAt")?,
        expires_at: time(&v, "expiresAt")?,
        consumed_at: opt_time(&v, "consumedAt")?,
        consumed_by: consumed_by(&v)?,
    };
    if (reply.state == State::Consumed) != reply.consumed_at.is_some() {
        return Err(ApiError::Unexpected);
    }
    Ok(reply)
}

fn status_error(status: u16) -> ApiError {
    match status {
        401 | 403 => ApiError::Denied,
        404 => ApiError::NotFound,
        429 => ApiError::TooManyRequests,
        _ => ApiError::Unexpected,
    }
}

impl Service {
    pub fn new(origin: Origin) -> Service {
        Service {
            not_after: None,
            origin,
            agent: api::agent(),
            creds: None,
            creds_read: false,
            limit: None,
        }
    }

    fn call(
        &mut self,
        method: &str,
        path: &str,
        extra: &[(&str, &str)],
        body: Option<&[u8]>,
    ) -> Result<api::Reply, ApiError> {
        if !self.creds_read {
            self.creds = access::user_preset().map_err(|_| ApiError::SignInRequired)?;
            self.creds_read = true;
        }
        let send = |s: &Service| {
            if s.not_after
                .is_some_and(|t| crate::time::SystemClock.now() >= t)
            {
                return Err(CliError::Msg(TOO_LATE.into()));
            }
            api::call(
                &s.agent,
                &s.origin,
                method,
                path,
                s.creds.as_ref(),
                extra,
                body,
            )
        };
        let r = match send(self) {
            // Access asks for a login: the request never reached the service. An existing
            // cloudflared session is used silently; no terminal login from the app.
            Err(CliError::Redirect(_)) if self.creds.is_none() => {
                self.creds = Some(
                    access::user_login(&self.origin, false)
                        .map_err(|_| ApiError::SignInRequired)?,
                );
                send(self)
            }
            r => r,
        };
        match r {
            Err(CliError::Msg(m)) if m == TOO_LATE => Err(ApiError::TooLate),
            r => r.map_err(from_cli),
        }
    }
}

impl SecretsApi for Service {
    fn origin(&self) -> &Origin {
        &self.origin
    }

    fn limit(&mut self) -> Result<usize, ApiError> {
        if let Some(n) = self.limit {
            return Ok(n);
        }
        let r = self.call("GET", "/api/limits", &[], None)?;
        if r.status != 200 {
            return Err(status_error(r.status));
        }
        let n = json(&r.body)?
            .get("maxBucket")
            .and_then(Value::as_u64)
            .map(|n| n as usize)
            .filter(|n| format::BUCKETS.contains(n))
            .ok_or(ApiError::Unexpected)?;
        self.limit = Some(n);
        Ok(n)
    }

    fn create(
        &mut self,
        content: &Content,
        passphrase: Option<&str>,
        ttl: u32,
    ) -> Result<Created, ApiError> {
        if ![3600, 86400, 604800].contains(&ttl) {
            return Err(ApiError::Unexpected);
        }
        let limit = self.limit()?;
        let (envelope, k_url) =
            format::encrypt(content, passphrase, limit).map_err(|e| match e {
                FormatError::TooLarge => ApiError::TooLarge { limit: Some(limit) },
                e => ApiError::Format(e),
            })?;
        let r = self.call(
            "POST",
            &format!("/api/secrets?ttl={ttl}"),
            &[("Content-Type", "application/octet-stream")],
            Some(&envelope),
        )?;
        match r.status {
            201 => {}
            413 => return Err(ApiError::TooLarge { limit: Some(limit) }),
            s => return Err(status_error(s)),
        }
        // From here the secret exists on the service: any failure is "created, unreadable".
        let lost = |_| ApiError::CreatedUnreadable;
        let v = json(&r.body).map_err(lost)?;
        let id = field(&v, "id").map_err(lost)?;
        let token = field(&v, "ownerToken").map_err(lost)?;
        let expires_at = time(&v, "expiresAt").map_err(lost)?;
        if id.len() != 64
            || !id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
            || format::decode_key(token).is_err()
        {
            return Err(ApiError::CreatedUnreadable);
        }
        let suffix = if passphrase.is_some() {
            format::PASSPHRASE_SUFFIX
        } else {
            ""
        };
        // Wiped buffers reserved up front: no reallocation leaves a copy of the key.
        let link = |kind: &str, extra: usize| {
            let mut l = Zeroizing::new(String::with_capacity(
                self.origin.as_str().len() + kind.len() + id.len() + 1 + extra,
            ));
            l.push_str(self.origin.as_str());
            l.push_str(kind);
            l.push_str(id);
            l.push('#');
            l
        };
        let mut recipient = link("/s/", 43 + suffix.len());
        format::push_key(&mut recipient, &k_url);
        recipient.push_str(suffix);
        let mut owner = link("/o/", token.len());
        owner.push_str(token);
        Ok(Created {
            recipient,
            owner,
            expires_at,
        })
    }

    fn consume(&mut self, id: &str) -> Result<Zeroizing<Vec<u8>>, ApiError> {
        let r = self.call("POST", &format!("/api/secrets/{id}/consume"), &[], None)?;
        match r.status {
            200 => Ok(Zeroizing::new(r.body)),
            s => Err(status_error(s)),
        }
    }

    fn status(&mut self, owner: &OwnerLink) -> Result<StatusReply, ApiError> {
        let auth = Zeroizing::new(format!("Bearer {}", owner.token.as_str()));
        let r = self.call(
            "GET",
            &format!("/api/secrets/{}/status", owner.id),
            &[("Authorization", &auth)],
            None,
        )?;
        match r.status {
            200 => parse_status(&r.body),
            s => Err(status_error(s)),
        }
    }

    fn revoke(&mut self, owner: &OwnerLink) -> Result<RevokeReply, ApiError> {
        let auth = Zeroizing::new(format!("Bearer {}", owner.token.as_str()));
        let r = self.call(
            "DELETE",
            &format!("/api/secrets/{}", owner.id),
            &[("Authorization", &auth)],
            None,
        )?;
        match r.status {
            204 => Ok(RevokeReply::Revoked),
            409 => Ok(RevokeReply::AlreadyRead(parse_status(&r.body)?)),
            s => Err(status_error(s)),
        }
    }

    fn reset_credentials(&mut self) {
        self.creds = None;
        self.creds_read = false;
    }

    fn status_until(
        &mut self,
        owner: &OwnerLink,
        not_after: Millis,
    ) -> Result<StatusReply, ApiError> {
        self.not_after = Some(not_after);
        let r = self.status(owner);
        self.not_after = None;
        r
    }
}

const TOO_LATE: &str = "too late";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_parsing_is_strict() {
        let ok = br#"{"state":"consumed","createdAt":"2026-10-22T12:00:00.000Z","expiresAt":"2026-10-23T12:00:00.000Z","consumedAt":"2026-10-22T14:05:00.000Z","consumedBy":"a@b.c"}"#;
        let s = parse_status(ok).unwrap();
        assert_eq!(s.state, State::Consumed);
        assert_eq!(s.consumed_by.as_deref(), Some("a@b.c"));
        let stored = br#"{"state":"stored","createdAt":"2026-10-22T12:00:00.000Z","expiresAt":"2026-10-23T12:00:00.000Z"}"#;
        assert_eq!(parse_status(stored).unwrap().state, State::Stored);
        for bad in [
            &br#"{"state":"gone","createdAt":"2026-10-22T12:00:00.000Z","expiresAt":"2026-10-23T12:00:00.000Z"}"#[..],
            br#"{"state":"stored","createdAt":"2026-10-22","expiresAt":"2026-10-23T12:00:00.000Z"}"#,
            br#"{"state":"consumed","createdAt":"2026-10-22T12:00:00.000Z","expiresAt":"2026-10-23T12:00:00.000Z"}"#,
            br#"{"state":"stored","createdAt":"2026-10-22T12:00:00.000Z","expiresAt":"2026-10-23T12:00:00.000Z","consumedAt":"2026-10-22T14:05:00.000Z"}"#,
            br#"{"state":"consumed","createdAt":"2026-10-22T12:00:00.000Z","expiresAt":"2026-10-23T12:00:00.000Z","consumedAt":"2026-10-22T14:05:00.000Z","consumedBy":"a\nb"}"#,
            br#"{"state":"consumed","createdAt":"2026-10-22T12:00:00.000Z","expiresAt":"2026-10-23T12:00:00.000Z","consumedAt":"2026-10-22T14:05:00.000Z","consumedBy":7}"#,
            b"not json",
        ] {
            assert!(parse_status(bad).is_err(), "{}", String::from_utf8_lossy(bad));
        }
    }
}
