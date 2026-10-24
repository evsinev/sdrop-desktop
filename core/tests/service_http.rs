//! `Service` against a local HTTP server (build with `--features test-loopback`): typed errors
//! from real status codes, no redirects followed, the headers FORMAT.md 6 requires.
#![cfg(feature = "test-loopback")]

use pnesecrets_core::sdrop::api::{Origin, parse_owner_link};
use pnesecrets_core::sdrop::format::{self, Content};
use pnesecrets_core::service::{ApiError, RevokeReply, SecretsApi, Service, State};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug)]
struct Req {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
}

type Handler = dyn Fn(&Req, &[u8]) -> (u16, Vec<(String, String)>, Vec<u8>) + Send + Sync;

struct Fake {
    origin: String,
    log: Arc<Mutex<Vec<Req>>>,
}

impl Fake {
    fn start(handler: Box<Handler>) -> Fake {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let log = Arc::new(Mutex::new(Vec::new()));
        let (log2, handler) = (log.clone(), Arc::new(handler));
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                if reader.read_line(&mut line).is_err() || line.is_empty() {
                    continue;
                }
                let mut parts = line.split_whitespace();
                let method = parts.next().unwrap_or("").to_owned();
                let path = parts.next().unwrap_or("").to_owned();
                let mut headers = Vec::new();
                loop {
                    let mut h = String::new();
                    reader.read_line(&mut h).unwrap();
                    let h = h.trim_end();
                    if h.is_empty() {
                        break;
                    }
                    let (k, v) = h.split_once(':').unwrap();
                    headers.push((k.trim().to_ascii_lowercase(), v.trim().to_owned()));
                }
                let len = headers
                    .iter()
                    .find(|(k, _)| k == "content-length")
                    .map_or(0, |(_, v)| v.parse().unwrap());
                let mut body = vec![0; len];
                reader.read_exact(&mut body).unwrap();
                let req = Req {
                    method,
                    path,
                    headers,
                };
                log2.lock().unwrap().push(req.clone());
                let (status, extra, out) = handler(&req, &body);
                let mut head = format!(
                    "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n",
                    out.len()
                );
                for (k, v) in extra {
                    head.push_str(&format!("{k}: {v}\r\n"));
                }
                head.push_str("\r\n");
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.write_all(&out);
            }
        });
        Fake { origin, log }
    }

    fn requests(&self) -> Vec<Req> {
        self.log.lock().unwrap().clone()
    }

    fn service(&self) -> Service {
        Service::new(Origin::parse(&self.origin).unwrap())
    }
}

const ID: &str = "4b1c0a7e5d9f3a2b8c6e1d0f7a9b3c5e2d4f6a8b0c1e3d5f7a9b2c4e6d8f0a1b";
const TOKEN: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";

fn limits() -> (u16, Vec<(String, String)>, Vec<u8>) {
    (200, vec![], br#"{"maxBucket":262144}"#.to_vec())
}

fn created() -> (u16, Vec<(String, String)>, Vec<u8>) {
    (
        201,
        vec![],
        format!(r#"{{"id":"{ID}","expiresAt":"2026-10-23T12:00:00.000Z","ownerToken":"{TOKEN}"}}"#)
            .into_bytes(),
    )
}

#[test]
fn create_builds_links_and_sends_the_envelope() {
    let envelope = Arc::new(Mutex::new(Vec::new()));
    let env2 = envelope.clone();
    let fake = Fake::start(Box::new(move |r, body| {
        match (r.method.as_str(), r.path.as_str()) {
            ("GET", "/api/limits") => limits(),
            ("POST", "/api/secrets?ttl=86400") => {
                *env2.lock().unwrap() = body.to_vec();
                created()
            }
            _ => (500, vec![], vec![]),
        }
    }));
    let mut s = fake.service();
    let c = s
        .create(&Content::Text("DB_PASSWORD=x"), Some("pw"), 86400)
        .unwrap();
    assert!(c.recipient.starts_with(&format!("{}/s/{ID}#", fake.origin)));
    assert!(c.recipient.ends_with("~p"));
    assert_eq!(c.owner.as_str(), format!("{}/o/{ID}#{TOKEN}", fake.origin));
    // The link opens the envelope the server got.
    let key = format::parse_recipient_fragment(c.recipient.split_once('#').unwrap().1)
        .unwrap()
        .0;
    let secret = format::decrypt(&envelope.lock().unwrap(), &key, Some("pw")).unwrap();
    assert_eq!(
        secret,
        format::Secret::Text(zeroize::Zeroizing::new("DB_PASSWORD=x".into()))
    );
    for r in fake.requests() {
        assert!(
            r.headers
                .iter()
                .any(|(k, v)| k == "x-secret-drop" && v == "1")
        );
        assert!(
            !r.headers
                .iter()
                .any(|(k, _)| k == "authorization" || k == "origin")
        );
        assert!(!r.path.contains('#'));
    }
    assert_eq!(
        fake.requests()
            .iter()
            .find(|r| r.method == "POST")
            .unwrap()
            .headers
            .iter()
            .find(|(k, _)| k == "content-type")
            .unwrap()
            .1,
        "application/octet-stream"
    );
}

#[test]
fn error_codes_are_typed() {
    for (status, want) in [
        (
            413,
            ApiError::TooLarge {
                limit: Some(262144),
            },
        ),
        (429, ApiError::TooManyRequests),
        (403, ApiError::Denied),
        (500, ApiError::Unexpected),
    ] {
        let fake = Fake::start(Box::new(move |r, _| match r.path.as_str() {
            "/api/limits" => limits(),
            _ => (
                status,
                vec![],
                br#"{"error":"x","maxBucket":262144}"#.to_vec(),
            ),
        }));
        let e = fake
            .service()
            .create(&Content::Text("x"), None, 3600)
            .err()
            .unwrap();
        assert_eq!(e, want, "{status}");
    }
    // Too large for the limit: refused before any upload.
    let fake = Fake::start(Box::new(|r, _| match r.path.as_str() {
        "/api/limits" => (200, vec![], br#"{"maxBucket":1024}"#.to_vec()),
        _ => created(),
    }));
    let big = "x".repeat(2000);
    assert_eq!(
        fake.service()
            .create(&Content::Text(&big), None, 3600)
            .err(),
        Some(ApiError::TooLarge { limit: Some(1024) })
    );
    assert!(fake.requests().iter().all(|r| r.method == "GET"));
    // A malformed 201 is not accepted.
    let fake = Fake::start(Box::new(|r, _| match r.path.as_str() {
        "/api/limits" => limits(),
        _ => (
            201,
            vec![],
            br#"{"id":"short","expiresAt":"2026-10-23T12:00:00.000Z","ownerToken":"x"}"#.to_vec(),
        ),
    }));
    assert_eq!(
        fake.service().create(&Content::Text("x"), None, 3600).err(),
        Some(ApiError::CreatedUnreadable)
    );
}

#[test]
fn redirect_is_not_followed_and_means_sign_in() {
    let fake = Fake::start(Box::new(|_, _| {
        (
            302,
            vec![("Location".into(), "https://login.example.com/".into())],
            vec![],
        )
    }));
    let mut s = fake.service();
    // Test build: no SDROP_TEST_* tokens set, cloudflared never called.
    assert_eq!(s.consume(ID).err(), Some(ApiError::SignInRequired));
    assert_eq!(
        fake.requests().len(),
        1,
        "no redirect followed, no retry without a token"
    );
}

#[test]
fn consume_status_and_revoke() {
    let fake = Fake::start(Box::new(|r, _| {
        let auth = r
            .headers
            .iter()
            .find(|(k, _)| k == "authorization")
            .map(|(_, v)| v.clone());
        let ok_auth = auth.as_deref() == Some(&format!("Bearer {TOKEN}"));
        match (r.method.as_str(), r.path.as_str()) {
            ("POST", p) if p == format!("/api/secrets/{ID}/consume") => {
                (200, vec![], vec![1, 2, 3])
            }
            ("POST", _) => (404, vec![], vec![]),
            ("GET", p) if p.ends_with("/status") && ok_auth => (
                200,
                vec![],
                br#"{"state":"consumed","createdAt":"2026-10-22T12:00:00.000Z","expiresAt":"2026-10-23T12:00:00.000Z","consumedAt":"2026-10-22T14:05:00.000Z","consumedBy":"r@example.com"}"#.to_vec(),
            ),
            ("DELETE", _) if ok_auth => (
                409,
                vec![],
                br#"{"state":"consumed","createdAt":"2026-10-22T12:00:00.000Z","expiresAt":"2026-10-23T12:00:00.000Z","consumedAt":"2026-10-22T14:05:00.000Z"}"#.to_vec(),
            ),
            _ => (404, vec![], vec![]),
        }
    }));
    let mut s = fake.service();
    assert_eq!(s.consume(ID).unwrap().as_slice(), &[1, 2, 3]);
    assert_eq!(s.consume(&"0".repeat(64)).err(), Some(ApiError::NotFound));
    let origin = Origin::parse(&fake.origin).unwrap();
    let owner = parse_owner_link(&origin, &format!("{}/o/{ID}#{TOKEN}", fake.origin)).unwrap();
    let st = s.status(&owner).unwrap();
    assert_eq!(st.state, State::Consumed);
    assert_eq!(st.consumed_by.as_deref(), Some("r@example.com"));
    assert!(matches!(
        s.revoke(&owner).unwrap(),
        RevokeReply::AlreadyRead(_)
    ));
    let wrong = parse_owner_link(
        &origin,
        &format!(
            "{}/o/{ID}#{}",
            fake.origin,
            format::encode_base64url(&[1u8; 32])
        ),
    )
    .unwrap();
    assert_eq!(s.status(&wrong).err(), Some(ApiError::NotFound));
    assert_eq!(s.revoke(&wrong).err(), Some(ApiError::NotFound));
}

#[test]
fn broken_connection_is_unknown() {
    // A port nobody listens on.
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = format!("http://{}", l.local_addr().unwrap());
    drop(l);
    let mut s = Service::new(Origin::parse(&origin).unwrap());
    assert_eq!(s.consume(ID).err(), Some(ApiError::Network));
}

#[test]
fn status_is_not_sent_after_its_deadline_even_as_an_access_retry() {
    // Every request redirects (Access); a deadline already past: nothing reaches the server.
    let fake = Fake::start(Box::new(|_, _| (302, vec![], vec![])));
    let mut s = fake.service();
    let origin = Origin::parse(&fake.origin).unwrap();
    let owner = parse_owner_link(&origin, &format!("{}/o/{ID}#{TOKEN}", fake.origin)).unwrap();
    assert_eq!(s.status_until(&owner, 0).err(), Some(ApiError::TooLate));
    assert!(fake.requests().is_empty());
    // A deadline in the future: the request goes (and the redirect is the Access answer).
    let later = pnesecrets_core::time::Clock::now(&pnesecrets_core::time::SystemClock) + 60_000;
    assert_eq!(
        s.status_until(&owner, later).err(),
        Some(ApiError::SignInRequired)
    );
    assert_eq!(fake.requests().len(), 1);
}
