//! A local service for development and e2e runs: the client API of FORMAT.md 6 in memory on
//! 127.0.0.1 (default port 8788). Not the real service; only builds with `test-loopback` talk to
//! it. `cargo run -p pnesecrets-core --features test-loopback --example dev_server [port]`.
//! `DEV_SERVER_READER=email` makes status report a reader (a service with login).

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use pnesecrets_core::sdrop::format;
use pnesecrets_core::time::format_iso;

struct Rec {
    envelope: Option<Vec<u8>>,
    token: String,
    state: &'static str,
    created: i64,
    expires: i64,
    consumed: Option<i64>,
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

fn hex(n: usize) -> String {
    let mut b = vec![0u8; n];
    getrandom::fill(&mut b).unwrap();
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn status_json(r: &Rec, reader: &Option<String>) -> String {
    let mut s = format!(
        r#"{{"state":"{}","createdAt":"{}","expiresAt":"{}""#,
        r.state,
        format_iso(r.created),
        format_iso(r.expires)
    );
    if let Some(c) = r.consumed {
        s.push_str(&format!(r#","consumedAt":"{}""#, format_iso(c)));
        if let Some(by) = reader {
            s.push_str(&format!(r#","consumedBy":"{by}""#));
        }
    }
    s.push('}');
    s
}

fn main() {
    let port = std::env::args().nth(1).unwrap_or_else(|| "8788".into());
    let reader = std::env::var("DEV_SERVER_READER").ok();
    let listener = TcpListener::bind(format!("127.0.0.1:{port}")).unwrap();
    println!("dev server on http://127.0.0.1:{port}");
    let db: Arc<Mutex<HashMap<String, Rec>>> = Arc::default();
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { continue };
        let db = db.clone();
        let reader = reader.clone();
        std::thread::spawn(move || {
            let mut r = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            if r.read_line(&mut line).is_err() {
                return;
            }
            let mut parts = line.split_whitespace();
            let (method, path) = (
                parts.next().unwrap_or("").to_owned(),
                parts.next().unwrap_or("").to_owned(),
            );
            let mut headers = HashMap::new();
            loop {
                let mut h = String::new();
                if r.read_line(&mut h).is_err() {
                    return;
                }
                let h = h.trim_end();
                if h.is_empty() {
                    break;
                }
                if let Some((k, v)) = h.split_once(':') {
                    headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_owned());
                }
            }
            let len: usize = headers
                .get("content-length")
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            let mut body = vec![0; len];
            if r.read_exact(&mut body).is_err() {
                return;
            }
            let bearer = headers
                .get("authorization")
                .and_then(|v| v.strip_prefix("Bearer "))
                .map(str::to_owned);
            let t = now();
            let mut db = db.lock().unwrap();
            db.retain(|_, rec| t < rec.expires);
            let (status, ctype, out): (u16, &str, Vec<u8>) =
                if headers.get("x-secret-drop").map(String::as_str) != Some("1") {
                    (400, "text/plain", b"x".to_vec())
                } else if method == "GET" && path == "/api/limits" {
                    (200, "application/json", br#"{"maxBucket":262144}"#.to_vec())
                } else if method == "POST" && path.starts_with("/api/secrets?ttl=") {
                    let ttl: i64 = path["/api/secrets?ttl=".len()..].parse().unwrap_or(0);
                    if ![3600, 86400, 604800].contains(&ttl)
                        || !format::envelope_lengths().contains(&body.len())
                    {
                        (400, "text/plain", vec![])
                    } else {
                        let id = hex(32);
                        let token = format::encode_base64url(&{
                            let mut b = [0u8; 32];
                            getrandom::fill(&mut b).unwrap();
                            b
                        });
                        let rec = Rec {
                            envelope: Some(body),
                            token: token.clone(),
                            state: "stored",
                            created: t,
                            expires: t + ttl * 1000,
                            consumed: None,
                        };
                        let out = format!(
                            r#"{{"id":"{id}","expiresAt":"{}","ownerToken":"{token}"}}"#,
                            format_iso(rec.expires)
                        );
                        db.insert(id, rec);
                        (201, "application/json", out.into_bytes())
                    }
                } else if let Some(rest) = path.strip_prefix("/api/secrets/") {
                    let (id, tail) = rest.split_once('/').unwrap_or((rest, ""));
                    match (method.as_str(), tail, db.get_mut(id)) {
                        ("POST", "consume", Some(rec)) if rec.state == "stored" => {
                            rec.state = "consumed";
                            rec.consumed = Some(t);
                            (
                                200,
                                "application/octet-stream",
                                rec.envelope.take().unwrap(),
                            )
                        }
                        ("GET", "status", Some(rec)) if bearer.as_deref() == Some(&rec.token) => (
                            200,
                            "application/json",
                            status_json(rec, &reader).into_bytes(),
                        ),
                        ("DELETE", "", Some(rec)) if bearer.as_deref() == Some(&rec.token) => {
                            if rec.state == "consumed" {
                                (
                                    409,
                                    "application/json",
                                    status_json(rec, &reader).into_bytes(),
                                )
                            } else {
                                rec.state = "revoked";
                                rec.envelope = None;
                                (204, "text/plain", vec![])
                            }
                        }
                        _ => (404, "text/plain", vec![]),
                    }
                } else {
                    (404, "text/plain", vec![])
                };
            drop(db);
            let head = format!(
                "HTTP/1.1 {status} X\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
                out.len()
            );
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(&out);
        });
    }
}
