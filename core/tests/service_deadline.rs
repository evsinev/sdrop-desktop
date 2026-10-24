//! A status whose first request answers with an Access redirect after its deadline: the retry
//! with the new token must not be sent (`--features test-loopback`; its own binary because it
//! sets the test token variable).
#![cfg(feature = "test-loopback")]

use pnesecrets_core::sdrop::api::{Origin, parse_owner_link};
use pnesecrets_core::service::{ApiError, SecretsApi, Service};
use pnesecrets_core::time::{Clock, SystemClock};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const ID: &str = "4b1c0a7e5d9f3a2b8c6e1d0f7a9b3c5e2d4f6a8b0c1e3d5f7a9b2c4e6d8f0a1b";
const TOKEN: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";

#[test]
fn the_retry_after_access_respects_the_deadline() {
    // The token cloudflared would give (test build: read from this variable).
    unsafe { std::env::set_var("SDROP_TEST_CLOUDFLARED_TOKEN", "a.b.c") };
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let hits = Arc::new(Mutex::new(0usize));
    let h = hits.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut r = BufReader::new(stream.try_clone().unwrap());
            let mut len = 0usize;
            loop {
                let mut line = String::new();
                if r.read_line(&mut line).unwrap_or(0) == 0 || line.trim_end().is_empty() {
                    break;
                }
                if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    len = v.trim().parse().unwrap_or(0);
                }
            }
            let mut body = vec![0; len];
            let _ = r.read_exact(&mut body);
            *h.lock().unwrap() += 1;
            // The redirect comes back only after the deadline has passed.
            std::thread::sleep(Duration::from_millis(600));
            let _ = stream.write_all(
                b"HTTP/1.1 302 X\r\nLocation: https://login.example.com/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            );
        }
    });
    let o = Origin::parse(&origin).unwrap();
    let owner = parse_owner_link(&o, &format!("{origin}/o/{ID}#{TOKEN}")).unwrap();
    let mut s = Service::new(o);
    let deadline = SystemClock.now() + 300;
    assert_eq!(
        s.status_until(&owner, deadline).err(),
        Some(ApiError::TooLate)
    );
    assert_eq!(
        *hits.lock().unwrap(),
        1,
        "the retry with the new token was not sent"
    );
}
