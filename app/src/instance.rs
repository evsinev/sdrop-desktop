//! One instance per user (SPEC 7): the running app listens on 127.0.0.1 at a random port; the
//! port and a random token are in a file only the user can read (0600 on Unix, the user's
//! profile ACL on Windows). A second launch sends its command there and exits. Commands carry
//! no secret: only "open the window" or "quick drop".

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, channel};
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    OpenWindow,
    QuickDrop,
}

impl Command {
    fn word(self) -> &'static str {
        match self {
            Command::OpenWindow => "open-window",
            Command::QuickDrop => "quick-drop",
        }
    }
    fn parse(s: &str) -> Option<Command> {
        match s {
            "open-window" => Some(Command::OpenWindow),
            "quick-drop" => Some(Command::QuickDrop),
            _ => None,
        }
    }
}

fn file() -> Option<PathBuf> {
    Some(crate::model::data_dir()?.join("instance"))
}

/// The process-wide lock, taken before the history is opened: two processes never own the same
/// history file at once (a second one would overwrite the first one's entries). Held until exit.
pub enum Lock {
    Held(#[allow(dead_code)] std::fs::File),
    /// Another instance has it (running, or starting right now).
    Busy,
    /// No data folder or no lock support: run without (better than not at all).
    Unavailable,
}

pub fn lock() -> Lock {
    let Some(dir) = crate::model::data_dir() else {
        return Lock::Unavailable;
    };
    if std::fs::create_dir_all(&dir).is_err() {
        return Lock::Unavailable;
    }
    let Ok(f) = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(dir.join("instance.lock"))
    else {
        return Lock::Unavailable;
    };
    match f.try_lock() {
        Ok(()) => Lock::Held(f),
        Err(std::fs::TryLockError::WouldBlock) => Lock::Busy,
        Err(std::fs::TryLockError::Error(_)) => Lock::Unavailable,
    }
}

/// Sends the command to a running instance. True if one took it.
pub fn forward(cmd: Command) -> bool {
    let Some(path) = file() else { return false };
    let Ok(s) = std::fs::read_to_string(&path) else {
        return false;
    };
    let mut parts = s.split_whitespace();
    let (Some(port), Some(token)) = (parts.next(), parts.next()) else {
        return false;
    };
    let Ok(port) = port.parse::<u16>() else {
        return false;
    };
    let Ok(mut stream) =
        TcpStream::connect_timeout(&([127, 0, 0, 1], port).into(), Duration::from_millis(500))
    else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    if writeln!(stream, "{token} {}", cmd.word()).is_err() {
        return false;
    }
    let mut ack = String::new();
    BufReader::new(stream).read_line(&mut ack).is_ok() && ack.trim() == "ok"
}

/// Becomes the instance: returns the commands later launches send.
pub fn listen() -> Option<Receiver<Command>> {
    let path = file()?;
    let listener = TcpListener::bind(("127.0.0.1", 0)).ok()?;
    let port = listener.local_addr().ok()?.port();
    let token = pnesecrets_core::history::new_local_id();
    std::fs::create_dir_all(path.parent()?).ok()?;
    pnesecrets_core::save::save_private(&path, format!("{port} {token}\n").as_bytes()).ok()?;
    let (tx, rx) = channel();
    std::thread::Builder::new()
        .name("pnesecrets-instance".into())
        .spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                let mut line = String::new();
                if BufReader::new(&stream).read_line(&mut line).is_err() {
                    continue;
                }
                let mut parts = line.split_whitespace();
                if parts.next() != Some(token.as_str()) {
                    continue;
                }
                if let Some(cmd) = parts.next().and_then(Command::parse) {
                    let _ = writeln!(stream, "ok");
                    let _ = tx.send(cmd);
                }
            }
        })
        .ok()?;
    Some(rx)
}
