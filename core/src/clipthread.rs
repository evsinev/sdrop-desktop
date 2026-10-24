//! The clipboard thread: owns the clipboard service alone, so its timers (60 s links, 30 s
//! secrets) and the clear on quit never wait behind a disk write or a vault call (SPEC 5).
//! It tells the engine what happened (link copied, value released) and the UI its state.

use std::sync::Arc;
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, channel};
use std::time::Duration;

use zeroize::Zeroizing;

use crate::clipboard::{ClipError, ClipboardService, CopyKind, Released};
use crate::time::{Clock, Millis};

pub enum ClipCmd {
    Copy {
        text: Zeroizing<String>,
        kind: CopyKind,
        /// The engine's create waits for the result; UI copies do not.
        reply: Option<Sender<Result<Option<Released>, ClipError>>>,
    },
    /// A received secret was destroyed: clear our copy of a secret now, if still ours.
    ReleaseSecret,
    Read {
        tag: u64,
    },
    Take {
        tag: u64,
    },
    Shutdown {
        done: Sender<()>,
    },
}

/// What the clipboard thread reports.
pub enum ClipNote {
    /// A link of a history entry went to the clipboard.
    LinkCopied {
        entry: String,
        at: Millis,
    },
    /// Our value left the clipboard (cleared or replaced).
    Released(Released),
    /// For the UI: what we hold and until when.
    State {
        holds: Option<CopyKind>,
        deadline: Option<Millis>,
    },
    Text {
        tag: u64,
        text: Option<Zeroizing<String>>,
        cleared: bool,
    },
    CopyFailed,
}

pub fn start(
    mut clip: ClipboardService,
    clock: Arc<dyn Clock>,
    notes: impl Fn(ClipNote) + Send + 'static,
) -> Sender<ClipCmd> {
    let (tx, rx): (Sender<ClipCmd>, Receiver<ClipCmd>) = channel();
    std::thread::Builder::new()
        .name("pnesecrets-clipboard".into())
        .spawn(move || {
            let state = |clip: &ClipboardService| ClipNote::State {
                holds: clip.holds().cloned(),
                deadline: clip.deadline(),
            };
            loop {
                let cmd = rx.recv_timeout(Duration::from_millis(250));
                let now = clock.now();
                match cmd {
                    Ok(ClipCmd::Copy { text, kind, reply }) => {
                        let entry = match &kind {
                            CopyKind::Link { entry } => entry.clone(),
                            CopyKind::Secret => None,
                        };
                        let r = clip.copy(text, kind, now);
                        match &r {
                            Ok(released) => {
                                if let Some(rel) = released {
                                    notes(ClipNote::Released(rel.clone()));
                                }
                                if let Some(entry) = entry {
                                    notes(ClipNote::LinkCopied { entry, at: now });
                                }
                            }
                            Err(_) => {
                                if reply.is_none() {
                                    notes(ClipNote::CopyFailed);
                                }
                            }
                        }
                        if let Some(reply) = reply {
                            let _ = reply.send(r);
                        }
                        notes(state(&clip));
                    }
                    Ok(ClipCmd::ReleaseSecret) => {
                        if clip.holds() == Some(&CopyKind::Secret)
                            && let Some(r) = clip.release(now)
                        {
                            notes(ClipNote::Released(r));
                        }
                        notes(state(&clip));
                    }
                    Ok(ClipCmd::Read { tag }) => notes(ClipNote::Text {
                        tag,
                        text: clip.read_text(),
                        cleared: false,
                    }),
                    Ok(ClipCmd::Take { tag }) => {
                        let (text, cleared) = match clip.take_text() {
                            Some((t, c)) => (Some(t), c),
                            None => (None, false),
                        };
                        notes(ClipNote::Text { tag, text, cleared });
                        notes(state(&clip));
                    }
                    Ok(ClipCmd::Shutdown { done }) => {
                        for _ in 0..5 {
                            if clip.holds().is_none() {
                                break;
                            }
                            if let Some(r) = clip.release(clock.now()) {
                                notes(ClipNote::Released(r));
                                break;
                            }
                            std::thread::sleep(Duration::from_millis(100));
                        }
                        let _ = done.send(());
                    }
                    Err(RecvTimeoutError::Timeout) => {}
                    Err(RecvTimeoutError::Disconnected) => {
                        let _ = clip.release(clock.now());
                        return;
                    }
                }
                if let Some(r) = clip.tick(clock.now()) {
                    notes(ClipNote::Released(r));
                    notes(state(&clip));
                }
            }
        })
        .expect("clipboard thread");
    tx
}
