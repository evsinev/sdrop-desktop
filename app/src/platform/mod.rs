//! Platform glue: the clipboard backend for `core`, notifications, the Quit guard, fonts.

#[cfg_attr(target_os = "macos", path = "macos.rs")]
#[cfg_attr(not(target_os = "macos"), path = "other.rs")]
mod os;

#[allow(unused_imports)]
pub use os::popup_kind;
pub use os::{CLICKED, HOLD, QUIT_ASKED, install_terminate_guard, notifications_init, notify};

use pnesecrets_core::clipboard::{ClipError, ClipboardBackend};
use zeroize::Zeroizing;

/// The system clipboard through arboard, writes marked concealed / excluded from history
/// (SPEC 5), with the OS change counter where there is one.
pub struct SystemClipboard {
    inner: arboard::Clipboard,
}

impl SystemClipboard {
    pub fn new() -> Option<SystemClipboard> {
        arboard::Clipboard::new()
            .ok()
            .map(|inner| SystemClipboard { inner })
    }
}

impl ClipboardBackend for SystemClipboard {
    fn write_concealed(&mut self, text: &str) -> Result<(), ClipError> {
        let set = self.inner.set();
        #[cfg(target_os = "macos")]
        let set = {
            use arboard::SetExtApple;
            set.exclude_from_history()
        };
        #[cfg(target_os = "windows")]
        let set = {
            use arboard::SetExtWindows;
            set.exclude_from_monitoring().exclude_from_history()
        };
        #[cfg(target_os = "linux")]
        let set = {
            use arboard::SetExtLinux;
            set.exclude_from_history()
        };
        set.text(text).map_err(|_| ClipError)
    }

    fn read_text(&mut self) -> Result<Option<Zeroizing<String>>, ClipError> {
        match self.inner.get_text() {
            Ok(t) => Ok(Some(Zeroizing::new(t))),
            Err(arboard::Error::ContentNotAvailable) => Ok(None),
            Err(_) => Err(ClipError),
        }
    }

    fn clear(&mut self) -> Result<(), ClipError> {
        self.inner.clear().map_err(|_| ClipError)
    }

    fn change_count(&mut self) -> Option<i64> {
        os::clipboard_change_count()
    }
}

/// A clipboard that is not there (no display server): every copy fails, nothing is read.
pub struct NoClipboard;

impl ClipboardBackend for NoClipboard {
    fn write_concealed(&mut self, _text: &str) -> Result<(), ClipError> {
        Err(ClipError)
    }
    fn read_text(&mut self) -> Result<Option<Zeroizing<String>>, ClipError> {
        Err(ClipError)
    }
    fn clear(&mut self) -> Result<(), ClipError> {
        Err(ClipError)
    }
    fn change_count(&mut self) -> Option<i64> {
        None
    }
}

/// Monospace family for secrets and links (SPEC 10).
pub fn mono_font() -> &'static str {
    if cfg!(target_os = "macos") {
        "Menlo"
    } else if cfg!(target_os = "windows") {
        "Consolas"
    } else {
        "DejaVu Sans Mono"
    }
}

/// The name of the OS vault in the sidebar footer (SPEC 6).
pub fn vault_name() -> &'static str {
    if cfg!(target_os = "macos") {
        "Keychain"
    } else if cfg!(target_os = "windows") {
        "Credential Manager"
    } else {
        "the system keyring"
    }
}

/// `⌘` on macOS, `Ctrl+` elsewhere, for hints in the UI.
pub fn cmd(key: &str) -> String {
    if cfg!(target_os = "macos") {
        format!("⌘{key}")
    } else {
        format!("Ctrl+{key}")
    }
}
