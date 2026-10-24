//! The global quick drop shortcut (SPEC 7): ⌘⇧S / Ctrl+Shift+S; on Wayland there are no global
//! shortcuts, the user binds a system shortcut to `pnesecrets --quick-drop`.

use global_hotkey::hotkey::{Code, HotKey, Modifiers};
use global_hotkey::{GlobalHotKeyEvent, GlobalHotKeyManager, HotKeyState};

pub fn wayland() -> bool {
    cfg!(target_os = "linux") && std::env::var_os("WAYLAND_DISPLAY").is_some()
}

pub fn hint() -> String {
    if wayland() {
        "system shortcut → pnesecrets --quick-drop".into()
    } else if cfg!(target_os = "macos") {
        "⌘⇧S".into()
    } else {
        "Ctrl+Shift+S".into()
    }
}

pub struct Hotkey {
    _manager: GlobalHotKeyManager,
}

impl Hotkey {
    pub fn register() -> Option<Hotkey> {
        if wayland() {
            return None;
        }
        let mods = if cfg!(target_os = "macos") {
            Modifiers::META | Modifiers::SHIFT
        } else {
            Modifiers::CONTROL | Modifiers::SHIFT
        };
        let manager = GlobalHotKeyManager::new().ok()?;
        manager.register(HotKey::new(Some(mods), Code::KeyS)).ok()?;
        Some(Hotkey { _manager: manager })
    }
}

/// True if the shortcut was pressed since the last call.
pub fn pressed() -> bool {
    let mut hit = false;
    while let Ok(e) = GlobalHotKeyEvent::receiver().try_recv() {
        hit |= e.state == HotKeyState::Pressed;
    }
    hit
}
