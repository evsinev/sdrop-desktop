//! Windows and Linux: no Quit guard is needed (with QuitMode::Explicit a quit comes only from our
//! own menu, keys and tray), notifications through notify-rust.

use std::sync::Mutex;
use std::sync::atomic::AtomicBool;

pub static HOLD: AtomicBool = AtomicBool::new(false);
pub static QUIT_ASKED: AtomicBool = AtomicBool::new(false);
pub static CLICKED: Mutex<Option<String>> = Mutex::new(None);

pub fn install_terminate_guard() -> bool {
    false
}

/// Wayland has no "always on top" for normal windows: the quick drop panel is a layer-shell
/// overlay where the compositor supports it (KDE, wlroots; not GNOME), else a normal window.
pub fn popup_kind() -> gpui_kit::WindowKind {
    #[cfg(target_os = "linux")]
    if std::env::var_os("WAYLAND_DISPLAY").is_some() {
        use gpui_kit::layer_shell::{Anchor, KeyboardInteractivity, Layer, LayerShellOptions};
        return gpui_kit::WindowKind::LayerShell(LayerShellOptions {
            namespace: "pnesecrets-quick-drop".into(),
            layer: Layer::Overlay,
            anchor: Anchor::empty(),
            keyboard_interactivity: KeyboardInteractivity::Exclusive,
            ..Default::default()
        });
    }
    gpui_kit::WindowKind::PopUp
}

/// Windows: GetClipboardSequenceNumber. Linux: none (the text is compared instead; SPEC 5).
pub fn clipboard_change_count() -> Option<i64> {
    #[cfg(target_os = "windows")]
    {
        let n = unsafe { windows_sys::Win32::System::DataExchange::GetClipboardSequenceNumber() };
        return (n != 0).then_some(n as i64);
    }
    #[allow(unreachable_code)]
    None
}

pub fn notifications_init(_report: impl Fn(String) + Send + Sync + 'static) -> Result<(), String> {
    Ok(())
}

pub fn notify(id: &str, title: &str, body: &str) -> Result<(), String> {
    let mut n = notify_rust::Notification::new();
    n.summary(title).body(body);
    #[cfg(target_os = "linux")]
    n.action("default", "Open");
    let handle = n.show().map_err(|e| e.to_string())?;
    let id = id.to_owned();
    std::thread::spawn(move || {
        #[cfg(target_os = "linux")]
        handle.wait_for_action(|action| {
            if action == "default" {
                *CLICKED.lock().unwrap() = Some(id);
            }
        });
        // Windows: a body click is NotificationResponse::Default (wait_for_action reports it as
        // "__closed").
        #[cfg(target_os = "windows")]
        let _ = handle.wait_for_response(move |r: &notify_rust::NotificationResponse| {
            if r.is_default_action() {
                *CLICKED.lock().unwrap() = Some(id);
            }
        });
    });
    Ok(())
}
