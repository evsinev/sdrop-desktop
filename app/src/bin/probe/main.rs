//! Step 0 platform probe (PLAN 0): one window with a button per check, results in a log list.
//! Not the app: it only answers whether GPUI 0.3.9 and the platform crates do what SPEC needs.
//! Run from the .app bundle on macOS (scripts/probe-bundle.sh) for notifications and open_urls.
//!
//! The hotkey, the tray, notification clicks and open_urls belong to the application, not to a
//! window: closing the main window keeps them working (QuitMode::Explicit), and the tray reopens it.

#[cfg_attr(target_os = "macos", path = "macos.rs")]
#[cfg_attr(not(target_os = "macos"), path = "other.rs")]
mod platform;

use std::sync::Mutex;
use std::sync::atomic::Ordering;
use std::time::Duration;

use gpui_kit::component::button::{Button, ButtonVariants as _};
use gpui_kit::component::input::{self, Input, InputState};
use gpui_kit::*;
use zeroize::Zeroizing;

actions!(probe, [Quit]);

/// URLs from the platform (open_urls arrives without an App context).
static OPENED: Mutex<Vec<String>> = Mutex::new(Vec::new());

const CANARY: &str = "canary-Xq7vR2m9LpTz4eW8";

/// Application-level state: lives as long as the process, whatever windows are open.
struct Probe {
    log: Vec<SharedString>,
    clipboard: Option<arboard::Clipboard>,
    /// What we put on the clipboard and the platform change counter right after (SPEC 5).
    ours: Option<(Zeroizing<String>, Option<i64>)>,
    _hotkeys: Option<global_hotkey::GlobalHotKeyManager>,
    _tray: Option<tray_icon::TrayIcon>,
    notify_seq: u32,
    main: Option<WindowHandle<MainView>>,
    notes: std::sync::mpsc::Receiver<String>,
}

struct ProbeGlobal(Entity<Probe>);
impl Global for ProbeGlobal {}

fn probe(cx: &App) -> Entity<Probe> {
    cx.global::<ProbeGlobal>().0.clone()
}

impl Probe {
    fn new() -> Self {
        let (tx, notes) = std::sync::mpsc::channel::<String>();
        let mut this = Self {
            log: Vec::new(),
            clipboard: None,
            ours: None,
            _hotkeys: None,
            _tray: None,
            notify_seq: 0,
            main: None,
            notes,
        };
        this.say(format!(
            "terminate guard installed: {}",
            platform::install_terminate_guard()
        ));
        this.say(format!("bundle id: {:?}", platform::bundle_id()));
        this.say(format!("session: {}", platform::session_kind()));
        match arboard::Clipboard::new() {
            Ok(c) => this.clipboard = Some(c),
            Err(e) => this.say(format!("clipboard: {e}")),
        }
        this.setup_hotkey();
        this.setup_tray();
        if let Err(e) = platform::notifications_init(move |m| {
            let _ = tx.send(m);
        }) {
            this.say(format!("notifications: {e}"));
        }
        this
    }

    fn say(&mut self, m: impl Into<String>) {
        let m = m.into();
        eprintln!("probe: {m}");
        self.log.push(m.into());
    }

    fn poll(&mut self, cx: &mut Context<Self>) {
        while let Ok(m) = self.notes.try_recv() {
            self.say(m);
        }
        while let Ok(e) = global_hotkey::GlobalHotKeyEvent::receiver().try_recv() {
            if e.state == global_hotkey::HotKeyState::Pressed {
                self.say("global hotkey pressed");
                cx.defer(open_popup);
            }
        }
        while let Ok(e) = tray_icon::menu::MenuEvent::receiver().try_recv() {
            self.say(format!("tray menu: {}", e.id.0));
            match e.id.0.as_str() {
                "open" => cx.defer(open_main),
                "quit" => cx.defer(|cx| cx.dispatch_action(&Quit)),
                _ => {}
            }
        }
        if platform::QUIT_ASKED.swap(false, Ordering::SeqCst) {
            self.say("platform quit was cancelled by the guard (Dock / app menu)");
            cx.defer(ask_quit);
        }
        if let Some(id) = platform::CLICKED.lock().unwrap().take() {
            self.say(format!("notification clicked: {id}"));
            cx.defer(open_main);
        }
        for url in std::mem::take(&mut *OPENED.lock().unwrap()) {
            // Only the shape: a real link carries the key.
            let scheme = url.split(':').next().unwrap_or("");
            self.say(format!("open_urls: scheme={scheme} len={}", url.len()));
        }
        cx.notify();
    }

    fn setup_hotkey(&mut self) {
        use global_hotkey::hotkey::{Code, HotKey, Modifiers};
        let mods = if cfg!(target_os = "macos") {
            Modifiers::META | Modifiers::SHIFT
        } else {
            Modifiers::CONTROL | Modifiers::SHIFT
        };
        match global_hotkey::GlobalHotKeyManager::new() {
            Ok(m) => {
                let r = m.register(HotKey::new(Some(mods), Code::KeyS));
                self.say(format!("global hotkey register: {r:?}"));
                self._hotkeys = Some(m);
            }
            Err(e) => self.say(format!("global hotkey manager: {e}")),
        }
    }

    fn setup_tray(&mut self) {
        use tray_icon::menu::{Menu, MenuItem};
        let menu = Menu::new();
        let _ = menu.append(&MenuItem::with_id("open", "Open window", true, None));
        let _ = menu.append(&MenuItem::with_id("quit", "Quit", true, None));
        // 22x22 filled square, a template image on macOS.
        let (w, h) = (22u32, 22u32);
        let mut rgba = vec![0u8; (w * h * 4) as usize];
        for y in 3..19 {
            for x in 4..18 {
                let i = ((y * w + x) * 4) as usize;
                rgba[i..i + 4].copy_from_slice(&[0, 0, 0, 255]);
            }
        }
        let icon = tray_icon::Icon::from_rgba(rgba, w, h).expect("icon");
        let b = tray_icon::TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_tooltip("Payneteasy Secrets (probe)");
        #[cfg(target_os = "macos")]
        let b = b.with_icon_templated(icon);
        #[cfg(not(target_os = "macos"))]
        let b = b.with_icon(icon);
        let tray = b.build();
        match tray {
            Ok(t) => {
                self.say("tray icon: ok");
                self._tray = Some(t);
            }
            Err(e) => self.say(format!("tray icon: {e}")),
        }
    }

    fn keyring_round_trip(&mut self) {
        let r = (|| -> Result<String, keyring::Error> {
            let e = keyring::Entry::new("com.payneteasy.secrets.probe", "probe-entry")?;
            e.set_password("probe-value-123")?;
            let got = e.get_password()?;
            e.delete_credential()?;
            let after = match e.get_password() {
                Err(keyring::Error::NoEntry) => "gone".to_string(),
                other => format!("{other:?}"),
            };
            Ok(format!(
                "read back ok={} after delete: {after}",
                got == "probe-value-123"
            ))
        })();
        self.say(format!("keyring: {r:?}"));
    }

    /// Concealed copy (SPEC 5): excluded from clipboard history / monitoring where supported.
    fn copy_concealed(&mut self, text: Zeroizing<String>) {
        let Some(c) = self.clipboard.as_mut() else {
            return;
        };
        let set = c.set();
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
        let r = set.text(text.as_str());
        let token = platform::clipboard_change_count();
        self.say(format!(
            "copy concealed ({} chars): {r:?}, change count after: {token:?}",
            text.chars().count()
        ));
        self.ours = Some((text, token));
    }

    /// Clears only our own value: by the platform change counter where there is one (no window
    /// between reading the text and clearing it, SPEC 5), else by comparing the text.
    fn clear_if_ours(&mut self) {
        let Some(c) = self.clipboard.as_mut() else {
            return;
        };
        let Some((value, token)) = self.ours.take() else {
            self.say("nothing of ours on the clipboard");
            return;
        };
        let now = platform::clipboard_change_count();
        let ours = match (token, now) {
            (Some(t), Some(n)) => t == n,
            _ => {
                c.get_text()
                    .ok()
                    .map(Zeroizing::new)
                    .as_deref()
                    .map(String::as_str)
                    == Some(value.as_str())
            }
        };
        if ours {
            let r = c.clear();
            self.say(format!(
                "clipboard still ours (count {now:?}), cleared: {r:?}"
            ));
        } else {
            self.say(format!(
                "clipboard changed since our copy (count {token:?} -> {now:?}): left alone"
            ));
        }
    }

    fn notify(&mut self) {
        self.notify_seq += 1;
        let id = format!("probe-{}", self.notify_seq);
        let r = platform::notify(&id, "Staging DB password was read", "14:05 · click to open");
        self.say(format!("notification {id}: {r:?}"));
    }
}

fn open_main(cx: &mut App) {
    let p = probe(cx);
    if let Some(w) = p.read(cx).main
        && w.update(cx, |_, window, _| window.activate_window())
            .is_ok()
    {
        cx.activate(true);
        return;
    }
    let bounds = Bounds::centered(None, size(px(900.), px(600.)), cx);
    let options = WindowOptions {
        window_bounds: Some(WindowBounds::Windowed(bounds)),
        titlebar: Some(TitlebarOptions {
            title: Some("Payneteasy Secrets probe".into()),
            ..Default::default()
        }),
        ..Default::default()
    };
    let r = gpui_kit::open_window(options, cx, |window, cx| {
        window.on_window_should_close(cx, |window, cx| {
            if !platform::HOLD.load(Ordering::SeqCst) {
                return true;
            }
            let rx = window.prompt(
                PromptLevel::Warning,
                "Destroy this secret?",
                Some("Closing the window removes it for good."),
                &["Cancel", "Destroy"],
                cx,
            );
            window
                .spawn(cx, async move |cx| {
                    if rx.await == Ok(1) {
                        platform::HOLD.store(false, Ordering::SeqCst);
                        let _ = cx.update(|window, _| window.remove_window());
                    }
                })
                .detach();
            false
        });
        cx.new(|cx| MainView::new(window, cx))
    });
    match r {
        Ok(w) => {
            let typed = w.0.downcast::<MainView>();
            p.update(cx, |p, _| p.main = typed);
        }
        Err(e) => p.update(cx, |p, _| p.say(format!("window failed: {e}"))),
    }
    cx.activate(true);
}

/// Quit through one coordinator: asks while a secret is held (our menu, keys, tray, and the
/// platform quit cancelled by the guard). Opens the main window to ask if it was closed.
fn ask_quit(cx: &mut App) {
    if !platform::HOLD.load(Ordering::SeqCst) {
        cx.quit();
        return;
    }
    open_main(cx);
    let Some(w) = probe(cx).read(cx).main else {
        return;
    };
    let _ = w.update(cx, |_, window, cx| {
        let rx = window.prompt(
            PromptLevel::Warning,
            "Destroy this secret?",
            Some("It is already deleted from the server and cannot be opened again."),
            &["Cancel", "Destroy and quit"],
            cx,
        );
        cx.spawn(async move |_, cx| {
            if rx.await == Ok(1) {
                platform::HOLD.store(false, Ordering::SeqCst);
                cx.update(|cx| cx.quit());
            }
        })
        .detach();
    });
}

fn open_popup(cx: &mut App) {
    let preferred = platform::popup_kind();
    let fallback = !matches!(preferred, WindowKind::PopUp);
    let r = open_popup_as(preferred, cx);
    let r = match r {
        // GNOME Wayland has no layer-shell: a normal focused window instead (SPEC 7).
        Err(e) if fallback => {
            probe(cx).update(cx, |p, _| {
                p.say(format!("layer-shell refused ({e}); normal window instead"))
            });
            open_popup_as(WindowKind::PopUp, cx)
        }
        r => r,
    };
    if let Err(e) = r {
        probe(cx).update(cx, |p, _| p.say(format!("popup failed: {e}")));
    }
    cx.activate(true);
}

fn open_popup_as(kind: WindowKind, cx: &mut App) -> Result<()> {
    let bounds = Bounds::centered(None, size(px(640.), px(200.)), cx);
    let options = WindowOptions {
        window_bounds: Some(WindowBounds::Windowed(bounds)),
        titlebar: None,
        kind,
        focus: true,
        show: true,
        is_movable: false,
        is_resizable: false,
        ..Default::default()
    };
    gpui_kit::open_window(options, cx, |window, cx| {
        cx.new(|cx| Popup::new(window, cx))
    })?;
    Ok(())
}

struct Popup {
    text: Entity<InputState>,
}

impl Popup {
    fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        let text = cx.new(|cx| InputState::new(window, cx).masked(true));
        text.update(cx, |s, cx| s.focus(window, cx));
        Self { text }
    }
}

impl Render for Popup {
    fn render(&mut self, _window: &mut Window, _cx: &mut Context<Self>) -> impl IntoElement {
        div()
            .size_full()
            .p(px(20.))
            .flex()
            .flex_col()
            .gap(px(12.))
            .bg(rgb(0x0f1c2b))
            .text_color(rgb(0xeef1f5))
            .capture_key_down(|ev, window, cx| {
                if ev.keystroke.key == "escape" {
                    probe(cx).update(cx, |p, _| p.say("popup Esc"));
                    window.remove_window();
                }
            })
            .child("Quick drop probe: on top, focused, typing goes here. Esc closes.")
            .child(Input::new(&self.text))
    }
}

struct MainView {
    secret: Entity<InputState>,
    _observe: Subscription,
}

impl MainView {
    fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        let secret = cx.new(|cx| InputState::new(window, cx).default_value(CANARY));
        let observe = cx.observe(&probe(cx), |_, _, cx| cx.notify());
        Self {
            secret,
            _observe: observe,
        }
    }

    fn copy_selection(&mut self, cut: bool, window: &mut Window, cx: &mut Context<Self>) {
        let sel = Zeroizing::new(self.secret.read(cx).selected_value().to_string());
        probe(cx).update(cx, |p, _| {
            p.say(if cut {
                "Cut intercepted"
            } else {
                "Copy intercepted"
            });
            p.copy_concealed(sel);
        });
        if cut {
            // The real app removes the selection through its own edit; the probe only shows that
            // the GPUI clipboard write did not happen.
            let _ = window;
        }
        cx.stop_propagation();
    }
}

impl Render for MainView {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let hold = platform::HOLD.load(Ordering::SeqCst);
        let log: Vec<SharedString> = probe(cx).read(cx).log.iter().rev().cloned().collect();
        let button = |id: &'static str, label: String| Button::new(id).primary().child(label);
        div()
            .size_full()
            .p(px(20.))
            .flex()
            .flex_col()
            .gap(px(10.))
            .bg(rgb(0x0b1622))
            .text_color(rgb(0xeef1f5))
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .gap(px(8.))
                    .child(
                        button(
                            "hold",
                            format!("Hold secret: {}", if hold { "ON" } else { "off" }),
                        )
                        .on_click(|_, _, cx| {
                            let v = !platform::HOLD.load(Ordering::SeqCst);
                            platform::HOLD.store(v, Ordering::SeqCst);
                            probe(cx).update(cx, |p, cx| {
                                p.say(format!("hold = {v}"));
                                cx.notify();
                            });
                        }),
                    )
                    .child(button("popup", "Open popup".into()).on_click(|_, _, cx| open_popup(cx)))
                    .child(
                        button("keyring", "Keyring round trip".into()).on_click(|_, _, cx| {
                            probe(cx).update(cx, |p, _| p.keyring_round_trip())
                        }),
                    )
                    .child(
                        button("clear", "Clear clipboard if ours".into())
                            .on_click(|_, _, cx| probe(cx).update(cx, |p, _| p.clear_if_ours())),
                    )
                    .child(
                        button("notify", "Notify".into())
                            .on_click(|_, _, cx| probe(cx).update(cx, |p, _| p.notify())),
                    )
                    .child(button("reset", "Clear field (set_value)".into()).on_click(
                        cx.listener(|this, _, window, cx| {
                            this.secret.update(cx, |s, cx| s.set_value("", window, cx));
                            probe(cx).update(cx, |p, _| {
                                p.say("field cleared with set_value: now try Undo in it")
                            });
                        }),
                    )),
            )
            .child("Secret field: Copy/Cut (keys, Edit menu, context menu) must be intercepted.")
            .child(
                div()
                    .capture_action(cx.listener(|this, _: &input::Copy, window, cx| {
                        this.copy_selection(false, window, cx)
                    }))
                    .capture_action(cx.listener(|this, _: &input::Cut, window, cx| {
                        this.copy_selection(true, window, cx)
                    }))
                    .child(Input::new(&self.secret)),
            )
            .child(
                div()
                    .id("log")
                    .flex_1()
                    .overflow_y_scroll()
                    .font_family("Menlo")
                    .text_size(px(12.))
                    .children(log.into_iter().map(|l| div().child(l))),
            )
    }
}

fn main() {
    // PROBE_HOLD=1: start holding a secret (the Quit guard can be checked without clicks).
    if std::env::var_os("PROBE_HOLD").is_some() {
        platform::HOLD.store(true, Ordering::SeqCst);
    }
    let app = gpui_kit::application().with_quit_mode(QuitMode::Explicit);
    app.on_open_urls(|urls| OPENED.lock().unwrap().extend(urls));
    // Dock click with no window open (macOS).
    app.on_reopen(open_main);
    app.run(|cx| {
        gpui_kit::init(cx);
        let p = cx.new(|_| Probe::new());
        cx.set_global(ProbeGlobal(p.clone()));
        // Platform events arrive on channels and statics; one app-level poll drains them.
        cx.spawn(async move |cx| {
            loop {
                cx.background_executor()
                    .timer(Duration::from_millis(100))
                    .await;
                p.update(cx, |p, cx| p.poll(cx));
            }
        })
        .detach();
        cx.bind_keys([
            KeyBinding::new("cmd-q", Quit, None),
            KeyBinding::new("ctrl-q", Quit, None),
        ]);
        cx.on_action(|_: &Quit, cx| ask_quit(cx));
        cx.set_menus([
            Menu::new("Probe").items([MenuItem::action("Quit Probe", Quit)]),
            Menu::new("Edit").items([
                MenuItem::os_action("Cut", input::Cut, OsAction::Cut),
                MenuItem::os_action("Copy", input::Copy, OsAction::Copy),
                MenuItem::os_action("Paste", input::Paste, OsAction::Paste),
            ]),
        ]);
        open_main(cx);
    });
}
