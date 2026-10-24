// No console window for the release build on Windows.
#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

//! Payneteasy Secrets desktop client (SPEC): the main window with history (A), the received
//! secret window (D), the quick drop panel (C), running in the background with a tray icon.

mod fmt;
mod hotkey;
mod instance;
mod model;
mod platform;
#[cfg(feature = "screenshot")]
mod shot;
mod theme;
mod tray;
mod views;

use std::sync::Mutex;
use std::sync::atomic::Ordering;
use std::time::Duration;

use gpui_kit::*;

use model::{AppModel, ModelGlobal, Screen, blocker_text, model};
use views::main_window::MainWindow;

actions!(
    pnesecrets,
    [Quit, NewSecret, OpenWindow, OpenLink, QuickDropAction]
);

/// URLs from the platform (open_urls arrives without an App context).
static OPENED: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// Platform objects that must live as long as the app (dropping them unregisters).
struct Keep {
    _tray: Option<tray_icon::TrayIcon>,
    _hotkey: Option<hotkey::Hotkey>,
    commands: Option<std::sync::mpsc::Receiver<instance::Command>>,
    quick: Option<AnyWindowHandle>,
}
impl Global for Keep {}

/// The main window, if open: the window (its root is gpui-kit's Root) and our view in it.
#[derive(Clone)]
pub struct Main {
    pub window: AnyWindowHandle,
    pub view: Entity<MainWindow>,
}

impl Main {
    pub fn update<R>(
        &self,
        cx: &mut App,
        f: impl FnOnce(&mut MainWindow, &mut Window, &mut Context<MainWindow>) -> R,
    ) -> Option<R> {
        let view = self.view.clone();
        cx.update_window(self.window, |_, window, cx| {
            view.update(cx, |v, cx| f(v, window, cx))
        })
        .ok()
    }
}

struct MainHandle(Option<Main>);
impl Global for MainHandle {}

pub fn open_main(cx: &mut App) -> Option<Main> {
    if let Some(w) = cx.try_global::<MainHandle>().and_then(|h| h.0.clone())
        && w.update(cx, |_, window, _| window.activate_window())
            .is_some()
    {
        cx.activate(true);
        return Some(w);
    }
    let bounds = Bounds::centered(None, size(px(1200.), px(780.)), cx);
    let options = WindowOptions {
        window_bounds: Some(WindowBounds::Windowed(bounds)),
        window_min_size: Some(size(px(960.), px(620.))),
        titlebar: Some(TitlebarOptions {
            title: Some("Payneteasy Secrets".into()),
            ..Default::default()
        }),
        app_id: Some("com.payneteasy.secrets".into()),
        ..Default::default()
    };
    let r = gpui_kit::open_window(options, cx, |window, cx| {
        // Closing the window leaves A2: an untracked link is not kept for the next opening.
        window.on_window_should_close(cx, |_, cx| {
            model(cx).update(cx, |m, cx| m.main_closed(cx));
            true
        });
        cx.new(|cx| MainWindow::new(window, cx))
    });
    let handle = r.ok().map(|(window, view)| Main { window, view });
    cx.set_global(MainHandle(handle.clone()));
    cx.activate(true);
    handle
}

/// Opens a received-secret window: for a receipt, or empty to paste a link (File → Open link…).
pub fn open_received(id: Option<u64>, cx: &mut App) {
    let bounds = Bounds::centered(None, size(px(760.), px(640.)), cx);
    let options = WindowOptions {
        window_bounds: Some(WindowBounds::Windowed(bounds)),
        window_min_size: Some(size(px(560.), px(420.))),
        titlebar: Some(TitlebarOptions {
            title: Some("Received secret".into()),
            ..Default::default()
        }),
        app_id: Some("com.payneteasy.secrets".into()),
        ..Default::default()
    };
    let r = gpui_kit::open_window(options, cx, |window, cx| {
        let view = cx.new(|cx| views::received::ReceivedWindow::new(id, window, cx));
        let v = view.clone();
        window.on_window_should_close(cx, move |window, cx| {
            v.update(cx, |v, cx| v.should_close(window, cx))
        });
        view
    });
    if let (Some(id), Ok((w, _))) = (id, r) {
        set_received_window(id, w, cx);
    }
    cx.activate(true);
}

pub fn set_received_window(id: u64, w: AnyWindowHandle, cx: &mut App) {
    model(cx).update(cx, |m, _| {
        if let Some(slot) = m.receipts.get_mut(&id) {
            slot.window = Some(w);
        }
    });
}

/// The window closed while the consume is in flight: the answer opens a new one.
pub fn forget_received_window(id: u64, cx: &mut App) {
    model(cx).update(cx, |m, _| {
        if let Some(slot) = m.receipts.get_mut(&id) {
            slot.window = None;
        }
    });
}

/// The quick drop panel (SPEC 7): centered, over everything, focused. On Wayland without
/// layer-shell (GNOME) it falls back to a normal focused window.
pub fn open_quick_drop(cx: &mut App) {
    if let Some(w) = cx.try_global::<Keep>().and_then(|k| k.quick)
        && cx
            .update_window(w, |_, window, _| window.activate_window())
            .is_ok()
    {
        cx.activate(true);
        return;
    }
    let open = |kind: WindowKind, cx: &mut App| {
        let bounds = Bounds::centered(None, size(px(640.), px(250.)), cx);
        let options = WindowOptions {
            window_bounds: Some(WindowBounds::Windowed(bounds)),
            titlebar: None,
            kind,
            focus: true,
            show: true,
            is_movable: true,
            is_resizable: false,
            window_background: WindowBackgroundAppearance::Transparent,
            ..Default::default()
        };
        gpui_kit::open_window(options, cx, |window, cx| {
            cx.new(|cx| views::quick_drop::QuickDrop::new(window, cx))
        })
    };
    let preferred = platform::popup_kind();
    let fallback = !matches!(preferred, WindowKind::PopUp);
    let r = match open(preferred, cx) {
        Err(_) if fallback => open(WindowKind::PopUp, cx),
        r => r,
    };
    if let Ok((w, _)) = r {
        cx.global_mut::<Keep>().quick = Some(w);
    }
    cx.activate(true);
}

/// `pnesecrets://s/<id>#<fragment>` (macOS) → the same link on the trusted origin.
fn scheme_link(url: &str, origin: &str) -> Option<String> {
    let rest = url.strip_prefix("pnesecrets://")?;
    rest.starts_with("s/").then(|| format!("{origin}/{rest}"))
}

fn file_path(url: &str) -> Option<std::path::PathBuf> {
    let rest = url.strip_prefix("file://")?;
    let rest = rest.strip_prefix("localhost").unwrap_or(rest);
    let mut bytes = Vec::new();
    let b = rest.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            let h = std::str::from_utf8(&b[i + 1..i + 3]).ok()?;
            bytes.push(u8::from_str_radix(h, 16).ok()?);
            i += 3;
        } else {
            bytes.push(b[i]);
            i += 1;
        }
    }
    Some(std::path::PathBuf::from(String::from_utf8(bytes).ok()?))
}

fn handle_urls(cx: &mut App) {
    let urls = std::mem::take(&mut *OPENED.lock().unwrap());
    if urls.is_empty() {
        return;
    }
    let origin = model(cx)
        .read(cx)
        .origin
        .as_ref()
        .map(|o| o.as_str().to_owned());
    let mut files = Vec::new();
    for u in urls {
        if let Some(p) = file_path(&u) {
            files.push(p);
        } else if let (Some(o), true) = (&origin, u.starts_with("pnesecrets://")) {
            // Parsed strictly against the trusted origin; a bad link opens nothing.
            let link = zeroize::Zeroizing::new(scheme_link(&u, o).unwrap_or_default());
            match model(cx).update(cx, |m, _| m.open_link(&link)) {
                Ok(id) => open_received(Some(id), cx),
                Err(_) => model(cx).update(cx, |m, cx| {
                    m.set_notice(
                        "The link opened from another app is broken or not for this service."
                            .into(),
                    );
                    cx.notify();
                }),
            }
        }
    }
    if !files.is_empty()
        && let Some(w) = open_main(cx)
    {
        w.update(cx, |main, window, cx| {
            main.new_secret(window, cx);
            main.form().update(cx, |f, cx| f.add_paths(&files, cx));
        });
    }
}

/// Every quit path ends here (SPEC 8): ask while something would be lost, then wipe and quit.
pub fn ask_quit(cx: &mut App) {
    let blockers = model(cx).read(cx).blockers();
    if blockers.is_empty() {
        quit_now(cx);
        return;
    }
    let Some(w) = open_main(cx) else {
        quit_now(cx);
        return;
    };
    let detail = format!(
        "Quitting loses {}. Received secrets are already deleted from the server.",
        blocker_text(&blockers)
    );
    w.update(cx, |_, window, cx| {
        let rx = window.prompt(
            PromptLevel::Warning,
            "Quit and lose it for good?",
            Some(&detail),
            &["Cancel", "Quit"],
            cx,
        );
        cx.spawn(async move |_, cx| {
            if rx.await == Ok(1) {
                cx.update(quit_now);
            }
        })
        .detach();
    });
}

fn quit_now(cx: &mut App) {
    model(cx).update(cx, |m, _| m.shutdown());
    platform::HOLD.store(false, Ordering::SeqCst);
    cx.quit();
}

fn main() {
    // A panic prints only where it happened, never its message (it could quote a secret).
    std::panic::set_hook(Box::new(|info| {
        let at = info
            .location()
            .map(|l| format!("{}:{}", l.file(), l.line()))
            .unwrap_or_default();
        eprintln!("pnesecrets: internal error at {at}");
    }));
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--version") {
        println!("pnesecrets {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    // The service this build talks to; a release build refuses http:// (checked in CI).
    if args.iter().any(|a| a == "--check-origin") {
        match pnesecrets_core::origin() {
            Ok(o) => println!("{}", o.as_str()),
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(1);
            }
        }
        return;
    }
    let command = if args.iter().any(|a| a == "--quick-drop") {
        instance::Command::QuickDrop
    } else {
        instance::Command::OpenWindow
    };
    // One instance owns the history: take the lock first; if another has it, hand it the
    // command (it may still be starting) and leave.
    let lock = match instance::lock() {
        instance::Lock::Busy => {
            for _ in 0..30 {
                if instance::forward(command) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            eprintln!("pnesecrets: another instance is running and does not answer");
            std::process::exit(1);
        }
        l => l,
    };
    let history_ok = matches!(lock, instance::Lock::Held(_));
    let commands = instance::listen();
    // Held for the life of the process (the OS releases it at exit).
    let _lock = lock;
    let app = gpui_kit::application().with_quit_mode(QuitMode::Explicit);
    app.on_reopen(|cx| {
        open_main(cx);
    });
    app.on_open_urls(|urls| OPENED.lock().unwrap().extend(urls));
    app.run(move |cx| {
        gpui_kit::init(cx);
        platform::install_terminate_guard();
        let _ = platform::notifications_init(|_| {});
        let m = cx.new(|_| AppModel::new(history_ok));
        cx.set_global(ModelGlobal(m.clone()));
        cx.set_global(MainHandle(None));
        theme::apply(cx.window_appearance(), cx);
        views::new_secret::bind_keys(cx);
        cx.bind_keys([
            KeyBinding::new("secondary-q", Quit, None),
            KeyBinding::new("secondary-n", NewSecret, None),
            KeyBinding::new("secondary-shift-o", OpenLink, None),
        ]);
        cx.on_action(|_: &OpenLink, cx| open_received(None, cx));
        cx.on_action(|_: &QuickDropAction, cx| open_quick_drop(cx));
        cx.set_global(Keep {
            _tray: tray::create(),
            _hotkey: hotkey::Hotkey::register(),
            commands,
            quick: None,
        });
        // A received secret whose window was closed while it was fetched: show it again.
        cx.subscribe(&m, |m, e: &model::ModelEvent, cx| {
            if let model::ModelEvent::ShowMain = e {
                open_main(cx);
            }
            if let model::ModelEvent::Receipt(id) = e {
                let orphan = m
                    .read(cx)
                    .receipts
                    .get(id)
                    .is_some_and(|s| s.window.is_none());
                if orphan {
                    open_received(Some(*id), cx);
                }
            }
        })
        .detach();
        cx.on_action(|_: &Quit, cx| ask_quit(cx));
        cx.on_action(|_: &OpenWindow, cx| {
            open_main(cx);
        });
        cx.on_action(|_: &NewSecret, cx| {
            if let Some(w) = open_main(cx) {
                w.update(cx, |main, window, cx| main.new_secret(window, cx));
            }
        });
        use gpui_kit::component::input;
        cx.set_menus([
            Menu::new("Payneteasy Secrets")
                .items([MenuItem::action("Quit Payneteasy Secrets", Quit)]),
            Menu::new("File").items([
                MenuItem::action("New secret", NewSecret),
                MenuItem::action("Open link…", OpenLink),
                MenuItem::action("Quick drop", QuickDropAction),
            ]),
            Menu::new("Edit").items([
                MenuItem::os_action("Cut", input::Cut, OsAction::Cut),
                MenuItem::os_action("Copy", input::Copy, OsAction::Copy),
                MenuItem::os_action("Paste", input::Paste, OsAction::Paste),
                MenuItem::os_action("Select All", input::SelectAll, OsAction::SelectAll),
            ]),
        ]);
        // Kept for the life of the app (a dropped Subscription would cancel it): any quit,
        // also one the Dock forces, wipes received secrets and clears our clipboard value.
        cx.on_app_quit(|cx| {
            model(cx).update(cx, |m, _| m.shutdown());
            async {}
        })
        .detach();
        // One app-level loop: model timers and platform events (hotkey, tray, notifications).
        cx.spawn(async move |cx| {
            loop {
                cx.background_executor()
                    .timer(Duration::from_millis(250))
                    .await;
                cx.update(|cx| {
                    if platform::QUIT_ASKED.swap(false, Ordering::SeqCst) {
                        ask_quit(cx);
                    }
                    if hotkey::pressed() {
                        open_quick_drop(cx);
                    }
                    for a in tray::poll() {
                        match a {
                            tray::TrayAction::Open => {
                                open_main(cx);
                            }
                            tray::TrayAction::QuickDrop => open_quick_drop(cx),
                            tray::TrayAction::Quit => ask_quit(cx),
                        }
                    }
                    let cmds: Vec<instance::Command> = cx
                        .global::<Keep>()
                        .commands
                        .as_ref()
                        .map(|rx| rx.try_iter().collect())
                        .unwrap_or_default();
                    for c in cmds {
                        match c {
                            instance::Command::OpenWindow => {
                                open_main(cx);
                            }
                            instance::Command::QuickDrop => open_quick_drop(cx),
                        }
                    }
                    handle_urls(cx);
                    if let Some(id) = platform::CLICKED.lock().unwrap().take() {
                        model(cx).update(cx, |m, cx| m.set_screen(Screen::Status(id), cx));
                        open_main(cx);
                    }
                });
            }
        })
        .detach();
        let m2 = m.clone();
        cx.spawn(async move |cx| {
            loop {
                cx.background_executor()
                    .timer(Duration::from_millis(100))
                    .await;
                m2.update(cx, |m, cx| m.drain(cx));
            }
        })
        .detach();
        let main = if command == instance::Command::QuickDrop {
            open_quick_drop(cx);
            None
        } else {
            open_main(cx)
        };
        #[cfg(feature = "screenshot")]
        if let Ok(out) = std::env::var("APP_SCREENSHOT") {
            let scene = std::env::var("APP_SCENE").unwrap_or_default();
            match scene.as_str() {
                "d" => {
                    let link = std::env::var("APP_LINK").unwrap_or_default();
                    if let Ok(id) = model(cx).update(cx, |m, _| m.open_link(&link)) {
                        open_received(Some(id), cx);
                        let w = model(cx).read(cx).receipts.get(&id).and_then(|s| s.window);
                        if let Some(w) = w {
                            shot::schedule(w, out, cx, move |_, cx| {
                                model(cx).update(cx, |m, cx| m.reveal(id, None, cx));
                            });
                        }
                    }
                }
                "c" => {
                    open_quick_drop(cx);
                    if let Some(w) = cx.global::<Keep>().quick {
                        shot::schedule(w, out, cx, |_, _| {});
                    }
                }
                _ => {
                    if let Some(w) = main.clone() {
                        let view = w.view.clone();
                        shot::schedule(w.window, out, cx, move |window, cx| {
                            let form = view.read(cx).form();
                            form.update(cx, |f, cx| f.demo(&scene, window, cx));
                        });
                    }
                }
            }
        }
        let _ = main;
    });
}
