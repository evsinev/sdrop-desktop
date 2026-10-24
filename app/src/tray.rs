//! The tray / menu bar icon (SPEC 7): only to show the app runs, with Open window, Quick drop and
//! Quit. No popover UI.

use tray_icon::menu::{Menu, MenuEvent, MenuItem};
use tray_icon::{Icon, TrayIcon, TrayIconBuilder};

pub enum TrayAction {
    Open,
    QuickDrop,
    Quit,
}

/// A 22×22 padlock, drawn as a template image (macOS tints it).
fn icon() -> Icon {
    let (w, h) = (22u32, 22u32);
    let mut px = vec![0u8; (w * h * 4) as usize];
    let mut set = |x: u32, y: u32| {
        let i = ((y * w + x) * 4) as usize;
        px[i..i + 4].copy_from_slice(&[0, 0, 0, 255]);
    };
    // Shackle.
    for y in 3..10 {
        for x in [6u32, 7, 14, 15] {
            set(x, y);
        }
    }
    for x in 7..15 {
        set(x, 2);
        set(x, 3);
    }
    // Body with a keyhole.
    for y in 10..20 {
        for x in 4..18 {
            let hole = (10..12).contains(&x) && (13..17).contains(&y);
            if !hole {
                set(x, y);
            }
        }
    }
    Icon::from_rgba(px, w, h).expect("tray icon")
}

pub fn create() -> Option<TrayIcon> {
    let menu = Menu::new();
    menu.append(&MenuItem::with_id("open", "Open window", true, None))
        .ok()?;
    menu.append(&MenuItem::with_id("quick", "Quick drop", true, None))
        .ok()?;
    menu.append(&MenuItem::with_id("quit", "Quit", true, None))
        .ok()?;
    TrayIconBuilder::new()
        .with_menu(Box::new(menu))
        .with_tooltip("Payneteasy Secrets")
        .with_icon_templated(icon())
        .build()
        .ok()
}

pub fn poll() -> Vec<TrayAction> {
    let mut v = Vec::new();
    while let Ok(e) = MenuEvent::receiver().try_recv() {
        match e.id.0.as_str() {
            "open" => v.push(TrayAction::Open),
            "quick" => v.push(TrayAction::QuickDrop),
            "quit" => v.push(TrayAction::Quit),
            _ => {}
        }
    }
    v
}
