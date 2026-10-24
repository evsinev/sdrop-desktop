//! Visual tokens (SPEC 10): the dark theme of the mockups, the light one of the web app; the
//! system appearance picks one and changes are followed live.

use gpui_kit::component::{Theme, ThemeMode};
use gpui_kit::*;

#[derive(Clone, Copy)]
pub struct Tokens {
    pub dark: bool,
    pub window: Hsla,
    pub side: Hsla,
    pub divider: Hsla,
    pub panel: Hsla,
    pub panel_ring: Hsla,
    pub field: Hsla,
    pub field_ring: Hsla,
    pub text: Hsla,
    pub text2: Hsla,
    pub muted: Hsla,
    pub accent: Hsla,
    pub accent_hover: Hsla,
    pub link: Hsla,
    pub on_accent: Hsla,
    pub waiting: Hsla,
    pub read: Hsla,
    pub revoked: Hsla,
    pub danger: Hsla,
    pub seg_active: Hsla,
    pub seg_active_text: Hsla,
    pub switch_off: Hsla,
    pub knob_off: Hsla,
    pub warn_bg: Hsla,
    pub warn_fg: Hsla,
    pub selected: Hsla,
    pub row_hover: Hsla,
    pub dot_off: Hsla,
}

fn c(hex: u32) -> Hsla {
    rgb(hex).into()
}

pub fn dark() -> Tokens {
    Tokens {
        dark: true,
        window: c(0x0b1622),
        side: c(0x07131f),
        divider: c(0x1a2a3c),
        panel: c(0x101e2d),
        panel_ring: c(0x22344a),
        field: c(0x0d1926),
        field_ring: c(0x2c3a4a),
        text: c(0xeef1f5),
        text2: c(0xd3dce8),
        muted: c(0x93a1b3),
        accent: c(0x348bff),
        accent_hover: c(0x347aff),
        link: c(0x5aa2ff),
        on_accent: c(0xffffff),
        waiting: c(0xf0b25a),
        read: c(0x4fd1a1),
        revoked: c(0xff8a80),
        danger: c(0xec493d),
        seg_active: c(0x1f3047),
        seg_active_text: c(0xffffff),
        switch_off: c(0x2c3a4a),
        knob_off: c(0xd3dce8),
        warn_bg: c(0x3a2a12),
        warn_fg: c(0xf6c27a),
        selected: c(0x13243a),
        row_hover: c(0x0e1c2c),
        dot_off: c(0x3a4c62),
    }
}

pub fn light() -> Tokens {
    Tokens {
        dark: false,
        window: c(0xf9f9f9),
        side: c(0xf1f4f8),
        divider: c(0xd3dce8),
        panel: c(0xffffff),
        panel_ring: c(0xd3dce8),
        field: c(0xffffff),
        field_ring: c(0xd3dce8),
        text: c(0x0a0b0c),
        text2: c(0x353c3f),
        muted: c(0x69747a),
        accent: c(0x348bff),
        accent_hover: c(0x347aff),
        link: c(0x1f6fe0),
        on_accent: c(0xffffff),
        waiting: c(0xb7741a),
        read: c(0x00875f),
        revoked: c(0xd0342c),
        danger: c(0xec493d),
        seg_active: c(0xe6eefb),
        seg_active_text: c(0x0a0b0c),
        switch_off: c(0xc6d0dc),
        knob_off: c(0xffffff),
        warn_bg: c(0xfff3dc),
        warn_fg: c(0x8a5a10),
        selected: c(0xe6eefb),
        row_hover: c(0xeef2f7),
        dot_off: c(0xb6c2cf),
    }
}

pub struct ActiveTokens(pub Tokens);
impl Global for ActiveTokens {}

pub fn tokens(cx: &App) -> Tokens {
    cx.try_global::<ActiveTokens>()
        .map(|t| t.0)
        .unwrap_or_else(dark)
}

fn is_dark(a: WindowAppearance) -> bool {
    matches!(a, WindowAppearance::Dark | WindowAppearance::VibrantDark)
}

/// Applies the tokens for this appearance to our globals and to gpui-kit's theme (inputs).
pub fn apply(appearance: WindowAppearance, cx: &mut App) {
    let t = if is_dark(appearance) { dark() } else { light() };
    if cx
        .try_global::<ActiveTokens>()
        .is_some_and(|a| a.0.dark == t.dark)
    {
        return;
    }
    cx.set_global(ActiveTokens(t));
    Theme::change(
        if t.dark {
            ThemeMode::Dark
        } else {
            ThemeMode::Light
        },
        None,
        cx,
    );
    Theme::update(cx, |th| {
        th.radius = px(8.);
        th.radius_lg = px(12.);
        let k = &mut th.colors;
        k.background = t.field;
        k.foreground = t.text;
        k.muted_foreground = t.muted;
        k.border = t.field_ring;
        k.input = t.field_ring;
        k.ring = t.accent;
        k.caret = t.text;
        k.selection = hsla(214. / 360., 1., 0.6, 0.35);
        k.primary = t.accent;
        k.primary_hover = t.accent_hover;
        k.primary_foreground = t.on_accent;
        k.popover = t.panel;
        k.popover_foreground = t.text;
    });
    cx.refresh_windows();
}
