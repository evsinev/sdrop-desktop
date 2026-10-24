//! Small drawn controls matching the mockups, and the guard that routes Copy / Cut of secret
//! fields through the clipboard service (SPEC 5).

use gpui_kit::component::input::{self, InputState, TextareaState};
use gpui_kit::*;
use pnesecrets_core::clipboard::CopyKind;
use zeroize::Zeroizing;

use crate::fmt::Tone;
use crate::model::model;
use crate::theme::Tokens;

pub fn tone_color(t: &Tokens, tone: Tone) -> Hsla {
    match tone {
        Tone::Waiting => t.waiting,
        Tone::Read => t.read,
        Tone::Revoked => t.revoked,
        Tone::Muted => t.muted,
    }
}

/// The 7 px status dot; muted ones are rings, as in the mockups.
pub fn dot(t: &Tokens, tone: Tone, size: f32) -> Div {
    let d = div().size(px(size)).rounded_full().flex_none();
    let c = tone_color(t, tone);
    if tone == Tone::Muted {
        d.border(px(1.5)).border_color(c)
    } else {
        d.bg(c)
    }
}

pub fn primary_button(
    t: &Tokens,
    id: impl Into<ElementId>,
    label: impl IntoElement,
) -> Stateful<Div> {
    let hover = t.accent_hover;
    div()
        .id(id)
        .h(px(36.))
        .px(px(16.))
        .flex()
        .items_center()
        .justify_center()
        .gap(px(8.))
        .rounded(px(8.))
        .bg(t.accent)
        .text_color(t.on_accent)
        .font_weight(FontWeight::SEMIBOLD)
        .cursor_pointer()
        .hover(move |s| s.bg(hover))
        .child(label)
}

pub fn outline_button(
    t: &Tokens,
    id: impl Into<ElementId>,
    label: impl IntoElement,
) -> Stateful<Div> {
    let hover = t.row_hover;
    div()
        .id(id)
        .h(px(36.))
        .px(px(14.))
        .flex()
        .items_center()
        .justify_center()
        .rounded(px(8.))
        .border_1()
        .border_color(t.field_ring)
        .text_color(t.text)
        .cursor_pointer()
        .hover(move |s| s.bg(hover))
        .child(label)
}

pub fn danger_button(
    t: &Tokens,
    id: impl Into<ElementId>,
    label: impl IntoElement,
) -> Stateful<Div> {
    div()
        .id(id)
        .h(px(36.))
        .px(px(14.))
        .flex()
        .items_center()
        .justify_center()
        .rounded(px(8.))
        .bg(t.danger)
        .text_color(t.on_accent)
        .font_weight(FontWeight::SEMIBOLD)
        .cursor_pointer()
        .hover(|s| s.opacity(0.9))
        .child(label)
}

pub fn link_button(
    t: &Tokens,
    id: impl Into<ElementId>,
    label: impl Into<SharedString>,
) -> Stateful<Div> {
    div()
        .id(id)
        .text_color(t.link)
        .cursor_pointer()
        .hover(|s| s.underline())
        .child(label.into())
}

/// The 34×20 switch of the mockups.
pub fn switch(t: &Tokens, id: impl Into<ElementId>, on: bool) -> Stateful<Div> {
    div()
        .id(id)
        .w(px(34.))
        .h(px(20.))
        .flex_none()
        .rounded(px(10.))
        .bg(if on { t.accent } else { t.switch_off })
        .cursor_pointer()
        .relative()
        .child(
            div()
                .absolute()
                .top(px(2.))
                .left(px(if on { 16. } else { 2. }))
                .size(px(16.))
                .rounded_full()
                .bg(if on { t.on_accent } else { t.knob_off }),
        )
}

pub fn kbd(t: &Tokens, text: impl Into<SharedString>) -> Div {
    div()
        .font_family(crate::platform::mono_font())
        .text_size(px(11.))
        .text_color(t.muted)
        .child(text.into())
}

/// Copy and Cut from a secret field go through the clipboard service: concealed, cleared after
/// 30 s, never GPUI's own clipboard write. The field's context menu is off (it would copy too).
pub fn guard_input(child: impl IntoElement, state: &Entity<InputState>) -> Div {
    let (a, b) = (state.clone(), state.clone());
    div()
        .capture_action(move |_: &input::Copy, _window, cx| {
            copy_selected(a.read(cx).selected_value().to_string(), cx);
            cx.stop_propagation();
        })
        .capture_action(move |_: &input::Cut, window, cx| {
            copy_selected(b.read(cx).selected_value().to_string(), cx);
            cx.stop_propagation();
            window.dispatch_action(Box::new(input::Backspace), cx);
        })
        .child(child)
}

pub fn guard_textarea(child: impl IntoElement, state: &Entity<TextareaState>) -> Div {
    let (a, b) = (state.clone(), state.clone());
    div()
        .size_full()
        .capture_action(move |_: &input::Copy, _window, cx| {
            copy_selected(a.read(cx).selected_value().to_string(), cx);
            cx.stop_propagation();
        })
        .capture_action(move |_: &input::Cut, window, cx| {
            copy_selected(b.read(cx).selected_value().to_string(), cx);
            cx.stop_propagation();
            window.dispatch_action(Box::new(input::Backspace), cx);
        })
        .child(child)
}

fn copy_selected(selected: String, cx: &mut App) {
    let text = Zeroizing::new(selected);
    if text.is_empty() {
        return;
    }
    model(cx).update(cx, |m, _| m.copy(text, CopyKind::Secret));
}
