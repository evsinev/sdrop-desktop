//! The main window (A): the sidebar with history, and A1 / A2 on the right.

use gpui_kit::component::input::{Input, InputState};
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::*;

use crate::fmt;
use crate::model::{Screen, model, now};
use crate::platform::{cmd, mono_font, vault_name};
use crate::theme::tokens;
use crate::views::new_secret::NewSecretForm;
use crate::views::status;
use crate::views::widgets::{dot, tone_color};

pub struct MainWindow {
    form: Entity<NewSecretForm>,
    search: Entity<InputState>,
    _subs: Vec<Subscription>,
}

impl MainWindow {
    pub fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        let form = cx.new(|cx| NewSecretForm::new(window, cx));
        let search = cx.new(|cx| InputState::new(window, cx).placeholder("Search by label"));
        let m = model(cx);
        let subs = vec![
            cx.observe(&m, |_, _, cx| cx.notify()),
            cx.observe_window_activation(window, |_, window, cx| {
                let active = window.is_window_active();
                model(cx).read(cx).set_focus(active);
            }),
            cx.observe_window_appearance(window, |_, window, cx| {
                crate::theme::apply(window.appearance(), cx);
            }),
        ];
        crate::theme::apply(window.appearance(), cx);
        form.update(cx, |f, cx| f.focus_secret(window, cx));
        Self {
            form,
            search,
            _subs: subs,
        }
    }

    pub fn new_secret(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        model(cx).update(cx, |m, cx| m.set_screen(Screen::New, cx));
        self.form.update(cx, |f, cx| f.focus_secret(window, cx));
    }

    pub fn form(&self) -> Entity<NewSecretForm> {
        self.form.clone()
    }

    fn sidebar(&self, cx: &mut Context<Self>) -> Div {
        let t = tokens(cx);
        let now = now();
        let m = model(cx);
        let mref = m.read(cx);
        let query = self.search.read(cx).value().to_string();
        let selected = match &mref.screen {
            Screen::Status(id) => Some(id.clone()),
            _ => None,
        };
        let new_active = mref.screen == Screen::New;
        let entries: Vec<_> = mref
            .snap
            .index
            .search(&query)
            .into_iter()
            .cloned()
            .collect();
        let rows = entries.into_iter().map(|e| {
            let (line, tone) = fmt::status_line(&e, now);
            let id = e.id.clone();
            let is_sel = selected.as_deref() == Some(e.id.as_str());
            let hover = t.row_hover;
            div()
                .id(SharedString::from(format!("entry-{}", e.id)))
                .flex()
                .flex_col()
                .gap(px(3.))
                .p(px(8.))
                .rounded(px(8.))
                .cursor_pointer()
                .when(is_sel, |d| {
                    d.bg(t.selected).border_1().border_color(t.panel_ring)
                })
                .when(!is_sel, |d| d.hover(move |s| s.bg(hover)))
                .on_click(move |_, _, cx| {
                    let id = id.clone();
                    model(cx).update(cx, |m, cx| m.set_screen(Screen::Status(id), cx));
                })
                .child(
                    div()
                        .flex()
                        .justify_between()
                        .gap(px(8.))
                        .child(
                            div()
                                .min_w_0()
                                .overflow_hidden()
                                .whitespace_nowrap()
                                .text_ellipsis()
                                .when(is_sel, |d| d.font_weight(FontWeight::SEMIBOLD))
                                .child(fmt::untitled(&e)),
                        )
                        .child(
                            div()
                                .flex_none()
                                .text_size(px(12.))
                                .text_color(t.muted)
                                .child(fmt::list_time(now, e.created_at)),
                        ),
                )
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap(px(6.))
                        .text_size(px(12.))
                        .text_color(tone_color(&t, tone))
                        .child(dot(&t, tone, 7.))
                        .child(line),
                )
        });
        let history_ok = mref.history_error.is_none();
        let vault_ok = history_ok && mref.snap.vault_ok;
        let hover = t.accent_hover;
        div()
            .w(px(264.))
            .flex_none()
            .h_full()
            .flex()
            .flex_col()
            .gap(px(14.))
            .px(px(12.))
            .py(px(16.))
            .bg(t.side)
            .border_r_1()
            .border_color(t.divider)
            .child(
                div()
                    .flex()
                    .items_baseline()
                    .gap(px(8.))
                    .px(px(6.))
                    .child(
                        div()
                            .text_size(px(20.))
                            .font_weight(FontWeight::LIGHT)
                            .text_color(t.text)
                            .child("payneteasy"),
                    )
                    .child(
                        div()
                            .text_size(px(13.))
                            .font_weight(FontWeight::SEMIBOLD)
                            .text_color(t.muted)
                            .child("Secrets"),
                    ),
            )
            .child(
                div()
                    .id("new-secret")
                    .h(px(38.))
                    .rounded(px(8.))
                    .flex()
                    .items_center()
                    .justify_center()
                    .gap(px(8.))
                    .font_weight(FontWeight::SEMIBOLD)
                    .cursor_pointer()
                    .when(new_active, |d| {
                        d.bg(t.accent)
                            .text_color(t.on_accent)
                            .hover(move |s| s.bg(hover))
                    })
                    .when(!new_active, |d| d.border_1().border_color(t.field_ring))
                    .on_click(cx.listener(|this, _, window, cx| this.new_secret(window, cx)))
                    .child("+  New secret")
                    .child(
                        div()
                            .font_weight(FontWeight::NORMAL)
                            .text_size(px(12.))
                            .opacity(0.8)
                            .child(cmd("N")),
                    ),
            )
            .child(
                Input::new(&self.search)
                    .h(px(34.))
                    .bg(t.field)
                    .border_color(t.panel_ring)
                    .rounded(px(8.))
                    .text_size(px(13.)),
            )
            .child(
                div()
                    .id("history")
                    .flex_1()
                    .min_h_0()
                    .overflow_y_scroll()
                    .flex()
                    .flex_col()
                    .gap(px(2.))
                    .child(
                        div()
                            .text_size(px(11.))
                            .font_weight(FontWeight::SEMIBOLD)
                            .text_color(t.muted)
                            .px(px(8.))
                            .py(px(6.))
                            .child("SENT · ON THIS COMPUTER"),
                    )
                    .children(rows),
            )
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap(px(6.))
                    .pt(px(10.))
                    .px(px(8.))
                    .border_t_1()
                    .border_color(t.divider)
                    .text_size(px(12.))
                    .text_color(t.muted)
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap(px(6.))
                            .child(
                                div()
                                    .text_color(if vault_ok { t.read } else { t.revoked })
                                    .child(if vault_ok { "✓" } else { "!" }),
                            )
                            .child(if vault_ok {
                                format!("Owner links kept in {}", vault_name())
                            } else if !history_ok {
                                "History unavailable".into()
                            } else {
                                format!("{} not available: links not kept", vault_name())
                            }),
                    )
                    .child(
                        div().flex().gap(px(4.)).child("Quick drop:").child(
                            div()
                                .font_family(mono_font())
                                .text_color(t.text2)
                                .child(crate::hotkey::hint()),
                        ),
                    ),
            )
    }
}

impl Render for MainWindow {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let t = tokens(cx);
        let screen = model(cx).read(cx).screen.clone();
        let notice = model(cx)
            .read(cx)
            .notice
            .clone()
            .filter(|(_, at)| now() - at < 15_000)
            .map(|(n, _)| n);
        let form = self.form.clone();
        let content: AnyElement = match screen {
            Screen::New => self.form.clone().into_any_element(),
            Screen::Status(id) => status::render_entry(&id, window, cx, move |a, window, cx| {
                let status::Action::SendAgain(p) = a;
                model(cx).update(cx, |m, cx| m.set_screen(Screen::New, cx));
                form.update(cx, |f, cx| {
                    f.apply_preset(p, window, cx);
                    f.focus_secret(window, cx);
                });
            }),
            Screen::Create(op) => status::render_create(op, cx),
        };
        let note = model(cx).read(cx).history_note.clone();
        div()
            .size_full()
            .flex()
            .bg(t.window)
            .text_color(t.text)
            .text_size(px(14.))
            .child(self.sidebar(cx))
            .child(
                div()
                    .flex_1()
                    .min_w_0()
                    .h_full()
                    .flex()
                    .flex_col()
                    .children(notice.or(note).map(|n| {
                        div()
                            .px(px(36.))
                            .py(px(8.))
                            .bg(t.warn_bg)
                            .text_color(t.warn_fg)
                            .text_size(px(13.))
                            .child(n)
                    }))
                    .child(div().flex_1().min_h_0().child(content)),
            )
    }
}
