//! A2 Sent secret status (SPEC 6): label and pill, the recipient link with Copy, the timeline,
//! the details, Revoke (confirmed) and Send again. Also the screen of a create whose local steps
//! failed or whose outcome is unknown.

use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::*;
use pnesecrets_core::clipboard::CopyKind;
use pnesecrets_core::history::{Entry, Status};
use pnesecrets_core::quit::CreatePhase;

use crate::fmt::{self, Tone};
use crate::model::{Preset, model, now};
use crate::platform::mono_font;
use crate::theme::{Tokens, tokens};
use crate::views::widgets::{danger_button, outline_button, primary_button, tone_color};

pub enum Action {
    SendAgain(Preset),
}

fn pill(t: &Tokens, text: &str, tone: Tone) -> Div {
    let (bg, fg) = match tone {
        Tone::Waiting => (t.warn_bg, t.warn_fg),
        _ => (t.panel, tone_color(t, tone)),
    };
    div()
        .flex()
        .items_center()
        .gap(px(6.))
        .h(px(26.))
        .px(px(10.))
        .rounded(px(6.))
        .bg(bg)
        .text_color(fg)
        .text_size(px(13.))
        .font_weight(FontWeight::SEMIBOLD)
        .child(crate::views::widgets::dot(t, tone, 7.))
        .child(text.to_string())
}

enum Mark {
    Done,
    Now(Tone),
    Later,
}

fn step(t: &Tokens, mark: Mark, title: String, sub: Option<String>) -> Div {
    let dot = div().size(px(10.)).mt(px(4.)).rounded_full().flex_none();
    let (dot, dim) = match mark {
        Mark::Done => (dot.bg(t.read), false),
        Mark::Now(tone) => (dot.border(px(2.)).border_color(tone_color(t, tone)), false),
        Mark::Later => (dot.border(px(2.)).border_color(t.dot_off), true),
    };
    div().flex().gap(px(12.)).child(dot).child(
        div()
            .flex()
            .flex_col()
            .gap(px(2.))
            .when(dim, |d| d.text_color(t.muted))
            .child(title)
            .children(sub.map(|s| div().text_size(px(12.)).text_color(t.muted).child(s))),
    )
}

fn timeline(t: &Tokens, e: &Entry, now: i64) -> Div {
    let mut v = vec![step(
        t,
        Mark::Done,
        "Created and encrypted".into(),
        Some(fmt::day_time(now, e.created_at)),
    )];
    match e.link_copied_at {
        Some(at) => v.push(step(
            t,
            Mark::Done,
            "Link copied".into(),
            Some(match e.clipboard_cleared_at {
                Some(c) if c >= at => {
                    format!(
                        "{} · clipboard cleared {}",
                        fmt::day_time(now, at),
                        fmt::clock(c)
                    )
                }
                _ => fmt::day_time(now, at),
            }),
        )),
        None => v.push(step(t, Mark::Later, "Link not copied yet".into(), None)),
    }
    match e.status {
        Status::Read => {
            let by = e
                .consumed_by
                .as_ref()
                .map(|b| format!(" by {b}"))
                .unwrap_or_default();
            v.push(step(
                t,
                Mark::Done,
                format!("Opened{by}"),
                e.consumed_at.map(|c| fmt::day_time(now, c)),
            ));
        }
        Status::Revoked => {
            v.push(step(
                t,
                Mark::Now(Tone::Revoked),
                "Revoked".into(),
                e.revoked_at.map(|r| fmt::day_time(now, r)),
            ));
        }
        Status::NotFound => v.push(step(
            t,
            Mark::Now(Tone::Muted),
            "Not found on the server".into(),
            e.checked_at
                .map(|c| format!("Checked {}", fmt::day_time(now, c))),
        )),
        Status::ExpiredUnknown => {
            if let Some(s) = e.stored_seen_at {
                v.push(step(
                    t,
                    Mark::Done,
                    format!("Not opened as of {}", fmt::day_time(now, s)),
                    None,
                ));
            }
            v.push(step(
                t,
                Mark::Now(Tone::Muted),
                "Expired: whether it was read is unknown".into(),
                Some(fmt::day_time(now, e.expires_at)),
            ));
        }
        Status::Waiting => {
            let sub = if !e.tracked {
                "Not tracked: the owner link could not be kept on this computer".to_string()
            } else {
                let checked = e
                    .checked_at
                    .map(|c| format!("Checked {}", fmt::ago(now - c)))
                    .unwrap_or_else(|| "Checking…".into());
                if e.notify {
                    format!("{checked} · you will get a notification")
                } else {
                    checked
                }
            };
            v.push(step(
                t,
                Mark::Now(Tone::Waiting),
                "Not opened yet".into(),
                Some(sub),
            ));
            v.push(step(
                t,
                Mark::Later,
                "Deleted if unread".into(),
                Some(fmt::day_time(now, e.expires_at)),
            ));
        }
    }
    div().flex().flex_col().gap(px(14.)).children(v)
}

fn detail(t: &Tokens, name: &str, value: impl IntoElement, last: bool) -> Div {
    div()
        .flex()
        .justify_between()
        .items_center()
        .gap(px(16.))
        .py(px(12.))
        .when(!last, |d| d.border_b_1().border_color(t.panel_ring))
        .child(div().text_color(t.muted).child(name.to_string()))
        .child(value)
}

fn panel(t: &Tokens) -> Div {
    div()
        .flex()
        .flex_col()
        .p(px(18.))
        .rounded(px(12.))
        .border_1()
        .border_color(t.panel_ring)
}

fn link_box(t: &Tokens, link: &str, copy: Stateful<Div>, note: &'static str) -> Div {
    panel(t)
        .bg(t.panel)
        .gap(px(8.))
        .child(
            div()
                .font_weight(FontWeight::SEMIBOLD)
                .child("Link for the recipient"),
        )
        .child(
            div()
                .flex()
                .gap(px(8.))
                .child(
                    div()
                        .flex_1()
                        .min_w_0()
                        .h(px(40.))
                        .flex()
                        .items_center()
                        .px(px(12.))
                        .rounded(px(8.))
                        .bg(t.field)
                        .border_1()
                        .border_color(t.field_ring)
                        .font_family(mono_font())
                        .text_size(px(13.))
                        .text_color(t.text2)
                        .overflow_hidden()
                        .whitespace_nowrap()
                        .text_ellipsis()
                        .child(link.to_string()),
                )
                .child(copy.h(px(40.))),
        )
        .child(div().text_size(px(12.)).text_color(t.muted).child(note))
}

pub fn render_entry(
    id: &str,
    _window: &mut Window,
    cx: &mut App,
    on_action: impl Fn(Action, &mut Window, &mut App) + 'static,
) -> AnyElement {
    let t = tokens(cx);
    let now = now();
    let m = model(cx);
    let mref = m.read(cx);
    let Some(e) = mref.entry(id).cloned() else {
        return div()
            .p(px(36.))
            .child("This secret is no longer in the history.")
            .into_any();
    };
    // Loaded from the vault by the engine; None until it answers (or when there is none). Shown
    // only while the secret can still be opened.
    let link = (e.status == Status::Waiting && now < e.expires_at)
        .then(|| mref.links.get(id).cloned().flatten())
        .flatten();
    let host = e.server.clone();
    let (pill_text, tone) = fmt::status_pill(&e);
    let can_revoke = e.status == Status::Waiting && e.tracked && now < e.expires_at;
    let preset = Preset {
        ttl: e.ttl,
        passphrase: e.passphrase,
    };
    let rid = id.to_owned();
    let cid = id.to_owned();

    let header = div()
        .flex()
        .items_start()
        .justify_between()
        .gap(px(16.))
        .child(
            div()
                .flex()
                .flex_col()
                .gap(px(8.))
                .child(
                    div()
                        .text_size(px(22.))
                        .font_weight(FontWeight::SEMIBOLD)
                        .child(fmt::untitled(&e)),
                )
                .child(div().flex().child(pill(&t, pill_text, tone))),
        )
        .child(
            div()
                .flex()
                .gap(px(8.))
                .child(
                    outline_button(&t, "send-again", "Send again")
                        .on_click(move |_, window, cx| on_action(Action::SendAgain(preset), window, cx)),
                )
                .when(can_revoke, |d| {
                    d.child(danger_button(&t, "revoke", "Revoke").on_click(move |_, window, cx| {
                        let rx = window.prompt(
                            PromptLevel::Warning,
                            "Revoke this secret?",
                            Some("The link stops working right away. The recipient will see that it is not found."),
                            &["Cancel", "Revoke"],
                            cx,
                        );
                        let id = rid.clone();
                        cx.spawn(async move |cx| {
                            if rx.await == Ok(1) {
                                cx.update(|cx| model(cx).update(cx, |m, _| m.revoke(&id)));
                            }
                        })
                        .detach();
                    }))
                }),
        );

    let link_panel = link.map(|l| {
        let text = l.clone();
        link_box(
            &t,
            &l,
            primary_button(&t, "copy-link", "Copy").on_click(move |_, _, cx| {
                let text = text.clone();
                let id = cid.clone();
                model(cx).update(cx, |m, _| m.copy(text, CopyKind::Link { entry: Some(id) }));
            }),
            "Opens once, then the secret is destroyed. Nothing to bookmark: this app keeps the owner link for you.",
        )
    });

    let content = match (e.text_lines, e.files.is_empty()) {
        (Some(1), true) => "Text · 1 line".to_string(),
        (Some(n), true) => format!("Text · {n} lines"),
        (None, false) => "Files".into(),
        (Some(n), false) => format!("Text · {n} lines and files"),
        (None, true) => "—".into(),
    };
    let files = if e.files.is_empty() {
        div().child("None")
    } else {
        div()
            .flex()
            .flex_col()
            .items_end()
            .gap(px(2.))
            .children(e.files.iter().map(|f| {
                div()
                    .font_family(mono_font())
                    .text_size(px(13.))
                    .child(format!("{} · {}", f.name, fmt::size(f.size)))
            }))
    };
    let expires = if now < e.expires_at {
        fmt::expires_in(e.expires_at - now)
    } else {
        format!("Expired {}", fmt::day_time(now, e.expires_at))
    };
    let details = panel(&t)
        .flex_1()
        .py(px(6.))
        .child(detail(&t, "Expires", div().child(expires), false))
        .child(detail(
            &t,
            "Passphrase",
            div().child(if e.passphrase { "Yes" } else { "No" }),
            false,
        ))
        .child(detail(&t, "Content", div().child(content), false))
        .child(detail(&t, "Files", files, false))
        .child(detail(&t, "Server", div().child(host), true));

    div()
        .id("status")
        .size_full()
        .overflow_y_scroll()
        .flex()
        .flex_col()
        .gap(px(22.))
        .px(px(36.))
        .py(px(28.))
        .child(header)
        .children(link_panel)
        .child(
            div()
                .flex()
                .gap(px(20.))
                .items_start()
                .child(
                    panel(&t)
                        .flex_1()
                        .gap(px(14.))
                        .child(div().font_weight(FontWeight::SEMIBOLD).child("Timeline"))
                        .child(timeline(&t, &e, now)),
                )
                .child(details),
        )
        .into_any()
}

/// A create whose local steps failed (the link exists only here) or whose outcome is unknown.
pub fn render_create(op: u64, cx: &mut App) -> AnyElement {
    let t = tokens(cx);
    let m = model(cx);
    let Some(c) = m.read(cx).create_view(op).cloned() else {
        return div().p(px(36.)).child("…").into_any();
    };
    let base = div()
        .size_full()
        .flex()
        .flex_col()
        .gap(px(20.))
        .px(px(36.))
        .py(px(28.));
    match (c.phase, c.recipient.clone()) {
        (CreatePhase::NotSavedLocally, Some(link)) => {
            let copy = link.clone();
            base.child(
                div()
                    .text_size(px(22.))
                    .font_weight(FontWeight::SEMIBOLD)
                    .child("Created, but not saved on this computer"),
            )
            .child(div().text_color(t.text2).child(
                "The secret is on the server. Copy the link now: it is not in your history yet and is lost if you leave this screen or quit.",
            ))
            .child(link_box(
                &t,
                &link,
                primary_button(&t, "copy-partial", "Copy").on_click(move |_, _, cx| {
                    let link = copy.clone();
                    model(cx).update(cx, |m, _| m.copy(link, CopyKind::Link { entry: None }));
                }),
                "Opens once, then the secret is destroyed.",
            ))
            .child(
                div().flex().gap(px(8.)).child(
                    primary_button(&t, "retry-local", "Retry saving").on_click(move |_, _, cx| {
                        model(cx).update(cx, |m, _| m.retry_local(op));
                    }),
                ),
            )
            .into_any()
        }
        _ => base
            .child(
                div()
                    .text_size(px(22.))
                    .font_weight(FontWeight::SEMIBOLD)
                    .child("The result is unknown"),
            )
            .child(div().text_color(t.text2).child(
                c.error
                    .map(|e| e.to_string())
                    .unwrap_or_else(|| "The connection broke.".into()),
            ))
            .child(div().text_color(t.muted).text_size(px(13.)).child(
                "The secret may exist on the server without a link you can use; it is deleted when it expires.",
            ))
            .child(
                div().flex().gap(px(8.)).child(
                    outline_button(&t, "create-again", "Back to New secret").on_click(
                        move |_, _, cx| {
                            model(cx).update(cx, |m, cx| m.create_again(op, cx));
                        },
                    ),
                ),
            )
            .into_any(),
    }
}
