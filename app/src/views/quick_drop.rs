//! C Quick drop (SPEC 7): a panel over everything; text from the clipboard is taken (masked) and
//! the clipboard cleared; Tab cycles the lifetime, ⌘P passphrase, ⌘O files, ⌘L label; Enter
//! creates and copies the link, Esc closes and wipes what was typed. Errors stay in the panel.

use std::path::PathBuf;

use gpui_kit::component::input::{Input, InputEvent, InputState};
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::*;
use pnesecrets_core::quit::CreatePhase;
use pnesecrets_core::sdrop::format::{self, MAX_FILES};
use pnesecrets_core::sent::{Draft, DraftFile};
use zeroize::Zeroizing;

use crate::fmt;
use crate::model::{ModelEvent, model};
use crate::platform::{cmd, mono_font};
use crate::theme::tokens;
use crate::views::widgets::{guard_input, kbd, link_button};

pub struct QuickDrop {
    text: Entity<InputState>,
    passphrase: Entity<InputState>,
    label: Entity<InputState>,
    masked: bool,
    ttl: u32,
    show_passphrase: bool,
    show_label: bool,
    files: Vec<DraftFile>,
    pasted: Option<String>,
    error: Option<String>,
    op: Option<u64>,
    take_tag: Option<u64>,
    focus: FocusHandle,
    _subs: Vec<Subscription>,
}

impl QuickDrop {
    pub fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        let text = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("Type or paste the secret")
                .masked(true)
                .context_menu(false)
        });
        let passphrase = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("Passphrase (send it another way)")
                .context_menu(false)
        });
        let label = cx.new(|cx| InputState::new(window, cx).placeholder("Label, only for you"));
        let m = model(cx);
        let take_tag = Some(m.update(cx, |m, _| m.take_clipboard()));
        let mut subs = vec![
            cx.subscribe_in(&m, window, |this, _, e: &ModelEvent, window, cx| {
                match e {
                    ModelEvent::ClipboardText { tag, text, cleared }
                        if this.take_tag == Some(*tag) =>
                    {
                        this.take_tag = None;
                        if let Some(t) = text
                            && this.text.read(cx).value().is_empty()
                        {
                            let n = t.chars().count();
                            let t = t.to_string();
                            this.text.update(cx, |s, cx| s.set_value(t, window, cx));
                            this.pasted = Some(format!(
                                "Pasted from clipboard · {n} characters · {}",
                                if *cleared {
                                    "clipboard cleared"
                                } else {
                                    "clipboard not cleared"
                                }
                            ));
                            this.sync_input_flag(cx);
                        }
                        cx.notify();
                    }
                    // The model shows the "Link copied" notification.
                    ModelEvent::Created { op } if this.op == Some(*op) => {
                        this.wipe(window, cx);
                        window.remove_window();
                    }
                    ModelEvent::CreateFailed { op, error, .. } if this.op == Some(*op) => {
                        this.op = None;
                        this.error = Some(error.clone());
                        cx.notify();
                    }
                    _ => {}
                }
            }),
        ];
        for input in [&text, &passphrase, &label] {
            subs.push(cx.subscribe_in(
                input,
                window,
                |this, _, e: &InputEvent, window, cx| match e {
                    InputEvent::PressEnter { .. } => this.create(window, cx),
                    InputEvent::Change => this.sync_input_flag(cx),
                    _ => {}
                },
            ));
        }
        text.update(cx, |s, cx| s.focus(window, cx));
        Self {
            text,
            passphrase,
            label,
            masked: true,
            ttl: 86400,
            show_passphrase: false,
            show_label: false,
            files: Vec::new(),
            pasted: None,
            error: None,
            op: None,
            take_tag,
            focus: cx.focus_handle(),
            _subs: subs,
        }
    }

    fn sync_input_flag(&mut self, cx: &mut Context<Self>) {
        let has = !self.text.read(cx).value().is_empty() || !self.files.is_empty();
        model(cx).update(cx, |m, _| {
            m.quick_drop_input = has;
            m.sync_hold();
        });
    }

    fn wipe(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        for s in [&self.text, &self.passphrase, &self.label] {
            s.update(cx, |s, cx| s.set_value("", window, cx));
        }
        self.files.clear();
        self.pasted = None;
        self.op = None;
        model(cx).update(cx, |m, _| {
            m.quick_drop_input = false;
            m.sync_hold();
        });
    }

    fn cancel(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        // After the request is out, Esc only hides the panel: the create goes on (SPEC 7).
        self.wipe(window, cx);
        window.remove_window();
    }

    fn cycle_ttl(&mut self, cx: &mut Context<Self>) {
        self.ttl = match self.ttl {
            3600 => 86400,
            86400 => 604800,
            _ => 3600,
        };
        cx.notify();
    }

    fn create(&mut self, _window: &mut Window, cx: &mut Context<Self>) {
        if self.op.is_some() {
            return;
        }
        let text = Zeroizing::new(self.text.read(cx).value().to_string());
        if text.is_empty() && self.files.is_empty() {
            self.error = Some("Type or paste the secret first.".into());
            cx.notify();
            return;
        }
        let passphrase = if self.show_passphrase {
            let p = Zeroizing::new(self.passphrase.read(cx).value().to_string());
            if p.is_empty() {
                self.error = Some("Enter the passphrase or turn it off (⌘P).".into());
                cx.notify();
                return;
            }
            Some(p)
        } else {
            None
        };
        // Checked before the files move into the draft: a refusal keeps them in the panel.
        if !model(cx).read(cx).can_create() {
            self.error = Some(model(cx).read(cx).cannot_create());
            cx.notify();
            return;
        }
        let draft = Draft {
            text,
            files: std::mem::take(&mut self.files),
            passphrase,
            ttl: self.ttl,
            label: self.label.read(cx).value().to_string(),
            notify: true,
        };
        self.error = None;
        self.op = model(cx).update(cx, |m, cx| m.create(draft, false, cx));
        if self.op.is_none() {
            self.error = Some(model(cx).read(cx).cannot_create());
        }
        cx.notify();
    }

    fn add_files(&mut self, cx: &mut Context<Self>) {
        let rx = cx.prompt_for_paths(PathPromptOptions {
            files: true,
            directories: false,
            multiple: true,
            prompt: None,
        });
        let limit = model(cx).read(cx).snap.limit.unwrap_or(format::MAX_BUCKET) as u64;
        cx.spawn(async move |this, cx| {
            let Ok(Ok(Some(paths))) = rx.await else {
                return;
            };
            let read = cx
                .background_executor()
                .spawn(async move { read_files(&paths, limit) })
                .await;
            let _ = this.update(cx, |this, cx| {
                for f in read {
                    if this.files.len() < MAX_FILES {
                        this.files.push(f);
                    }
                }
                this.sync_input_flag(cx);
                cx.notify();
            });
        })
        .detach();
    }

    /// The create is still on its way when the panel is gone (Esc): stays detached in the engine.
    fn phase(&self, cx: &App) -> Option<CreatePhase> {
        let op = self.op?;
        let m = model(cx);
        let m = m.read(cx);
        if m.creating(op) {
            return Some(CreatePhase::Sending);
        }
        m.create_view(op).map(|c| c.phase)
    }
}

fn read_files(paths: &[PathBuf], limit: u64) -> Vec<DraftFile> {
    paths
        .iter()
        .filter_map(|p| {
            let m = std::fs::metadata(p).ok()?;
            if !m.is_file() || m.len() == 0 || m.len() > limit {
                return None;
            }
            let raw = p.file_name()?.to_string_lossy().into_owned();
            Some(DraftFile {
                name: format::sanitize_file_name(&raw),
                data: Zeroizing::new(std::fs::read(p).ok()?),
            })
        })
        .collect()
}

impl Focusable for QuickDrop {
    fn focus_handle(&self, _: &App) -> FocusHandle {
        self.focus.clone()
    }
}

impl Render for QuickDrop {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let t = tokens(cx);
        let phase = self.phase(cx);
        let sending = phase == Some(CreatePhase::Sending);
        let chip = |id: &'static str, label: SharedString, key: String, on: bool| {
            div()
                .id(id)
                .flex()
                .items_center()
                .gap(px(8.))
                .h(px(30.))
                .px(px(10.))
                .rounded(px(6.))
                .border_1()
                .text_size(px(13.))
                .cursor_pointer()
                .when(on, |d| d.bg(t.seg_active).border_color(t.accent))
                .when(!on, |d| d.border_color(t.field_ring).text_color(t.text2))
                .child(label)
                .child(kbd(&t, key))
        };
        let field = |input: Input| {
            input
                .h(px(34.))
                .bg(t.field)
                .border_color(t.field_ring)
                .rounded(px(8.))
        };
        div()
            .key_context("QuickDrop")
            .track_focus(&self.focus)
            .capture_key_down(cx.listener(|this, ev: &KeyDownEvent, window, cx| {
                let k = &ev.keystroke;
                let cmd = k.modifiers.secondary();
                match (k.key.as_str(), cmd) {
                    ("escape", _) => {
                        this.cancel(window, cx);
                        cx.stop_propagation();
                    }
                    ("tab", false) if !k.modifiers.shift => {
                        this.cycle_ttl(cx);
                        cx.stop_propagation();
                    }
                    ("p", true) => {
                        this.show_passphrase = !this.show_passphrase;
                        if this.show_passphrase {
                            this.passphrase.update(cx, |s, cx| s.focus(window, cx));
                        } else {
                            this.passphrase
                                .update(cx, |s, cx| s.set_value("", window, cx));
                            this.text.update(cx, |s, cx| s.focus(window, cx));
                        }
                        cx.notify();
                        cx.stop_propagation();
                    }
                    ("o", true) => {
                        this.add_files(cx);
                        cx.stop_propagation();
                    }
                    ("l", true) => {
                        this.show_label = !this.show_label;
                        if this.show_label {
                            this.label.update(cx, |s, cx| s.focus(window, cx));
                        }
                        cx.notify();
                        cx.stop_propagation();
                    }
                    _ => {}
                }
            }))
            .size_full()
            .flex()
            .flex_col()
            .rounded(px(14.))
            .bg(t.panel)
            .border_1()
            .border_color(t.panel_ring)
            .text_color(t.text)
            .text_size(px(14.))
            .overflow_hidden()
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap(px(14.))
                    .px(px(18.))
                    .pt(px(16.))
                    .pb(px(6.))
                    .child(div().text_color(t.link).text_size(px(18.)).child("🔒"))
                    .child(
                        div().flex_1().child(guard_input(
                            Input::new(&self.text)
                                .appearance(false)
                                .font_family(mono_font())
                                .text_size(px(18.)),
                            &self.text,
                        )),
                    )
                    .child(
                        link_button(&t, "show", if self.masked { "Show" } else { "Hide" })
                            .text_size(px(13.))
                            .on_click(cx.listener(|this, _, window, cx| {
                                this.masked = !this.masked;
                                let m = this.masked;
                                this.text.update(cx, |s, cx| s.set_masked(m, window, cx));
                                cx.notify();
                            })),
                    ),
            )
            .child(
                div()
                    .px(px(18.))
                    .pl(px(54.))
                    .pb(px(12.))
                    .text_size(px(12.))
                    .text_color(t.muted)
                    .child(self.pasted.clone().unwrap_or_else(|| {
                        if self.files.is_empty() {
                            " ".into()
                        } else {
                            format!("{} file(s) attached", self.files.len())
                        }
                    })),
            )
            .when(self.show_passphrase, |d| {
                d.child(div().px(px(18.)).pb(px(10.)).child(guard_input(
                    field(Input::new(&self.passphrase)),
                    &self.passphrase,
                )))
            })
            .when(self.show_label, |d| {
                d.child(
                    div()
                        .px(px(18.))
                        .pb(px(10.))
                        .child(field(Input::new(&self.label))),
                )
            })
            .child(
                div()
                    .flex()
                    .flex_wrap()
                    .gap(px(8.))
                    .px(px(18.))
                    .py(px(12.))
                    .border_t_1()
                    .border_color(t.panel_ring)
                    .child(
                        chip(
                            "ttl",
                            format!("Delete after {}", fmt::ttl_short(self.ttl)).into(),
                            "Tab".into(),
                            true,
                        )
                        .on_click(cx.listener(|this, _, _, cx| this.cycle_ttl(cx))),
                    )
                    .child(chip(
                        "pass",
                        if self.show_passphrase {
                            "Passphrase on".into()
                        } else {
                            "Passphrase off".into()
                        },
                        cmd("P"),
                        self.show_passphrase,
                    ))
                    .child(
                        chip(
                            "files",
                            "Add files".into(),
                            cmd("O"),
                            !self.files.is_empty(),
                        )
                        .on_click(cx.listener(|this, _, _, cx| this.add_files(cx))),
                    )
                    .child(chip("label", "Label".into(), cmd("L"), self.show_label)),
            )
            .children(
                self.error
                    .clone()
                    .or_else(|| {
                        (phase == Some(CreatePhase::Unknown)).then(|| {
                            "The connection broke: the result is unknown. Esc to close.".to_string()
                        })
                    })
                    .map(|e| {
                        div()
                            .px(px(18.))
                            .pb(px(8.))
                            .text_size(px(13.))
                            .text_color(t.revoked)
                            .child(e)
                    }),
            )
            .child(
                div()
                    .mt_auto()
                    .flex()
                    .items_center()
                    .justify_between()
                    .px(px(18.))
                    .py(px(12.))
                    .bg(t.window)
                    .border_t_1()
                    .border_color(t.panel_ring)
                    .text_size(px(12.))
                    .text_color(t.muted)
                    .child("Esc to cancel")
                    .child(
                        div()
                            .id("go")
                            .flex()
                            .items_center()
                            .gap(px(10.))
                            .cursor_pointer()
                            .on_click(cx.listener(|this, _, window, cx| this.create(window, cx)))
                            .child(if sending {
                                "Creating…"
                            } else {
                                "Create one-time link and copy"
                            })
                            .child(
                                div()
                                    .h(px(24.))
                                    .px(px(8.))
                                    .rounded(px(5.))
                                    .bg(t.accent)
                                    .text_color(t.on_accent)
                                    .font_weight(FontWeight::SEMIBOLD)
                                    .flex()
                                    .items_center()
                                    .child("↵"),
                            ),
                    ),
            )
    }
}
