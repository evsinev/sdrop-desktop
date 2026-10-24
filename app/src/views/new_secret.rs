//! A1 New secret (SPEC 6): the secret, files, label, lifetime, passphrase, notify; Create and
//! copy link. The form is cleared only after the create finished; on errors it stays.

use std::path::PathBuf;

use gpui_kit::component::input::{Input, InputEvent, InputState, Textarea, TextareaState};
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::*;
use pnesecrets_core::sdrop::format::{self, MAX_FILES};
use pnesecrets_core::sent::{Draft, DraftFile};
use zeroize::Zeroizing;

use crate::fmt;
use crate::model::{ModelEvent, Preset, model};
use crate::platform::{cmd, mono_font};
use crate::theme::tokens;
use crate::views::widgets::{guard_input, guard_textarea, link_button, switch};

actions!(new_secret, [Create]);

pub fn bind_keys(cx: &mut App) {
    cx.bind_keys([KeyBinding::new(
        "secondary-enter",
        Create,
        Some("NewSecret"),
    )]);
}

pub struct NewSecretForm {
    secret: Entity<TextareaState>,
    label: Entity<InputState>,
    passphrase: Entity<InputState>,
    ttl: u32,
    protect: bool,
    notify: bool,
    files: Vec<DraftFile>,
    error: Option<String>,
    /// The create in flight from this form.
    op: Option<u64>,
    focus: FocusHandle,
    /// A Paste from clipboard request in flight.
    paste_tag: Option<u64>,
    /// The last create needed a Cloudflare Access sign-in.
    sign_in: bool,
    /// Bumped on every clear: a file read that finishes later belongs to an old draft.
    generation: u64,
    _subs: Vec<Subscription>,
}

impl NewSecretForm {
    pub fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        let secret = cx.new(|cx| {
            TextareaState::new(window, cx)
                .placeholder("Password, key, token, config…")
                .context_menu(false)
        });
        let label =
            cx.new(|cx| InputState::new(window, cx).placeholder("e.g. Staging DB password"));
        let passphrase = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("Passphrase")
                .context_menu(false)
        });
        let mut subs = vec![cx.subscribe_in(
            &model(cx),
            window,
            |this, _, e: &ModelEvent, window, cx| match e {
                // Cleared at once (not on the next render): the form may not be on screen.
                ModelEvent::Created { op } if this.op == Some(*op) => {
                    this.op = None;
                    this.clear(window, cx);
                }
                ModelEvent::CreateFailed { op, error, sign_in } if this.op == Some(*op) => {
                    this.op = None;
                    this.sign_in = *sign_in;
                    this.error = Some(format!("{error} Attach the files again if there were any."));
                    cx.notify();
                }
                ModelEvent::ClipboardText { tag, text, .. } if this.paste_tag == Some(*tag) => {
                    this.paste_tag = None;
                    match text {
                        Some(t) if !t.is_empty() => {
                            let t = t.to_string();
                            this.secret.update(cx, |s, cx| s.set_value(t, window, cx));
                        }
                        _ => this.error = Some("The clipboard holds no text.".into()),
                    }
                    cx.notify();
                }
                _ => {}
            },
        )];
        subs.push(
            cx.subscribe_in(&secret, window, |this, _, e: &InputEvent, window, cx| {
                if let InputEvent::PressEnter {
                    secondary: true, ..
                } = e
                {
                    this.create(window, cx);
                }
            }),
        );
        subs.push(cx.subscribe_in(
            &passphrase,
            window,
            |this, _, e: &InputEvent, window, cx| {
                if let InputEvent::PressEnter { .. } = e {
                    this.create(window, cx);
                }
            },
        ));
        subs.push(
            cx.subscribe_in(&label, window, |this, _, e: &InputEvent, window, cx| {
                if let InputEvent::PressEnter {
                    secondary: true, ..
                } = e
                {
                    this.create(window, cx);
                }
            }),
        );
        Self {
            secret,
            label,
            passphrase,
            ttl: 86400,
            protect: false,
            notify: true,
            files: Vec::new(),
            error: None,
            op: None,
            focus: cx.focus_handle(),
            _subs: subs,
            paste_tag: None,
            sign_in: false,
            generation: 0,
        }
    }

    pub fn focus_secret(&self, window: &mut Window, cx: &mut App) {
        self.secret.update(cx, |s, cx| s.focus(window, cx));
    }

    /// "Send again": the same lifetime and passphrase setting, nothing else (SPEC 6, A2).
    pub fn apply_preset(&mut self, p: Preset, window: &mut Window, cx: &mut Context<Self>) {
        self.clear(window, cx);
        self.ttl = p.ttl;
        self.protect = p.passphrase;
        cx.notify();
    }

    fn clear(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        // set_value also drops the undo history: Undo cannot bring the secret back.
        self.secret.update(cx, |s, cx| s.set_value("", window, cx));
        self.label.update(cx, |s, cx| s.set_value("", window, cx));
        self.passphrase
            .update(cx, |s, cx| s.set_value("", window, cx));
        self.files.clear();
        self.generation += 1;
        self.ttl = 86400;
        self.protect = false;
        self.notify = true;
        self.error = None;
        cx.notify();
    }

    /// Reads the files off the UI thread (a slow or hung volume must not stop the app).
    pub fn add_paths(&mut self, paths: &[PathBuf], cx: &mut Context<Self>) {
        let limit = model(cx).read(cx).snap.limit.unwrap_or(format::MAX_BUCKET) as u64;
        let room = MAX_FILES.saturating_sub(self.files.len());
        let paths: Vec<PathBuf> = paths.to_vec();
        let generation = self.generation;
        cx.spawn(async move |this, cx| {
            let read = cx
                .background_executor()
                .spawn(async move { read_files(&paths, room, limit) })
                .await;
            let _ = this.update(cx, |this, cx| {
                // The form was cleared (sent) meanwhile: these files are not for the next one.
                if this.generation != generation {
                    return;
                }
                let (files, error) = read;
                for f in files {
                    if this.files.len() < MAX_FILES {
                        this.files.push(f);
                    }
                }
                if error.is_some() {
                    this.error = error;
                }
                cx.notify();
            });
        })
        .detach();
    }

    fn choose_files(&mut self, cx: &mut Context<Self>) {
        let rx = cx.prompt_for_paths(PathPromptOptions {
            files: true,
            directories: false,
            multiple: true,
            prompt: None,
        });
        cx.spawn(async move |this, cx| {
            let Ok(Ok(Some(paths))) = rx.await else {
                return;
            };
            let _ = this.update(cx, |this, cx| this.add_paths(&paths, cx));
        })
        .detach();
    }

    fn paste(&mut self, _window: &mut Window, cx: &mut Context<Self>) {
        self.paste_tag = Some(model(cx).update(cx, |m, _| m.read_clipboard()));
    }

    fn generate(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let pw = pnesecrets_core::sdrop::password::generate();
        self.secret
            .update(cx, |s, cx| s.set_value(pw.to_string(), window, cx));
        cx.notify();
    }

    fn create(&mut self, _window: &mut Window, cx: &mut Context<Self>) {
        if self.op.is_some() {
            return;
        }
        let text = Zeroizing::new(self.secret.read(cx).value().to_string());
        if text.is_empty() && self.files.is_empty() {
            self.error = Some("Enter a secret or add files.".into());
            cx.notify();
            return;
        }
        let passphrase = if self.protect {
            let p = Zeroizing::new(self.passphrase.read(cx).value().to_string());
            if p.is_empty() {
                self.error = Some("Enter the passphrase or turn the protection off.".into());
                cx.notify();
                return;
            }
            Some(p)
        } else {
            None
        };
        let m = model(cx);
        if !m.read(cx).can_create() {
            self.error = Some(m.read(cx).cannot_create());
            cx.notify();
            return;
        }
        // The files move into the draft: re-attach them by hand if the create fails.
        let draft = Draft {
            text,
            files: std::mem::take(&mut self.files),
            passphrase,
            ttl: self.ttl,
            label: self.label.read(cx).value().to_string(),
            notify: self.notify,
        };
        if let Some(limit) = m.read(cx).snap.limit
            && draft.plaintext_len() + 4 > limit
        {
            self.files = draft.files;
            self.error = Some(format!(
                "The secret is larger than the service limit of {}.",
                fmt::size(limit as u64)
            ));
            cx.notify();
            return;
        }
        self.error = None;
        self.sign_in = false;
        self.op = m.update(cx, |m, cx| m.create(draft, true, cx));
        cx.notify();
    }

    /// The create of this form is gone without an event (Back from the unknown-outcome screen).
    fn sync(&mut self, cx: &mut Context<Self>) {
        if let Some(op) = self.op {
            let m = model(cx);
            let m = m.read(cx);
            if !m.creating(op) && m.create_view(op).is_none() {
                self.op = None;
            }
        }
    }
}

#[cfg(feature = "screenshot")]
impl NewSecretForm {
    /// Screenshot scenes: the mockup's sample (not a real secret) and, for `a2`, create it.
    pub fn demo(&mut self, scene: &str, window: &mut Window, cx: &mut Context<Self>) {
        self.secret.update(cx, |s, cx| {
            s.set_value(
                "DB_HOST=stage-db-2.int\nDB_USER=paynet_app\nDB_PASSWORD=Xq7!vR2m-9LpTz4eW8sN",
                window,
                cx,
            )
        });
        self.label
            .update(cx, |s, cx| s.set_value("Staging DB password", window, cx));
        if scene == "a2" {
            self.create(window, cx);
        }
        window.blur(cx);
        cx.notify();
    }
}

fn read_files(paths: &[PathBuf], room: usize, limit: u64) -> (Vec<DraftFile>, Option<String>) {
    let mut files = Vec::new();
    let mut error = None;
    for p in paths {
        if files.len() >= room {
            error = Some(format!("At most {MAX_FILES} files."));
            break;
        }
        let raw = p
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let size = match std::fs::metadata(p) {
            Ok(m) if m.is_file() => m.len(),
            _ => {
                error = Some("Only files can be attached, not folders.".into());
                continue;
            }
        };
        if size == 0 {
            error = Some("Empty files cannot be sent.".into());
            continue;
        }
        if size > limit {
            error = Some(format!(
                "The file is larger than the service limit of {}.",
                fmt::size(limit)
            ));
            continue;
        }
        match std::fs::read(p) {
            Ok(data) => files.push(DraftFile {
                name: format::sanitize_file_name(&raw),
                data: Zeroizing::new(data),
            }),
            Err(_) => error = Some("The file could not be read.".into()),
        }
    }
    (files, error)
}

impl Focusable for NewSecretForm {
    fn focus_handle(&self, _: &App) -> FocusHandle {
        self.focus.clone()
    }
}

impl Render for NewSecretForm {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        self.sync(cx);
        let t = tokens(cx);
        let limit = model(cx).read(cx).snap.limit;
        let vault_ok = model(cx).read(cx).snap.vault_ok;
        let sending = self.op.is_some();
        let label_text = |s: &'static str| div().font_weight(FontWeight::SEMIBOLD).child(s);

        let secret_box = div()
            .flex()
            .flex_col()
            .gap(px(8.))
            .flex_1()
            .min_h_0()
            .child(
                div()
                    .flex()
                    .justify_between()
                    .items_center()
                    .child(label_text("Secret"))
                    .child(
                        div()
                            .flex()
                            .gap(px(14.))
                            .text_size(px(13.))
                            .child(link_button(&t, "paste", "Paste from clipboard").on_click(
                                cx.listener(|this, _, window, cx| this.paste(window, cx)),
                            ))
                            .child(link_button(&t, "generate", "Generate password").on_click(
                                cx.listener(|this, _, window, cx| this.generate(window, cx)),
                            )),
                    ),
            )
            .child(
                div().flex_1().min_h_0().child(guard_textarea(
                    Textarea::new(&self.secret)
                        .h_full()
                        .bg(t.field)
                        .border_color(t.field_ring)
                        .rounded(px(8.))
                        .font_family(mono_font())
                        .text_size(px(14.))
                        .line_height(px(21.)),
                    &self.secret,
                )),
            );

        let files =
            div()
                .flex()
                .flex_col()
                .gap(px(6.))
                .children(self.files.iter().enumerate().map(|(i, f)| {
                    div()
                        .flex()
                        .items_center()
                        .gap(px(10.))
                        .px(px(12.))
                        .py(px(8.))
                        .rounded(px(8.))
                        .border_1()
                        .border_color(t.field_ring)
                        .child(
                            div()
                                .flex_1()
                                .font_family(mono_font())
                                .text_size(px(13.))
                                .child(f.name.to_string()),
                        )
                        .child(
                            div()
                                .text_size(px(12.))
                                .text_color(t.muted)
                                .child(fmt::size(f.data.len() as u64)),
                        )
                        .child(
                            link_button(&t, ("remove", i), "Remove")
                                .text_size(px(13.))
                                .on_click(cx.listener(move |this, _, _, cx| {
                                    if i < this.files.len() {
                                        this.files.remove(i);
                                    }
                                    cx.notify();
                                })),
                        )
                }));

        let accent = t.accent;
        let drop = div()
            .id("drop")
            .flex()
            .items_center()
            .gap(px(14.))
            .px(px(16.))
            .py(px(14.))
            .rounded(px(8.))
            .border_1()
            .border_color(t.field_ring)
            .bg(t.field)
            .drag_over::<ExternalPaths>(move |s, _, _, _| s.border_color(accent))
            .on_drop(cx.listener(|this, paths: &ExternalPaths, _, cx| {
                this.add_paths(paths.paths(), cx);
            }))
            .child(div().text_color(t.link).text_size(px(20.)).child("↓"))
            .child(
                div()
                    .flex_1()
                    .flex()
                    .flex_wrap()
                    .text_color(t.text2)
                    .child(if cfg!(target_os = "macos") {
                        "Drop files here, on the Dock icon, or\u{a0}"
                    } else {
                        "Drop files here, or\u{a0}"
                    })
                    .child(
                        link_button(&t, "choose", "choose files")
                            .on_click(cx.listener(|this, _, _, cx| this.choose_files(cx))),
                    ),
            )
            .child(div().text_size(px(12.)).text_color(t.muted).child(format!(
                "Up to {MAX_FILES} files, {}",
                limit.map_or("…".to_string(), |n| fmt::size(n as u64))
            )));

        let left = div()
            .flex()
            .flex_col()
            .gap(px(16.))
            .flex_1()
            .min_w_0()
            .min_h_0()
            .child(secret_box)
            .child(files)
            .child(drop);

        let seg = div()
            .flex()
            .gap(px(2.))
            .p(px(3.))
            .rounded(px(8.))
            .bg(t.field)
            .border_1()
            .border_color(t.field_ring)
            .children([3600u32, 86400, 604800].into_iter().map(|ttl| {
                let on = self.ttl == ttl;
                div()
                    .id(("ttl", ttl as usize))
                    .flex_1()
                    .h(px(30.))
                    .flex()
                    .items_center()
                    .justify_center()
                    .rounded(px(6.))
                    .text_size(px(13.))
                    .cursor_pointer()
                    .when(on, |d| {
                        d.bg(t.seg_active)
                            .text_color(t.seg_active_text)
                            .font_weight(FontWeight::SEMIBOLD)
                    })
                    .when(!on, |d| d.text_color(t.text2))
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.ttl = ttl;
                        cx.notify();
                    }))
                    .child(fmt::ttl_long(ttl))
            }));

        let field = |input: Input| {
            input
                .h(px(36.))
                .bg(t.field)
                .border_color(t.field_ring)
                .rounded(px(8.))
        };

        let model_ref = model(cx);
        let m = model_ref.read(cx);
        let blocked = m.history_error.clone().or_else(|| m.origin_error.clone());

        let right = div()
            .w(px(300.))
            .flex_none()
            .flex()
            .flex_col()
            .gap(px(18.))
            .p(px(18.))
            .rounded(px(12.))
            .bg(t.panel)
            .border_1()
            .border_color(t.panel_ring)
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap(px(6.))
                    .child(
                        div()
                            .flex()
                            .gap(px(4.))
                            .child(label_text("Label"))
                            .child(div().text_color(t.muted).child("only for you")),
                    )
                    .child(field(Input::new(&self.label)))
                    .child(
                        div()
                            .text_size(px(12.))
                            .text_color(t.muted)
                            .child("Shown in your history. Not sent with the secret."),
                    ),
            )
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap(px(8.))
                    .child(label_text("If nobody opens it, delete after"))
                    .child(seg),
            )
            .child(
                div()
                    .id("protect")
                    .flex()
                    .items_center()
                    .justify_between()
                    .cursor_pointer()
                    .on_click(cx.listener(|this, _, window, cx| {
                        this.protect = !this.protect;
                        if this.protect {
                            this.passphrase.update(cx, |s, cx| s.focus(window, cx));
                        } else {
                            this.passphrase.update(cx, |s, cx| s.set_value("", window, cx));
                        }
                        cx.notify();
                    }))
                    .child(label_text("Protect with a passphrase"))
                    .child(switch(&t, "protect-switch", self.protect)),
            )
            .when(self.protect, |d| {
                d.child(
                    div()
                        .flex()
                        .flex_col()
                        .gap(px(6.))
                        .mt(px(-8.))
                        .child(guard_input(field(Input::new(&self.passphrase)), &self.passphrase))
                        .child(div().text_size(px(12.)).text_color(t.muted).child(
                            "Shown as you type. Send it through a different channel than the link.",
                        )),
                )
            })
            .child(
                div()
                    .id("notify")
                    .flex()
                    .items_center()
                    .justify_between()
                    .cursor_pointer()
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.notify = !this.notify;
                        cx.notify();
                    }))
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .gap(px(2.))
                            .child(label_text("Notify me when it is read"))
                            .child(
                                div()
                                    .text_size(px(12.))
                                    .text_color(t.muted)
                                    .child("System notification"),
                            ),
                    )
                    .child(switch(&t, "notify-switch", self.notify)),
            )
            .child(
                div()
                    .mt_auto()
                    .flex()
                    .flex_col()
                    .gap(px(8.))
                    .when(!vault_ok, |d| {
                        d.child(div().text_size(px(12.)).text_color(t.waiting).child(
                            "The system keyring is not available: the owner link will not be kept. No revoke or read notification after you leave its page.",
                        ))
                    })
                    .children(self.error.clone().or(blocked).map(|e| {
                        div()
                            .text_size(px(13.))
                            .text_color(t.revoked)
                            .child(e)
                    }))
                    .when(self.sign_in, |d| {
                        d.child(link_button(&t, "sign-in", "Sign in with cloudflared").on_click(
                            cx.listener(|this, _, _, cx| {
                                this.sign_in = false;
                                model(cx).update(cx, |m, cx| m.sign_in(cx));
                            }),
                        ))
                    })
                    .child(
                        div()
                            .id("create")
                            .h(px(44.))
                            .rounded(px(8.))
                            .bg(t.accent)
                            .text_color(t.on_accent)
                            .font_weight(FontWeight::SEMIBOLD)
                            .flex()
                            .items_center()
                            .justify_center()
                            .gap(px(10.))
                            .cursor_pointer()
                            .when(sending, |d| d.opacity(0.7))
                            .hover(|s| s.opacity(0.92))
                            .on_click(cx.listener(|this, _, window, cx| this.create(window, cx)))
                            .child(if sending {
                                "Creating…"
                            } else {
                                "Create and copy link"
                            })
                            .child(
                                div()
                                    .font_weight(FontWeight::NORMAL)
                                    .text_size(px(12.))
                                    .opacity(0.85)
                                    .child(cmd("↵")),
                            ),
                    )
                    .child(
                        div()
                            .text_size(px(12.))
                            .text_color(t.muted)
                            .text_center()
                            .child("The link goes to the clipboard. It clears after 60 s."),
                    ),
            );

        div()
            .key_context("NewSecret")
            .track_focus(&self.focus)
            .on_action(cx.listener(|this, _: &Create, window, cx| this.create(window, cx)))
            .size_full()
            .flex()
            .flex_col()
            .gap(px(20.))
            .px(px(36.))
            .py(px(28.))
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .child(
                        div()
                            .text_size(px(22.))
                            .font_weight(FontWeight::SEMIBOLD)
                            .child("New secret"),
                    )
                    .child(
                        div()
                            .text_size(px(13.))
                            .text_color(t.muted)
                            .child("Encrypted on this computer. The server never sees it."),
                    ),
            )
            .child(
                div()
                    .flex_1()
                    .min_h_0()
                    .flex()
                    .gap(px(24.))
                    .child(left)
                    .child(right),
            )
    }
}
