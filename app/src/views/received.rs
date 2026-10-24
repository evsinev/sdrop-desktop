//! D Received secret (SPEC 8): a pasted link, Reveal (one consume), the passphrase before and
//! after, then the text (not selectable: copied only by the button, cleared in 30 s) and files
//! (saved, never opened). Closing asks while the secret is here and not saved to files.

use gpui_kit::component::input::{Input, InputEvent, InputState};
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::*;
use pnesecrets_core::clipboard::CopyKind;
use pnesecrets_core::receive::{Gone, OnClose, Phase};
use pnesecrets_core::save::{save_private, suggested_name};
use pnesecrets_core::sdrop::ops::NOT_FOUND;
use zeroize::Zeroizing;

use crate::fmt;
use crate::model::{ModelEvent, model, now};
use crate::platform::mono_font;
use crate::theme::tokens;
use crate::views::widgets::{guard_input, link_button, outline_button, primary_button};

pub struct ReceivedWindow {
    /// None until a link was entered.
    id: Option<u64>,
    link: Entity<InputState>,
    passphrase: Entity<InputState>,
    error: Option<String>,
    saved_note: Option<String>,
    _subs: Vec<Subscription>,
}

impl ReceivedWindow {
    pub fn new(id: Option<u64>, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let link = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("https://…/s/…#…")
                .masked(false)
                .context_menu(false)
        });
        let passphrase = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("Passphrase")
                .context_menu(false)
        });
        let subs = vec![
            cx.observe(&model(cx), |_, _, cx| cx.notify()),
            cx.subscribe_in(&link, window, |this, _, e: &InputEvent, window, cx| {
                if let InputEvent::PressEnter { .. } = e {
                    this.open(window, cx);
                }
            }),
            cx.subscribe_in(
                &passphrase,
                window,
                |this, _, e: &InputEvent, window, cx| {
                    if let InputEvent::PressEnter { .. } = e {
                        this.primary(window, cx);
                    }
                },
            ),
            cx.subscribe(&model(cx), |_, _, e: &ModelEvent, cx| {
                if let ModelEvent::Receipt(_) = e {
                    cx.notify();
                }
            }),
        ];
        if id.is_none() {
            link.update(cx, |s, cx| s.focus(window, cx));
        } else {
            passphrase.update(cx, |s, cx| s.focus(window, cx));
        }
        Self {
            id,
            link,
            passphrase,
            error: None,
            saved_note: None,
            _subs: subs,
        }
    }

    fn open(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.id.is_some() {
            return;
        }
        let url = Zeroizing::new(self.link.read(cx).value().to_string());
        let r = model(cx).update(cx, |m, _| m.open_link(&url));
        // Never keep the link in the field: it carries the key.
        self.link.update(cx, |s, cx| s.set_value("", window, cx));
        match r {
            Ok(id) => {
                self.id = Some(id);
                self.error = None;
                crate::set_received_window(id, window.window_handle(), cx);
                self.passphrase.update(cx, |s, cx| s.focus(window, cx));
            }
            Err(_) => {
                self.error = Some(
                    "This is not a link to a secret of this service, or it is incomplete. Nothing was opened."
                        .into(),
                );
            }
        }
        cx.notify();
    }

    fn take_passphrase(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Zeroizing<String> {
        let p = Zeroizing::new(self.passphrase.read(cx).value().to_string());
        self.passphrase
            .update(cx, |s, cx| s.set_value("", window, cx));
        p
    }

    /// Enter / the main button: Reveal, or try the passphrase on the kept envelope.
    fn primary(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(id) = self.id else {
            self.open(window, cx);
            return;
        };
        let phase = model(cx)
            .read(cx)
            .receipts
            .get(&id)
            .and_then(|s| s.receipt.as_ref())
            .map(|r| r.phase().clone());
        match phase {
            Some(Phase::Ready) => {
                let p = self.take_passphrase(window, cx);
                let p = (!p.is_empty()).then_some(p);
                model(cx).update(cx, |m, cx| m.reveal(id, p, cx));
            }
            Some(Phase::NeedPassphrase | Phase::WrongPassphrase) => {
                let p = self.take_passphrase(window, cx);
                if !p.is_empty() {
                    model(cx).update(cx, |m, cx| m.try_passphrase(id, p, cx));
                }
            }
            _ => {}
        }
    }

    fn save_text(&mut self, cx: &mut Context<Self>) {
        self.save(None, "secret.txt".into(), cx);
    }

    fn save_file(&mut self, index: usize, cx: &mut Context<Self>) {
        let Some(id) = self.id else { return };
        let name = model(cx)
            .read(cx)
            .receipts
            .get(&id)
            .and_then(|s| s.receipt.as_ref())
            .and_then(|r| r.received())
            .and_then(|r| r.files.get(index))
            .map(|f| suggested_name(&f.name))
            .unwrap_or_else(|| "file".into());
        self.save(Some(index), name, cx);
    }

    /// The save dialog, then the write off the UI thread (a slow volume must not freeze the
    /// window); on failure the secret stays here and another place can be chosen.
    fn save(&mut self, file: Option<usize>, name: String, cx: &mut Context<Self>) {
        let Some(id) = self.id else { return };
        let rx = cx.prompt_for_new_path(&home(), Some(&name));
        cx.spawn(async move |this, cx| {
            let Ok(Ok(Some(path))) = rx.await else { return };
            let bytes = this.update(cx, |_, cx| {
                let m = model(cx);
                let m = m.read(cx);
                let r = m.receipts.get(&id)?.receipt.as_ref()?.received()?;
                Some(match file {
                    None => Zeroizing::new(r.text.as_bytes().to_vec()),
                    Some(i) => r.files.get(i)?.data.clone(),
                })
            });
            let Ok(Some(bytes)) = bytes else { return };
            let ok = cx
                .background_executor()
                .spawn(async move { save_private(&path, &bytes).is_ok() })
                .await;
            let _ = this.update(cx, |this, cx| {
                if ok {
                    model(cx).update(cx, |m, cx| {
                        if let Some(r) = m.receipts.get_mut(&id).and_then(|s| s.receipt.as_mut()) {
                            match file {
                                None => r.mark_text_saved(),
                                Some(i) => r.mark_file_saved(i),
                            }
                        }
                        m.sync_hold();
                        cx.notify();
                    });
                    this.saved_note = Some(if file.is_none() {
                        "Text saved.".into()
                    } else {
                        "File saved.".into()
                    });
                } else {
                    this.saved_note =
                        Some("Not saved: choose another place. The secret is still here.".into());
                }
                cx.notify();
            });
        })
        .detach();
    }

    fn copy_text(&mut self, cx: &mut Context<Self>) {
        let Some(id) = self.id else { return };
        let m = model(cx);
        let text = m.read(cx).receipts.get(&id).and_then(|s| {
            s.receipt
                .as_ref()
                .and_then(|r| r.received())
                .map(|r| r.text.clone())
        });
        if let Some(text) = text {
            m.update(cx, |m, _| m.copy(text, CopyKind::Secret));
        }
    }

    /// Window close (SPEC 8): drop, keep in the background, or ask with Cancel as the default.
    pub fn should_close(&mut self, window: &mut Window, cx: &mut Context<Self>) -> bool {
        let Some(id) = self.id else {
            return true;
        };
        let m = model(cx);
        match m.read(cx).receipt_on_close(id) {
            OnClose::Drop => {
                m.update(cx, |m, cx| m.destroy_receipt(id, cx));
                true
            }
            OnClose::KeepInBackground => {
                crate::forget_received_window(id, cx);
                true
            }
            OnClose::Confirm => {
                let rx = window.prompt(
                    PromptLevel::Warning,
                    "Destroy this secret?",
                    Some("It is already deleted from the server and cannot be opened again. Copying does not save it."),
                    &["Cancel", "Destroy"],
                    cx,
                );
                cx.spawn_in(window, async move |_, cx| {
                    if rx.await == Ok(1) {
                        let _ = cx.update(|window, cx| {
                            model(cx).update(cx, |m, cx| m.destroy_receipt(id, cx));
                            window.remove_window();
                        });
                    }
                })
                .detach();
                false
            }
        }
    }
}

fn home() -> std::path::PathBuf {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("."))
}

impl Render for ReceivedWindow {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let t = tokens(cx);
        let m = model(cx);
        let mref = m.read(cx);
        let host = mref.host();
        let slot = self.id.and_then(|id| mref.receipts.get(&id));
        let busy = slot.is_some_and(|s| s.receipt.is_none());
        let receipt = slot.and_then(|s| s.receipt.as_ref());
        let phase = receipt.map(|r| r.phase().clone());
        let hint = receipt.is_some_and(|r| r.passphrase_hint());
        let error = receipt.and_then(|r| r.error()).map(|e| e.to_string());
        let sign_in = receipt.and_then(|r| r.error())
            == Some(&pnesecrets_core::service::ApiError::SignInRequired);
        let secret_held = matches!(
            phase,
            Some(Phase::Revealed | Phase::NeedPassphrase | Phase::WrongPassphrase)
        );
        let copy_left = (mref.clip_holds == Some(CopyKind::Secret))
            .then(|| mref.clip_deadline.map(|d| ((d - now()) / 1000).max(0)))
            .flatten();

        let banner = secret_held.then(|| {
            div()
                .flex()
                .items_center()
                .gap(px(10.))
                .px(px(24.))
                .py(px(10.))
                .bg(t.warn_bg)
                .text_color(t.warn_fg)
                .text_size(px(13.))
                .child("⚠")
                .child("Already deleted from the server. Closing this window removes it for good.")
        });

        let field = |input: Input| {
            input
                .h(px(38.))
                .bg(t.field)
                .border_color(t.field_ring)
                .rounded(px(8.))
        };
        let heading = |s: &str| {
            div()
                .text_size(px(20.))
                .font_weight(FontWeight::SEMIBOLD)
                .child(s.to_string())
        };
        let para = |s: String| div().text_color(t.text2).child(s);

        let body: AnyElement = match (&phase, busy) {
            (_, true) => div()
                .flex()
                .flex_col()
                .gap(px(12.))
                .child(heading("Opening…"))
                .child(para("The secret is being fetched and decrypted.".into()))
                .into_any(),
            (None, false) => div()
                .flex()
                .flex_col()
                .gap(px(12.))
                .child(heading("Open a link"))
                .child(para(
                    "Paste the link you received. Nothing is requested until you press Reveal."
                        .into(),
                ))
                .child(guard_input(field(Input::new(&self.link).font_family(mono_font())), &self.link))
                .children(self.error.clone().map(|e| div().text_color(t.revoked).child(e)))
                .child(
                    div().flex().child(
                        primary_button(&t, "open", "Continue")
                            .on_click(cx.listener(|this, _, window, cx| this.open(window, cx))),
                    ),
                )
                .into_any(),
            (Some(Phase::Ready), _) => div()
                .flex()
                .flex_col()
                .gap(px(12.))
                .child(heading("Reveal the secret?"))
                .child(para(format!(
                    "It will be destroyed as soon as you reveal it: the link opens once. From {host}."
                )))
                .when(hint, |d| {
                    d.child(div().font_weight(FontWeight::SEMIBOLD).child("Passphrase"))
                        .child(guard_input(field(Input::new(&self.passphrase)), &self.passphrase))
                })
                .children(error.map(|e| div().text_color(t.revoked).child(e)))
                .when(sign_in, |d| {
                    d.child(link_button(&t, "sign-in", "Sign in with cloudflared").on_click(
                        |_, _, cx| model(cx).update(cx, |m, cx| m.sign_in(cx)),
                    ))
                })
                .child(
                    div().flex().child(
                        primary_button(&t, "reveal", "Reveal secret")
                            .on_click(cx.listener(|this, _, window, cx| this.primary(window, cx))),
                    ),
                )
                .into_any(),
            (Some(p @ (Phase::NeedPassphrase | Phase::WrongPassphrase)), _) => div()
                .flex()
                .flex_col()
                .gap(px(12.))
                .child(heading("Enter the passphrase"))
                .child(para(if *p == Phase::WrongPassphrase {
                    "That passphrase did not open it. Try again: it is kept here, not fetched again."
                        .into()
                } else {
                    "The sender protected it with a passphrase, sent to you another way.".into()
                }))
                .child(guard_input(field(Input::new(&self.passphrase)), &self.passphrase))
                .child(
                    div().flex().child(
                        primary_button(&t, "decrypt", "Decrypt")
                            .on_click(cx.listener(|this, _, window, cx| this.primary(window, cx))),
                    ),
                )
                .into_any(),
            (Some(Phase::Revealed), _) => {
                let r = receipt.and_then(|r| r.received());
                let opened = receipt.and_then(|r| r.opened_at()).map(fmt::clock).unwrap_or_default();
                let text = r.map(|r| r.text.to_string()).unwrap_or_default();
                let files: Vec<(String, usize, bool)> = r
                    .map(|r| {
                        r.files
                            .iter()
                            .map(|f| (f.name.to_string(), f.data.len(), f.saved))
                            .collect()
                    })
                    .unwrap_or_default();
                let has_text = !text.is_empty();
                div()
                    .flex_1()
                    .min_h_0()
                    .flex()
                    .flex_col()
                    .gap(px(18.))
                    .child(
                        div()
                            .flex()
                            .items_baseline()
                            .justify_between()
                            .child(heading("Your secret"))
                            .child(
                                div()
                                    .text_size(px(12.))
                                    .text_color(t.muted)
                                    .child(format!("Opened from {host} link · {opened}")),
                            ),
                    )
                    .when(has_text, |d| {
                        d.child(
                            div()
                                .flex_1()
                                .min_h(px(120.))
                                .flex()
                                .flex_col()
                                .rounded(px(8.))
                                .bg(t.field)
                                .border_1()
                                .border_color(t.field_ring)
                                .child(
                                    div()
                                        .id("secret-text")
                                        .flex_1()
                                        .min_h_0()
                                        .overflow_y_scroll()
                                        .p(px(14.))
                                        .font_family(mono_font())
                                        .text_size(px(14.))
                                        .line_height(px(21.))
                                        .children(text.lines().map(|l| div().child(l.to_string()))),
                                )
                                .child(
                                    div()
                                        .flex()
                                        .justify_end()
                                        .gap(px(8.))
                                        .p(px(10.))
                                        .border_t_1()
                                        .border_color(t.panel_ring)
                                        .child(
                                            outline_button(&t, "save-text", "Save to file…").on_click(
                                                cx.listener(|this, _, _, cx| this.save_text(cx)),
                                            ),
                                        )
                                        .child(
                                            primary_button(
                                                &t,
                                                "copy-text",
                                                match copy_left {
                                                    Some(s) => format!("Copied · clears in {s} s"),
                                                    None => "Copy · clears in 30 s".into(),
                                                },
                                            )
                                            .on_click(cx.listener(|this, _, _, cx| this.copy_text(cx))),
                                        ),
                                ),
                        )
                    })
                    .when(!files.is_empty(), |d| {
                        d.child(
                            div()
                                .flex()
                                .flex_col()
                                .gap(px(8.))
                                .child(div().font_weight(FontWeight::SEMIBOLD).child("Files"))
                                .children(files.into_iter().enumerate().map(|(i, (name, size, saved))| {
                                    div()
                                        .flex()
                                        .items_center()
                                        .gap(px(12.))
                                        .px(px(12.))
                                        .py(px(10.))
                                        .rounded(px(8.))
                                        .border_1()
                                        .border_color(t.panel_ring)
                                        .child(
                                            div()
                                                .flex_1()
                                                .font_family(mono_font())
                                                .text_size(px(13.))
                                                .child(name),
                                        )
                                        .child(
                                            div()
                                                .text_size(px(12.))
                                                .text_color(t.muted)
                                                .child(fmt::size(size as u64)),
                                        )
                                        .child(
                                            link_button(&t, ("save-file", i), if saved { "Saved ✓" } else { "Save…" })
                                                .text_size(px(13.))
                                                .on_click(cx.listener(move |this, _, _, cx| {
                                                    this.save_file(i, cx)
                                                })),
                                        )
                                }))
                                .child(
                                    div()
                                        .text_size(px(12.))
                                        .text_color(t.muted)
                                        .child("Files are saved as is and never opened by the app."),
                                ),
                        )
                    })
                    .children(self.saved_note.clone().map(|n| {
                        div().text_size(px(13.)).text_color(t.text2).child(n)
                    }))
                    .into_any()
            }
            (Some(Phase::Gone(Gone::NotFound)), _) => div()
                .flex()
                .flex_col()
                .gap(px(12.))
                .child(heading("Not found"))
                .child(para(NOT_FOUND.replace("secret not found", "The secret was not found")))
                .into_any(),
            (Some(Phase::Gone(Gone::Damaged)), _) => div()
                .flex()
                .flex_col()
                .gap(px(12.))
                .child(heading("The secret is damaged"))
                .child(para(
                    "It cannot be shown: the link is wrong or the secret was changed. Ask the sender to send it again."
                        .into(),
                ))
                .into_any(),
            (Some(Phase::Unknown), _) => div()
                .flex()
                .flex_col()
                .gap(px(12.))
                .child(heading("The result is unknown"))
                .child(para(
                    "The connection broke while fetching. The secret may already be destroyed on the server. You can try once more; if it is not found, ask the sender to send it again."
                        .into(),
                ))
                .child(div().flex().child(outline_button(&t, "retry", "Try again").on_click(
                    cx.listener(|this, _, _, cx| {
                        if let Some(id) = this.id {
                            model(cx).update(cx, |m, cx| m.retry_unknown(id, cx));
                        }
                    }),
                )))
                .into_any(),
            (Some(Phase::Consuming | Phase::Destroyed), _) => div().child(heading("…")).into_any(),
        };

        div()
            .size_full()
            .flex()
            .flex_col()
            .bg(t.window)
            .text_color(t.text)
            .text_size(px(14.))
            .children(banner)
            .child(
                div()
                    .flex_1()
                    .min_h_0()
                    .flex()
                    .flex_col()
                    .p(px(24.))
                    .child(body),
            )
    }
}
