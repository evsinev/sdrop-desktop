# Payneteasy Secrets — desktop

Desktop client for Payneteasy Secrets: one-time links for passwords, keys and files, encrypted on
your computer. The same service and format as the web app and the command line client
[`sdrop`](https://github.com/payneteasy/sdrop): links made here open there, and the other way
round. Built with Rust and [GPUI](https://www.gpui.rs) for macOS, Windows and Linux.

- **New secret**: text and up to 20 files, a local label, lifetime 1 hour / 24 hours / 7 days, an
  optional passphrase, a read notification. *Create and copy link* encrypts here, uploads the
  envelope and copies the recipient link.
- **Sent secrets**: a history on this computer with the status of each link (waiting, read,
  revoked, expired), checked in the background; revoke; a system notification when it is read.
- **Quick drop**: a global shortcut (⌘⇧S / Ctrl+Shift+S) opens a small panel over everything,
  takes text from the clipboard and clears it; Enter creates and copies the link.
- **Open a link**: File → Open link…; nothing is requested until *Reveal*; the secret is shown
  once, copied or saved to a file only you can read.

## Security model

- Encryption, key handling and the link format come from the `sdrop` crate (see its
  `FORMAT.md` and `CLIENTS.md`). The key travels only in the `#fragment` of the link.
- The owner links (status, revoke) and the recipient links are kept in the OS secret store:
  macOS Keychain, Windows Credential Manager, Linux Secret Service. The history file in the app
  data folder holds only labels, times, statuses and file names, never a secret, a link or a token.
- Copies to the clipboard are marked concealed where the OS supports it and cleared after 60 s
  (links) or 30 s (revealed secrets), only if the clipboard still holds our value.
- Nothing is logged; a crash reports only where it happened.
- Limit: copies of text inside the UI framework's own buffers are freed without being overwritten.

## Install

Download from the [latest release](../../releases/latest) and check the files with `SHA256SUMS`
(`gh attestation verify <file> --repo <owner>/<repo>` checks they were built by this repository).

| Platform | File |
|---|---|
| macOS Apple Silicon | `Payneteasy-Secrets-macos-arm64.dmg` |
| macOS Intel | `Payneteasy-Secrets-macos-x86_64.dmg` |
| Windows x86_64 | `Payneteasy-Secrets-windows-x86_64.zip` |
| Linux x86_64 | `pnesecrets-linux-x86_64.deb`, `pnesecrets-linux-x86_64.tar.gz` |

The macOS builds are not notarized yet: right-click the app → Open the first time, or run
`xattr -d com.apple.quarantine "/Applications/Payneteasy Secrets.app"`.

On Wayland there are no global shortcuts: bind a system shortcut to `pnesecrets --quick-drop`.

## Build

```sh
SDROP_DEFAULT_ORIGIN=https://secrets.example.com cargo build --release -p pnesecrets
```

`SDROP_ORIGIN` overrides the built-in service at run time. Linux needs the development packages
of xkbcommon, wayland, vulkan, xcb, fontconfig, freetype and dbus.

## Develop

```sh
cargo test -p pnesecrets-core --features test-loopback
cargo run -p pnesecrets-core --features test-loopback --example dev_server     # 127.0.0.1:8788
SDROP_ORIGIN=http://127.0.0.1:8788 PNESECRETS_DATA_DIR=/tmp/pnesecrets \
  PNESECRETS_VAULT_SERVICE=com.payneteasy.secrets.dev \
  cargo run -p pnesecrets --features test-loopback
```

The `test-loopback` feature exists for tests and local runs only: it allows `http://127.0.0.1`
(the in-memory dev server). Release builds are made without it and refuse `http://`.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
