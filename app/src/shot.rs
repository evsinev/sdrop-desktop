//! Self-screenshot: render the window once through GPUI, save a PNG, quit.
//! Built only with `--features screenshot` (GPUI render_to_image is test-support only).

use std::time::Duration;

use gpui_kit::*;

pub fn schedule(
    window: AnyWindowHandle,
    out: String,
    cx: &mut App,
    prepare: impl FnOnce(&mut Window, &mut App) + 'static,
) {
    cx.spawn(async move |cx| {
        cx.background_executor()
            .timer(Duration::from_millis(500))
            .await;
        let _ = cx.update_window(window, |_, window, cx| prepare(window, cx));
        // Let fonts, the SVG logo and a few frames settle.
        let settle = std::env::var("APP_DELAY_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1500);
        cx.background_executor()
            .timer(Duration::from_millis(settle))
            .await;
        let result = cx.update_window(window, |_, window, _| {
            let scale = window.scale_factor().round().max(1.0) as u32;
            window.render_to_image().map(|img| {
                let (w, h) = (img.width(), img.height());
                (downscale(img.as_raw(), w, h, scale), w / scale, h / scale)
            })
        });
        match result {
            Ok(Ok((rgba, w, h))) => {
                std::fs::write(&out, encode_png(&rgba, w, h)).expect("write png");
                eprintln!("screenshot saved to {out} ({w}x{h})");
            }
            Ok(Err(e)) => eprintln!("render_to_image failed: {e}"),
            Err(e) => eprintln!("window update failed: {e}"),
        }
        cx.update(|cx| cx.quit());
    })
    .detach();
}

/// Box-filter the device-pixel image down to logical pixels (the reference is 1x).
fn downscale(src: &[u8], w: u32, h: u32, k: u32) -> Vec<u8> {
    if k == 1 {
        return src.to_vec();
    }
    let (ow, oh) = (w / k, h / k);
    let mut out = vec![0u8; (ow * oh * 4) as usize];
    for y in 0..oh {
        for x in 0..ow {
            for c in 0..4 {
                let mut sum = 0u32;
                for dy in 0..k {
                    for dx in 0..k {
                        sum += src[(((y * k + dy) * w + x * k + dx) * 4 + c) as usize] as u32;
                    }
                }
                out[((y * ow + x) * 4 + c) as usize] = (sum / (k * k)) as u8;
            }
        }
    }
    out
}

/// Minimal PNG encoder: RGBA8, zlib "stored" blocks (no compression), no dependencies.
fn encode_png(rgba: &[u8], w: u32, h: u32) -> Vec<u8> {
    let mut raw = Vec::with_capacity(((w * 4 + 1) * h) as usize);
    for row in rgba.chunks((w * 4) as usize) {
        raw.push(0); // filter: none
        raw.extend_from_slice(row);
    }
    let mut z = vec![0x78, 0x01];
    let mut blocks = raw.chunks(65535).peekable();
    while let Some(b) = blocks.next() {
        z.push(blocks.peek().is_none() as u8);
        z.extend_from_slice(&(b.len() as u16).to_le_bytes());
        z.extend_from_slice(&(!(b.len() as u16)).to_le_bytes());
        z.extend_from_slice(b);
    }
    z.extend_from_slice(&adler32(&raw).to_be_bytes());

    let mut ihdr = Vec::new();
    ihdr.extend_from_slice(&w.to_be_bytes());
    ihdr.extend_from_slice(&h.to_be_bytes());
    ihdr.extend_from_slice(&[8, 6, 0, 0, 0]);

    let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
    for (kind, data) in [(b"IHDR", &ihdr), (b"IDAT", &z), (b"IEND", &Vec::new())] {
        png.extend_from_slice(&(data.len() as u32).to_be_bytes());
        let start = png.len();
        png.extend_from_slice(kind);
        png.extend_from_slice(data);
        let crc = crc32(&png[start..]);
        png.extend_from_slice(&crc.to_be_bytes());
    }
    png
}

fn adler32(data: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for &x in data {
        a = (a + x as u32) % 65521;
        b = (b + a) % 65521;
    }
    (b << 16) | a
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &x in data {
        crc ^= x as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}
