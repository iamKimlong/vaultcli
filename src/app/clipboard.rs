use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use zeroize::Zeroize;

pub static CLIPBOARD_COPY_ID: AtomicU64 = AtomicU64::new(0);

pub fn copy_with_timeout(text: &str, timeout: Duration) {
    let copy_id = CLIPBOARD_COPY_ID.fetch_add(1, Ordering::SeqCst) + 1;
    let mut text = text.to_string();

    std::thread::spawn(move || copy_thread(&mut text, timeout, copy_id));
}

#[cfg(target_os = "linux")]
fn copy_thread(text: &mut String, timeout: Duration, copy_id: u64) {
    let is_wayland = std::env::var("WAYLAND_DISPLAY").is_ok();

    let ok = if is_wayland { set_wayland(text) } else { set_x11(text) };
    if !ok {
        return;
    }

    std::thread::sleep(timeout);
    text.zeroize();

    if CLIPBOARD_COPY_ID.load(Ordering::SeqCst) != copy_id {
        return;
    }

    clear_clipboard(is_wayland);
}

#[cfg(target_os = "linux")]
fn set_wayland(text: &str) -> bool {
    use std::io::Write;
    use std::process::{Command, Stdio};

    Command::new("wl-copy")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .ok()
        .and_then(|mut c| c.stdin.take()?.write_all(text.as_bytes()).ok())
        .is_some()
}

#[cfg(target_os = "linux")]
fn set_x11(text: &str) -> bool {
    use std::io::Write;
    use std::process::{Command, Stdio};

    Command::new("xclip")
        .args(["-selection", "clipboard"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .ok()
        .and_then(|mut c| c.stdin.take()?.write_all(text.as_bytes()).ok())
        .is_some()
}

#[cfg(target_os = "linux")]
fn clear_clipboard(is_wayland: bool) {
    use std::process::{Command, Stdio};

    if is_wayland {
        let _ = Command::new("wl-copy").arg("--clear").output();
    } else {
        let _ = Command::new("xclip")
            .args(["-selection", "clipboard"])
            .stdin(Stdio::piped())
            .output();
    }
}

#[cfg(not(target_os = "linux"))]
fn copy_thread(text: &mut String, timeout: Duration, copy_id: u64) {
    let Ok(mut clipboard) = arboard::Clipboard::new() else { return };

    if clipboard.set_text(&*text).is_err() {
        return;
    }

    std::thread::sleep(timeout);
    text.zeroize();

    if CLIPBOARD_COPY_ID.load(Ordering::SeqCst) == copy_id {
        let _ = clipboard.clear();
    }
}
