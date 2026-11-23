//! Keeps the agent from sitting in the tray with a window that never opened.
//!
//! Cuau's laptop, 22 Nov 2026: the agent started at the first sign-in after a
//! Windows Update restart, WebView2 failed to start, and the Tauri runtime only
//! logged it. The "main" label stayed registered for a window the runtime never
//! stored, so "Open Compliance Agent", the Start menu and a second launch all
//! did nothing, and the window's updater never ran. The process sat tray-only
//! for 29 hours.
//!
//! The rule now does not depend on why WebView2 failed: the page tells the
//! process it loaded (`window_ready`). If that does not happen in time, a new
//! window is built (twice, spaced out). If none loads, the person is told once,
//! the tray says so, the background checks and reports go on, and on Windows the
//! process looks for an update itself, so a fix can always arrive.

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Mutex;
use std::time::Duration;
use tauri::{AppHandle, Manager, WebviewUrl, WebviewWindowBuilder};

pub const TRAY_ID: &str = "main";
const TRAY_TIP: &str = "Compliance Agent";
const TRAY_TIP_BROKEN: &str = "Compliance Agent: the window couldn't open. It still checks this computer. Restart your computer.";

/// How long a page has to say it loaded. A cold WebView2 start at sign-in can
/// take a while, so this is generous.
fn ready_wait() -> Duration {
    if fast_for_tests() {
        Duration::from_secs(8)
    } else {
        Duration::from_secs(30)
    }
}

/// The pauses before each new window.
fn retry_waits() -> [Duration; 2] {
    if fast_for_tests() {
        [Duration::from_secs(1), Duration::from_secs(2)]
    } else {
        [Duration::from_secs(20), Duration::from_secs(120)]
    }
}

/// Development builds only: shorter waits and ignoring the first ready
/// signals, so CI can drive both recovery paths in a few seconds. An installed
/// build never reads these.
fn fast_for_tests() -> bool {
    cfg!(debug_assertions) && std::env::var_os("CA_TEST_FAST_WINDOW").is_some()
}

fn ignored_ready_signals() -> u32 {
    if !cfg!(debug_assertions) {
        return 0;
    }
    std::env::var("CA_TEST_IGNORE_READY")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

pub struct WindowHealth {
    /// The label of the window in use: "main", then "main-2", "main-3".
    label: Mutex<String>,
    ready: AtomicBool,
    /// The person asked to see the window before it was ready.
    wants_show: AtomicBool,
    /// Recovery gave up and the person was told.
    failed: AtomicBool,
    /// A recovery is running.
    recovering: AtomicBool,
    generation: AtomicU32,
    ready_signals: AtomicU32,
}

impl WindowHealth {
    pub fn new(show_at_start: bool) -> Self {
        Self {
            label: Mutex::new("main".into()),
            ready: AtomicBool::new(false),
            wants_show: AtomicBool::new(show_at_start),
            failed: AtomicBool::new(false),
            recovering: AtomicBool::new(false),
            generation: AtomicU32::new(1),
            ready_signals: AtomicU32::new(0),
        }
    }
}

fn health(app: &AppHandle) -> tauri::State<'_, WindowHealth> {
    app.state::<WindowHealth>()
}

pub fn current_label(app: &AppHandle) -> String {
    health(app)
        .label
        .lock()
        .map(|l| l.clone())
        .unwrap_or_else(|_| "main".into())
}

pub fn is_failed(app: &AppHandle) -> bool {
    health(app).failed.load(Ordering::SeqCst)
}

/// The page loaded and can talk to the process.
pub fn mark_ready(app: &AppHandle, label: &str) {
    let h = health(app);
    let seen = h.ready_signals.fetch_add(1, Ordering::SeqCst) + 1;
    if seen <= ignored_ready_signals() {
        log::info!("window {label}: ready signal {seen} ignored for a test");
        return;
    }
    if label != current_label(app) {
        return;
    }
    let was_failed = h.failed.swap(false, Ordering::SeqCst);
    h.ready.store(true, Ordering::SeqCst);
    log::info!("window {label} ready");
    if was_failed {
        log::warn!("window {label} recovered after recovery had given up");
        set_tray_tip(app, TRAY_TIP);
    }
    if h.wants_show.swap(false, Ordering::SeqCst) {
        show(app);
    }
}

/// "Open Compliance Agent", the Start menu, a second launch.
pub fn request_show(app: &AppHandle) {
    let h = health(app);
    if h.ready.load(Ordering::SeqCst) {
        show(app);
        return;
    }
    // Not loaded yet: show it the moment it is. If recovery already gave up,
    // the person just asked again, so try once more now.
    h.wants_show.store(true, Ordering::SeqCst);
    if h.failed.load(Ordering::SeqCst) {
        start_recovery(app, true);
    }
}

fn show(app: &AppHandle) {
    if let Some(window) = app.get_webview_window(&current_label(app)) {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

/// Started once from setup: waits for the first page, recovers if it never
/// says it loaded.
pub fn watch(app: &AppHandle) {
    let app = app.clone();
    std::thread::spawn(move || {
        std::thread::sleep(ready_wait());
        if !health(&app).ready.load(Ordering::SeqCst) {
            log::error!(
                "window main did not load within {}s; WebView2 or the page failed to start",
                ready_wait().as_secs()
            );
            start_recovery(&app, false);
        }
    });
}

fn start_recovery(app: &AppHandle, immediate: bool) {
    let h = health(app);
    if h.recovering.swap(true, Ordering::SeqCst) {
        return;
    }
    let app = app.clone();
    std::thread::spawn(move || {
        let waits = retry_waits();
        let tries: Vec<Duration> = if immediate {
            vec![Duration::ZERO]
        } else {
            waits.to_vec()
        };
        for (i, wait) in tries.iter().enumerate() {
            std::thread::sleep(*wait);
            if health(&app).ready.load(Ordering::SeqCst) {
                break;
            }
            let generation = health(&app).generation.fetch_add(1, Ordering::SeqCst) + 1;
            let label = format!("main-{generation}");
            log::warn!(
                "building a new window {label} (try {} of {})",
                i + 1,
                tries.len()
            );
            match build_window(&app, &label) {
                Ok(()) => {
                    if let Ok(mut current) = health(&app).label.lock() {
                        *current = label.clone();
                    }
                }
                Err(error) => log::error!("window {label} could not be built: {error}"),
            }
            std::thread::sleep(ready_wait());
            if health(&app).ready.load(Ordering::SeqCst) {
                log::warn!("window {label} recovered");
                break;
            }
            log::error!(
                "window {label} did not load within {}s",
                ready_wait().as_secs()
            );
        }
        let h = health(&app);
        if !h.ready.load(Ordering::SeqCst) {
            give_up(&app);
        }
        h.recovering.store(false, Ordering::SeqCst);
    });
}

fn build_window(app: &AppHandle, label: &str) -> Result<(), String> {
    WebviewWindowBuilder::new(app, label, WebviewUrl::App("index.html".into()))
        .title("Compliance Agent")
        .inner_size(1020.0, 760.0)
        .min_inner_size(820.0, 700.0)
        .resizable(true)
        .visible(false)
        .build()
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// No window loaded: say so, keep working, and look for a fix.
fn give_up(app: &AppHandle) {
    let first_time = !health(app).failed.swap(true, Ordering::SeqCst);
    log::error!("no window could be opened; telling the person, checks and reports go on");
    set_tray_tip(app, TRAY_TIP_BROKEN);
    if first_time {
        crate::notify_window_failed(app);
    }
    crate::update_without_window(app);
}

fn set_tray_tip(app: &AppHandle, tip: &str) {
    if let Some(tray) = app.tray_by_id(TRAY_ID) {
        let _ = tray.set_tooltip(Some(tip));
    }
}
