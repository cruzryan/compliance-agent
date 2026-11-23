#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::process::{Command, Output};
#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;
use std::sync::Mutex;
use std::time::{Duration, SystemTime};
use tauri::{
    menu::{Menu, MenuItem},
    tray::TrayIconBuilder,
    AppHandle, Emitter, Manager,
};

mod agent_log;
mod window_health;

// The Go collector communicates through captured stdout/stderr. Its short
// checks must never create a visible console window on Windows.
#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// How often the resident app asks the collector for one scheduler tick. The
/// collector itself decides whether a full report or a heartbeat is due.
const BACKGROUND_EVERY: Duration = Duration::from_secs(60 * 60);
/// Granularity of the background loop. Also used to notice the computer waking.
const BACKGROUND_POLL: Duration = Duration::from_secs(30);
/// A loop iteration that took this much wall-clock time means the computer slept.
const WAKE_GAP: Duration = Duration::from_secs(120);
/// After a wake, give the network a moment before the catch-up tick.
const AFTER_WAKE_DELAY: Duration = Duration::from_secs(45);
/// How often the agent asks for the company's compliance dates. The collector
/// tells the person once about a new task or a task that just became late.
const DUE_EVERY: Duration = Duration::from_secs(15 * 60);
/// The first dates check after launch (and so after sign-in).
const FIRST_DUE_AFTER: Duration = Duration::from_secs(20);
const MAX_ERROR_CHARS: usize = 300;
/// While no window could be opened, the process looks for an update itself
/// this often (the window's own updater cannot run).
const UPDATE_WITHOUT_WINDOW_EVERY: Duration = Duration::from_secs(6 * 60 * 60);

/// The ONLY collector invocations this app can make. Every argument is fixed
/// here; no UI value ever becomes an argument or a shell command.
#[derive(Clone, Copy)]
enum Collector {
    Status,
    Report,
    RunOnce,
    Last,
    Diagnose,
    Connection,
    Pair,
    Disconnect,
    Due,
    DueCached,
    NotifySettings,
    NotifyOn,
    NotifyOff,
    NotifyUpdate,
    NotifyWindowFailed,
    WebFilterStatus,
    WebFilterPlan,
    WebFilterOn,
    WebFilterOff,
}

impl Collector {
    fn args(self) -> &'static [&'static str] {
        match self {
            Collector::Status => &["status"],
            Collector::Report => &["report"],
            Collector::RunOnce => &["run", "--once"],
            Collector::Last => &["last"],
            Collector::Diagnose => &["diagnose"],
            Collector::Connection => &["connection"],
            Collector::Pair => &["pair"],
            Collector::Disconnect => &["disconnect"],
            Collector::Due => &["due"],
            Collector::DueCached => &["due", "--cached"],
            Collector::NotifySettings => &["notify-settings"],
            Collector::NotifyOn => &["notify-settings", "on"],
            Collector::NotifyOff => &["notify-settings", "off"],
            Collector::NotifyUpdate => &["notify-update"],
            Collector::NotifyWindowFailed => &["notify-window-failed"],
            Collector::WebFilterStatus => &["webfilter", "status"],
            Collector::WebFilterPlan => &["webfilter", "plan"],
            Collector::WebFilterOn => &["webfilter", "on"],
            Collector::WebFilterOff => &["webfilter", "off"],
        }
    }
}

/// Serialises collector runs that collect or change state (manual check,
/// background tick, pair, disconnect). The collector also holds its own lock
/// file; this keeps the app from racing itself and surfacing a lock error.
struct CollectorGate(Mutex<()>);

#[cfg(target_os = "windows")]
fn is_elevated() -> bool {
    Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", "([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)"])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map(|out| out.status.success() && String::from_utf8_lossy(&out.stdout).trim().eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

#[cfg(not(target_os = "windows"))]
fn is_elevated() -> bool {
    true
}

#[derive(Deserialize, Serialize)]
struct Connection {
    paired: bool,
    workspace_name: Option<String>,
    person_name: Option<String>,
}

fn checker_path(app: &AppHandle) -> Result<PathBuf, String> {
    // An installed build resolves this from its bundled resources. During
    // development this fixed path points at the locally built Windows collector.
    // An environment override is for packaging/CI only; it never comes from UI.
    if let Some(path) = std::env::var_os("HACKZERO_CHECKER_BIN") {
        return Ok(PathBuf::from(path));
    }
    let development = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../bin/device-checker-windows-amd64.exe");
    if cfg!(debug_assertions) && cfg!(target_os = "windows") && development.exists() {
        return Ok(development);
    }
    let bundled_name = if cfg!(target_os = "windows") {
        "device-checker-windows-amd64.exe"
    } else if cfg!(target_os = "macos") {
        // A universal (arm64 + x86_64) binary, so Intel and Apple silicon Macs
        // both run the same bundled collector.
        "device-checker-macos-universal"
    } else {
        "device-checker-linux-amd64"
    };
    app.path()
        .resource_dir()
        .map(|dir| dir.join(bundled_name))
        .map_err(|_| "Compliance Agent's files are missing. Reinstall Compliance Agent.".to_string())
}

fn run_collector(app: &AppHandle, which: Collector, extra: &[String]) -> Result<Output, String> {
    let mut command = Command::new(checker_path(app)?);
    command.args(which.args());
    command.args(extra);
    #[cfg(target_os = "windows")]
    command.creation_flags(CREATE_NO_WINDOW);
    command
        .output()
        .map_err(|error| short_error(format!("Could not start Compliance Agent: {error}").as_bytes()))
}

/// A short, printable-ASCII message for the UI. Collector errors are our own
/// short messages, but they are still capped and stripped of control bytes.
fn short_error(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    let text = text.trim();
    let text = text.strip_prefix("device-checker:").unwrap_or(text).trim();
    let cleaned: String = text
        .chars()
        .map(|c| if c.is_ascii_graphic() || c == ' ' { c } else { ' ' })
        .take(MAX_ERROR_CHARS)
        .collect();
    let cleaned = cleaned.split_whitespace().collect::<Vec<_>>().join(" ");
    if cleaned.is_empty() {
        "Compliance Agent stopped without a message.".into()
    } else {
        cleaned
    }
}

fn failure_message(output: &Output) -> String {
    if output.stderr.iter().any(|b| !b.is_ascii_whitespace()) {
        short_error(&output.stderr)
    } else {
        short_error(&output.stdout)
    }
}

/// The collector prints one JSON document; tolerate stray lines before it by
/// taking the last complete JSON value on stdout.
fn parse_json(stdout: &[u8]) -> Option<Value> {
    serde_json::Deserializer::from_slice(stdout)
        .into_iter::<Value>()
        .filter_map(Result::ok)
        .last()
}

/// Defence in depth: never pass anything that looks like private key material
/// to the webview, even though the collector's `diagnose` never includes it.
fn scrub(value: &mut Value) {
    match value {
        Value::Object(map) => {
            map.retain(|key, _| {
                let key = key.to_ascii_lowercase();
                !(key.contains("private") || key.contains("secret") || key == "identity")
            });
            for child in map.values_mut() {
                scrub(child);
            }
        }
        Value::Array(items) => items.iter_mut().for_each(scrub),
        _ => {}
    }
}

fn read_connection(app: &AppHandle) -> Result<Connection, String> {
    let output = run_collector(app, Collector::Connection, &[])?;
    if !output.status.success() {
        return Err(failure_message(&output));
    }
    serde_json::from_slice(&output.stdout).map_err(|_| "Compliance Agent returned an unreadable connection status.".to_string())
}

fn gate(app: &AppHandle) -> std::sync::MutexGuard<'_, ()> {
    app.state::<CollectorGate>().inner().0.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn blocking<T: Send + 'static>(task: impl FnOnce() -> Result<T, String> + Send + 'static) -> impl std::future::Future<Output = Result<T, String>> {
    async move {
        tauri::async_runtime::spawn_blocking(task)
            .await
            .map_err(|error| short_error(error.to_string().as_bytes()))?
    }
}

/// One visible check. When connected this is exactly ONE signed `report`
/// (collect, sign, send, persist) and the UI shows exactly that RunResult.
/// When not connected it is a local-only `status`, wrapped in the same shape
/// with `delivery: "not_sent"`.
#[tauri::command]
async fn check_now(app: AppHandle) -> Result<Value, String> {
    blocking(move || {
        let _guard = gate(&app);
        let paired = read_connection(&app).map(|c| c.paired).unwrap_or(false);
        if paired {
            let output = run_collector(&app, Collector::Report, &[])?;
            if let Some(result) = parse_json(&output.stdout) {
                if result.get("report").map(Value::is_object).unwrap_or(false) {
                    return Ok(result);
                }
            }
            return Err(failure_message(&output));
        }
        let output = run_collector(&app, Collector::Status, &[])?;
        if !output.status.success() {
            return Err(failure_message(&output));
        }
        let report = parse_json(&output.stdout)
            .filter(Value::is_object)
            .ok_or_else(|| "Compliance Agent returned an unreadable result.".to_string())?;
        let checked_at = report
            .get("collected_at")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());
        Ok(json!({ "source": "manual", "checked_at": checked_at, "report": report, "delivery": "not_sent" }))
    })
    .await
}

/// The last persisted RunResult (manual or background), or `{"available": false}`.
#[tauri::command]
async fn last_report(app: AppHandle) -> Result<Value, String> {
    blocking(move || {
        let output = run_collector(&app, Collector::Last, &[])?;
        if !output.status.success() {
            return Err(failure_message(&output));
        }
        parse_json(&output.stdout).ok_or_else(|| "Compliance Agent returned an unreadable last report.".to_string())
    })
    .await
}

#[tauri::command]
async fn diagnose(app: AppHandle) -> Result<Value, String> {
    blocking(move || {
        let output = run_collector(&app, Collector::Diagnose, &[])?;
        if !output.status.success() {
            return Err(failure_message(&output));
        }
        let mut value = parse_json(&output.stdout).ok_or_else(|| "Compliance Agent returned unreadable diagnostics.".to_string())?;
        scrub(&mut value);
        Ok(value)
    })
    .await
}

#[tauri::command]
async fn connection_status(app: AppHandle) -> Result<Connection, String> {
    blocking(move || read_connection(&app)).await
}

#[tauri::command]
async fn connect_device(app: AppHandle) -> Result<Connection, String> {
    // Browser login stays in the default browser. The app waits only for the
    // loopback callback, then receives a one-use code and no browser session.
    blocking(move || {
        let _guard = gate(&app);
        let server = std::env::var("HACKZERO_SERVER").unwrap_or_else(|_| "https://app.complianceeverywhere.com".into());
        let output = run_collector(&app, Collector::Pair, &["--server".to_string(), server])?;
        if !output.status.success() {
            return Err(failure_message(&output));
        }
        serde_json::from_slice(&output.stdout).map_err(|_| "Invalid pairing response.".to_string())
    })
    .await
}

fn disconnect(app: &AppHandle) -> Result<(), String> {
    let output = run_collector(app, Collector::Disconnect, &[])?;
    if !output.status.success() {
        return Err(failure_message(&output));
    }
    Ok(())
}

#[tauri::command]
async fn disconnect_device(app: AppHandle) -> Result<Connection, String> {
    blocking(move || {
        let _guard = gate(&app);
        disconnect(&app)?;
        Ok(Connection { paired: false, workspace_name: None, person_name: None })
    })
    .await
}

/// Runs one collector command and returns the JSON it printed.
fn collector_json(app: &AppHandle, which: Collector, extra: &[String]) -> Result<Value, String> {
    let output = run_collector(app, which, extra)?;
    if output.status.success() {
        if let Some(value) = parse_json(&output.stdout) {
            return Ok(value);
        }
    }
    Err(failure_message(&output))
}

/// The saved compliance dates, without the network. The background loop
/// refreshes them every 15 minutes and then emits `due-updated`.
#[tauri::command]
async fn due_soon(app: AppHandle) -> Result<Value, String> {
    blocking(move || collector_json(&app, Collector::DueCached, &[])).await
}

/// Asks the service for the dates now ("Check again").
#[tauri::command]
async fn refresh_due(app: AppHandle) -> Result<Value, String> {
    blocking(move || {
        let _guard = gate(&app);
        collector_json(&app, Collector::Due, &[])
    })
    .await
}

/// The one switch, "Notify me about new tasks", and what the system allows.
#[tauri::command]
async fn notification_settings(app: AppHandle) -> Result<Value, String> {
    blocking(move || collector_json(&app, Collector::NotifySettings, &[])).await
}

#[tauri::command]
async fn set_notifications(app: AppHandle, enabled: bool) -> Result<Value, String> {
    let which = if enabled { Collector::NotifyOn } else { Collector::NotifyOff };
    blocking(move || collector_json(&app, which, &[])).await
}

/// How web filtering would be turned on here: the exact commands, shown
/// before the person agrees.
#[tauri::command]
async fn web_filter_plan(app: AppHandle) -> Result<Value, String> {
    blocking(move || collector_json(&app, Collector::WebFilterPlan, &[])).await
}

#[tauri::command]
async fn web_filter_status(app: AppHandle) -> Result<Value, String> {
    blocking(move || collector_json(&app, Collector::WebFilterStatus, &[])).await
}

/// Turns web filtering on or off. Only the window's button calls this, after
/// the person agreed; nothing in the background ever does.
#[tauri::command]
async fn set_web_filter(app: AppHandle, on: bool) -> Result<Value, String> {
    let which = if on { Collector::WebFilterOn } else { Collector::WebFilterOff };
    blocking(move || {
        let _guard = gate(&app);
        collector_json(&app, which, &[])
    })
    .await
}

/// A plain version number such as 0.2.0, and nothing else.
fn plain_version(value: &str) -> bool {
    let parts: Vec<&str> = value.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.len() <= 6 && part.chars().all(|c| c.is_ascii_digit()))
}

/// The one reminder that an update is waiting. The version is checked here,
/// so only a plain version number ever becomes a collector argument.
#[tauri::command]
async fn notify_update(app: AppHandle, version: String) -> Result<Value, String> {
    if !plain_version(&version) {
        return Err("Not a version number.".into());
    }
    blocking(move || {
        let extra = vec!["--version".to_string(), version];
        collector_json(&app, Collector::NotifyUpdate, &extra)
    })
    .await
}

/// The page loaded and can talk to this process. Without it within 30
/// seconds, the window is treated as broken (window_health).
#[tauri::command]
fn window_ready(app: AppHandle, window: tauri::WebviewWindow) {
    window_health::mark_ready(&app, window.label());
}

/// Tells the person, once, that no window could be opened.
pub(crate) fn notify_window_failed(app: &AppHandle) {
    let app = app.clone();
    std::thread::spawn(move || {
        if let Err(error) = run_collector(&app, Collector::NotifyWindowFailed, &[]) {
            log::error!("could not show the window-failed notification: {error}");
        }
    });
}

/// With no window, its updater never runs, so a fix could never arrive. On an
/// installed Windows build (where updates already install unattended, with no
/// prompt) this process checks and installs the update itself.
pub(crate) fn update_without_window(app: &AppHandle) {
    if cfg!(debug_assertions) || !cfg!(target_os = "windows") {
        return;
    }
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        use tauri_plugin_updater::UpdaterExt;
        let updater = match app.updater() {
            Ok(updater) => updater,
            Err(error) => {
                log::error!("updater unavailable without a window: {error}");
                return;
            }
        };
        match updater.check().await {
            Ok(Some(update)) => {
                log::warn!("installing {} without a window", update.version);
                if let Err(error) = update.download_and_install(|_, _| {}, || {}).await {
                    log::error!("update {} failed without a window: {error}", update.version);
                } else {
                    app.restart();
                }
            }
            Ok(None) => log::info!("no update waiting"),
            Err(error) => log::warn!("update check without a window failed: {error}"),
        }
    });
}

/// Brings the window back from the tray (the update window opens in it).
#[tauri::command]
fn show_window(app: AppHandle) {
    show_main_window(&app);
}

/// The sign-in task on Windows. The app needs administrator rights, and
/// Windows silently skips such apps in the per-user Run key, so a scheduled
/// task with the highest run level starts it instead, without a prompt.
#[cfg(target_os = "windows")]
const SIGN_IN_TASK: &str = "Compliance Agent";

#[cfg(target_os = "windows")]
fn xml_text(value: &str) -> String {
    value.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

#[cfg(target_os = "windows")]
fn schtasks(args: &[&str]) -> Result<(), String> {
    let output = Command::new("schtasks.exe")
        .args(args)
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|error| short_error(error.to_string().as_bytes()))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(failure_message(&output))
    }
}

/// Creates or refreshes the sign-in task for the signed-in person. It runs on
/// every launch, so a first install and every update both leave it pointing
/// at the installed app. No time limit and no battery rule: the task's
/// defaults would stop the checker after three days or keep it off on battery.
#[cfg(target_os = "windows")]
fn start_at_sign_in(app: &AppHandle) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|error| short_error(error.to_string().as_bytes()))?;
    let user = match (std::env::var("USERDOMAIN"), std::env::var("USERNAME")) {
        (Ok(domain), Ok(name)) if !domain.is_empty() && !name.is_empty() => format!("{domain}\\{name}"),
        _ => return Err("Could not read the signed-in account.".into()),
    };
    let xml = format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>Starts Compliance Agent when you sign in.</Description></RegistrationInfo>
  <Triggers><LogonTrigger><Enabled>true</Enabled><UserId>{user}</UserId></LogonTrigger></Triggers>
  <Principals><Principal id="Author"><UserId>{user}</UserId><LogonType>InteractiveToken</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <StartWhenAvailable>true</StartWhenAvailable>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="Author"><Exec><Command>{exe}</Command><Arguments>--background</Arguments></Exec></Actions>
</Task>
"#,
        user = xml_text(&user),
        exe = xml_text(&exe.display().to_string()),
    );
    // schtasks reads UTF-16 with a byte-order mark.
    let mut bytes = vec![0xFF, 0xFE];
    bytes.extend(xml.encode_utf16().flat_map(u16::to_le_bytes));
    let file = std::env::temp_dir().join(format!("compliance-agent-sign-in-{}.xml", std::process::id()));
    std::fs::write(&file, bytes).map_err(|error| short_error(error.to_string().as_bytes()))?;
    let created = schtasks(&["/Create", "/TN", SIGN_IN_TASK, "/XML", &file.display().to_string(), "/F"]);
    let _ = std::fs::remove_file(&file);
    created?;
    remove_legacy_sign_in_entries(app);
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn start_at_sign_in(app: &AppHandle) -> Result<(), String> {
    use tauri_plugin_autostart::ManagerExt;
    app.autolaunch().enable().map_err(|error| short_error(error.to_string().as_bytes()))?;
    remove_legacy_sign_in_entries(app);
    Ok(())
}

/// The name this app was installed under before it became Compliance
/// Everywhere. Its sign-in entries are removed so the app never starts twice.
const LEGACY_APP_NAME: &str = "HackZero Device Checker";

/// Windows: the per-user Run-key entries, which never worked for an
/// administrator app. macOS and Linux: the entry written under the old name.
fn remove_legacy_sign_in_entries(app: &AppHandle) {
    #[cfg(target_os = "windows")]
    {
        use tauri_plugin_autostart::ManagerExt;
        let _ = app.autolaunch().disable();
        let _ = Command::new("reg.exe")
            .args(["delete", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "/v", LEGACY_APP_NAME, "/f"])
            .creation_flags(CREATE_NO_WINDOW)
            .output();
    }
    #[cfg(target_os = "macos")]
    if let Ok(home) = app.path().home_dir() {
        let _ = std::fs::remove_file(home.join("Library/LaunchAgents").join(format!("{LEGACY_APP_NAME}.plist")));
    }
    #[cfg(target_os = "linux")]
    if let Ok(config) = app.path().config_dir() {
        let _ = std::fs::remove_file(config.join("autostart").join(format!("{LEGACY_APP_NAME}.desktop")));
    }
}

fn stop_starting_at_sign_in(app: &AppHandle) {
    #[cfg(target_os = "windows")]
    let _ = schtasks(&["/Delete", "/TN", SIGN_IN_TASK, "/F"]);
    use tauri_plugin_autostart::ManagerExt;
    let _ = app.autolaunch().disable();
    remove_legacy_sign_in_entries(app);
}

#[derive(Serialize)]
struct Uninstall {
    platform: &'static str,
    local_data_removed: bool,
    local_data_path: Option<String>,
}

/// The collector's state directories under `os.UserConfigDir()`: the current
/// one first, then the one used before the app was renamed (the collector
/// moves it on first run, but it stays where it is if that move failed).
/// Tauri's config_dir is the same base on every platform.
fn state_dirs(app: &AppHandle) -> Vec<PathBuf> {
    match app.path().config_dir() {
        Ok(base) if base.is_absolute() => vec![
            base.join("ComplianceEverywhere").join("ComplianceAgent"),
            base.join("HackZero").join("DeviceChecker"),
        ],
        _ => Vec::new(),
    }
}

fn remove_state_dir(dir: &PathBuf) -> bool {
    match std::fs::symlink_metadata(dir) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
        Err(_) => false,
        // Never follow a link: remove exactly this app's own directory.
        Ok(meta) if meta.file_type().is_symlink() || !meta.is_dir() => false,
        Ok(_) => std::fs::remove_dir_all(dir).is_ok(),
    }
}

/// Disconnect (revokes this device with Compliance Everywhere and deletes its identity),
/// stop starting at login, and delete the app's local state directory. The
/// app bundle itself is removed by the person (see the platform steps in UI).
#[tauri::command]
async fn uninstall_device_checker(app: AppHandle) -> Result<Uninstall, String> {
    blocking(move || {
        let _guard = gate(&app);
        disconnect(&app)?;
        stop_starting_at_sign_in(&app);
        let dirs = state_dirs(&app);
        // Try every directory; one that cannot be removed is shown to the person.
        let left_behind: Vec<&PathBuf> = dirs.iter().filter(|dir| !remove_state_dir(dir)).collect();
        Ok(Uninstall {
            platform: std::env::consts::OS,
            local_data_removed: !dirs.is_empty() && left_behind.is_empty(),
            local_data_path: left_behind.first().map(|dir| dir.display().to_string()),
        })
    })
    .await
}

#[cfg(target_os = "macos")]
fn app_bundle_path() -> PathBuf {
    let installed = PathBuf::from("/Applications/Compliance Agent.app");
    if installed.exists() {
        return installed;
    }
    // An install that updated itself in place keeps the bundle name it was
    // first installed with, so the running bundle is the next best answer.
    // .../<name>.app/Contents/MacOS/<binary>
    std::env::current_exe()
        .ok()
        .and_then(|exe| exe.ancestors().nth(3).map(PathBuf::from))
        .filter(|bundle| bundle.extension().map(|ext| ext == "app").unwrap_or(false))
        .unwrap_or(installed)
}

/// Opens the place where the person finishes uninstalling. Fixed per platform.
#[tauri::command]
fn open_uninstall_location(app: AppHandle) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        let _ = &app;
        Command::new("/usr/bin/open")
            .arg("-R")
            .arg(app_bundle_path())
            .spawn()
            .map(|_| ())
            .map_err(|_| "Could not open Finder.".to_string())
    }
    #[cfg(target_os = "windows")]
    {
        use tauri_plugin_opener::OpenerExt;
        app.opener()
            .open_url("ms-settings:appsfeatures", None::<&str>)
            .map_err(|_| "Could not open Installed apps.".to_string())
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        let _ = &app;
        Ok(())
    }
}

/// True for an installed release. A development build never installs an
/// update over the installed app.
#[tauri::command]
fn installed_build() -> bool {
    !cfg!(debug_assertions)
}

#[tauri::command]
fn quit_app(app: AppHandle) {
    app.exit(0);
}

fn show_main_window(app: &AppHandle) {
    // Shows the window in use, or, when its page has not loaded (WebView2
    // failed to start), shows it once it has and tries again if recovery
    // already gave up. Never a silent click.
    window_health::request_show(app);
    // The page reloads the last saved result (a background tick may have run
    // while it was hidden) and re-checks for app updates if due.
    let _ = app.emit("window-shown", ());
}

/// One scheduler tick in a short-lived child, then tell the page to reload.
fn background_tick(app: &AppHandle) {
    let _guard = gate(app);
    let paired = read_connection(app).map(|c| c.paired).unwrap_or(false);
    if !paired {
        return;
    }
    // Failures are retried by the collector's durable queue on the next tick;
    // a network outage must never become a posture failure.
    let _ = run_collector(app, Collector::RunOnce, &[]);
    let _ = app.emit("report-updated", ());
}

/// One compliance dates check: the collector asks the service, tells the
/// person once about new and late tasks, and saves the answer for the window.
fn due_tick(app: &AppHandle) {
    let _guard = gate(app);
    let paired = read_connection(app).map(|c| c.paired).unwrap_or(false);
    if !paired {
        return;
    }
    let _ = run_collector(app, Collector::Due, &[]);
    let _ = app.emit("due-updated", ());
}

/// The Tauri process is the resident tray host. It runs the collector's
/// scheduler tick once an hour, and the compliance dates check every 15
/// minutes. The first scheduler tick waits a full interval: the launch check
/// already sent a report. A long gap between loop iterations means the
/// computer slept; then the page reloads and both catch up.
fn background_loop(app: AppHandle) {
    let mut last_wall = SystemTime::now();
    let mut next_tick = last_wall + BACKGROUND_EVERY;
    let mut next_due = last_wall + FIRST_DUE_AFTER;
    let mut next_update = last_wall + UPDATE_WITHOUT_WINDOW_EVERY;
    loop {
        std::thread::sleep(BACKGROUND_POLL);
        let now = SystemTime::now();
        let gap = now.duration_since(last_wall).unwrap_or_default();
        last_wall = now;
        if gap > WAKE_GAP {
            let _ = app.emit("system-resumed", ());
            next_tick = now + AFTER_WAKE_DELAY;
            next_due = now + AFTER_WAKE_DELAY;
        }
        // The clock moved backwards (manual change): do not wait longer than one interval.
        if next_tick.duration_since(now).map(|wait| wait > BACKGROUND_EVERY).unwrap_or(false) {
            next_tick = now + BACKGROUND_EVERY;
        }
        if next_due.duration_since(now).map(|wait| wait > DUE_EVERY).unwrap_or(false) {
            next_due = now + DUE_EVERY;
        }
        if now >= next_tick {
            next_tick = now + BACKGROUND_EVERY;
            background_tick(&app);
        }
        if now >= next_due {
            next_due = SystemTime::now() + DUE_EVERY;
            due_tick(&app);
        }
        if now >= next_update {
            next_update = now + UPDATE_WITHOUT_WINDOW_EVERY;
            if window_health::is_failed(&app) {
                update_without_window(&app);
            }
        }
    }
}

fn main() {
    let launch_in_background = std::env::args().any(|arg| arg == "--background");
    tauri::Builder::default()
        // A second launch focuses the resident checker instead of making
        // another scheduler/reporting process. This also prevents duplicate
        // tray icons at login.
        .plugin(tauri_plugin_single_instance::init(|app, _, _| show_main_window(app)))
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            Some(vec!["--background"]),
        ))
        .manage(CollectorGate(Mutex::new(())))
        .manage(window_health::WindowHealth::new(!launch_in_background))
        .setup(move |app| {
            if let Some(dir) = state_dirs(app.handle()).into_iter().next() {
                agent_log::init(&dir);
            }
            log::info!(
                "Compliance Agent {} starting{}",
                app.package_info().version,
                if launch_in_background { " at sign-in (--background)" } else { "" }
            );
            // The manifest prompts before this in a normal Windows build. This
            // prevents a malformed launcher from ever presenting partial
            // posture as a legitimate assessment.
            if cfg!(target_os = "windows") && !is_elevated() {
                app.handle().exit(1);
                return Ok(());
            }
            let show = MenuItem::with_id(app, "show", "Open Compliance Agent", true, None::<&str>)?;
            let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show, &quit])?;
            TrayIconBuilder::with_id(window_health::TRAY_ID)
                // An explicit icon is required: without it Windows can create
                // an empty/invisible tray entry during development.
                .icon(app.default_window_icon().expect("application icon is bundled").clone())
                .tooltip("Compliance Agent")
                .menu(&menu)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "show" => show_main_window(app),
                    "quit" => app.exit(0),
                    _ => {}
                })
                .build(app)?;
            if launch_in_background {
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.hide();
                }
            }
            // Installed builds only: a development build must never register
            // itself to start at sign-in.
            if !cfg!(debug_assertions) {
                let handle = app.handle().clone();
                std::thread::spawn(move || {
                    if let Err(error) = start_at_sign_in(&handle) {
                        log::error!("could not set itself to start at sign-in: {error}");
                    }
                });
            }
            // The window must say its page loaded; if it never does, a new one
            // is built and, failing that, the person is told.
            window_health::watch(app.handle());
            let handle = app.handle().clone();
            std::thread::spawn(move || background_loop(handle));
            Ok(())
        })
        .on_window_event(move |window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .invoke_handler(tauri::generate_handler![
            check_now,
            last_report,
            diagnose,
            connection_status,
            connect_device,
            disconnect_device,
            uninstall_device_checker,
            open_uninstall_location,
            installed_build,
            quit_app,
            due_soon,
            refresh_due,
            notification_settings,
            set_notifications,
            web_filter_plan,
            web_filter_status,
            set_web_filter,
            notify_update,
            show_window,
            window_ready
        ])
        .run(tauri::generate_context!())
        .expect("Tauri application error");
}
