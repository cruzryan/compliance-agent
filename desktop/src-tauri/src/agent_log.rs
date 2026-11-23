//! A small log file next to the agent's state: `agent.log`.
//!
//! Without a logger, everything the Tauri runtime reports through the `log`
//! crate is dropped. That is how the WebView2 error behind a window that never
//! opened was lost on Cuau's laptop (22 Nov 2026): tauri-runtime-wry only logs
//! a failed window creation. Warnings and errors from every crate, and this
//! app's own notes, now go to the file. It never holds report contents.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;

/// The file is started over above this size, keeping one previous file.
const MAX_BYTES: u64 = 1024 * 1024;

struct FileLog {
    file: Mutex<File>,
}

impl log::Log for FileLog {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        // This app's own notes at info; everything else from warnings up.
        metadata.level() <= log::Level::Warn
            || (metadata.level() <= log::Level::Info
                && metadata.target().starts_with("compliance_agent"))
    }

    fn log(&self, record: &log::Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let line = format!(
            "{} {:<5} {}: {}\n",
            chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ"),
            record.level(),
            record.target(),
            record.args()
        );
        if let Ok(mut file) = self.file.lock() {
            let _ = file.write_all(line.as_bytes());
            let _ = file.flush();
        }
    }

    fn flush(&self) {
        if let Ok(mut file) = self.file.lock() {
            let _ = file.flush();
        }
    }
}

/// Starts writing `agent.log` in `dir`. Any failure leaves logging off: a log
/// file is never a reason for the agent not to start.
pub fn init(dir: &Path) {
    if std::fs::create_dir_all(dir).is_err() {
        return;
    }
    let path = dir.join("agent.log");
    if std::fs::metadata(&path)
        .map(|m| m.len() > MAX_BYTES)
        .unwrap_or(false)
    {
        let _ = std::fs::rename(&path, dir.join("agent.log.1"));
    }
    let Ok(file) = OpenOptions::new().create(true).append(true).open(&path) else {
        return;
    };
    if log::set_boxed_logger(Box::new(FileLog {
        file: Mutex::new(file),
    }))
    .is_ok()
    {
        log::set_max_level(log::LevelFilter::Info);
    }
}
