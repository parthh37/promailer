//! Connection settings persisted per Windows user (`%APPDATA%\Promailer\manager.json`).

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub url: String,
    /// Only stored when the user ticks "Remember API key".
    pub api_key: String,
    pub remember_key: bool,
    pub last_check_domain: String,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            url: "http://127.0.0.1:8025".into(),
            api_key: String::new(),
            remember_key: false,
            last_check_domain: String::new(),
        }
    }
}

fn path() -> Option<PathBuf> {
    let base = if cfg!(windows) {
        std::env::var_os("APPDATA").map(PathBuf::from)
    } else {
        std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
    }?;
    Some(base.join("Promailer").join("manager.json"))
}

impl Settings {
    pub fn load() -> Self {
        path().and_then(|p| std::fs::read(p).ok()).and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
    }

    pub fn save(&self) -> Result<(), String> {
        let p = path().ok_or("no user profile directory")?;
        if let Some(dir) = p.parent() {
            std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        }
        let mut copy = self.clone();
        if !copy.remember_key {
            copy.api_key.clear();
        }
        let json = serde_json::to_vec_pretty(&copy).map_err(|e| e.to_string())?;
        std::fs::write(&p, json).map_err(|e| format!("{}: {e}", p.display()))
    }
}
