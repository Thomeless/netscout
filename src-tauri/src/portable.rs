// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Tomáš Nesrsta
//! Přenosný režim: když je vedle programu soubor `portable`, ukládají se všechna data (profily, inventář,
//! nastavení i data okna WebView2) do složky `data` vedle programu místo do profilu uživatele.

use std::path::PathBuf;
use std::sync::OnceLock;
use tauri::{AppHandle, Manager};

fn exe_dir() -> Option<PathBuf> {
    std::env::current_exe().ok()?.parent().map(|p| p.to_path_buf())
}

pub fn is_portable() -> bool {
    static P: OnceLock<bool> = OnceLock::new();
    *P.get_or_init(|| exe_dir().is_some_and(|d| d.join("portable").exists()))
}

/// Složka s daty aplikace (vytvoří se, pokud neexistuje).
pub fn data_dir(app: &AppHandle) -> Result<PathBuf, String> {
    let d = match (is_portable(), exe_dir()) {
        (true, Some(dir)) => dir.join("data"),
        _ => app.path().app_data_dir().map_err(|e| e.to_string())?,
    };
    std::fs::create_dir_all(&d).map_err(|e| format!("Složku s daty nelze vytvořit ({}): {e}", d.display()))?;
    Ok(d)
}

/// Musí proběhnout před vytvořením okna: WebView2 pak ukládá svá data (včetně nastavení v UI) vedle programu.
pub fn init() {
    if !is_portable() || std::env::var_os("WEBVIEW2_USER_DATA_FOLDER").is_some() {
        return;
    }
    if let Some(dir) = exe_dir() {
        let wv = dir.join("data").join("webview");
        if std::fs::create_dir_all(&wv).is_ok() {
            // Voláno na začátku `main`, dokud nebězí žádná další vlákna.
            unsafe { std::env::set_var("WEBVIEW2_USER_DATA_FOLDER", wv) };
        }
    }
}
