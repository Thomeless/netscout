// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Tomáš Nesrsta
//! Trvalý inventář zařízení podle MAC: vlastní název, poznámka, oblíbené a poslední známé údaje
//! (aby šla zařízení vidět i offline po restartu). Dynamická data (sken, neighbours) zůstávají ve frontendu.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use tauri::{AppHandle, Manager};

#[derive(Serialize, Deserialize, Clone, Default, Debug)]
pub struct Meta {
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub note: String,
    #[serde(default)]
    pub favorite: bool,
    #[serde(default)]
    pub first_seen: u64,
    #[serde(default)]
    pub last_seen: u64,
    #[serde(default)]
    pub last_ip: String,
    #[serde(default)]
    pub vendor: String,
    /// Poslední známý název (hostname / identita).
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub kind: String,
}

/// Co frontend právě vidí o zařízení.
#[derive(Deserialize)]
pub struct Seen {
    pub mac: String,
    #[serde(default)]
    pub ip: String,
    #[serde(default)]
    pub vendor: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub kind: String,
}

pub type Db = HashMap<String, Meta>;

fn file(app: &AppHandle) -> Result<PathBuf, String> {
    let d = app.path().app_data_dir().map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&d).map_err(|e| e.to_string())?;
    Ok(d.join("inventory.json"))
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

pub fn norm_mac(mac: &str) -> Option<String> {
    let h: String = mac.chars().filter(|c| c.is_ascii_hexdigit()).collect::<String>().to_uppercase();
    (h.len() == 12).then(|| (0..6).map(|i| &h[i * 2..i * 2 + 2]).collect::<Vec<_>>().join(":"))
}

pub fn load(app: &AppHandle) -> Result<Db, String> {
    match std::fs::read_to_string(file(app)?) {
        Ok(s) => serde_json::from_str(&s).map_err(|e| format!("Poškozený inventory.json: {e}")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Db::new()),
        Err(e) => Err(e.to_string()),
    }
}

fn store(app: &AppHandle, db: &Db) -> Result<(), String> {
    let json = serde_json::to_string_pretty(db).map_err(|e| e.to_string())?;
    // Zápis přes dočasný soubor, aby při pádu nezůstal poloprázdný inventář.
    let path = file(app)?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, json).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, &path).map_err(|e| e.to_string())
}

pub fn record_seen(app: &AppHandle, seen: Vec<Seen>) -> Result<Db, String> {
    let mut db = load(app)?;
    let t = now();
    for s in seen {
        let Some(mac) = norm_mac(&s.mac) else { continue };
        let m = db.entry(mac).or_default();
        if m.first_seen == 0 {
            m.first_seen = t;
        }
        m.last_seen = t;
        // Prázdné hodnoty nepřepisují dřív zjištěné.
        for (dst, src) in [(&mut m.last_ip, &s.ip), (&mut m.vendor, &s.vendor), (&mut m.name, &s.name), (&mut m.kind, &s.kind)] {
            if !src.is_empty() {
                *dst = src.clone();
            }
        }
    }
    store(app, &db)?;
    Ok(db)
}

pub fn update(app: &AppHandle, mac: &str, label: String, note: String, favorite: bool) -> Result<Db, String> {
    let mac = norm_mac(mac).ok_or("Neplatná MAC adresa")?;
    let mut db = load(app)?;
    let m = db.entry(mac).or_default();
    m.label = label.trim().to_string();
    m.note = note;
    m.favorite = favorite;
    store(app, &db)?;
    Ok(db)
}

pub fn forget(app: &AppHandle, mac: &str) -> Result<Db, String> {
    let mac = norm_mac(mac).ok_or("Neplatná MAC adresa")?;
    let mut db = load(app)?;
    db.remove(&mac);
    store(app, &db)?;
    Ok(db)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_normalization() {
        assert_eq!(norm_mac("c0-56-e3-aa-bb-cc").as_deref(), Some("C0:56:E3:AA:BB:CC"));
        assert_eq!(norm_mac("C056.E3AA.BBCC").as_deref(), Some("C0:56:E3:AA:BB:CC"));
        assert_eq!(norm_mac("nope"), None);
    }
}
