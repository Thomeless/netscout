// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Tomáš Nesrsta
//! Ukládání IP profilů (JSON v datové složce aplikace) a snímku předchozího stavu.

use crate::netcfg::IpConfig;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use tauri::AppHandle;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Profile {
    /// Prázdné id = nový profil, přidělí se při uložení.
    #[serde(default)]
    pub id: String,
    pub name: String,
    /// Výchozí rozhraní profilu (lze změnit při použití).
    #[serde(default)]
    pub interface: String,
    #[serde(flatten)]
    pub config: IpConfig,
}

#[derive(Serialize, Deserialize)]
struct Snapshot {
    interface: String,
    config: IpConfig,
}

fn dir(app: &AppHandle) -> Result<PathBuf, String> {
    let d = crate::portable::data_dir(app)?;
    Ok(d)
}

fn write(path: PathBuf, data: &impl Serialize) -> Result<(), String> {
    let json = serde_json::to_string_pretty(data).map_err(|e| e.to_string())?;
    std::fs::write(path, json).map_err(|e| e.to_string())
}

pub fn load(app: &AppHandle) -> Result<Vec<Profile>, String> {
    let path = dir(app)?.join("profiles.json");
    match std::fs::read_to_string(&path) {
        Ok(s) => serde_json::from_str(&s).map_err(|e| format!("Poškozený profiles.json: {e}")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(vec![]),
        Err(e) => Err(e.to_string()),
    }
}

pub fn save(app: &AppHandle, mut profile: Profile) -> Result<Vec<Profile>, String> {
    if profile.name.trim().is_empty() {
        return Err("Profil musí mít název".into());
    }
    crate::netcfg::validate(&profile.config)?;
    let mut all = load(app)?;
    if profile.id.is_empty() {
        let ms = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|e| e.to_string())?.as_millis();
        profile.id = format!("p{ms}");
        all.push(profile);
    } else if let Some(slot) = all.iter_mut().find(|p| p.id == profile.id) {
        *slot = profile;
    } else {
        all.push(profile);
    }
    write(dir(app)?.join("profiles.json"), &all)?;
    Ok(all)
}

pub fn delete(app: &AppHandle, id: &str) -> Result<Vec<Profile>, String> {
    let mut all = load(app)?;
    all.retain(|p| p.id != id);
    write(dir(app)?.join("profiles.json"), &all)?;
    Ok(all)
}

pub fn save_snapshot(app: &AppHandle, interface: &str, config: &IpConfig) -> Result<(), String> {
    write(
        dir(app)?.join("last_state.json"),
        &Snapshot { interface: interface.to_string(), config: config.clone() },
    )
}

pub fn load_snapshot(app: &AppHandle) -> Result<Option<(String, IpConfig)>, String> {
    match std::fs::read_to_string(dir(app)?.join("last_state.json")) {
        Ok(s) => {
            let snap: Snapshot = serde_json::from_str(&s).map_err(|e| e.to_string())?;
            Ok(Some((snap.interface, snap.config)))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}
