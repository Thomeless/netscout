// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Tomáš Nesrsta
//! Databáze výrobců podle MAC (IEEE OUI, soubor oui.csv v datové složce aplikace).
//! Bez souboru se výrobce nezobrazí; soubor je ve formátu IEEE: Registry,Assignment,Organization Name,...

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use tauri::{AppHandle, Manager};

static EMBEDDED: &[u8] = include_bytes!("../resources/oui.csv");

pub type Db =HashMap<[u8; 3], String>;

pub fn path(app: &AppHandle) -> Result<PathBuf, String> {
    Ok(app.path().app_data_dir().map_err(|e| e.to_string())?.join("oui.csv"))
}

fn split_csv(line: &str) -> Vec<String> {
    let mut out = vec![];
    let mut cur = String::new();
    let mut quoted = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' if quoted && chars.peek() == Some(&'"') => {
                cur.push('"');
                chars.next();
            }
            '"' => quoted = !quoted,
            ',' if !quoted => out.push(std::mem::take(&mut cur)),
            _ => cur.push(c),
        }
    }
    out.push(cur);
    out
}

/// Databáze se při prvním použití načte a pak se sdílí (40 tisíc řádků se neparsuje opakovaně).
pub fn load(app: &AppHandle) -> Arc<Db> {
    static CACHE: OnceLock<Arc<Db>> = OnceLock::new();
    CACHE.get_or_init(|| Arc::new(parse(app))).clone()
}

fn parse(app: &AppHandle) -> Db {
    let mut db = Db::new();
    // Vlastní oui.csv v datové složce má přednost před vestavěným (IEEE, stažen při vývoji).
    let text = path(app)
        .and_then(|p| std::fs::read_to_string(p).map_err(|e| e.to_string()))
        .unwrap_or_else(|_| String::from_utf8_lossy(EMBEDDED).into_owned());
    for line in text.lines() {
        let f = split_csv(line);
        if f.len() < 3 || f[1].len() != 6 {
            continue;
        }
        if let Ok(v) = u32::from_str_radix(&f[1], 16) {
            let b = v.to_be_bytes();
            db.insert([b[1], b[2], b[3]], f[2].trim().to_string());
        }
    }
    db
}

pub fn lookup(db: &Db, mac: &[u8; 6]) -> Option<String> {
    db.get(&[mac[0], mac[1], mac[2]]).cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_has_known_vendors() {
        let mut db = Db::new();
        for line in String::from_utf8_lossy(EMBEDDED).lines() {
            let f = split_csv(line);
            if f.len() >= 3 && f[1].len() == 6 {
                if let Ok(v) = u32::from_str_radix(&f[1], 16) {
                    let b = v.to_be_bytes();
                    db.insert([b[1], b[2], b[3]], f[2].clone());
                }
            }
        }
        assert!(db.len() > 30_000);
        println!("{} záznamů; 00:09:0F -> {:?}", db.len(), lookup(&db, &[0x00, 0x09, 0x0F, 1, 2, 3]));
    }
}
