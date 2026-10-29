// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Tomáš Nesrsta
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod inventory;
mod l2cap;
mod neighbors;
mod netcfg;
mod oui;
mod proto;
mod profiles;
mod ps;
mod scan;

use neighbors::NeighborControl;
use netcfg::Iface;
use profiles::Profile;
use scan::ScanControl;
use std::sync::Arc;
use tauri::{AppHandle, State};

#[tauri::command]
fn is_admin() -> bool {
    netcfg::is_admin()
}

#[tauri::command]
fn list_interfaces() -> Result<Vec<Iface>, String> {
    netcfg::list_interfaces()
}

#[tauri::command]
fn list_profiles(app: AppHandle) -> Result<Vec<Profile>, String> {
    profiles::load(&app)
}

#[tauri::command]
fn save_profile(app: AppHandle, profile: Profile) -> Result<Vec<Profile>, String> {
    profiles::save(&app, profile)
}

#[tauri::command]
fn delete_profile(app: AppHandle, id: String) -> Result<Vec<Profile>, String> {
    profiles::delete(&app, &id)
}

/// Použije profil na rozhraní; předchozí stav uloží pro tlačítko Zpět.
#[tauri::command]
fn apply_profile(app: AppHandle, id: String, interface: String) -> Result<(), String> {
    let profile = profiles::load(&app)?
        .into_iter()
        .find(|p| p.id == id)
        .ok_or("Profil nenalezen")?;
    netcfg::validate(&profile.config)?;
    let before = netcfg::list_interfaces()?
        .into_iter()
        .find(|i| i.name == interface)
        .ok_or("Rozhraní nenalezeno")?;
    profiles::save_snapshot(&app, &interface, &before.to_config())?;
    netcfg::apply(&interface, &profile.config)
}

#[tauri::command]
fn revert_last(app: AppHandle) -> Result<String, String> {
    let (interface, cfg) = profiles::load_snapshot(&app)?.ok_or("Není uložen žádný předchozí stav")?;
    netcfg::apply(&interface, &cfg)?;
    Ok(interface)
}

#[tauri::command]
fn has_snapshot(app: AppHandle) -> bool {
    profiles::load_snapshot(&app).ok().flatten().is_some()
}

#[tauri::command]
fn inventory_load(app: AppHandle) -> Result<inventory::Db, String> {
    inventory::load(&app)
}

#[tauri::command]
fn inventory_seen(app: AppHandle, seen: Vec<inventory::Seen>) -> Result<inventory::Db, String> {
    inventory::record_seen(&app, seen)
}

#[tauri::command]
fn inventory_update(app: AppHandle, mac: String, label: String, note: String, favorite: bool) -> Result<inventory::Db, String> {
    inventory::update(&app, &mac, label, note, favorite)
}

#[tauri::command]
fn inventory_forget(app: AppHandle, mac: String) -> Result<inventory::Db, String> {
    inventory::forget(&app, &mac)
}

#[tauri::command]
fn start_scan(app: AppHandle, ctl: State<'_, Arc<ScanControl>>, range: String) -> Result<(), String> {
    scan::start(app, ctl.inner().clone(), range)
}

#[tauri::command]
fn start_neighbors(app: AppHandle, ctl: State<'_, Arc<NeighborControl>>) -> Result<(), String> {
    neighbors::start(app, ctl.inner().clone())
}

#[tauri::command]
fn stop_neighbors(ctl: State<'_, Arc<NeighborControl>>) {
    ctl.stop();
}

#[tauri::command]
fn neighbors_running(ctl: State<'_, Arc<NeighborControl>>) -> bool {
    ctl.running()
}

#[tauri::command]
fn cancel_scan(ctl: State<'_, Arc<ScanControl>>) {
    ctl.cancel();
}

/// Počet načtených výrobců z oui.csv a cesta, kam soubor patří.
#[tauri::command]
fn oui_info(app: AppHandle) -> Result<(usize, String), String> {
    Ok((oui::load(&app).len(), oui::path(&app)?.display().to_string()))
}

#[tauri::command]
fn open_web(ip: String, port: u16) -> Result<(), String> {
    let ip: std::net::Ipv4Addr = ip.parse().map_err(|_| "Neplatná IP adresa")?;
    let scheme = if port == 443 { "https" } else { "http" };
    opener::open(format!("{scheme}://{ip}:{port}/")).map_err(|e| e.to_string())
}

#[tauri::command]
fn open_rdp(ip: String) -> Result<(), String> {
    use std::os::windows::process::CommandExt;
    let ip: std::net::Ipv4Addr = ip.parse().map_err(|_| "Neplatná IP adresa")?;
    std::process::Command::new("mstsc.exe")
        .arg(format!("/v:{ip}"))
        .creation_flags(0x0800_0000)
        .spawn()
        .map(|_| ())
        .map_err(|e| e.to_string())
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_process::init())
        .manage(Arc::new(ScanControl::default()))
        .manage(Arc::new(NeighborControl::default()))
        .invoke_handler(tauri::generate_handler![
            inventory_load,
            inventory_seen,
            inventory_update,
            inventory_forget,
            start_scan,
            cancel_scan,
            start_neighbors,
            stop_neighbors,
            neighbors_running,
            oui_info,
            open_web,
            open_rdp,
            is_admin,
            list_interfaces,
            list_profiles,
            save_profile,
            delete_profile,
            apply_profile,
            revert_last,
            has_snapshot
        ])
        .run(tauri::generate_context!())
        .expect("chyba při spuštění aplikace");
}
