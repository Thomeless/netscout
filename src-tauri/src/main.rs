// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Tomáš Nesrsta
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod firewall;
mod inventory;
mod l2cap;
mod mdns;
mod mikrotik;
mod neighbors;
mod netcfg;
mod oui;
mod proto;
mod profiles;
mod ps;
mod scan;
mod ssdp;

use neighbors::NeighborControl;
use netcfg::Iface;
use profiles::Profile;
use scan::ScanControl;
use std::sync::Arc;
use tauri::{AppHandle, State};

#[tauri::command]
async fn is_admin() -> bool {
    netcfg::is_admin()
}

#[tauri::command]
async fn list_interfaces() -> Result<Vec<Iface>, String> {
    netcfg::list_interfaces()
}

#[tauri::command]
async fn list_profiles(app: AppHandle) -> Result<Vec<Profile>, String> {
    profiles::load(&app)
}

#[tauri::command]
async fn save_profile(app: AppHandle, profile: Profile) -> Result<Vec<Profile>, String> {
    profiles::save(&app, profile)
}

#[tauri::command]
async fn delete_profile(app: AppHandle, id: String) -> Result<Vec<Profile>, String> {
    profiles::delete(&app, &id)
}

/// Použije profil na rozhraní; předchozí stav uloží pro tlačítko Zpět.
#[tauri::command]
async fn apply_profile(app: AppHandle, id: String, interface: String) -> Result<(), String> {
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
async fn revert_last(app: AppHandle) -> Result<String, String> {
    let (interface, cfg) = profiles::load_snapshot(&app)?.ok_or("Není uložen žádný předchozí stav")?;
    netcfg::apply(&interface, &cfg)?;
    Ok(interface)
}

#[tauri::command]
async fn has_snapshot(app: AppHandle) -> bool {
    profiles::load_snapshot(&app).ok().flatten().is_some()
}

#[tauri::command]
async fn inventory_load(app: AppHandle) -> Result<inventory::Db, String> {
    inventory::load(&app)
}

#[tauri::command]
async fn inventory_seen(app: AppHandle, seen: Vec<inventory::Seen>) -> Result<inventory::Db, String> {
    inventory::record_seen(&app, seen)
}

#[tauri::command]
async fn inventory_update(app: AppHandle, mac: String, label: String, note: String, favorite: bool) -> Result<inventory::Db, String> {
    inventory::update(&app, &mac, label, note, favorite)
}

#[tauri::command]
async fn inventory_forget(app: AppHandle, mac: String) -> Result<inventory::Db, String> {
    inventory::forget(&app, &mac)
}

#[tauri::command]
async fn mikrotik_settings(app: AppHandle) -> mikrotik::Settings {
    mikrotik::settings(&app)
}

/// Uloží adresu a uživatele routeru; heslo jen pokud je zadané.
#[tauri::command]
async fn mikrotik_save(app: AppHandle, host: String, user: String, password: Option<String>) -> Result<(), String> {
    mikrotik::save(&app, &host, &user, password.as_deref())
}

#[tauri::command]
async fn mikrotik_clear(app: AppHandle) -> Result<(), String> {
    mikrotik::clear(&app)
}

/// Vyzkouší přihlášení; bez zadaného hesla použije uložené. Vrací počet leasů.
#[tauri::command]
async fn mikrotik_test(app: AppHandle, host: String, user: String, password: Option<String>) -> Result<usize, String> {
    let password = match password.filter(|p| !p.is_empty()) {
        Some(p) => p,
        None => mikrotik::credentials(&app).map(|c| c.2).ok_or("Heslo není uloženo")?,
    };
    mikrotik::fetch_leases(&host, &user, &password).map(|l| l.len())
}

/// DHCP leasy z uloženého routeru; bez nastavení vrací prázdný seznam.
#[tauri::command]
async fn mikrotik_leases(app: AppHandle) -> Result<Vec<mikrotik::Lease>, String> {
    match mikrotik::credentials(&app) {
        Some((host, user, pass)) => mikrotik::fetch_leases(&host, &user, &pass),
        None => Ok(vec![]),
    }
}

#[tauri::command]
async fn start_scan(app: AppHandle, ctl: State<'_, Arc<ScanControl>>, range: String, thorough: bool) -> Result<(), String> {
    scan::start(app, ctl.inner().clone(), range, thorough)
}

#[tauri::command]
async fn start_neighbors(app: AppHandle, ctl: State<'_, Arc<NeighborControl>>) -> Result<(), String> {
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
async fn oui_info(app: AppHandle) -> Result<(usize, String), String> {
    Ok((oui::load(&app).len(), oui::path(&app)?.display().to_string()))
}

#[tauri::command]
async fn open_web(ip: String, port: u16) -> Result<(), String> {
    let ip: std::net::Ipv4Addr = ip.parse().map_err(|_| "Neplatná IP adresa")?;
    let scheme = if port == 443 { "https" } else { "http" };
    opener::open(format!("{scheme}://{ip}:{port}/")).map_err(|e| e.to_string())
}

#[tauri::command]
async fn open_rdp(ip: String) -> Result<(), String> {
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
        .setup(|_app| {
            // Pravidlo firewallu se řeší na pozadí, aby nezdržovalo start okna.
            std::thread::spawn(firewall::ensure_rule);
            Ok(())
        })
        .manage(Arc::new(ScanControl::default()))
        .manage(Arc::new(NeighborControl::default()))
        .invoke_handler(tauri::generate_handler![
            inventory_load,
            inventory_seen,
            inventory_update,
            inventory_forget,
            mikrotik_settings,
            mikrotik_save,
            mikrotik_clear,
            mikrotik_test,
            mikrotik_leases,
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
