// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Tomáš Nesrsta
//! MikroTik RouterOS API (TCP 8728): čtení DHCP leasů routeru (jméno hostitele, Class ID, Client ID, komentář).
//! Router zná jména i zařízení, která se na sken nehlásí. Přihlašovací údaje se ukládají šifrované přes
//! Windows DPAPI (jen pro tohoto uživatele Windows). API na portu 8728 posílá heslo nešifrovaně, proto
//! doporučujeme na routeru samostatného uživatele jen s právem čtení.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::ffi::c_void;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::path::PathBuf;
use std::time::Duration;
use tauri::{AppHandle, Manager};
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Cryptography::{CryptProtectData, CryptUnprotectData, CRYPT_INTEGER_BLOB};

pub const API_PORT: u16 = 8728;

#[derive(Serialize, Clone, Debug, Default, PartialEq)]
pub struct Lease {
    pub mac: String,
    pub address: String,
    pub host_name: String,
    pub class_id: String,
    pub client_id: String,
    pub status: String,
    pub server: String,
    pub comment: String,
    pub last_seen: String,
    pub dynamic: bool,
}

// ---------------------------------------------------------------- protokol (slova s délkou)

fn put_len(out: &mut Vec<u8>, n: usize) {
    match n {
        0..=0x7F => out.push(n as u8),
        0x80..=0x3FFF => out.extend(((n as u16) | 0x8000).to_be_bytes()),
        0x4000..=0x1F_FFFF => out.extend((((n as u32) | 0xC0_0000) as u32).to_be_bytes()[1..].iter()),
        0x20_0000..=0xFFF_FFFF => out.extend(((n as u32) | 0xE000_0000).to_be_bytes()),
        _ => {
            out.push(0xF0);
            out.extend((n as u32).to_be_bytes());
        }
    }
}

/// Jedna věta API: slova s délkou a prázdné slovo na konci.
pub fn encode_sentence(words: &[&str]) -> Vec<u8> {
    let mut out = vec![];
    for w in words {
        put_len(&mut out, w.len());
        out.extend(w.as_bytes());
    }
    out.push(0);
    out
}

fn read_exact(r: &mut impl Read, n: usize) -> Result<Vec<u8>, String> {
    let mut b = vec![0u8; n];
    r.read_exact(&mut b).map_err(|e| format!("Spojení s routerem se přerušilo: {e}"))?;
    Ok(b)
}

fn read_len(r: &mut impl Read) -> Result<usize, String> {
    let b0 = read_exact(r, 1)?[0] as usize;
    Ok(match b0 {
        0..=0x7F => b0,
        0x80..=0xBF => ((b0 & 0x3F) << 8) | read_exact(r, 1)?[0] as usize,
        0xC0..=0xDF => {
            let b = read_exact(r, 2)?;
            ((b0 & 0x1F) << 16) | (b[0] as usize) << 8 | b[1] as usize
        }
        0xE0..=0xEF => {
            let b = read_exact(r, 3)?;
            ((b0 & 0x0F) << 24) | (b[0] as usize) << 16 | (b[1] as usize) << 8 | b[2] as usize
        }
        _ => {
            let b = read_exact(r, 4)?;
            (b[0] as usize) << 24 | (b[1] as usize) << 16 | (b[2] as usize) << 8 | b[3] as usize
        }
    })
}

/// Přečte jednu větu (seznam slov do prázdného slova).
fn read_sentence(r: &mut impl Read) -> Result<Vec<String>, String> {
    let mut words = vec![];
    loop {
        let len = read_len(r)?;
        if len == 0 {
            return Ok(words);
        }
        if len > 1_000_000 {
            return Err("Neplatná odpověď routeru".into());
        }
        words.push(String::from_utf8_lossy(&read_exact(r, len)?).into_owned());
    }
}

/// `=klíč=hodnota` → (klíč, hodnota)
fn attr(word: &str) -> Option<(&str, &str)> {
    word.strip_prefix('=')?.split_once('=')
}

/// Pošle příkaz a vrátí řádky `!re` jako mapy klíč → hodnota.
fn command(stream: &mut (impl Read + Write), words: &[&str]) -> Result<Vec<HashMap<String, String>>, String> {
    stream.write_all(&encode_sentence(words)).map_err(|e| format!("Zápis do routeru selhal: {e}"))?;
    let mut rows = vec![];
    loop {
        let s = read_sentence(stream)?;
        match s.first().map(String::as_str) {
            Some("!re") => rows.push(s.iter().skip(1).filter_map(|w| attr(w)).map(|(k, v)| (k.to_string(), v.to_string())).collect()),
            Some("!done") => {
                // Starší RouterOS (před 6.43) vrací výzvu `=ret=`; to nepodporujeme.
                if s.iter().any(|w| w.starts_with("=ret=")) && words.first() == Some(&"/login") {
                    return Err("RouterOS starší než 6.43 není podporován".into());
                }
                return Ok(rows);
            }
            Some("!trap") => {
                let msg = s.iter().filter_map(|w| attr(w)).find(|(k, _)| *k == "message").map_or("chyba", |(_, v)| v);
                return Err(format!("Router odmítl příkaz: {msg}"));
            }
            Some("!fatal") => return Err(format!("Router ukončil spojení: {}", s.get(1).cloned().unwrap_or_default())),
            _ => {}
        }
    }
}

pub fn parse_lease(row: &HashMap<String, String>) -> Lease {
    let get = |k: &str| row.get(k).cloned().unwrap_or_default();
    // „Active…“ hodnoty jsou ty, které klient právě používá; jinak platí nastavené v leasu.
    let pick = |a: &str, b: &str| Some(get(a)).filter(|v| !v.is_empty()).unwrap_or_else(|| get(b));
    Lease {
        mac: pick("active-mac-address", "mac-address").to_uppercase(),
        address: pick("active-address", "address"),
        host_name: get("host-name"),
        class_id: get("class-id"),
        client_id: pick("active-client-id", "client-id"),
        status: get("status"),
        server: pick("active-server", "server"),
        comment: get("comment"),
        last_seen: get("last-seen"),
        dynamic: get("dynamic") == "true",
    }
}

/// Přihlásí se k API na `addr` a stáhne DHCP leasy.
pub fn fetch_leases_at(addr: SocketAddr, user: &str, password: &str) -> Result<Vec<Lease>, String> {
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(3)).map_err(|e| format!("Router {addr} neodpovídá: {e}"))?;
    s.set_read_timeout(Some(Duration::from_secs(6))).map_err(|e| e.to_string())?;
    s.set_write_timeout(Some(Duration::from_secs(6))).map_err(|e| e.to_string())?;
    command(&mut s, &["/login", &format!("=name={user}"), &format!("=password={password}")])?;
    let rows = command(&mut s, &["/ip/dhcp-server/lease/print"])?;
    Ok(rows.iter().map(parse_lease).filter(|l| !l.mac.is_empty()).collect())
}

pub fn fetch_leases(host: &str, user: &str, password: &str) -> Result<Vec<Lease>, String> {
    let ip: Ipv4Addr = host.trim().parse().map_err(|_| "Adresa routeru musí být IPv4 adresa".to_string())?;
    fetch_leases_at(SocketAddr::new(ip.into(), API_PORT), user, password)
}

// ---------------------------------------------------------------- uložení údajů (DPAPI)

fn blob(data: &[u8]) -> CRYPT_INTEGER_BLOB {
    CRYPT_INTEGER_BLOB { cbData: data.len() as u32, pbData: data.as_ptr() as *mut u8 }
}

fn take_blob(b: CRYPT_INTEGER_BLOB) -> Vec<u8> {
    let v = unsafe { std::slice::from_raw_parts(b.pbData, b.cbData as usize) }.to_vec();
    unsafe { LocalFree(b.pbData as *mut c_void) };
    v
}

fn protect(data: &[u8]) -> Option<Vec<u8>> {
    let input = blob(data);
    let mut out = CRYPT_INTEGER_BLOB { cbData: 0, pbData: std::ptr::null_mut() };
    let ok = unsafe { CryptProtectData(&input, std::ptr::null(), std::ptr::null(), std::ptr::null(), std::ptr::null(), 0, &mut out) };
    (ok != 0).then(|| take_blob(out))
}

fn unprotect(data: &[u8]) -> Option<Vec<u8>> {
    let input = blob(data);
    let mut out = CRYPT_INTEGER_BLOB { cbData: 0, pbData: std::ptr::null_mut() };
    let ok = unsafe { CryptUnprotectData(&input, std::ptr::null_mut(), std::ptr::null(), std::ptr::null(), std::ptr::null(), 0, &mut out) };
    (ok != 0).then(|| take_blob(out))
}

fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn from_hex(s: &str) -> Option<Vec<u8>> {
    (s.len() % 2 == 0).then(|| ())?;
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

#[derive(Serialize, Deserialize, Default, Clone)]
struct Stored {
    host: String,
    user: String,
    /// Heslo zašifrované DPAPI, hex.
    password: String,
}

/// Co se posílá do rozhraní: heslo nikdy, jen informace, zda je uloženo.
#[derive(Serialize)]
pub struct Settings {
    pub host: String,
    pub user: String,
    pub has_password: bool,
}

fn file(app: &AppHandle) -> Result<PathBuf, String> {
    let d = app.path().app_data_dir().map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&d).map_err(|e| e.to_string())?;
    Ok(d.join("mikrotik.json"))
}

fn load(app: &AppHandle) -> Stored {
    file(app).ok().and_then(|p| std::fs::read_to_string(p).ok()).and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
}

pub fn settings(app: &AppHandle) -> Settings {
    let s = load(app);
    Settings { has_password: !s.password.is_empty(), host: s.host, user: s.user }
}

/// Uloží adresu a uživatele; heslo jen když je zadané (prázdné ponechá dosavadní).
pub fn save(app: &AppHandle, host: &str, user: &str, password: Option<&str>) -> Result<(), String> {
    host.trim().parse::<Ipv4Addr>().map_err(|_| "Adresa routeru musí být IPv4 adresa".to_string())?;
    let mut s = load(app);
    s.host = host.trim().to_string();
    s.user = user.trim().to_string();
    if let Some(p) = password.filter(|p| !p.is_empty()) {
        s.password = to_hex(&protect(p.as_bytes()).ok_or("Heslo se nepodařilo zašifrovat (DPAPI)")?);
    }
    std::fs::write(file(app)?, serde_json::to_string_pretty(&s).map_err(|e| e.to_string())?).map_err(|e| e.to_string())
}

pub fn clear(app: &AppHandle) -> Result<(), String> {
    match std::fs::remove_file(file(app)?) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}

/// Uložené údaje: adresa, uživatel, heslo (dešifrované jen v paměti).
pub fn credentials(app: &AppHandle) -> Option<(String, String, String)> {
    let s = load(app);
    if s.host.is_empty() || s.password.is_empty() {
        return None;
    }
    let pass = String::from_utf8(unprotect(&from_hex(&s.password)?)?).ok()?;
    Some((s.host, s.user, pass))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::net::TcpListener;

    #[test]
    fn length_encoding_roundtrip() {
        for n in [0usize, 1, 0x7F, 0x80, 0x3FFF, 0x4000, 0x1F_FFFF, 0x20_0000, 0xFFF_FFFF] {
            let mut b = vec![];
            put_len(&mut b, n);
            assert_eq!(read_len(&mut Cursor::new(b)).unwrap(), n, "délka {n}");
        }
    }

    #[test]
    fn sentence_roundtrip() {
        let enc = encode_sentence(&["/login", "=name=admin", "=password=tajne heslo"]);
        assert_eq!(read_sentence(&mut Cursor::new(enc)).unwrap(), vec!["/login", "=name=admin", "=password=tajne heslo"]);
    }

    #[test]
    fn lease_prefers_active_values() {
        let row: HashMap<String, String> = [
            ("mac-address", "aa:bb:cc:00:11:22"),
            ("address", "192.168.88.100"),
            ("active-address", "192.168.88.17"),
            ("host-name", "Pixel-8"),
            ("class-id", "android-dhcp-15"),
            ("client-id", "1:aa:bb:cc:00:11:22"),
            ("status", "bound"),
            ("dynamic", "true"),
        ]
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        let l = parse_lease(&row);
        assert_eq!((l.mac.as_str(), l.address.as_str(), l.host_name.as_str(), l.class_id.as_str()), ("AA:BB:CC:00:11:22", "192.168.88.17", "Pixel-8", "android-dhcp-15"));
        assert!(l.dynamic);
    }

    /// Falešný router: přijme přihlášení a vrátí dva leasy.
    #[test]
    fn fetch_from_fake_router() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut c, _) = listener.accept().unwrap();
            let login = read_sentence(&mut c).unwrap();
            assert_eq!(login[0], "/login");
            assert_eq!(login[1], "=name=ro");
            assert_eq!(login[2], "=password=pw");
            c.write_all(&encode_sentence(&["!done"])).unwrap();
            assert_eq!(read_sentence(&mut c).unwrap(), vec!["/ip/dhcp-server/lease/print"]);
            c.write_all(&encode_sentence(&["!re", "=mac-address=AA:BB:CC:00:11:22", "=address=192.168.88.17", "=host-name=Pixel-8", "=class-id=android-dhcp-15", "=status=bound"])).unwrap();
            c.write_all(&encode_sentence(&["!re", "=mac-address=AA:BB:CC:00:11:33", "=address=192.168.88.51", "=host-name=NPIAE635E", "=comment=Tiskárna"])).unwrap();
            c.write_all(&encode_sentence(&["!done"])).unwrap();
        });
        let leases = fetch_leases_at(addr, "ro", "pw").unwrap();
        server.join().unwrap();
        assert_eq!(leases.len(), 2);
        assert_eq!(leases[0].host_name, "Pixel-8");
        assert_eq!(leases[1].comment, "Tiskárna");
    }

    #[test]
    fn trap_is_reported_as_error() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let (mut c, _) = listener.accept().unwrap();
            let _ = read_sentence(&mut c);
            c.write_all(&encode_sentence(&["!trap", "=message=invalid user name or password (6)"])).unwrap();
        });
        let err = fetch_leases_at(addr, "x", "y").unwrap_err();
        assert!(err.contains("invalid user name"), "{err}");
    }

    #[test]
    fn dpapi_roundtrip() {
        let enc = protect(b"tajne heslo").expect("DPAPI");
        assert_ne!(enc, b"tajne heslo");
        assert_eq!(unprotect(&enc).as_deref(), Some(&b"tajne heslo"[..]));
        assert_eq!(from_hex(&to_hex(&enc)), Some(enc));
    }
}
