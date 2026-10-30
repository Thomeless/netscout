// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Tomáš Nesrsta
//! IP sken lokální sítě: ARP (SendARP), reverzní DNS, základní TCP porty, výrobce z OUI.

use crate::mdns::{self, MdnsInfo};
use crate::ssdp::{self, UpnpInfo};
use crate::{netcfg, oui};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tauri::{AppHandle, Emitter};
use windows_sys::Win32::NetworkManagement::IpHelper::SendARP;

const MAX_HOSTS: u32 = 65_536;
const REPORT_THREADS: usize = 24;
const PORTS: &[u16] = &[21, 22, 23, 53, 80, 139, 443, 445, 554, 3389, 8000, 8080, 8291, 8728, 9100, 37777];

/// Režim skenu od nejtišího po nejhlasitější.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    /// Nic neodesílá: čte ARP tabulku Windows a poslouchá mDNS oznámení.
    Quiet,
    /// Jen ARP dotazy v malé rychlosti a náhodném pořadí, bez UDP sweepu a bez skenu portů.
    Careful,
    /// ARP vyvolaný UDP „šťouchnutím“, mDNS a UPnP dotazy.
    Normal,
    /// Jako běžný, ale čeká déle (zařízení v úsporném režimu).
    Thorough,
}

impl Mode {
    pub fn parse(s: &str) -> Result<Mode, String> {
        match s {
            "quiet" => Ok(Mode::Quiet),
            "careful" => Ok(Mode::Careful),
            "normal" => Ok(Mode::Normal),
            "thorough" => Ok(Mode::Thorough),
            other => Err(format!("Neznámý režim skenu: {other}")),
        }
    }
}

/// Náhodné pořadí adres, aby sken nevypadal jako souvislé procházení rozsahu.
fn shuffled(mut v: Vec<u32>) -> Vec<u32> {
    let mut x = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(1, |d| d.as_nanos() as u64) | 1;
    for i in (1..v.len()).rev() {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        v.swap(i, (x % (i as u64 + 1)) as usize);
    }
    v
}

#[derive(Default)]
pub struct ScanControl {
    running: AtomicBool,
    cancel: AtomicBool,
}

impl ScanControl {
    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::SeqCst);
    }
}

#[derive(Serialize, Clone)]
pub struct Host {
    ip: String,
    mac: String,
    vendor: Option<String>,
    /// Reverzní DNS.
    hostname: Option<String>,
    /// Nejlepší dostupné jméno (mDNS, UPnP, titulek webu).
    name: Option<String>,
    /// Model zařízení (mDNS TXT, UPnP).
    model: Option<String>,
    /// Čitelný popis služeb, které zařízení nabízí (mDNS, UPnP).
    services: Vec<String>,
    web_title: Option<String>,
    web_server: Option<String>,
    /// Soukromá (náhodná) MAC adresa: telefony a tablety ji používají místo skutečné, výrobce nelze určit.
    private_mac: bool,
    kind: Option<String>,
    ports: Vec<u16>,
    latency_ms: u32,
}

#[derive(Serialize, Clone)]
struct Progress {
    done: usize,
    total: usize,
}

/// Rozsah jako CIDR, "a.b.c.d-e.f.g.h", "a.b.c.d-N" (poslední oktet) nebo jedna adresa.
fn parse_range(text: &str) -> Result<(u32, u32), String> {
    let text = text.trim();
    let ip = |s: &str| s.trim().parse::<Ipv4Addr>().map(u32::from).map_err(|_| format!("Neplatná IPv4 adresa: {s}"));
    let (start, end) = if let Some((a, p)) = text.split_once('/') {
        let prefix: u32 = p.trim().parse().map_err(|_| "Neplatný prefix".to_string())?;
        if !(16..=32).contains(&prefix) {
            return Err("Prefix musí být 16–32 (max. 65 536 adres)".into());
        }
        let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
        let net = ip(a)? & mask;
        let bc = net | !mask;
        if prefix < 31 { (net + 1, bc - 1) } else { (net, bc) }
    } else if let Some((a, b)) = text.split_once('-') {
        let s = ip(a)?;
        let e = if b.contains('.') {
            ip(b)?
        } else {
            let last: u32 = b.trim().parse().map_err(|_| "Neplatný konec rozsahu".to_string())?;
            if last > 255 {
                return Err("Neplatný konec rozsahu".into());
            }
            (s & !0xff) | last
        };
        (s, e)
    } else {
        let s = ip(text)?;
        (s, s)
    };
    if end < start {
        return Err("Konec rozsahu je před začátkem".into());
    }
    if end - start + 1 > MAX_HOSTS {
        return Err("Rozsah je příliš velký (max. 65 536 adres)".into());
    }
    Ok((start, end))
}

/// ARP funguje jen v lokální podsíti: najdi adresu rozhraní, do jehož podsítě rozsah patří.
fn find_source(start: u32, end: u32, ifaces: &[netcfg::Iface]) -> Result<Ipv4Addr, String> {
    for i in ifaces.iter().filter(|i| i.status == "Up") {
        for a in &i.addresses {
            let Ok(ip) = a.ip.parse::<Ipv4Addr>() else { continue };
            if a.prefix == 0 || a.prefix > 32 || a.ip.starts_with("169.254.") {
                continue;
            }
            let mask = if a.prefix == 32 { u32::MAX } else { u32::MAX << (32 - a.prefix as u32) };
            let net = u32::from(ip) & mask;
            if start & mask == net && end & mask == net {
                return Ok(ip);
            }
        }
    }
    Err("Rozsah není v lokální podsíti žádného aktivního rozhraní (zatím je podporován jen ARP sken lokální sítě)".into())
}

/// Jednotlivý ARP dotaz přes SendARP: v opatrném režimu jediný provoz, který sken vyvolá.
fn arp(src: Ipv4Addr, dst: Ipv4Addr) -> Option<([u8; 6], u32)> {
    let mut mac = [0u32; 2];
    let mut len: u32 = 6;
    let t = Instant::now();
    let r = unsafe {
        SendARP(
            u32::from_ne_bytes(dst.octets()),
            u32::from_ne_bytes(src.octets()),
            mac.as_mut_ptr().cast(),
            &mut len,
        )
    };
    if r != 0 || len != 6 {
        return None;
    }
    let (a, b) = (mac[0].to_ne_bytes(), mac[1].to_ne_bytes());
    Some(([a[0], a[1], a[2], a[3], b[0], b[1]], t.elapsed().as_millis() as u32))
}

/// Otevřené porty ze seznamu a nejkratší doba navázání spojení (orientační latence).
fn open_ports(ip: Ipv4Addr) -> (Vec<u16>, Option<u32>) {
    let found = Mutex::new(vec![]);
    std::thread::scope(|s| {
        for &p in PORTS {
            let found = &found;
            s.spawn(move || {
                let addr = SocketAddr::new(IpAddr::V4(ip), p);
                let t = Instant::now();
                if TcpStream::connect_timeout(&addr, Duration::from_millis(600)).is_ok() {
                    found.lock().unwrap().push((p, t.elapsed().as_millis() as u32));
                }
            });
        }
    });
    let mut v = found.into_inner().unwrap();
    v.sort_unstable();
    let best = v.iter().map(|(_, ms)| *ms).min();
    (v.into_iter().map(|(p, _)| p).collect(), best)
}

/// Reverzní DNS s časovým limitem (systémové volání se jinak může zdržet na několik vteřin).
fn reverse_dns(ip: Ipv4Addr) -> Option<String> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(dns_lookup::lookup_addr(&IpAddr::V4(ip)).ok());
    });
    rx.recv_timeout(Duration::from_millis(1500)).ok().flatten().filter(|h| h.parse::<IpAddr>().is_err())
}

/// Odhad typu zařízení z výrobce, otevřených portů a toho, co o sobě zařízení řeklo (mDNS, UPnP).
fn guess_kind(vendor: Option<&str>, ports: &[u16], mdns: Option<&MdnsInfo>, upnp: Option<&UpnpInfo>, private_mac: bool) -> Option<String> {
    let v = vendor.unwrap_or("").to_lowercase();
    let has = |p: u16| ports.contains(&p);
    let svc = |name: &str| mdns.is_some_and(|m| m.services.iter().any(|s| s.contains(name)));
    let model = [mdns.and_then(|m| m.model.as_deref()), upnp.and_then(|u| u.model_name.as_deref())]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase();
    let maker = upnp.and_then(|u| u.manufacturer.as_deref()).unwrap_or("").to_lowercase();
    let is = |needles: &[&str]| needles.iter().any(|n| v.contains(n) || model.contains(n) || maker.contains(n));

    let kind = if svc("_ipp") || svc("_printer") || svc("_pdl-datastream") || svc("_scanner") || has(9100) || is(&["laserjet", "officejet", "deskjet", "printer", "tiskárn"]) {
        "Tiskárna / multifunkce"
    } else if v.contains("mikrotik") || v.contains("routerboard") || ((has(8291) || has(8728)) && vendor.is_none()) {
        "MikroTik / router"
    } else if v.contains("hikvision") || v.contains("dahua") || has(554) || has(8000) || has(37777) {
        "Kamera / NVR"
    } else if svc("_googlecast") && (model.contains("nest") || model.contains("home") || model.contains("chromecast")) {
        "Google Nest / Chromecast"
    } else if svc("_googlecast") || svc("_androidtvremote") {
        "Chromecast / Android TV"
    } else if svc("_airplay") || svc("_companion-link") || model.contains("appletv") {
        "Apple TV / Apple zařízení"
    } else if svc("_hap") || svc("_homekit") || svc("_matter") {
        "Chytrá domácnost"
    } else if svc("_homeconnect") || is(&["bsh", "bosch", "siemens", "neff", "gaggenau"]) {
        "Spotřebič Bosch / BSH"
    } else if v.contains("ubiquiti") {
        "Ubiquiti zařízení"
    } else if v.contains("cisco") || v.contains("juniper") || v.contains("aruba") {
        "Síťový prvek"
    } else if has(3389) {
        "Windows (RDP)"
    } else if svc("_smb") || has(445) || has(139) {
        "Počítač / úložiště (SMB)"
    } else if v.contains("espressif") {
        "IoT zařízení (ESP)"
    } else if ["nothing technology", "oneplus", "oppo", "vivo", "motorola", "samsung", "honor", "realme"].iter().any(|k| v.contains(k)) {
        "Mobil / tablet"
    } else if v.contains("xiaomi") {
        "Zařízení Xiaomi (mobil / IoT)"
    } else if v.contains("apple") {
        "Zařízení Apple"
    } else if private_mac && ports.is_empty() {
        "Mobil / tablet (soukromá MAC)"
    } else if has(22) {
        "Linux / SSH zařízení"
    } else if has(80) || has(443) || has(8080) {
        "Zařízení s webovým rozhraním"
    } else {
        return None;
    };
    Some(kind.to_string())
}

/// `Server` a `<title>` úvodní stránky; jen pro rychlé určení typu zařízení (tiskárny, kamery, brány).
fn http_probe(ip: Ipv4Addr, port: u16) -> (Option<String>, Option<String>) {
    let addr = SocketAddr::new(IpAddr::V4(ip), port);
    let Ok(mut s) = TcpStream::connect_timeout(&addr, Duration::from_millis(700)) else { return (None, None) };
    let _ = s.set_read_timeout(Some(Duration::from_millis(1000)));
    if s.write_all(format!("GET / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: NetScout\r\nConnection: close\r\n\r\n").as_bytes()).is_err() {
        return (None, None);
    }
    let mut buf = Vec::new();
    let mut chunk = [0u8; 2048];
    while buf.len() < 8192 {
        match s.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
    parse_http(&String::from_utf8_lossy(&buf))
}

fn parse_http(resp: &str) -> (Option<String>, Option<String>) {
    let server = resp
        .lines()
        .take_while(|l| !l.trim().is_empty())
        .find_map(|l| l.split_once(':').filter(|(k, _)| k.trim().eq_ignore_ascii_case("server")).map(|(_, v)| v.trim().to_string()))
        .filter(|v| !v.is_empty());
    let lower = resp.to_lowercase();
    let title = lower.find("<title").and_then(|i| {
        let start = lower[i..].find('>')? + i + 1;
        let end = lower[start..].find("</title")? + start;
        // Pozice ve zmenšené kopii odpovídají původnímu textu (bez ohledu na velikost písmen).
        let t = resp.get(start..end)?.split_whitespace().collect::<Vec<_>>().join(" ");
        (!t.is_empty()).then(|| t.chars().take(80).collect())
    });
    (title, server)
}

fn fmt_mac(m: &[u8; 6]) -> String {
    m.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(":")
}

unsafe extern "system" {
    fn GetIpNetTable(table: *mut u8, size: *mut u32, order: i32) -> u32;
}

/// ARP tabulka systému (`GetIpNetTable`): jen vyřešené záznamy (dynamické a statické) s unicast MAC.
fn arp_table() -> Vec<(u32, [u8; 6])> {
    const ROW: usize = 24; // MIB_IPNETROW: index, délka MAC, MAC[8], adresa, typ
    let mut size: u32 = 0;
    unsafe { GetIpNetTable(std::ptr::null_mut(), &mut size, 0) };
    if size == 0 {
        return vec![];
    }
    let mut buf = vec![0u8; size as usize + 4096];
    let mut size = buf.len() as u32;
    if unsafe { GetIpNetTable(buf.as_mut_ptr(), &mut size, 0) } != 0 {
        return vec![];
    }
    let count = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    let mut out = vec![];
    for k in 0..count {
        let Some(row) = buf.get(4 + k * ROW..4 + (k + 1) * ROW) else { break };
        let len = u32::from_ne_bytes([row[4], row[5], row[6], row[7]]);
        let ty = u32::from_ne_bytes([row[20], row[21], row[22], row[23]]);
        let mac: [u8; 6] = row[8..14].try_into().unwrap();
        if len == 6 && (ty == 3 || ty == 4) && mac[0] & 1 == 0 && mac != [0; 6] {
            out.push((u32::from_be_bytes([row[16], row[17], row[18], row[19]]), mac));
        }
    }
    out
}

/// "AA-BB-CC-DD-EE-FF" nebo "AA:BB:…" → bajty (jen unicast).
fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let hex: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hex.len() != 12 {
        return None;
    }
    let mut m = [0u8; 6];
    for (i, b) in m.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    (m[0] & 1 == 0).then_some(m)
}

/// Výsledek průzkumu: zařízení z ARP tabulky a co o sobě řekla přes mDNS a UPnP.
struct Discovered {
    list: Vec<(u32, [u8; 6])>,
    mdns: HashMap<Ipv4Addr, MdnsInfo>,
    upnp: HashMap<Ipv4Addr, UpnpInfo>,
}

/// Najde živá zařízení v lokální podsíti. `SendARP` se při souběžném použití ukázal jako nespolehlivý
/// (ARP dotazy se ztrácely a výsledky se mezi běhy lišily), proto systém donutíme poslat ARP dotazy sám:
/// prázdný UDP datagram na každou adresu spustí překlad adresy v síťovém zásobníku (s jeho vlastním
/// opakováním) a pak přečteme ARP tabulku. Nevyřešené adresy se „šťouchnou“ opakovaně.
/// Mezitím se paralelně ptáme přes mDNS a UPnP, aby se zařízení poznala podle toho, co o sobě říkají.
/// Důkladný režim čeká déle, aby se ozvala i zařízení v úsporném režimu (spotřebiče, tiskárny, telefony).
fn discover(
    src: Ipv4Addr,
    s: u32,
    e: u32,
    mode: Mode,
    cancelled: &(dyn Fn() -> bool + Sync),
    progress: &(dyn Fn(usize) + Sync),
    early: &(dyn Fn(u32, [u8; 6]) + Sync),
) -> Discovered {
    let n = (e - s + 1) as usize;
    let in_range = || arp_table().into_iter().filter(|(ip, _)| (s..=e).contains(ip)).collect::<Vec<_>>();
    let announced: Mutex<HashSet<u32>> = Mutex::new(HashSet::new());
    let announce = |ip: u32, mac: [u8; 6]| {
        // Nově nalezená zařízení se ukážou hned, doplnění údajů přijde po skončení průzkumu.
        if announced.lock().unwrap().insert(ip) {
            early(ip, mac);
        }
    };
    let wait = |ms: u64| {
        let end = Instant::now() + Duration::from_millis(ms);
        while Instant::now() < end && !cancelled() {
            std::thread::sleep(Duration::from_millis(100));
        }
    };

    match mode {
        Mode::Quiet => {
            let listen = Duration::from_secs(12);
            let mdns = std::thread::scope(|scope| {
                let m = scope.spawn(|| mdns::listen(src, listen, cancelled));
                progress(n);
                let end = Instant::now() + listen;
                while Instant::now() < end && !cancelled() {
                    for (ip, mac) in in_range() {
                        announce(ip, mac);
                    }
                    wait(1000);
                }
                m.join().unwrap_or_default()
            });
            Discovered { list: in_range(), mdns, upnp: HashMap::new() }
        }
        Mode::Careful => {
            // Jediný odeslaný provoz jsou ARP dotazy (SendARP), nejvýš 12 dotazů najednou, v náhodném pořadí.
            let order = shuffled((s..=e).collect());
            let next = AtomicUsize::new(0);
            let done = AtomicUsize::new(0);
            let mdns = std::thread::scope(|scope| {
                let m = scope.spawn(|| mdns::listen(src, Duration::from_secs(25), cancelled));
                for _ in 0..12 {
                    scope.spawn(|| loop {
                        let k = next.fetch_add(1, Ordering::SeqCst);
                        if k >= order.len() || cancelled() {
                            break;
                        }
                        let ip = Ipv4Addr::from(order[k]);
                        if ip != src {
                            if let Some((mac, _)) = arp(src, ip) {
                                if mac[0] & 1 == 0 && mac != [0; 6] {
                                    announce(order[k], mac);
                                }
                            }
                        }
                        progress(done.fetch_add(1, Ordering::SeqCst) + 1);
                        std::thread::sleep(Duration::from_millis(200 + (k as u64 * 37) % 200));
                    });
                }
                m.join().unwrap_or_default()
            });
            progress(n);
            Discovered { list: in_range(), mdns, upnp: HashMap::new() }
        }
        Mode::Normal | Mode::Thorough => {
            // `SendARP` se při souběžném použití ukázal jako nespolehlivý (ARP dotazy se ztrácely),
            // proto systém donutíme poslat ARP dotazy sám: prázdný UDP datagram na každou adresu spustí
            // překlad adresy v síťovém zásobníku (s jeho vlastním opakováním) a pak přečteme ARP tabulku.
            let sock = UdpSocket::bind((src, 0)).ok();
            let poke = |skip: &HashSet<u32>| {
                let Some(sock) = &sock else { return };
                for ip in s..=e {
                    if cancelled() {
                        break;
                    }
                    if !skip.contains(&ip) {
                        let _ = sock.send_to(&[0u8], (Ipv4Addr::from(ip), 9));
                    }
                }
            };
            let pauses: &[u64] = if mode == Mode::Thorough { &[3000, 3000, 3000, 3000, 3000, 3000, 2000] } else { &[2500, 2500, 2000] };
            let probe_time = Duration::from_millis(pauses.iter().sum::<u64>().saturating_sub(1500));
            let (mdns, upnp, list) = std::thread::scope(|scope| {
                let m = scope.spawn(|| mdns::probe(src, probe_time, cancelled));
                let u = scope.spawn(|| ssdp::probe(src, probe_time, cancelled));
                poke(&HashSet::new());
                progress(n);
                for (i, pause) in pauses.iter().enumerate() {
                    wait(*pause);
                    let current = in_range();
                    for (ip, mac) in &current {
                        announce(*ip, *mac);
                    }
                    if i + 1 < pauses.len() {
                        let resolved: HashSet<u32> = current.iter().map(|(ip, _)| *ip).collect();
                        poke(&resolved);
                    }
                }
                let (m, u) = (m.join().unwrap_or_default(), u.join().unwrap_or_default());
                (m, u, in_range())
            });
            Discovered { list, mdns, upnp }
        }
    }
}

pub fn start(app: AppHandle, ctl: Arc<ScanControl>, range: String, mode: Mode, ports_scan: bool) -> Result<(), String> {
    if ctl.running.swap(true, Ordering::SeqCst) {
        return Err("Sken již běží".into());
    }
    let setup = (|| {
        let (s, e) = parse_range(&range)?;
        let ifaces = netcfg::list_interfaces()?;
        let src = find_source(s, e, &ifaces)?;
        Ok::<_, String>((s, e, src, ifaces))
    })();
    let (s, e, src, ifaces) = match setup {
        Ok(v) => v,
        Err(err) => {
            ctl.running.store(false, Ordering::SeqCst);
            return Err(err);
        }
    };
    ctl.cancel.store(false, Ordering::SeqCst);

    std::thread::spawn(move || {
        let db = oui::load(&app);
        let n = (e - s + 1) as usize;
        let cancelled = || ctl.cancel.load(Ordering::SeqCst);
        let done = AtomicUsize::new(0);
        let total = AtomicUsize::new(n);
        let progress = || {
            let t = total.load(Ordering::SeqCst);
            let _ = app.emit("scan-progress", Progress { done: done.load(Ordering::SeqCst).min(t), total: t });
        };

        // Adresa je projitá hned po rozeslání dotazů; zbytek času běží čekání na odpovědi.
        let disc = discover(
            src,
            s,
            e,
            mode,
            &cancelled,
            &|k| {
                done.store(k.min(n), Ordering::SeqCst);
                progress();
            },
            &|v, mac| {
                let vendor = oui::lookup(&db, &mac);
                let private_mac = mac[0] & 2 != 0;
                let _ = app.emit(
                    "scan-host",
                    Host {
                        ip: Ipv4Addr::from(v).to_string(),
                        mac: fmt_mac(&mac),
                        kind: guess_kind(vendor.as_deref(), &[], None, None, private_mac),
                        vendor,
                        hostname: None,
                        name: None,
                        model: None,
                        services: vec![],
                        web_title: None,
                        web_server: None,
                        private_mac,
                        ports: vec![],
                        latency_ms: 0,
                    },
                );
            },
        );
        let (mdns_info, upnp_info) = (disc.mdns, disc.upnp);
        let mut list = disc.list;
        // Vlastní adresy počítače systém v ARP tabulce nemá.
        for i in ifaces.iter().filter(|i| i.status == "Up") {
            for a in &i.addresses {
                let Ok(ip) = a.ip.parse::<Ipv4Addr>() else { continue };
                let v = u32::from(ip);
                if (s..=e).contains(&v) && !list.iter().any(|(x, _)| *x == v) {
                    if let Some(mac) = parse_mac(&i.mac) {
                        list.push((v, mac));
                    }
                }
            }
        }
        total.fetch_add(list.len(), Ordering::SeqCst);

        // Doplnění údajů (latence, výrobce, porty, hostname) paralelně po zařízeních.
        let next = AtomicUsize::new(0);
        std::thread::scope(|scope| {
            for _ in 0..REPORT_THREADS.min(list.len()) {
                scope.spawn(|| loop {
                    let k = next.fetch_add(1, Ordering::SeqCst);
                    if k >= list.len() || cancelled() {
                        break;
                    }
                    let (v, mac) = list[k];
                    let ip = Ipv4Addr::from(v);
                    let vendor = oui::lookup(&db, &mac);
                    let (mdns, upnp) = (mdns_info.get(&ip), upnp_info.get(&ip));
                    let private_mac = mac[0] & 2 != 0;
                    let model = mdns
                        .and_then(|m| m.model.clone())
                        .or_else(|| upnp.and_then(|u| u.model_name.clone()).map(|m| match upnp.and_then(|u| u.manufacturer.as_deref()) {
                            Some(maker) if !m.to_lowercase().contains(&maker.to_lowercase()) => format!("{maker} {m}"),
                            _ => m,
                        }));
                    let mut services: Vec<String> = mdns.map(|m| m.services.iter().map(|x| mdns::describe_service(x)).collect()).unwrap_or_default();
                    services.sort();
                    services.dedup();
                    if upnp.is_some() {
                        services.push("UPnP".into());
                    }
                    let local_name = |h: &String| h.trim_end_matches(".local").to_string();
                    let mut name = mdns
                        .and_then(|m| m.friendly.clone().or_else(|| m.hostnames.iter().next().map(local_name)))
                        .or_else(|| upnp.and_then(|u| u.friendly_name.clone()));
                    // Nejdřív zařízení hned ukážeme se základními údaji, doplnění portů a jména přijde chvíli po něm.
                    let mut host = Host {
                        ip: ip.to_string(),
                        mac: fmt_mac(&mac),
                        kind: guess_kind(vendor.as_deref(), &[], mdns, upnp, private_mac),
                        vendor,
                        hostname: None,
                        name: name.clone(),
                        model: model.clone(),
                        services: services.clone(),
                        web_title: None,
                        web_server: None,
                        private_mac,
                        ports: vec![],
                        latency_ms: 0,
                    };
                    let _ = app.emit("scan-host", host.clone());
                    let (ports, latency) = if ports_scan { open_ports(ip) } else { (vec![], None) };
                    host.latency_ms = latency.unwrap_or(0);
                    // Tichý režim nic neodesílá, tedy ani dotazy na DNS.
                    if mode != Mode::Quiet {
                        host.hostname = reverse_dns(ip);
                    }
                    if let Some(port) = [80u16, 8080, 8000].into_iter().find(|p| ports.contains(p)) {
                        let (title, server) = http_probe(ip, port);
                        host.web_title = title;
                        host.web_server = server;
                    }
                    if name.is_none() {
                        let useful = |t: &String| {
                            t.len() > 2 && !["error", "index", "untitled", "document", "home", "welcome", "login", "not found", "unauthorized"].iter().any(|g| t.to_lowercase().starts_with(g))
                        };
                        name = host.web_title.clone().filter(useful).or_else(|| host.hostname.clone());
                        host.name = name;
                    }
                    host.kind = guess_kind(host.vendor.as_deref(), &ports, mdns, upnp, private_mac).or_else(|| {
                        host.web_title.as_deref().filter(|t| ["hp ", "laserjet", "officejet", "printer"].iter().any(|k| t.to_lowercase().contains(k))).map(|_| "Tiskárna / multifunkce".to_string())
                    });
                    host.ports = ports;
                    let _ = app.emit("scan-host", host);
                    done.fetch_add(1, Ordering::SeqCst);
                    progress();
                });
            }
        });
        let t = total.load(Ordering::SeqCst);
        done.store(t, Ordering::SeqCst);
        progress();
        let was_cancelled = cancelled();
        ctl.running.store(false, Ordering::SeqCst);
        let _ = app.emit("scan-done", was_cancelled);
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(s: &str) -> Result<(Ipv4Addr, Ipv4Addr), String> {
        parse_range(s).map(|(a, b)| (Ipv4Addr::from(a), Ipv4Addr::from(b)))
    }

    #[test]
    fn ranges() {
        assert_eq!(r("192.168.1.0/24").unwrap(), ("192.168.1.1".parse().unwrap(), "192.168.1.254".parse().unwrap()));
        assert_eq!(r("10.0.0.5-20").unwrap().1, "10.0.0.20".parse::<Ipv4Addr>().unwrap());
        assert_eq!(r("10.0.0.5-10.0.0.9").unwrap().1, "10.0.0.9".parse::<Ipv4Addr>().unwrap());
        assert_eq!(r("10.0.0.7").unwrap().0, r("10.0.0.7").unwrap().1);
        assert!(r("10.0.0.0/8").is_err());
        assert!(r("10.0.0.9-3").is_err());
        assert!(r("abc").is_err());
    }

    #[test]
    fn http_title_and_server() {
        let (t, srv) = parse_http("HTTP/1.0 200 OK\r\nServer: HP HTTP Server; HP Color LaserJet MFP M477fdn\r\n\r\n<html><HEAD><TITLE> HP Color LaserJet\n MFP M477fdn </TITLE></HEAD>");
        assert_eq!(t.as_deref(), Some("HP Color LaserJet MFP M477fdn"));
        assert_eq!(srv.as_deref(), Some("HP HTTP Server; HP Color LaserJet MFP M477fdn"));
        assert_eq!(parse_http("garbage"), (None, None));
    }

    #[test]
    fn kind_from_mdns_and_private_mac() {
        let mut m = MdnsInfo::default();
        m.services.insert("_ipp._tcp".into());
        assert_eq!(guess_kind(None, &[], Some(&m), None, false).as_deref(), Some("Tiskárna / multifunkce"));
        assert_eq!(guess_kind(None, &[], None, None, true).as_deref(), Some("Mobil / tablet (soukromá MAC)"));
        assert_eq!(guess_kind(Some("BSH Hausgeraete GmbH"), &[], None, None, false).as_deref(), Some("Spotřebič Bosch / BSH"));
        assert_eq!(guess_kind(None, &[], None, None, false), None);
        // HP tiskárna s otevřeným portem 8291 není MikroTik.
        assert_eq!(guess_kind(Some("Hewlett Packard"), &[80, 8291, 9100], None, None, false).as_deref(), Some("Tiskárna / multifunkce"));
        assert_eq!(guess_kind(Some("Hewlett Packard"), &[8291], None, None, false), None);
        assert_eq!(guess_kind(Some("Routerboard.com"), &[], None, None, false).as_deref(), Some("MikroTik / router"));
        assert_eq!(guess_kind(Some("Nothing Technology Limited"), &[], None, None, false).as_deref(), Some("Mobil / tablet"));
    }

    #[test]
    fn mac_parsing() {
        assert_eq!(parse_mac("2C-C8-1B-41-6E-9A"), Some([0x2c, 0xc8, 0x1b, 0x41, 0x6e, 0x9a]));
        assert!(parse_mac("2c:c8:1b:41:6e:9a").is_some());
        assert_eq!(parse_mac("FF-FF-FF-FF-FF-FF"), None);
        assert_eq!(parse_mac("01-00-5E-00-00-FB"), None);
        assert_eq!(parse_mac("zz"), None);
    }

    /// Živý test: ARP tabulka systému se dá přečíst a obsahuje jen unicast MAC.
    #[test]
    #[ignore]
    fn live_arp_table() {
        let t = arp_table();
        println!("položek: {}", t.len());
        for (ip, mac) in t.iter().take(6) {
            println!("  {} {}", Ipv4Addr::from(*ip), fmt_mac(mac));
        }
        assert!(t.iter().all(|(_, m)| m[0] & 1 == 0));
    }

    /// Živý test: opakované běhy discover() na /24 musí dávat stabilní výsledek.
    #[test]
    #[ignore]
    fn live_discover_stable() {
        let ifaces = netcfg::list_interfaces().unwrap();
        let (src, prefix) = ifaces
            .iter()
            .filter(|i| i.status == "Up")
            .flat_map(|i| i.addresses.iter())
            .find_map(|a| a.ip.parse::<Ipv4Addr>().ok().filter(|ip| !ip.is_link_local() && a.prefix == 24).map(|ip| (ip, a.prefix)))
            .expect("žádné rozhraní s /24");
        let _ = prefix;
        let base = u32::from(src) & !0xff;
        for run in 1..=3 {
            let t = Instant::now();
            let found = discover(src, base + 1, base + 254, Mode::Normal, &|| false, &|_| {}, &|_, _| {}).list;
            let mut ips: Vec<String> = found.iter().map(|(ip, _)| Ipv4Addr::from(*ip).to_string().rsplit('.').next().unwrap().to_string()).collect();
            ips.sort_by_key(|x| x.parse::<u32>().unwrap());
            println!("běh {run}: {} zařízení za {} ms: {}", found.len(), t.elapsed().as_millis(), ips.join(","));
        }
    }

    /// Živý test: ARP na výchozí bránu aktivního rozhraní (jen pro lokální ruční spuštění).
    #[test]
    #[ignore]
    fn live_arp() {
        let ifaces = netcfg::list_interfaces().unwrap();
        let i = ifaces.iter().find(|i| i.status == "Up" && i.gateway.is_some()).unwrap();
        let src: Ipv4Addr = i.addresses[0].ip.parse().unwrap();
        let gw: Ipv4Addr = i.gateway.clone().unwrap().parse().unwrap();
        let (mac, ms) = arp(src, gw).expect("brána neodpověděla");
        println!("GW {gw} -> {} ({ms} ms)", fmt_mac(&mac));
    }

    /// Živý test: porovná počet nalezených zařízení v jednotlivých režimech (potřebuje reálnou síť).
    #[test]
    #[ignore]
    fn live_modes() {
        let ifaces = netcfg::list_interfaces().unwrap();
        let src = ifaces
            .iter()
            .filter(|i| i.status == "Up")
            .flat_map(|i| i.addresses.iter())
            .find_map(|a| a.ip.parse::<Ipv4Addr>().ok().filter(|ip| !ip.is_link_local() && (16..=24).contains(&a.prefix)))
            .expect("rozhraní s podsítí /16–/24");
        let base = u32::from(src) & !0xff;
        // Běžný režim se záměrně nezkouší: test může běžet na cizí síti s ochranou proti skenování.
        for mode in [Mode::Quiet, Mode::Careful] {
            let t = Instant::now();
            let d = discover(src, base + 1, base + 254, mode, &|| false, &|_| {}, &|_, _| {});
            println!("{mode:?}: {} zařízení, mDNS {}, {} s", d.list.len(), d.mdns.len(), t.elapsed().as_secs());
        }
    }
}
