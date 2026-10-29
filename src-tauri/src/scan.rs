// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Tomáš Nesrsta
//! IP sken lokální sítě: ARP (SendARP), reverzní DNS, základní TCP porty, výrobce z OUI.

use crate::{netcfg, oui};
use serde::Serialize;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tauri::{AppHandle, Emitter};
#[cfg(test)]
use windows_sys::Win32::NetworkManagement::IpHelper::SendARP;

const MAX_HOSTS: u32 = 65_536;
const REPORT_THREADS: usize = 24;
const PORTS: &[u16] = &[21, 22, 23, 53, 80, 139, 443, 445, 554, 3389, 8000, 8080, 8291, 8728, 9100, 37777];

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
    hostname: Option<String>,
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

/// Jednotlivý ARP dotaz přes SendARP (jen pro diagnostické testy; při souběhu je nespolehlivý).
#[cfg(test)]
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

/// Hrubý odhad typu zařízení z otevřených portů a výrobce.
fn guess_kind(vendor: Option<&str>, ports: &[u16]) -> Option<String> {
    let v = vendor.unwrap_or("").to_lowercase();
    let has = |p: u16| ports.contains(&p);
    let kind = if v.contains("mikrotik") || v.contains("routerboard") || has(8291) || has(8728) {
        "MikroTik / router"
    } else if v.contains("hikvision") || v.contains("dahua") || has(554) || has(8000) || has(37777) {
        "Kamera / NVR"
    } else if v.contains("ubiquiti") {
        "Ubiquiti zařízení"
    } else if v.contains("cisco") || v.contains("juniper") || v.contains("aruba") {
        "Síťový prvek"
    } else if has(9100) {
        "Tiskárna"
    } else if has(3389) {
        "Windows (RDP)"
    } else if has(445) || has(139) {
        "Windows / SMB"
    } else if has(22) {
        "Linux / SSH zařízení"
    } else if has(80) || has(443) || has(8080) {
        "Zařízení s webovým rozhraním"
    } else {
        return None;
    };
    Some(kind.to_string())
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

/// Najde živá zařízení v lokální podsíti. `SendARP` se při souběžném použití ukázal jako nespolehlivý
/// (ARP dotazy se ztrácely a výsledky se mezi běhy lišily), proto systém donutíme poslat ARP dotazy sám:
/// prázdný UDP datagram na každou adresu spustí překlad adresy v síťovém zásobníku (s jeho vlastním
/// opakováním) a pak přečteme ARP tabulku. Nevyřešené adresy se „šťouchnou“ ještě jednou.
fn discover(src: Ipv4Addr, s: u32, e: u32, cancelled: &dyn Fn() -> bool, poked: &dyn Fn()) -> Vec<(u32, [u8; 6])> {
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
    let wait = |ms: u64| {
        let end = Instant::now() + Duration::from_millis(ms);
        while Instant::now() < end && !cancelled() {
            std::thread::sleep(Duration::from_millis(100));
        }
    };
    let in_range = || arp_table().into_iter().filter(|(ip, _)| (s..=e).contains(ip)).collect::<Vec<_>>();

    poke(&HashSet::new());
    poked();
    for pause in [2500, 2500, 2000] {
        wait(pause);
        let resolved: HashSet<u32> = in_range().iter().map(|(ip, _)| *ip).collect();
        if pause != 2000 {
            poke(&resolved);
        }
    }
    in_range()
}

pub fn start(app: AppHandle, ctl: Arc<ScanControl>, range: String) -> Result<(), String> {
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
        let mut list = discover(src, s, e, &cancelled, &|| {
            done.store(n, Ordering::SeqCst);
            progress();
        });
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
                    // Nejdřív zařízení hned ukážeme se základními údaji, doplnění portů a jména přijde chvíli po něm.
                    let mut host = Host {
                        ip: ip.to_string(),
                        mac: fmt_mac(&mac),
                        kind: guess_kind(vendor.as_deref(), &[]),
                        vendor,
                        hostname: None,
                        ports: vec![],
                        latency_ms: 0,
                    };
                    let _ = app.emit("scan-host", host.clone());
                    let (ports, latency) = open_ports(ip);
                    host.latency_ms = latency.unwrap_or(0);
                    host.kind = guess_kind(host.vendor.as_deref(), &ports);
                    host.ports = ports;
                    host.hostname = reverse_dns(ip);
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
            let found = discover(src, base + 1, base + 254, &|| false, &|| {});
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
}
