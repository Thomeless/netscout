// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Tomáš Nesrsta
//! IP sken lokální sítě: ARP (SendARP), reverzní DNS, základní TCP porty, výrobce z OUI.

use crate::{netcfg, oui};
use serde::Serialize;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tauri::{AppHandle, Emitter};
use windows_sys::Win32::NetworkManagement::IpHelper::SendARP;

const MAX_HOSTS: u32 = 65_536;
const MAX_THREADS: usize = 128;
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

fn open_ports(ip: Ipv4Addr) -> Vec<u16> {
    let found = Mutex::new(vec![]);
    std::thread::scope(|s| {
        for &p in PORTS {
            let found = &found;
            s.spawn(move || {
                let addr = SocketAddr::new(IpAddr::V4(ip), p);
                if TcpStream::connect_timeout(&addr, Duration::from_millis(600)).is_ok() {
                    found.lock().unwrap().push(p);
                }
            });
        }
    });
    let mut v = found.into_inner().unwrap();
    v.sort_unstable();
    v
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

pub fn start(app: AppHandle, ctl: Arc<ScanControl>, range: String) -> Result<(), String> {
    if ctl.running.swap(true, Ordering::SeqCst) {
        return Err("Sken již běží".into());
    }
    let setup = (|| {
        let (s, e) = parse_range(&range)?;
        let src = find_source(s, e, &netcfg::list_interfaces()?)?;
        Ok::<_, String>((s, e, src))
    })();
    let (s, e, src) = match setup {
        Ok(v) => v,
        Err(err) => {
            ctl.running.store(false, Ordering::SeqCst);
            return Err(err);
        }
    };
    ctl.cancel.store(false, Ordering::SeqCst);

    std::thread::spawn(move || {
        let db = oui::load(&app);
        let total = (e - s + 1) as usize;
        let next = AtomicUsize::new(0);
        let done = AtomicUsize::new(0);
        std::thread::scope(|scope| {
            for _ in 0..total.min(MAX_THREADS) {
                scope.spawn(|| loop {
                    let i = next.fetch_add(1, Ordering::SeqCst);
                    if i >= total || ctl.cancel.load(Ordering::SeqCst) {
                        break;
                    }
                    let ip = Ipv4Addr::from(s + i as u32);
                    if let Some((mac, latency_ms)) = arp(src, ip) {
                        let vendor = oui::lookup(&db, &mac);
                        let ports = open_ports(ip);
                        let hostname = dns_lookup::lookup_addr(&IpAddr::V4(ip))
                            .ok()
                            .filter(|h| h.parse::<IpAddr>().is_err());
                        let kind = guess_kind(vendor.as_deref(), &ports);
                        let _ = app.emit(
                            "scan-host",
                            Host { ip: ip.to_string(), mac: fmt_mac(&mac), vendor, hostname, kind, ports, latency_ms },
                        );
                    }
                    let d = done.fetch_add(1, Ordering::SeqCst) + 1;
                    if d % 4 == 0 || d == total {
                        let _ = app.emit("scan-progress", Progress { done: d, total });
                    }
                });
            }
        });
        let cancelled = ctl.cancel.load(Ordering::SeqCst);
        ctl.running.store(false, Ordering::SeqCst);
        let _ = app.emit("scan-done", cancelled);
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
