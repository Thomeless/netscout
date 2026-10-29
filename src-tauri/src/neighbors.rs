// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Tomáš Nesrsta
//! Neighbour discovery: aktivní dotazy (probe) na každém aktivním rozhraní + pasivní poslech MNDP.
//! Protokoly: MikroTik MNDP, Ubiquiti discovery, Hikvision SADP, ONVIF WS-Discovery.

use crate::proto::{self, Neighbor};
use crate::l2cap;
use crate::{netcfg, oui};
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tauri::{AppHandle, Emitter};

const PROBE_EVERY: Duration = Duration::from_secs(3);

#[derive(Default)]
pub struct NeighborControl {
    running: AtomicBool,
    stop: AtomicBool,
}

impl NeighborControl {
    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
    }
    pub fn running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }
}

#[derive(Clone, Copy)]
enum Kind {
    Mndp,
    Ubnt,
    Sadp,
    Onvif,
}

const KINDS: [Kind; 4] = [Kind::Mndp, Kind::Ubnt, Kind::Sadp, Kind::Onvif];

impl Kind {
    fn dest(self) -> SocketAddrV4 {
        match self {
            Kind::Mndp => SocketAddrV4::new(Ipv4Addr::BROADCAST, 5678),
            Kind::Ubnt => SocketAddrV4::new(Ipv4Addr::BROADCAST, 10001),
            Kind::Sadp => SocketAddrV4::new(Ipv4Addr::new(239, 255, 255, 250), 37020),
            Kind::Onvif => SocketAddrV4::new(Ipv4Addr::new(239, 255, 255, 250), 3702),
        }
    }

    fn multicast(self) -> bool {
        matches!(self, Kind::Sadp | Kind::Onvif)
    }

    fn probe(self) -> Vec<u8> {
        match self {
            Kind::Mndp => vec![0, 0, 0, 0],
            Kind::Ubnt => vec![1, 0, 0, 0],
            Kind::Sadp => format!(
                "<?xml version=\"1.0\" encoding=\"utf-8\"?><Probe><Uuid>{}</Uuid><Types>inquiry</Types></Probe>",
                uuid().to_uppercase()
            )
            .into_bytes(),
            Kind::Onvif => format!(
                "<?xml version=\"1.0\" encoding=\"utf-8\"?><e:Envelope xmlns:e=\"http://www.w3.org/2003/05/soap-envelope\" \
                 xmlns:w=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" \
                 xmlns:d=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\" \
                 xmlns:dn=\"http://www.onvif.org/ver10/network/wsdl\"><e:Header><w:MessageID>uuid:{}</w:MessageID>\
                 <w:To e:mustUnderstand=\"true\">urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>\
                 <w:Action e:mustUnderstand=\"true\">http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action></e:Header>\
                 <e:Body><d:Probe><d:Types>dn:NetworkVideoTransmitter</d:Types></d:Probe></e:Body></e:Envelope>",
                uuid()
            )
            .into_bytes(),
        }
    }

    fn parse(self, data: &[u8], from: SocketAddr) -> Option<Neighbor> {
        match self {
            Kind::Mndp => proto::parse_mndp(data, from),
            Kind::Ubnt => proto::parse_ubnt(data, from),
            Kind::Sadp => proto::parse_sadp(data, from),
            Kind::Onvif => proto::parse_onvif(data, from),
        }
    }
}

/// Pseudonáhodné UUID (stačí pro identifikaci dotazu, nejde o bezpečnostní prvek).
fn uuid() -> String {
    let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_nanos());
    let h = t.wrapping_mul(0x9E37_79B9_7F4A_7C15_F39C_C060_5CED_C835);
    let s = format!("{h:032x}");
    format!("{}-{}-4{}-a{}-{}", &s[0..8], &s[8..12], &s[13..16], &s[17..20], &s[20..32])
}

struct Local {
    name: String,
    ip: Ipv4Addr,
    prefix: u8,
}

fn same_subnet(l: &Local, ip: Ipv4Addr) -> bool {
    let mask = if l.prefix >= 32 { u32::MAX } else { u32::MAX << (32 - l.prefix as u32) };
    u32::from(l.ip) & mask == u32::from(ip) & mask
}

fn probe_socket(local: Ipv4Addr, kind: Kind) -> std::io::Result<UdpSocket> {
    let s = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    s.set_broadcast(true)?;
    s.bind(&SocketAddrV4::new(local, 0).into())?;
    if kind.multicast() {
        s.set_multicast_if_v4(&local)?;
        s.set_multicast_ttl_v4(2)?;
        s.set_multicast_loop_v4(false)?;
    }
    s.set_read_timeout(Some(Duration::from_millis(500)))?;
    Ok(s.into())
}

/// Pasivní poslech MNDP: zařízení MikroTik vysílají broadcast na UDP 5678 sama (typicky po 60 s).
fn passive_mndp() -> std::io::Result<UdpSocket> {
    let s = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    s.set_reuse_address(true)?;
    s.set_broadcast(true)?;
    s.bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 5678).into())?;
    s.set_read_timeout(Some(Duration::from_millis(500)))?;
    Ok(s.into())
}

fn worker(app: &AppHandle, ctl: &NeighborControl, sock: UdpSocket, kind: Kind, locals: &[Local], bound: Option<&Local>) {
    let mut buf = vec![0u8; 8192];
    let mut last_probe: Option<Instant> = None;
    while !ctl.stop.load(Ordering::SeqCst) {
        if bound.is_some() && last_probe.is_none_or(|t| t.elapsed() >= PROBE_EVERY) {
            let _ = sock.send_to(&kind.probe(), kind.dest());
            last_probe = Some(Instant::now());
        }
        let Ok((n, from)) = sock.recv_from(&mut buf) else { continue };
        let Some(mut nb) = kind.parse(&buf[..n], from) else { continue };
        nb.local_iface = match bound {
            Some(l) => l.name.clone(),
            None => match from.ip() {
                std::net::IpAddr::V4(ip) => locals.iter().find(|l| same_subnet(l, ip)).map(|l| l.name.clone()).unwrap_or_default(),
                _ => String::new(),
            },
        };
        let _ = app.emit("neighbor", nb);
    }
}

const L2_FILTER: &str = "ether dst 01:00:0c:cc:cc:cc or ether dst 01:80:c2:00:00:0e or ether dst 01:80:c2:00:00:03 or ether dst 01:80:c2:00:00:00";

/// Otevře pasivní zachytávání CDP/LLDP na každém rozhraní (vyžaduje Npcap / wpcap.dll).
fn open_captures(locals: &[Local]) -> Result<Vec<(l2cap::Capture, usize)>, String> {
    let api = l2cap::Api::load().map_err(|e| format!("CDP/LLDP vypnuto: {e}"))?;
    let devs = api.devices().map_err(|e| format!("CDP/LLDP vypnuto, Npcap neodpovídá: {e}"))?;
    let mut seen = vec![];
    let mut out = vec![];
    for (idx, l) in locals.iter().enumerate() {
        let Some(dev) = devs.iter().find(|d| d.addrs.contains(&l.ip)) else { continue };
        if seen.contains(&dev.name) {
            continue;
        }
        seen.push(dev.name.clone());
        match api.open(&dev.name, L2_FILTER) {
            Ok(c) => out.push((c, idx)),
            Err(e) => return Err(format!("CDP/LLDP na {} se nepodařilo spustit: {e}", l.name)),
        }
    }
    if out.is_empty() {
        return Err("CDP/LLDP vypnuto: Npcap nenabízí žádné odpovídající rozhraní (je nainstalován ovladač Npcap?)".into());
    }
    Ok(out)
}

fn capture_worker(app: &AppHandle, ctl: &NeighborControl, mut cap: l2cap::Capture, local: &Local, db: &oui::Db) {
    while !ctl.stop.load(Ordering::SeqCst) {
        let frame = match cap.next() {
            Ok(Some(f)) => f,
            Ok(None) => continue,
            Err(_) => break,
        };
        let Some(mut nb) = proto::parse_cdp(&frame).or_else(|| proto::parse_lldp(&frame)) else { continue };
        if let Ok(src) = <[u8; 6]>::try_from(&frame[6..12]) {
            nb.vendor = oui::lookup(db, &src).unwrap_or_default();
        }
        nb.local_iface = local.name.clone();
        let _ = app.emit("neighbor", nb);
    }
}

pub fn start(app: AppHandle, ctl: Arc<NeighborControl>) -> Result<(), String> {
    if ctl.running.swap(true, Ordering::SeqCst) {
        return Err("Discovery již běží".into());
    }
    let locals: Result<Vec<Local>, String> = netcfg::list_interfaces().map(|ifaces| {
        ifaces
            .iter()
            .filter(|i| i.status == "Up")
            .flat_map(|i| {
                i.addresses.iter().filter_map(move |a| {
                    let ip = a.ip.parse::<Ipv4Addr>().ok()?;
                    (!ip.is_link_local() && !ip.is_loopback()).then(|| Local { name: i.name.clone(), ip, prefix: a.prefix })
                })
            })
            .collect()
    });
    let locals = match locals {
        Ok(l) if !l.is_empty() => l,
        Ok(_) => {
            ctl.running.store(false, Ordering::SeqCst);
            return Err("Žádné aktivní rozhraní s IPv4 adresou".into());
        }
        Err(e) => {
            ctl.running.store(false, Ordering::SeqCst);
            return Err(e);
        }
    };
    ctl.stop.store(false, Ordering::SeqCst);

    std::thread::spawn(move || {
        let mut socks: Vec<(UdpSocket, Kind, Option<usize>)> = vec![];
        for (idx, l) in locals.iter().enumerate() {
            for k in KINDS {
                if let Ok(s) = probe_socket(l.ip, k) {
                    socks.push((s, k, Some(idx)));
                }
            }
        }
        if let Ok(s) = passive_mndp() {
            socks.push((s, Kind::Mndp, None));
        }
        let db = oui::load(&app);
        let caps = open_captures(&locals).unwrap_or_else(|e| {
            let _ = app.emit("neighbors-warn", e);
            vec![]
        });
        std::thread::scope(|scope| {
            for (cap, idx) in caps {
                let (app, ctl, local, db) = (&app, &*ctl, &locals[idx], &db);
                scope.spawn(move || capture_worker(app, ctl, cap, local, db));
            }
            for (sock, kind, idx) in socks {
                let (app, ctl, locals) = (&app, &*ctl, &locals);
                scope.spawn(move || worker(app, ctl, sock, kind, locals, idx.map(|i| &locals[i])));
            }
        });
        ctl.running.store(false, Ordering::SeqCst);
        let _ = app.emit("neighbors-done", ());
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Živý test: vytvoří sockety na aktivních rozhraních, odešle probe a poslouchá pár sekund.
    #[test]
    #[ignore]
    fn live_probe() {
        let ifaces = netcfg::list_interfaces().unwrap();
        let ip: Ipv4Addr = ifaces
            .iter()
            .filter(|i| i.status == "Up")
            .flat_map(|i| i.addresses.iter())
            .find_map(|a| a.ip.parse().ok().filter(|ip: &Ipv4Addr| !ip.is_link_local()))
            .unwrap();
        println!("lokální IP {ip}");
        let mut socks = vec![];
        for k in KINDS {
            let s = probe_socket(ip, k).map_err(|e| println!("socket selhal: {e}")).ok();
            if let Some(s) = &s {
                println!("probe odeslán: {:?}", s.send_to(&k.probe(), k.dest()));
            }
            socks.push(s);
        }
        println!("pasivní MNDP: {:?}", passive_mndp().map(|_| ()));
        let end = Instant::now() + Duration::from_secs(4);
        let mut buf = [0u8; 4096];
        while Instant::now() < end {
            for (i, s) in socks.iter().enumerate() {
                if let Some(s) = s {
                    if let Ok((n, from)) = s.recv_from(&mut buf) {
                        println!("odpověď kind {i} od {from} ({n} B)");
                    }
                }
            }
        }
    }

    /// Živý test: otevře CDP/LLDP zachytávání na aktivních rozhraních (potřebuje Npcap a práva správce).
    #[test]
    #[ignore]
    fn live_capture_open() {
        let locals: Vec<Local> = netcfg::list_interfaces()
            .unwrap()
            .iter()
            .filter(|i| i.status == "Up")
            .flat_map(|i| {
                i.addresses.iter().filter_map(move |a| {
                    let ip = a.ip.parse::<Ipv4Addr>().ok().filter(|ip| !ip.is_link_local())?;
                    Some(Local { name: i.name.clone(), ip, prefix: a.prefix })
                })
            })
            .collect();
        match open_captures(&locals) {
            Ok(c) => println!("otevřeno zachytávání: {} rozhraní", c.len()),
            Err(e) => println!("CHYBA: {e}"),
        }
    }
}
