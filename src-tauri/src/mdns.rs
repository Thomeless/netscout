// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Tomáš Nesrsta
//! mDNS / DNS-SD (UDP 5353): zařízení se samy popíšou (jméno, služby, model v TXT záznamech).
//! Telefony (Pixel), tiskárny (HP), chytré spotřebiče a TV se tak dají poznat i bez otevřených portů.

use socket2::{Domain, Protocol, Socket, Type};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::time::{Duration, Instant};

const GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);

/// Co o zařízení vyplynulo z mDNS odpovědí.
#[derive(Default, Clone, Debug, PartialEq)]
pub struct MdnsInfo {
    /// Jména hostitele (`pixel-8.local`).
    pub hostnames: BTreeSet<String>,
    /// Typy služeb (`_ipp._tcp`).
    pub services: BTreeSet<String>,
    /// Názvy instancí (`HP LaserJet Pro M404 [ABC123]`).
    pub instances: BTreeSet<String>,
    /// Model / typ z TXT záznamů.
    pub model: Option<String>,
    /// Přátelské jméno z TXT (`fn`).
    pub friendly: Option<String>,
}

/// Služby, na které se ptáme hned; další se doplní z výčtu `_services._dns-sd._udp`.
const KNOWN: &[&str] = &[
    "_services._dns-sd._udp", "_ipp._tcp", "_ipps._tcp", "_printer._tcp", "_pdl-datastream._tcp", "_scanner._tcp",
    "_http._tcp", "_https._tcp", "_googlecast._tcp", "_airplay._tcp", "_raop._tcp", "_hap._tcp", "_homekit._tcp",
    "_workstation._tcp", "_device-info._tcp", "_smb._tcp", "_companion-link._tcp", "_androidtvremote2._tcp",
    "_spotify-connect._tcp", "_matter._tcp", "_matterc._udp", "_meshcop._udp", "_homeconnect._tcp", "_sleep-proxy._udp",
];

// ---------------------------------------------------------------- DNS zpráva

fn put_name(out: &mut Vec<u8>, name: &str) {
    for label in name.split('.').filter(|l| !l.is_empty()) {
        out.push(label.len().min(63) as u8);
        out.extend_from_slice(&label.as_bytes()[..label.len().min(63)]);
    }
    out.push(0);
}

/// Dotaz PTR pro seznam služeb (`<typ>.local`), s bitem QU = „odpověz mi přímo (unicast)“.
pub fn build_query(types: &[&str]) -> Vec<u8> {
    let mut q = vec![0, 0, 0, 0];
    q.extend((types.len() as u16).to_be_bytes());
    q.extend([0, 0, 0, 0, 0, 0]);
    for t in types {
        put_name(&mut q, &format!("{t}.local"));
        q.extend(12u16.to_be_bytes());
        q.extend(0x8001u16.to_be_bytes());
    }
    q
}

/// Jméno v DNS zprávě včetně komprese; vrací jméno a pozici za ním.
fn read_name(msg: &[u8], start: usize) -> Option<(String, usize)> {
    let mut name = String::new();
    let mut pos = start;
    let mut end = None;
    for _ in 0..40 {
        let len = *msg.get(pos)? as usize;
        if len == 0 {
            return Some((name, end.unwrap_or(pos + 1)));
        }
        if len & 0xC0 == 0xC0 {
            let ptr = ((len & 0x3F) << 8) | *msg.get(pos + 1)? as usize;
            end.get_or_insert(pos + 2);
            pos = ptr;
        } else {
            let label = msg.get(pos + 1..pos + 1 + len)?;
            if !name.is_empty() {
                name.push('.');
            }
            name.push_str(&String::from_utf8_lossy(label));
            pos += 1 + len;
        }
    }
    None
}

#[derive(Debug)]
enum Rdata {
    A,
    Ptr(String),
    Srv(String),
    Txt(Vec<(String, String)>),
    Other,
}

struct Record {
    name: String,
    rdata: Rdata,
}

fn parse_records(msg: &[u8]) -> Vec<Record> {
    let mut out = vec![];
    if msg.len() < 12 {
        return out;
    }
    let qd = u16::from_be_bytes([msg[4], msg[5]]) as usize;
    let rr = u16::from_be_bytes([msg[6], msg[7]]) as usize + u16::from_be_bytes([msg[8], msg[9]]) as usize + u16::from_be_bytes([msg[10], msg[11]]) as usize;
    let mut pos = 12;
    for _ in 0..qd {
        let Some((_, p)) = read_name(msg, pos) else { return out };
        pos = p + 4;
    }
    for _ in 0..rr {
        let Some((name, p)) = read_name(msg, pos) else { break };
        let Some(h) = msg.get(p..p + 10) else { break };
        let ty = u16::from_be_bytes([h[0], h[1]]);
        let len = u16::from_be_bytes([h[8], h[9]]) as usize;
        let start = p + 10;
        let Some(data) = msg.get(start..start + len) else { break };
        let rdata = match ty {
            1 if len == 4 => Rdata::A,
            12 => read_name(msg, start).map_or(Rdata::Other, |(n, _)| Rdata::Ptr(n)),
            33 if len > 6 => read_name(msg, start + 6).map_or(Rdata::Other, |(n, _)| Rdata::Srv(n)),
            16 => {
                let mut kv = vec![];
                let mut i = 0;
                while i < data.len() {
                    let l = data[i] as usize;
                    let Some(s) = data.get(i + 1..i + 1 + l) else { break };
                    let text = String::from_utf8_lossy(s);
                    if let Some((k, v)) = text.split_once('=') {
                        kv.push((k.to_string(), v.to_string()));
                    }
                    i += 1 + l;
                }
                Rdata::Txt(kv)
            }
            _ => Rdata::Other,
        };
        out.push(Record { name, rdata });
        pos = start + len;
    }
    out
}

/// Typ služby z názvu instance (`HP Tisk._ipp._tcp.local` → `_ipp._tcp`).
fn service_of(instance: &str) -> Option<String> {
    let lower = instance.trim_end_matches('.');
    let base = lower.strip_suffix(".local").unwrap_or(lower);
    let parts: Vec<&str> = base.split('.').collect();
    let i = parts.iter().position(|p| p.starts_with('_'))?;
    (parts.len() >= i + 2).then(|| format!("{}.{}", parts[i], parts[i + 1]))
}

/// Zapracuje obsah jedné odpovědi do údajů o zařízení, které odpovědělo. Vrací nové typy služeb.
pub fn absorb(info: &mut MdnsInfo, msg: &[u8]) -> Vec<String> {
    let mut new_types = vec![];
    for r in parse_records(msg) {
        match r.rdata {
            Rdata::Ptr(target) => {
                if r.name.starts_with("_services._dns-sd") {
                    // Výčet typů služeb zařízení.
                    new_types.push(target.trim_end_matches(".local").trim_end_matches('.').to_string());
                } else if let Some(svc) = service_of(&target) {
                    info.services.insert(svc);
                    let inst = target.split("._").next().unwrap_or(&target).to_string();
                    if !inst.is_empty() {
                        info.instances.insert(inst);
                    }
                }
            }
            Rdata::Srv(host) => {
                info.hostnames.insert(host.trim_end_matches('.').to_string());
                if let Some(svc) = service_of(&r.name) {
                    info.services.insert(svc);
                }
            }
            Rdata::A => {
                if !r.name.contains("._") {
                    info.hostnames.insert(r.name.trim_end_matches('.').to_string());
                }
            }
            Rdata::Txt(kv) => {
                let map: BTreeMap<String, String> = kv.into_iter().map(|(k, v)| (k.to_lowercase(), v)).collect();
                // md = Google Cast, ty = tiskárny, usb_mdl, model/am = Apple, product je v závorkách.
                let model = ["md", "ty", "usb_mdl", "model", "am", "rpmd", "product"]
                    .iter()
                    .find_map(|k| map.get(*k).filter(|v| !v.is_empty()))
                    .map(|v| v.trim_matches(|c| c == '(' || c == ')').to_string());
                if info.model.is_none() {
                    info.model = model;
                }
                if info.friendly.is_none() {
                    info.friendly = ["fn", "name", "note"].iter().find_map(|k| map.get(*k).filter(|v| !v.is_empty()).cloned());
                }
                if let Some(svc) = service_of(&r.name) {
                    info.services.insert(svc);
                }
            }
            Rdata::Other => {}
        }
    }
    new_types
}

/// Srozumitelný popis typu služby.
pub fn describe_service(svc: &str) -> String {
    let s = match svc {
        "_ipp._tcp" | "_ipps._tcp" => "Tisk (IPP)",
        "_printer._tcp" => "Tiskárna (LPD)",
        "_pdl-datastream._tcp" => "Tiskárna (RAW)",
        "_scanner._tcp" => "Skener",
        "_googlecast._tcp" => "Google Cast",
        "_airplay._tcp" | "_raop._tcp" => "AirPlay",
        "_hap._tcp" | "_homekit._tcp" => "HomeKit",
        "_smb._tcp" => "SMB",
        "_workstation._tcp" => "Počítač",
        "_companion-link._tcp" => "Apple zařízení",
        "_androidtvremote2._tcp" => "Android TV",
        "_spotify-connect._tcp" => "Spotify Connect",
        "_matter._tcp" | "_matterc._udp" => "Matter",
        "_homeconnect._tcp" => "Home Connect",
        "_http._tcp" | "_https._tcp" => "Web",
        _ => return svc.to_string(),
    };
    s.to_string()
}

// ---------------------------------------------------------------- síť

fn socket(src: Ipv4Addr) -> std::io::Result<UdpSocket> {
    let s = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    s.bind(&SocketAddrV4::new(src, 0).into())?;
    s.set_multicast_if_v4(&src)?;
    s.set_multicast_ttl_v4(255)?;
    s.set_multicast_loop_v4(false)?;
    s.set_read_timeout(Some(Duration::from_millis(250)))?;
    Ok(s.into())
}

/// Jen poslouchá oznámení na multicastové skupině mDNS (UDP 5353), nic neodesílá.
/// Zachytí odpovědi, které zařízení posílají jiným počítačům, takže je slyšet jen to, co se v síti děje samo.
pub fn listen(src: Ipv4Addr, duration: Duration, cancelled: &(dyn Fn() -> bool + Sync)) -> HashMap<Ipv4Addr, MdnsInfo> {
    let mut found: HashMap<Ipv4Addr, MdnsInfo> = HashMap::new();
    let sock = (|| -> std::io::Result<UdpSocket> {
        let s = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        s.set_reuse_address(true)?;
        s.bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 5353).into())?;
        s.join_multicast_v4(&GROUP, &src)?;
        s.set_read_timeout(Some(Duration::from_millis(250)))?;
        Ok(s.into())
    })();
    let Ok(sock) = sock else { return found };
    let start = Instant::now();
    let mut buf = vec![0u8; 9000];
    while start.elapsed() < duration && !cancelled() {
        let Ok((n, from)) = sock.recv_from(&mut buf) else { continue };
        let std::net::SocketAddr::V4(from) = from else { continue };
        absorb(found.entry(*from.ip()).or_default(), &buf[..n]);
    }
    found.retain(|_, i| *i != MdnsInfo::default());
    found
}

/// Zeptá se na služby na síti rozhraní `src` a po dobu `duration` sbírá odpovědi.
/// Po první vlně se zeptá i na typy služeb, které zařízení samy vyjmenovala.
pub fn probe(src: Ipv4Addr, duration: Duration, cancelled: &(dyn Fn() -> bool + Sync)) -> HashMap<Ipv4Addr, MdnsInfo> {
    let mut found: HashMap<Ipv4Addr, MdnsInfo> = HashMap::new();
    let Ok(sock) = socket(src) else { return found };
    let dest = SocketAddrV4::new(GROUP, 5353);
    let _ = sock.send_to(&build_query(KNOWN), dest);

    let start = Instant::now();
    let mut asked: BTreeSet<String> = KNOWN.iter().map(|s| s.to_string()).collect();
    let mut second_wave = false;
    let mut pending: BTreeSet<String> = BTreeSet::new();
    let mut buf = vec![0u8; 9000];
    while start.elapsed() < duration && !cancelled() {
        if !second_wave && start.elapsed() > duration / 3 {
            second_wave = true;
            let extra: Vec<&str> = pending.iter().filter(|t| !asked.contains(*t)).map(|s| s.as_str()).take(40).collect();
            if !extra.is_empty() {
                let _ = sock.send_to(&build_query(&extra), dest);
                asked.extend(extra.iter().map(|s| s.to_string()));
            }
        }
        let Ok((n, from)) = sock.recv_from(&mut buf) else { continue };
        let std::net::SocketAddr::V4(from) = from else { continue };
        let info = found.entry(*from.ip()).or_default();
        pending.extend(absorb(info, &buf[..n]));
    }
    found.retain(|_, i| *i != MdnsInfo::default());
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(out: &mut Vec<u8>, n: &str) {
        put_name(out, n);
    }

    /// Odpověď tiskárny: PTR + SRV + TXT + A.
    fn printer_response() -> Vec<u8> {
        let mut m = vec![0, 0, 0x84, 0, 0, 0, 0, 4, 0, 0, 0, 0];
        let instance = "HP LaserJet Pro M404 [ABC123]._ipp._tcp.local";
        // PTR _ipp._tcp.local -> instance
        name(&mut m, "_ipp._tcp.local");
        m.extend([0, 12, 0, 1, 0, 0, 0x11, 0x94]);
        let mut rd = vec![];
        name(&mut rd, instance);
        m.extend((rd.len() as u16).to_be_bytes());
        m.extend(&rd);
        // SRV instance -> NPIABC123.local
        name(&mut m, instance);
        m.extend([0, 33, 0x80, 1, 0, 0, 0, 120]);
        let mut rd = vec![0, 0, 0, 0, 0x02, 0x77];
        name(&mut rd, "NPIABC123.local");
        m.extend((rd.len() as u16).to_be_bytes());
        m.extend(&rd);
        // TXT instance
        name(&mut m, instance);
        m.extend([0, 16, 0x80, 1, 0, 0, 0, 120]);
        let txt: Vec<u8> = ["ty=HP LaserJet Pro M404dn", "rp=ipp/print"].iter().flat_map(|s| [vec![s.len() as u8], s.as_bytes().to_vec()].concat()).collect();
        m.extend((txt.len() as u16).to_be_bytes());
        m.extend(&txt);
        // A NPIABC123.local
        name(&mut m, "NPIABC123.local");
        m.extend([0, 1, 0x80, 1, 0, 0, 0, 120, 0, 4, 192, 168, 88, 14]);
        m
    }

    #[test]
    fn printer_is_recognised() {
        let mut info = MdnsInfo::default();
        absorb(&mut info, &printer_response());
        assert!(info.services.contains("_ipp._tcp"));
        assert!(info.hostnames.contains("NPIABC123.local"));
        assert_eq!(info.model.as_deref(), Some("HP LaserJet Pro M404dn"));
        assert!(info.instances.iter().any(|i| i.starts_with("HP LaserJet Pro M404")));
    }

    #[test]
    fn service_enumeration_is_reported() {
        let mut m = vec![0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0];
        name(&mut m, "_services._dns-sd._udp.local");
        m.extend([0, 12, 0, 1, 0, 0, 0x11, 0x94]);
        let mut rd = vec![];
        name(&mut rd, "_googlecast._tcp.local");
        m.extend((rd.len() as u16).to_be_bytes());
        m.extend(&rd);
        let mut info = MdnsInfo::default();
        assert_eq!(absorb(&mut info, &m), vec!["_googlecast._tcp".to_string()]);
    }

    #[test]
    fn query_roundtrip_and_garbage() {
        let q = build_query(&["_ipp._tcp"]);
        assert_eq!(u16::from_be_bytes([q[4], q[5]]), 1);
        assert!(parse_records(&q).is_empty());
        let mut info = MdnsInfo::default();
        assert!(absorb(&mut info, &[1, 2, 3]).is_empty());
        assert!(absorb(&mut info, &[0xFF; 40]).is_empty());
    }

    /// Živý test: zeptá se na lokální síti a vypíše, co zařízení řekla.
    #[test]
    #[ignore]
    fn live_probe() {
        let ifaces = crate::netcfg::list_interfaces().unwrap();
        let src: Ipv4Addr = ifaces
            .iter()
            .filter(|i| i.status == "Up")
            .flat_map(|i| i.addresses.iter())
            .find_map(|a| a.ip.parse().ok().filter(|ip: &Ipv4Addr| !ip.is_link_local()))
            .unwrap();
        let found = probe(src, Duration::from_secs(6), &|| false);
        for (ip, i) in &found {
            println!("{ip}: hosts={:?} services={:?} model={:?} friendly={:?} instances={:?}", i.hostnames, i.services, i.model, i.friendly, i.instances);
        }
        println!("celkem {} zařízení", found.len());
    }
}
