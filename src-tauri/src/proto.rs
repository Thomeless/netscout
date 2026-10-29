// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Tomáš Nesrsta
//! Parsery discovery protokolů (čisté funkce nad bajty, bez síťové vrstvy).
//! Formáty vycházejí z veřejných popisů protokolů; ověření na reálném HW probíhá postupně.

use serde::Serialize;
use std::net::{IpAddr, SocketAddr};

#[derive(Serialize, Clone, Debug, Default)]
pub struct Neighbor {
    /// Unikátní klíč záznamu (protokol + MAC, případně IP).
    pub key: String,
    pub protocol: &'static str,
    pub vendor: String,
    pub ip: String,
    pub mac: String,
    pub identity: String,
    pub model: String,
    pub version: String,
    /// Lokální rozhraní, na kterém jsme odpověď přijali.
    pub local_iface: String,
    /// Všechna dekódovaná pole tak, jak je zařízení vysílá.
    pub fields: Vec<(String, String)>,
    /// Surový paket (text u XML, jinak hexdump).
    pub raw: String,
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect::<Vec<_>>().join(" ")
}

pub fn fmt_mac(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02X}")).collect::<Vec<_>>().join(":")
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).trim_end_matches('\0').trim().to_string()
}

fn uptime(secs: u64) -> String {
    format!("{}d {:02}:{:02}:{:02}", secs / 86400, secs / 3600 % 24, secs / 60 % 60, secs % 60)
}

fn src_ip(from: SocketAddr) -> String {
    match from.ip() {
        IpAddr::V4(a) => a.to_string(),
        IpAddr::V6(a) => a.to_string(),
    }
}

// ---------------------------------------------------------------- MikroTik MNDP

/// MNDP: hlavička 4 B (typ + sekvence), pak TLV: typ u16 BE, délka u16 BE, hodnota.
pub fn parse_mndp(data: &[u8], from: SocketAddr) -> Option<Neighbor> {
    if data.len() < 8 {
        return None;
    }
    let mut n = Neighbor { protocol: "MNDP", vendor: "MikroTik".into(), ip: src_ip(from), ..Default::default() };
    let mut pos = 4;
    while pos + 4 <= data.len() {
        let t = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;
        let v = data.get(pos..pos + len)?;
        pos += len;
        match t {
            1 if len == 6 => {
                n.mac = fmt_mac(v);
                n.fields.push(("MAC".into(), n.mac.clone()));
            }
            5 => {
                n.identity = text(v);
                n.fields.push(("Identity".into(), n.identity.clone()));
            }
            7 => {
                n.version = text(v);
                n.fields.push(("Verze RouterOS".into(), n.version.clone()));
            }
            8 => n.fields.push(("Platforma".into(), text(v))),
            10 if len == 4 => {
                let s = u32::from_le_bytes([v[0], v[1], v[2], v[3]]) as u64;
                n.fields.push(("Uptime".into(), uptime(s)));
            }
            11 => n.fields.push(("Software ID".into(), text(v))),
            12 => {
                n.model = text(v);
                n.fields.push(("Board".into(), n.model.clone()));
            }
            14 => n.fields.push(("Unpack".into(), hex(v))),
            15 if len == 16 => n.fields.push(("IPv6".into(), std::net::Ipv6Addr::from(<[u8; 16]>::try_from(v).ok()?).to_string())),
            16 => n.fields.push(("Rozhraní zařízení".into(), text(v))),
            17 if len == 4 => n.fields.push(("IPv4".into(), format!("{}.{}.{}.{}", v[0], v[1], v[2], v[3]))),
            _ => n.fields.push((format!("TLV {t}"), hex(v))),
        }
    }
    if n.mac.is_empty() && n.identity.is_empty() {
        return None;
    }
    // Platformu využijeme jako model, pokud chybí board.
    if n.model.is_empty() {
        if let Some((_, p)) = n.fields.iter().find(|(k, _)| k == "Platforma") {
            n.model = p.clone();
        }
    }
    n.key = format!("MNDP:{}", if n.mac.is_empty() { &n.ip } else { &n.mac });
    n.raw = hex(data);
    Some(n)
}

// ---------------------------------------------------------------- Ubiquiti

/// Ubiquiti discovery v1: verze, příkaz, délka u16 BE, pak TLV: typ u8, délka u16 BE.
pub fn parse_ubnt(data: &[u8], from: SocketAddr) -> Option<Neighbor> {
    if data.len() < 4 || data[0] != 1 {
        return None;
    }
    let total = u16::from_be_bytes([data[2], data[3]]) as usize;
    let end = (4 + total).min(data.len());
    let mut n = Neighbor { protocol: "Ubiquiti", vendor: "Ubiquiti".into(), ip: src_ip(from), ..Default::default() };
    let mut pos = 4;
    while pos + 3 <= end {
        let t = data[pos];
        let len = u16::from_be_bytes([data[pos + 1], data[pos + 2]]) as usize;
        pos += 3;
        let v = data.get(pos..pos + len)?;
        pos += len;
        match t {
            0x01 if len == 6 => {
                n.mac = fmt_mac(v);
                n.fields.push(("MAC".into(), n.mac.clone()));
            }
            0x02 if len == 10 => {
                n.fields.push(("MAC (adresa)".into(), fmt_mac(&v[..6])));
                n.fields.push(("IPv4".into(), format!("{}.{}.{}.{}", v[6], v[7], v[8], v[9])));
                if n.mac.is_empty() {
                    n.mac = fmt_mac(&v[..6]);
                }
            }
            0x03 => {
                n.version = text(v);
                n.fields.push(("Firmware".into(), n.version.clone()));
            }
            0x0a if len == 4 => n.fields.push(("Uptime".into(), uptime(u32::from_be_bytes([v[0], v[1], v[2], v[3]]) as u64))),
            0x0b => {
                n.identity = text(v);
                n.fields.push(("Hostname".into(), n.identity.clone()));
            }
            0x0c => n.fields.push(("Platforma".into(), text(v))),
            0x0d => n.fields.push(("ESSID".into(), text(v))),
            0x14 => {
                n.model = text(v);
                n.fields.push(("Model".into(), n.model.clone()));
            }
            _ => n.fields.push((format!("TLV 0x{t:02x}"), if v.iter().all(|b| b.is_ascii_graphic() || *b == b' ') { text(v) } else { hex(v) })),
        }
    }
    if n.mac.is_empty() {
        return None;
    }
    if n.model.is_empty() {
        if let Some((_, p)) = n.fields.iter().find(|(k, _)| k == "Platforma") {
            n.model = p.clone();
        }
    }
    n.key = format!("Ubiquiti:{}", n.mac);
    n.raw = hex(data);
    Some(n)
}

// ---------------------------------------------------------------- XML (SADP, ONVIF)

/// Obsah prvního elementu `name` (s libovolným prefixem jmenného prostoru).
pub fn xml_tag(xml: &str, name: &str) -> Option<String> {
    let mut rest = xml;
    while let Some(lt) = rest.find('<') {
        rest = &rest[lt + 1..];
        let gt = rest.find('>')?;
        let tag = rest[..gt].split_whitespace().next().unwrap_or("");
        if !tag.starts_with('/') && tag.rsplit(':').next() == Some(name) {
            let body = &rest[gt + 1..];
            let end = body.find('<')?;
            return Some(body[..end].trim().to_string());
        }
    }
    None
}

/// Všechny jednoduché páry `<Tag>hodnota</Tag>` v pořadí výskytu.
fn xml_pairs(xml: &str) -> Vec<(String, String)> {
    let mut out = vec![];
    let mut rest = xml;
    while let Some(lt) = rest.find('<') {
        rest = &rest[lt + 1..];
        let Some(gt) = rest.find('>') else { break };
        let name = &rest[..gt];
        if name.is_empty() || name.starts_with(['/', '?', '!']) || name.ends_with('/') || name.contains(' ') {
            continue;
        }
        let body = &rest[gt + 1..];
        if let Some(end) = body.find('<') {
            if body[end..].starts_with(&format!("</{name}>")) && !body[..end].trim().is_empty() {
                out.push((name.to_string(), body[..end].trim().to_string()));
            }
        }
    }
    out
}

fn norm_mac(s: &str) -> String {
    let hexs: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect::<String>().to_uppercase();
    if hexs.len() != 12 {
        return s.to_string();
    }
    (0..6).map(|i| &hexs[i * 2..i * 2 + 2]).collect::<Vec<_>>().join(":")
}

/// Hikvision SADP: odpověď `<ProbeMatch>` s XML poli.
pub fn parse_sadp(data: &[u8], from: SocketAddr) -> Option<Neighbor> {
    let xml = String::from_utf8_lossy(data).into_owned();
    if !xml.contains("ProbeMatch") {
        return None;
    }
    let pairs = xml_pairs(&xml);
    let get = |k: &str| pairs.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone()).unwrap_or_default();
    let mac = norm_mac(&get("MAC"));
    if mac.is_empty() {
        return None;
    }
    let ip = Some(get("IPv4Address")).filter(|s| !s.is_empty()).unwrap_or_else(|| src_ip(from));
    let model = get("DeviceType");
    let n = Neighbor {
        key: format!("SADP:{mac}"),
        protocol: "SADP",
        vendor: "Hikvision".into(),
        ip,
        mac,
        identity: get("DeviceDescription"),
        model,
        version: get("SoftwareVersion"),
        fields: pairs.into_iter().filter(|(k, _)| !matches!(k.as_str(), "Uuid" | "Types")).collect(),
        raw: xml,
        ..Default::default()
    };
    Some(n)
}

/// ONVIF WS-Discovery: `ProbeMatches` s XAddrs a Scopes.
pub fn parse_onvif(data: &[u8], from: SocketAddr) -> Option<Neighbor> {
    let xml = String::from_utf8_lossy(data).into_owned();
    if !xml.contains("ProbeMatch") {
        return None;
    }
    let xaddrs = xml_tag(&xml, "XAddrs").unwrap_or_default();
    let scopes = xml_tag(&xml, "Scopes").unwrap_or_default();
    let mut n = Neighbor { protocol: "ONVIF", vendor: "ONVIF kamera".into(), ip: src_ip(from), raw: xml, ..Default::default() };
    if !xaddrs.is_empty() {
        n.fields.push(("XAddrs".into(), xaddrs.clone()));
    }
    for s in scopes.split_whitespace() {
        let Some(rest) = s.strip_prefix("onvif://www.onvif.org/") else {
            n.fields.push(("Scope".into(), s.to_string()));
            continue;
        };
        let (k, v) = rest.split_once('/').unwrap_or((rest, ""));
        let v = v.replace("%20", " ");
        match k {
            "name" => n.identity = v.clone(),
            "hardware" => n.model = v.clone(),
            _ => {}
        }
        n.fields.push((format!("Scope {k}"), v));
    }
    n.key = format!("ONVIF:{}", n.ip);
    Some(n)
}

// ---------------------------------------------------------------- CDP / LLDP (L2, Npcap)

pub const CDP_MAC: [u8; 6] = [0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc];

fn ipv4(a: &[u8]) -> String {
    format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3])
}

fn cdp_caps(c: u32) -> String {
    const N: [(u32, &str); 7] =
        [(1, "Router"), (2, "Transparent bridge"), (4, "Source-route bridge"), (8, "Switch"), (16, "Host"), (32, "IGMP"), (64, "Repeater")];
    N.iter().filter(|(b, _)| c & b != 0).map(|(_, n)| *n).collect::<Vec<_>>().join(", ")
}

/// CDP rámec: 802.3 + LLC/SNAP (00-00-0C, 0x2000), pak verze, TTL, kontrolní součet a TLV (typ u16, délka u16 včetně hlavičky).
pub fn parse_cdp(frame: &[u8]) -> Option<Neighbor> {
    if frame.len() < 26 || frame[..6] != CDP_MAC || frame[14..22] != [0xAA, 0xAA, 0x03, 0x00, 0x00, 0x0C, 0x20, 0x00] {
        return None;
    }
    let p = &frame[22..];
    let mut n = Neighbor { protocol: "CDP", mac: fmt_mac(&frame[6..12]), ..Default::default() };
    n.fields.push(("Verze CDP".into(), p[0].to_string()));
    n.fields.push(("TTL".into(), format!("{} s", p[1])));
    let mut pos = 4;
    while pos + 4 <= p.len() {
        let t = u16::from_be_bytes([p[pos], p[pos + 1]]);
        let len = u16::from_be_bytes([p[pos + 2], p[pos + 3]]) as usize;
        if len < 4 || pos + len > p.len() {
            break;
        }
        let v = &p[pos + 4..pos + len];
        pos += len;
        match t {
            0x01 => {
                n.identity = text(v);
                n.fields.push(("Device ID".into(), n.identity.clone()));
            }
            0x02 | 0x16 => {
                // počet adres (u32), pak (typ protokolu, délka, protokol, délka adresy u16, adresa)
                let mut q = 4;
                while q + 2 <= v.len() {
                    let (pl, plen) = (v[q], v[q + 1] as usize);
                    let Some(proto_b) = v.get(q + 2..q + 2 + plen) else { break };
                    let Some(al) = v.get(q + 2 + plen..q + 4 + plen) else { break };
                    let alen = u16::from_be_bytes([al[0], al[1]]) as usize;
                    let Some(addr) = v.get(q + 4 + plen..q + 4 + plen + alen) else { break };
                    q += 4 + plen + alen;
                    let label = if t == 0x02 { "Adresa" } else { "Management adresa" };
                    if pl == 1 && proto_b == [0xCC] && alen == 4 {
                        let ip = ipv4(addr);
                        if n.ip.is_empty() {
                            n.ip = ip.clone();
                        }
                        n.fields.push((label.into(), ip));
                    } else {
                        n.fields.push((format!("{label} (jiný protokol)"), hex(addr)));
                    }
                }
            }
            0x03 => n.fields.push(("Port ID".into(), text(v))),
            0x04 if v.len() == 4 => n.fields.push(("Capabilities".into(), cdp_caps(u32::from_be_bytes([v[0], v[1], v[2], v[3]])))),
            0x05 => {
                n.version = text(v).lines().next().unwrap_or("").to_string();
                n.fields.push(("Software".into(), text(v)));
            }
            0x06 => {
                n.model = text(v);
                n.fields.push(("Platforma".into(), n.model.clone()));
            }
            0x0a if v.len() == 2 => n.fields.push(("Native VLAN".into(), u16::from_be_bytes([v[0], v[1]]).to_string())),
            0x0b if v.len() == 1 => n.fields.push(("Duplex".into(), if v[0] == 1 { "full" } else { "half" }.into())),
            _ => n.fields.push((format!("TLV 0x{t:04x}"), hex(v))),
        }
    }
    n.key = format!("CDP:{}", n.mac);
    n.raw = hex(frame);
    Some(n)
}

fn lldp_caps(c: u16) -> String {
    const N: [(u16, &str); 8] = [
        (1, "Other"),
        (2, "Repeater"),
        (4, "Bridge"),
        (8, "WLAN AP"),
        (16, "Router"),
        (32, "Telefon"),
        (64, "DOCSIS"),
        (128, "Station"),
    ];
    N.iter().filter(|(b, _)| c & b != 0).map(|(_, n)| *n).collect::<Vec<_>>().join(", ")
}

/// Chassis ID / Port ID: podtyp (1 B) + hodnota. MAC (3, 4), síťová adresa IPv4 (5 u chassis), jinak text.
fn lldp_id(v: &[u8]) -> String {
    match v[0] {
        4 | 3 if v.len() == 7 => fmt_mac(&v[1..]),
        5 if v.len() == 6 && v[1] == 1 => ipv4(&v[2..]),
        _ => text(&v[1..]),
    }
}

/// LLDP rámec (ethertype 0x88CC): TLV s 7bitovým typem a 9bitovou délkou.
pub fn parse_lldp(frame: &[u8]) -> Option<Neighbor> {
    if frame.len() < 18 || frame[12..14] != [0x88, 0xCC] {
        return None;
    }
    let mut n = Neighbor { protocol: "LLDP", mac: fmt_mac(&frame[6..12]), ..Default::default() };
    let mut pos = 14;
    let (mut chassis, mut port) = (String::new(), String::new());
    while pos + 2 <= frame.len() {
        let h = u16::from_be_bytes([frame[pos], frame[pos + 1]]);
        let (t, len) = (h >> 9, (h & 0x1ff) as usize);
        pos += 2;
        if t == 0 {
            break;
        }
        let Some(v) = frame.get(pos..pos + len) else { break };
        pos += len;
        match t {
            1 if !v.is_empty() => {
                chassis = lldp_id(v);
                n.fields.push(("Chassis ID".into(), chassis.clone()));
            }
            2 if !v.is_empty() => {
                port = lldp_id(v);
                n.fields.push(("Port ID".into(), port.clone()));
            }
            3 if len == 2 => n.fields.push(("TTL".into(), format!("{} s", u16::from_be_bytes([v[0], v[1]])))),
            4 => n.fields.push(("Popis portu".into(), text(v))),
            5 => {
                n.identity = text(v);
                n.fields.push(("System name".into(), n.identity.clone()));
            }
            6 => {
                let d = text(v);
                n.model = d.lines().next().unwrap_or("").chars().take(60).collect();
                n.fields.push(("System description".into(), d));
            }
            7 if len == 4 => {
                n.fields.push(("Capabilities".into(), lldp_caps(u16::from_be_bytes([v[0], v[1]]))));
                n.fields.push(("Povolené capabilities".into(), lldp_caps(u16::from_be_bytes([v[2], v[3]]))));
            }
            8 if len >= 2 => {
                let alen = v[0] as usize;
                match v.get(2..1 + alen) {
                    Some(a) if v[1] == 1 && a.len() == 4 => {
                        let ip = ipv4(a);
                        if n.ip.is_empty() {
                            n.ip = ip.clone();
                        }
                        n.fields.push(("Management IPv4".into(), ip));
                    }
                    _ => n.fields.push(("Management adresa".into(), hex(v))),
                }
            }
            127 if len >= 4 => {
                let (oui, sub, d) = (&v[..3], v[3], &v[4..]);
                match (oui, sub) {
                    ([0x00, 0x80, 0xC2], 1) if d.len() == 2 => n.fields.push(("Port VLAN ID".into(), u16::from_be_bytes([d[0], d[1]]).to_string())),
                    ([0x00, 0x80, 0xC2], 3) if d.len() > 3 => {
                        n.fields.push(("VLAN".into(), format!("{} ({})", u16::from_be_bytes([d[0], d[1]]), text(&d[3..]))))
                    }
                    _ => n.fields.push((format!("Org {} / {sub}", fmt_mac(oui).replace(':', "-")), hex(d))),
                }
            }
            _ => n.fields.push((format!("TLV {t}"), hex(v))),
        }
    }
    if chassis.is_empty() && port.is_empty() {
        return None;
    }
    n.key = format!("LLDP:{}:{chassis}:{port}", n.mac);
    n.raw = hex(frame);
    Some(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn from() -> SocketAddr {
        "192.168.88.1:5678".parse().unwrap()
    }

    fn tlv16(t: u16, v: &[u8]) -> Vec<u8> {
        [&t.to_be_bytes()[..], &(v.len() as u16).to_be_bytes(), v].concat()
    }

    #[test]
    fn mndp() {
        let mut p = vec![0, 0, 0, 1];
        p.extend(tlv16(1, &[0x4C, 0x5E, 0x0C, 1, 2, 3]));
        p.extend(tlv16(5, b"MikroTik"));
        p.extend(tlv16(7, b"7.15 (stable)"));
        p.extend(tlv16(10, &3700u32.to_le_bytes()));
        p.extend(tlv16(12, b"RB750Gr3"));
        let n = parse_mndp(&p, from()).unwrap();
        assert_eq!((n.mac.as_str(), n.identity.as_str(), n.model.as_str()), ("4C:5E:0C:01:02:03", "MikroTik", "RB750Gr3"));
        assert!(n.fields.iter().any(|(k, v)| k == "Uptime" && v == "0d 01:01:40"));
        assert!(parse_mndp(&[0, 0, 0, 0], from()).is_none());
    }

    #[test]
    fn ubnt() {
        let tlv = |t: u8, v: &[u8]| [&[t][..], &(v.len() as u16).to_be_bytes(), v].concat();
        let body = [tlv(1, &[0x24, 0xA4, 0x3C, 1, 2, 3]), tlv(0x0b, b"AP-Lobby"), tlv(0x14, b"UAP-AC-Pro"), tlv(3, b"BZ.qca956x.v6.0.0")].concat();
        let mut p = vec![1, 0];
        p.extend((body.len() as u16).to_be_bytes());
        p.extend(body);
        let n = parse_ubnt(&p, from()).unwrap();
        assert_eq!((n.mac.as_str(), n.identity.as_str(), n.model.as_str()), ("24:A4:3C:01:02:03", "AP-Lobby", "UAP-AC-Pro"));
    }

    #[test]
    fn sadp() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?><ProbeMatch><Uuid>X</Uuid><Types>inquiry</Types><DeviceType>DS-2CD2143G0-I</DeviceType><DeviceDescription>DS-2CD2143G0-I</DeviceDescription><MAC>c0-56-e3-aa-bb-cc</MAC><IPv4Address>192.168.1.64</IPv4Address><SoftwareVersion>V5.5.82</SoftwareVersion><Activated>true</Activated></ProbeMatch>"#;
        let n = parse_sadp(xml.as_bytes(), from()).unwrap();
        assert_eq!((n.mac.as_str(), n.ip.as_str(), n.version.as_str()), ("C0:56:E3:AA:BB:CC", "192.168.1.64", "V5.5.82"));
        assert!(n.fields.iter().any(|(k, v)| k == "Activated" && v == "true"));
    }

    #[test]
    fn onvif() {
        let xml = r#"<s:Envelope xmlns:s="x"><s:Body><d:ProbeMatches><d:ProbeMatch><d:Scopes>onvif://www.onvif.org/name/Front%20Door onvif://www.onvif.org/hardware/IPC-HFW</d:Scopes><d:XAddrs>http://10.0.0.5/onvif/device_service</d:XAddrs></d:ProbeMatch></d:ProbeMatches></s:Body></s:Envelope>"#;
        let n = parse_onvif(xml.as_bytes(), from()).unwrap();
        assert_eq!((n.identity.as_str(), n.model.as_str()), ("Front Door", "IPC-HFW"));
        assert!(n.fields.iter().any(|(k, v)| k == "XAddrs" && v.contains("10.0.0.5")));
    }

    #[test]
    fn cdp() {
        let tlv = |t: u16, v: &[u8]| [&t.to_be_bytes()[..], &((v.len() + 4) as u16).to_be_bytes(), v].concat();
        let addrs = [&1u32.to_be_bytes()[..], &[1, 1, 0xCC], &4u16.to_be_bytes(), &[10, 0, 0, 2]].concat();
        let mut body = vec![2, 180, 0, 0];
        body.extend(tlv(1, b"SW-CORE"));
        body.extend(tlv(2, &addrs));
        body.extend(tlv(3, b"GigabitEthernet0/1"));
        body.extend(tlv(4, &9u32.to_be_bytes()));
        body.extend(tlv(6, b"cisco WS-C2960"));
        let mut f = vec![0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc, 0xAA, 0xBB, 0xCC, 1, 2, 3, 0, 0];
        f.extend([0xAA, 0xAA, 0x03, 0x00, 0x00, 0x0C, 0x20, 0x00]);
        f.extend(body);
        let n = parse_cdp(&f).unwrap();
        assert_eq!((n.identity.as_str(), n.ip.as_str(), n.model.as_str()), ("SW-CORE", "10.0.0.2", "cisco WS-C2960"));
        assert!(n.fields.iter().any(|(k, v)| k == "Capabilities" && v == "Router, Switch"));
        assert!(n.fields.iter().any(|(k, v)| k == "Port ID" && v == "GigabitEthernet0/1"));
    }

    #[test]
    fn lldp() {
        let tlv = |t: u16, v: &[u8]| [&((t << 9) | v.len() as u16).to_be_bytes()[..], v].concat();
        let mut f = vec![0x01, 0x80, 0xc2, 0, 0, 0x0e, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x88, 0xCC];
        f.extend(tlv(1, &[4, 0, 0x11, 0x22, 0x33, 0x44, 0x55]));
        f.extend(tlv(2, &[5, b'g', b'e', b'1']));
        f.extend(tlv(3, &120u16.to_be_bytes()));
        f.extend(tlv(5, b"switch1"));
        f.extend(tlv(8, &[5, 1, 192, 168, 1, 2, 2, 0, 0, 0, 1, 0]));
        f.extend(tlv(127, &[0x00, 0x80, 0xC2, 1, 0, 10]));
        f.extend(tlv(0, &[]));
        let n = parse_lldp(&f).unwrap();
        assert_eq!((n.identity.as_str(), n.ip.as_str()), ("switch1", "192.168.1.2"));
        assert!(n.fields.iter().any(|(k, v)| k == "Chassis ID" && v == "00:11:22:33:44:55"));
        assert!(n.fields.iter().any(|(k, v)| k == "Port ID" && v == "ge1"));
        assert!(n.fields.iter().any(|(k, v)| k == "Port VLAN ID" && v == "10"));
    }
}
