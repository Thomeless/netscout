// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Tomáš Nesrsta
//! SSDP / UPnP (UDP 1900): televize, routery, tiskárny a chytré spotřebiče popisují sebe a svůj model
//! v XML popisu zařízení. Popis se stahuje jen z adresy, ze které odpověď přišla.

use crate::proto::xml_tag;
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

#[derive(Default, Clone, Debug, PartialEq)]
pub struct UpnpInfo {
    pub friendly_name: Option<String>,
    pub manufacturer: Option<String>,
    pub model_name: Option<String>,
    pub model_description: Option<String>,
    /// Hlavička SERVER z odpovědi (`Linux/4.9 UPnP/1.0 ...`).
    pub server: Option<String>,
}

fn search_message() -> Vec<u8> {
    "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\nUSER-AGENT: NetScout\r\n\r\n"
        .as_bytes()
        .to_vec()
}

fn header(resp: &str, name: &str) -> Option<String> {
    resp.lines().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.trim().eq_ignore_ascii_case(name).then(|| v.trim().to_string())
    })
}

/// `http://IP:port/cesta` → (port, cesta), jen pokud adresa odpovídá odesílateli.
fn parse_location(loc: &str, sender: Ipv4Addr) -> Option<(u16, String)> {
    let rest = loc.strip_prefix("http://")?;
    let (hostport, path) = rest.split_once('/').map_or((rest, ""), |(h, p)| (h, p));
    let (host, port) = hostport.split_once(':').map_or((hostport, "80"), |(h, p)| (h, p));
    if host.parse::<Ipv4Addr>().ok()? != sender {
        return None;
    }
    Some((port.parse().ok()?, format!("/{path}")))
}

fn http_get(ip: Ipv4Addr, port: u16, path: &str) -> Option<String> {
    let addr = SocketAddr::V4(SocketAddrV4::new(ip, port));
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_millis(800)).ok()?;
    s.set_read_timeout(Some(Duration::from_millis(1200))).ok()?;
    s.write_all(format!("GET {path} HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: NetScout\r\nConnection: close\r\n\r\n").as_bytes()).ok()?;
    let mut body = Vec::new();
    let mut chunk = [0u8; 4096];
    while body.len() < 64 * 1024 {
        match s.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => body.extend_from_slice(&chunk[..n]),
        }
    }
    Some(String::from_utf8_lossy(&body).into_owned())
}

pub fn parse_description(xml: &str) -> UpnpInfo {
    let get = |t: &str| xml_tag(xml, t).filter(|v| !v.is_empty());
    UpnpInfo {
        friendly_name: get("friendlyName"),
        manufacturer: get("manufacturer"),
        model_name: get("modelName"),
        model_description: get("modelDescription"),
        server: None,
    }
}

/// Rozešle M-SEARCH, po `duration` sbírá odpovědi a stáhne popisy zařízení.
pub fn probe(src: Ipv4Addr, duration: Duration, cancelled: &(dyn Fn() -> bool + Sync)) -> HashMap<Ipv4Addr, UpnpInfo> {
    let mut found: HashMap<Ipv4Addr, UpnpInfo> = HashMap::new();
    let mut locations: HashMap<Ipv4Addr, String> = HashMap::new();
    let Ok(sock) = (|| -> std::io::Result<UdpSocket> {
        let s = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        s.bind(&SocketAddrV4::new(src, 0).into())?;
        s.set_multicast_if_v4(&src)?;
        s.set_multicast_ttl_v4(2)?;
        s.set_multicast_loop_v4(false)?;
        s.set_read_timeout(Some(Duration::from_millis(250)))?;
        Ok(s.into())
    })() else {
        return found;
    };
    let dest = SocketAddrV4::new(Ipv4Addr::new(239, 255, 255, 250), 1900);
    let _ = sock.send_to(&search_message(), dest);
    let start = Instant::now();
    let mut resent = false;
    let mut buf = vec![0u8; 4096];
    while start.elapsed() < duration && !cancelled() {
        if !resent && start.elapsed() > duration / 2 {
            resent = true;
            let _ = sock.send_to(&search_message(), dest);
        }
        let Ok((n, SocketAddr::V4(from))) = sock.recv_from(&mut buf) else { continue };
        let text = String::from_utf8_lossy(&buf[..n]).into_owned();
        let info = found.entry(*from.ip()).or_default();
        if info.server.is_none() {
            info.server = header(&text, "SERVER");
        }
        if let Some(loc) = header(&text, "LOCATION") {
            locations.entry(*from.ip()).or_insert(loc);
        }
    }
    for (ip, loc) in locations {
        if cancelled() {
            break;
        }
        let Some((port, path)) = parse_location(&loc, ip) else { continue };
        if let Some(body) = http_get(ip, port, &path) {
            let d = parse_description(&body);
            let e = found.entry(ip).or_default();
            e.friendly_name = d.friendly_name;
            e.manufacturer = d.manufacturer;
            e.model_name = d.model_name;
            e.model_description = d.model_description;
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn description_is_parsed() {
        let xml = r#"<root xmlns="urn:schemas-upnp-org:device-1-0"><device><friendlyName>Pračka</friendlyName><manufacturer>BSH</manufacturer><modelName>WGB256A0EU</modelName></device></root>"#;
        let d = parse_description(xml);
        assert_eq!(d.friendly_name.as_deref(), Some("Pračka"));
        assert_eq!(d.manufacturer.as_deref(), Some("BSH"));
        assert_eq!(d.model_name.as_deref(), Some("WGB256A0EU"));
    }

    #[test]
    fn location_must_match_sender() {
        let ip: Ipv4Addr = "192.168.88.5".parse().unwrap();
        assert_eq!(parse_location("http://192.168.88.5:49152/desc.xml", ip), Some((49152, "/desc.xml".into())));
        assert_eq!(parse_location("http://192.168.88.5/", ip), Some((80, "/".into())));
        assert_eq!(parse_location("http://10.0.0.1:80/x", ip), None);
        assert_eq!(parse_location("https://192.168.88.5/x", ip), None);
    }

    #[test]
    fn header_lookup_is_case_insensitive() {
        assert_eq!(header("HTTP/1.1 200 OK\r\nLocation: http://a/\r\nServer: X/1\r\n", "location").as_deref(), Some("http://a/"));
        assert_eq!(header("HTTP/1.1 200 OK\r\n", "SERVER"), None);
    }

    /// Živý test: vypíše UPnP zařízení na lokální síti.
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
            println!("{ip}: {:?} | {:?} | {:?} | {:?}", i.friendly_name, i.manufacturer, i.model_name, i.server);
        }
        println!("celkem {} zařízení", found.len());
    }
}
