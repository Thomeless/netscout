// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Tomáš Nesrsta
//! Výpis síťových rozhraní a aplikace IP konfigurace (statická / DHCP).

use crate::ps;
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Addr {
    pub ip: String,
    pub prefix: u8,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Static,
    Dhcp,
}

/// Cílová konfigurace IPv4 jednoho rozhraní.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct IpConfig {
    pub mode: Mode,
    #[serde(default)]
    pub addresses: Vec<Addr>,
    #[serde(default)]
    pub gateway: String,
    #[serde(default)]
    pub dns: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Iface {
    pub name: String,
    pub description: String,
    pub mac: String,
    pub status: String,
    pub index: u32,
    pub dhcp: bool,
    #[serde(default)]
    pub addresses: Vec<Addr>,
    pub gateway: Option<String>,
    #[serde(default)]
    pub dns: Vec<String>,
}

impl Iface {
    pub fn to_config(&self) -> IpConfig {
        if self.dhcp {
            IpConfig { mode: Mode::Dhcp, addresses: vec![], gateway: String::new(), dns: vec![] }
        } else {
            IpConfig {
                mode: Mode::Static,
                addresses: self.addresses.iter().filter(|a| !a.ip.starts_with("169.254.")).cloned().collect(),
                gateway: self.gateway.clone().unwrap_or_default(),
                dns: self.dns.clone(),
            }
        }
    }
}

const LIST_SCRIPT: &str = r#"
$out = foreach ($a in (Get-NetAdapter | Sort-Object ifIndex)) {
  $i = $a.ifIndex
  $v4 = Get-NetIPInterface -InterfaceIndex $i -AddressFamily IPv4 -ErrorAction SilentlyContinue
  $addr = @(Get-NetIPAddress -InterfaceIndex $i -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object { [pscustomobject]@{ ip = [string]$_.IPAddress; prefix = [int]$_.PrefixLength } })
  $gw = Get-NetRoute -InterfaceIndex $i -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Where-Object { $_.NextHop -ne '0.0.0.0' } | Select-Object -First 1
  $dns = @(Get-DnsClientServerAddress -InterfaceIndex $i -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object { $_.ServerAddresses } | Where-Object { $_ })
  [pscustomobject]@{
    name = [string]$a.Name; description = [string]$a.InterfaceDescription; mac = [string]$a.MacAddress
    status = [string]$a.Status; index = [int]$i; dhcp = ([string]$v4.Dhcp -eq 'Enabled')
    addresses = $addr; gateway = $(if ($gw) { [string]$gw.NextHop } else { $null }); dns = $dns
  }
}
ConvertTo-Json -InputObject @($out) -Depth 5 -Compress
"#;

static CACHE: Mutex<Option<(Instant, Vec<Iface>)>> = Mutex::new(None);

/// Seznam rozhraní se krátce sdílí: start aplikace žádá stejná data z více míst najednou
/// (rozhraní, discovery, sken) a každé volání PowerShellu stojí vteřiny. Zámek zároveň zajistí,
/// že souběžná volání čekají na jeden společný dotaz.
pub fn list_interfaces() -> Result<Vec<Iface>, String> {
    let mut cache = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((at, list)) = cache.as_ref() {
        if at.elapsed() < Duration::from_secs(2) {
            return Ok(list.clone());
        }
    }
    let json = ps::run(LIST_SCRIPT, &[])?;
    let list: Vec<Iface> = serde_json::from_str(&json).map_err(|e| format!("Neplatný výstup z PowerShellu: {e}"))?;
    *cache = Some((Instant::now(), list.clone()));
    Ok(list)
}

pub fn is_admin() -> bool {
    unsafe { windows_sys::Win32::UI::Shell::IsUserAnAdmin() != 0 }
}

pub fn validate(cfg: &IpConfig) -> Result<(), String> {
    let ip = |s: &str, what: &str| {
        s.trim().parse::<Ipv4Addr>().map_err(|_| format!("Neplatná IPv4 adresa ({what}): {s}"))
    };
    if let Mode::Static = cfg.mode {
        if cfg.addresses.is_empty() {
            return Err("Statická konfigurace vyžaduje alespoň jednu IP adresu".into());
        }
        for a in &cfg.addresses {
            ip(&a.ip, "adresa")?;
            if a.prefix == 0 || a.prefix > 32 {
                return Err(format!("Neplatná délka prefixu: {}", a.prefix));
            }
        }
        if !cfg.gateway.trim().is_empty() {
            ip(&cfg.gateway, "brána")?;
        }
        for d in &cfg.dns {
            ip(d, "DNS")?;
        }
    }
    Ok(())
}

const APPLY_SCRIPT: &str = r#"
$a = Get-NetAdapter -Name $env:NA_IFACE
$idx = $a.ifIndex
Get-NetIPAddress -InterfaceIndex $idx -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.PrefixOrigin -eq 'Manual' } | Remove-NetIPAddress -Confirm:$false
Remove-NetRoute -InterfaceIndex $idx -DestinationPrefix '0.0.0.0/0' -Confirm:$false -ErrorAction SilentlyContinue
if ($env:NA_MODE -eq 'dhcp') {
  Set-NetIPInterface -InterfaceIndex $idx -AddressFamily IPv4 -Dhcp Enabled
  Set-DnsClientServerAddress -InterfaceIndex $idx -ResetServerAddresses
} else {
  Set-NetIPInterface -InterfaceIndex $idx -AddressFamily IPv4 -Dhcp Disabled
  $first = $true
  foreach ($item in ($env:NA_ADDRS -split ';' | Where-Object { $_ })) {
    $ip, $pl = $item -split '/'
    if ($first -and $env:NA_GW) {
      New-NetIPAddress -InterfaceIndex $idx -AddressFamily IPv4 -IPAddress $ip -PrefixLength ([int]$pl) -DefaultGateway $env:NA_GW | Out-Null
    } else {
      New-NetIPAddress -InterfaceIndex $idx -AddressFamily IPv4 -IPAddress $ip -PrefixLength ([int]$pl) | Out-Null
    }
    $first = $false
  }
  $dns = @($env:NA_DNS -split ';' | Where-Object { $_ })
  if ($dns.Count -gt 0) { Set-DnsClientServerAddress -InterfaceIndex $idx -ServerAddresses $dns } else { Set-DnsClientServerAddress -InterfaceIndex $idx -ResetServerAddresses }
}
"#;

pub fn apply(iface: &str, cfg: &IpConfig) -> Result<(), String> {
    validate(cfg)?;
    let addrs = cfg.addresses.iter().map(|a| format!("{}/{}", a.ip.trim(), a.prefix)).collect::<Vec<_>>().join(";");
    let mode = match cfg.mode {
        Mode::Static => "static",
        Mode::Dhcp => "dhcp",
    };
    ps::run(
        APPLY_SCRIPT,
        &[
            ("NA_IFACE", iface.to_string()),
            ("NA_MODE", mode.to_string()),
            ("NA_ADDRS", addrs),
            ("NA_GW", cfg.gateway.trim().to_string()),
            ("NA_DNS", cfg.dns.iter().map(|d| d.trim()).collect::<Vec<_>>().join(";")),
        ],
    )
    .map(|_| {
        *CACHE.lock().unwrap_or_else(|e| e.into_inner()) = None;
    })
}
