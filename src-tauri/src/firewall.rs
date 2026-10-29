// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Tomáš Nesrsta
//! Příchozí UDP pravidlo Windows Firewallu jen pro tento program, aby se systém při každém
//! spuštění nevyptával na povolení (odpovědi na discovery přicházejí jako příchozí UDP).
//! Pravidlo se přidá jen když pro aktuální cestu k programu chybí a jen s právy správce
//! (bez nich `netsh` selže a nic se nestane).

use std::os::windows::process::CommandExt;
use std::process::Command;

// Jiný název než "NetScout", pod kterým rule vytváří systémová výzva (ta zakládá jen profil Private/Public podle toho, co uživatel zaškrtne).
const RULE: &str = "NetScout discovery";
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

fn netsh(args: &[String]) -> Option<String> {
    let mut cmd = Command::new("netsh.exe");
    cmd.creation_flags(CREATE_NO_WINDOW);
    for a in args {
        cmd.raw_arg(a);
    }
    let out = cmd.output().ok()?;
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

pub fn ensure_rule() {
    let Ok(exe) = std::env::current_exe() else { return };
    let exe = exe.display().to_string();
    let show = netsh(&["advfirewall".into(), "firewall".into(), "show".into(), "rule".into(), format!("name=\"{RULE}\""), "verbose".into()])
        .unwrap_or_default();
    if show.to_lowercase().contains(&exe.to_lowercase()) {
        return;
    }
    let _ = netsh(&[
        "advfirewall".into(),
        "firewall".into(),
        "add".into(),
        "rule".into(),
        format!("name=\"{RULE}\""),
        "dir=in".into(),
        "action=allow".into(),
        format!("program=\"{exe}\""),
        "enable=yes".into(),
        "profile=any".into(),
        "protocol=UDP".into(),
    ]);
}
