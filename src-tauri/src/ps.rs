// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Tomáš Nesrsta
//! Spouštění PowerShellu bez okna. Vstupní hodnoty se předávají přes proměnné
//! prostředí (NA_*), nikdy se nevkládají do textu skriptu.

use std::os::windows::process::CommandExt;
use std::process::Command;

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

pub fn run(script: &str, envs: &[(&str, String)]) -> Result<String, String> {
    let wrapped = format!(
        "[Console]::OutputEncoding=[Text.Encoding]::UTF8;$ProgressPreference='SilentlyContinue';\
         $ErrorActionPreference='Stop';\
         try {{ {script} }} catch {{ [Console]::Error.WriteLine($_.Exception.Message); exit 1 }}"
    );
    let mut cmd = Command::new("powershell.exe");
    cmd.args([
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        &wrapped,
    ])
    .creation_flags(CREATE_NO_WINDOW);
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let out = cmd.output().map_err(|e| format!("Nelze spustit PowerShell: {e}"))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    } else {
        let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
        Err(if err.is_empty() { "PowerShell skončil chybou".into() } else { err })
    }
}
