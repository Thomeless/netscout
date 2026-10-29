// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Tomáš Nesrsta
fn main() {
    // Release build si při startu vyžádá práva správce (změna IP je jinak nemožná).
    // Dev build manifest nemá, aby šel spustit z běžného terminálu (pak ho spusť jako správce).
    let release = std::env::var("PROFILE").is_ok_and(|p| p == "release");
    let attrs = if release {
        tauri_build::Attributes::new().windows_attributes(
            tauri_build::WindowsAttributes::new().app_manifest(include_str!("app.manifest")),
        )
    } else {
        tauri_build::Attributes::new()
    };
    tauri_build::try_build(attrs).expect("tauri build failed");
}
