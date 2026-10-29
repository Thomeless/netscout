# NetScout

Nástroj pro IT adminy a správce sítí (Windows, Rust + Tauri + React): sken sítě, neighbour discovery výrobců síťové techniky a rychlé přepínání IP profilů na síťových kartách.

**Autor:** Tomáš Nesrsta ([@Thomeless](https://github.com/Thomeless)) · **Licence:** [GNU AGPL-3.0](LICENSE) · Copyright (C) 2026 Tomáš Nesrsta

> Stav: aktivní vývoj. Instalátory: <https://github.com/Thomeless/netscout/releases>
> (instalátor zatím není podepsaný certifikátem, Windows SmartScreen se zeptá: *Další informace → Přesto spustit*; aktualizace aplikace jsou podepsané vlastním klíčem a ověřují se).

## Funkce

- **Inventář** – sloučený přehled zařízení ze skenu a neighbour discovery podle MAC adresy; vlastní názvy, poznámky, oblíbené, uložené offline záznamy, export CSV.
- **IP profily** – uložené konfigurace IPv4 (statická / DHCP) pro síťové karty, použití jedním kliknutím, tlačítko Zpět.
- **Sken sítě** – ARP sken lokální podsítě, výrobce (IEEE OUI), hostname, základní porty, odhad typu zařízení, export CSV.
- **Neighbors** – MikroTik MNDP, Ubiquiti discovery, Hikvision SADP, ONVIF WS-Discovery, Cisco CDP a LLDP (ty vyžadují [Npcap](https://npcap.com)).

## Vývoj

Požadavky: Node.js, Rust (MSVC toolchain), WebView2. Pro změnu IP a skenování spouštěj z terminálu jako správce.

```powershell
npm install
npm --prefix ui install
npm run dev
```

Instalátor (NSIS), release build si sám vyžádá práva správce:

```powershell
npm run build
```

Výsledek je v `target/release/bundle/nsis/`.

## Struktura

- `src-tauri/src/netcfg.rs` – výpis a změna IP (PowerShell NetTCPIP cmdlety, hodnoty přes proměnné prostředí)
- `src-tauri/src/scan.rs` – ARP sken (`SendARP`), porty, reverzní DNS
- `src-tauri/src/neighbors.rs`, `proto.rs` – discovery sokety a parsery protokolů
- `src-tauri/src/l2cap.rs` – zachytávání CDP/LLDP; `wpcap.dll` se načítá za běhu, bez Npcap SDK
- `src-tauri/src/inventory.rs`, `profiles.rs` – ukládání do datové složky aplikace (JSON)
- `src-tauri/resources/oui.csv` – databáze výrobců z IEEE, zabudovaná do programu
- `ui/` – React frontend; sken a sousedé se sdílí přes `ui/src/store.ts`

Plán a průzkum trhu: [docs/PLAN.md](docs/PLAN.md).

## Stav ověření

Parsery protokolů jsou ověřené testy na vyrobených paketech; ověření na reálném hardwaru probíhá. Automatické aktualizace (GitHub Releases, podpis `.sig`) jsou zapojené, ale zatím nevyzkoušené na skutečném vydání.

## Zdrojový kód a AGPL

NetScout je pod AGPL-3.0: kdo ho šíří (i upravený), musí příjemcům dát zdrojový kód pod stejnou licencí a ponechat poznámku o autorství ([`NOTICE`](NOTICE)).
Součásti třetích stran: [`THIRD_PARTY_LICENSES.md`](THIRD_PARTY_LICENSES.md).

## Podíl na vývoji

Nápady a chyby: *Issues*. Změny: *Pull request* (viz [`CONTRIBUTING.md`](CONTRIBUTING.md)). Bezpečnostní problémy hlaste podle [`SECURITY.md`](SECURITY.md), ne veřejně.

## Nezávislost

NetScout je nezávislý projekt. Názvy výrobců a protokolů (MikroTik, Ubiquiti, Hikvision, Cisco, ONVIF…) patří jejich vlastníkům a jsou použity jen k popisu kompatibility; projekt s nimi není spojen.
