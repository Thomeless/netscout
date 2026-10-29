# NetScout – průzkum trhu a plán implementace

## 1. Průzkum trhu

| Nástroj | Co umí | Slabiny |
|---|---|---|
| **Advanced IP Scanner** (Windows) | Rychlý sken, MAC, výrobce, otevřené porty, RDP/HTTP/FTP, Wake-on-LAN, export | Žádná neighbour discovery, žádná správa IP, zastaralé UI |
| **Angry IP Scanner** (open source, multiplatform) | Rychlý sken IP/portů, pluginy, portable | Jen hostname/porty, bez reportů, bez výrobce zařízení |
| **Fing Desktop** | Sken, databáze zařízení, monitoring | Komerční, cloud, část funkcí placená |
| **SoftPerfect Network Scanner** | Sken, SNMP, sdílené složky, vzdálené akce | Bez neighbour a IP profilů |
| **WinBox (MikroTik)** | MNDP neighbors (+CDP/LLDP), spuštění správy | Jen MikroTik ekosystém |
| **MndpTray** (open source, GPL-3) | MNDP monitor v tray | Jen MikroTik |
| **SADP Tool (Hikvision)** | Nalezení + aktivace + změna IP kamer/NVR (UDP 37020, XML) | Jen Hikvision |
| **Ubiquiti Discovery Tool** | Nalezení UniFi/airMAX zařízení | Jen Ubiquiti |
| **Simple IP Config** (open source) | Profily IP, DHCP/static, portable | Jen IP změna, minimum dalšího |
| **NetSetMan** | Profily IP/DNS/tiskárny, automatické přepínání | Placená pro firmy, těžkopádné |
| **IP Shifter / Ultimate IP Changer** | Profily IP | Zastaralé |

**Zjištění:** neexistuje jediná aplikace, která by spojila *sken + neighbour discovery více výrobců + přepínání IP profilů*. Admin dnes používá 3–5 nástrojů (Advanced IP Scanner, WinBox, SADP, Ubiquiti tool, NetSetMan). To je tvoje mezera na trhu.

Neověřeno průzkumem (nutné ověřit při implementaci pomocí Wiresharku): přesné porty/formáty Ubiquiti, Cisco CDP/LLDP a dalších.

## 2. Discovery protokoly (neighbour)

| Protokol | Výrobci | Transport | Poznámka |
|---|---|---|---|
| **MNDP** | MikroTik | UDP 5678 broadcast, TLV | Identity, verze, platforma, MAC, IP, interface, uptime |
| **CDP** | Cisco (a řada dalších) | L2 multicast 01:00:0C:CC:CC:CC | Pasivní odposlech, potřeba Npcap |
| **LLDP** | Standard (HP, Aruba, Cisco, Ubiquiti, Mikrotik…) | L2 multicast 01:80:C2:00:00:0E | Pasivní, Npcap |
| **SADP** | Hikvision | UDP multicast 239.255.255.250:37020, XML | Aktivní dotaz + odpověď |
| **Ubiquiti discovery** | Ubiquiti | UDP broadcast (údajně 10001, ověřit) | Aktivní dotaz |
| **SSDP / mDNS / NetBIOS / WS-Discovery** | Mnoho zařízení | UDP multicast | Doplňkové |
| **ONVIF WS-Discovery** | IP kamery (všech značek) | UDP 3702 | Pokrývá kamery mimo Hikvision |
| **Dahua DHDiscover, TP-Link, Cambium** | Další | různé | Pozdější rozšíření |

Architektura: každý protokol = samostatný plugin za společným rozhraním `DiscoveryProvider`.

## 3. Doporučený stack

Navazuje na WinMailer: **Rust + Tauri + React/TypeScript** (již znáš).
- Rust: sockety, ARP, ICMP, paketové parsování (`pnet`/`socket2`, `pcap` s Npcap), rychlé a bezpečné.
- Změna IP: `netsh` / PowerShell `NetIPAddress` / WMI (Rust volá `netsh interface ip` – nejjednodušší, spolehlivé).
- Lokální DB: SQLite (profily, historie skenů, vendor OUI).
- **Oprávnění:** změna IP a raw sockety vyžadují admina → manifest `requireAdministrator` (nebo oddělený privilegovaný helper, později).
- OUI databáze výrobců: IEEE `oui.csv` zabalená v aplikaci + aktualizace.

## 4. Plán implementace (fáze)

**Fáze 0 – Základ (1–2 dny)**
- Repo `C:/dev/netadmin`, Tauri+React skeleton, navigace se 3 záložkami (Scan / Neighbors / IP profily), SQLite, logování.

**Fáze 1 – Změna IP profilů (MVP #1, nejjednodušší a nejužitečnější)** 
- Výpis síťových rozhraní (název, MAC, stav, aktuální IP/GW/DNS, DHCP ano/ne).
- CRUD profilů: název, IPv4, maska/prefix, brána, DNS, volitelně více IP na jednom rozhraní, DHCP režim.
- Apply na vybraný adaptér (`netsh`), zobrazení výsledku, tlačítko Zpět na předchozí stav.
- Validace (kolize s existující IP v síti přes ARP probe, formát).
- Tray menu / rychlé přepnutí; import/export profilů (JSON).

**Fáze 2 – IP scan (MVP #2)**
- Automatická detekce podsítě z rozhraní, vlastní rozsah/CIDR.
- ARP sken (rychlé v lokální síti) + ICMP ping + volitelně TCP probe; asynchronně (tokio), progres.
- Výsledky: IP, MAC, hostname (rDNS, NetBIOS, mDNS), výrobce z OUI, latence, otevřené porty (základní set).
- Rozpoznání typu zařízení (heuristiky: OUI + porty + banner/HTTP title).
- Akce: otevřít v prohlížeči, RDP/SSH, Wake-on-LAN, kopírovat, export CSV.
- Uložení skenů a porovnání (nové/zmizelá zařízení).

**Fáze 3 – Neighbour discovery**
- 3a: MNDP (pasivní + aktivní), SADP, Ubiquiti, ONVIF WS-Discovery.
- 3b: CDP + LLDP (Npcap, pasivní odposlech) – dependency na Npcap (installer musí ověřit/nabídnout instalaci).
- Jednotný model záznamu + zobrazení všech TLV polí „jak je zařízení vysílá" (raw view).
- Filtr dle výrobce/interface; přechod z neighbour → akce (otevřít web, WinBox, změnit IP zařízení tam kde protokol umožňuje – např. SADP).
- Zachycení paketů do souboru pro ladění nových protokolů.

**Fáze 4 – Propojení a polish**
- Dashboard: sken + neighbours sloučené do jednoho inventáře zařízení (klíč = MAC).
- Poznámky/štítky u zařízení, favorites.
- Instalátor (MSI/NSIS), podpis, auto-update.

**Fáze 5 – Nápady navíc (podle zájmu)**
- Změna IP *na cizím zařízení* (SADP, MikroTik MAC-Telnet).
- Ping/traceroute/port scanner/DNS lookup/subnet kalkulačka – malé „utility".
- Monitoring (periodický ping, upozornění).
- Wi-Fi analyzér, SNMP walk, SSH/Telnet klient, TFTP/DHCP server pro provisioning.
- Detekce konfliktu IP/rogue DHCP serveru.
- Automatické přepnutí profilu podle připojeného neighbour (např. když vidím MikroTik → aplikuj 192.168.88.x).
- Export do Excel/PDF reportu.

## 5. Rizika
- **Npcap** (licence, instalace) – CDP/LLDP bez něj nelze; MNDP/SADP/Ubiquiti fungují přes běžné UDP sockety.
- **Windows Firewall** blokuje broadcast odpovědi → onboarding krok / pravidlo.
- **Více adaptérů:** broadcast se musí posílat na každé rozhraní zvlášť (bind na IP rozhraní).
- **Admin práva** – UAC; zvážit privilegovaný service.
- Reverzní inženýrství proprietárních protokolů (Ubiquiti, Dahua) – ověřit Wiresharkem na vlastních zařízeních.

## 6. Otevřené otázky
1. Jen Windows, nebo i Linux/macOS později?
2. Distribuce: interní nástroj, nebo veřejně/komerčně (ovlivní licenci Npcap, GPL kódu)?
3. Název aplikace.
4. Kterou funkci chceš dostat první? (doporučeno: IP profily)
