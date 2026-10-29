# Bezpečnost

NetScout posílá pakety do sítě a mění nastavení síťových karet, proto berte bezpečnostní problémy vážně.

## Jak nahlásit zranitelnost
Použijte **soukromé hlášení** na GitHubu: záložka *Security → Report a vulnerability* v repozitáři <https://github.com/Thomeless/netscout>. Neotevírejte kvůli tomu veřejné *Issue*.
Napište, jak chybu vyvolat, jakou verzi používáte a co by mohl útočník získat. Odpovím, jakmile to bude možné, a opravu zveřejním s poděkováním (pokud si nepřejete zůstat anonymní).

## Podporované verze
Opravy dostává poslední vydaná verze. Starší verze se neudržují.

## Co je v rozsahu
Zpracování paketů z discovery protokolů (MNDP, Ubiquiti, SADP, ONVIF, CDP, LLDP, mDNS, UPnP), RouterOS API a uložené přihlašovací údaje, změna IP konfigurace, spouštění externích programů (PowerShell, `mstsc`, otevření prohlížeče), aktualizace aplikace, ukládání dat v datové složce.

## Co aplikace dělá pro bezpečnost
Hodnoty z formulářů se do PowerShellu předávají přes proměnné prostředí, ne vložením do textu skriptu. IP adresy a prefixy se před použitím validují. Volitelný zdroj dat z routeru MikroTik používá API na portu 8728, které posílá heslo po síti nešifrovaně: používej na routeru samostatného uživatele jen s právem čtení. Heslo se ukládá šifrované přes Windows DPAPI a do rozhraní se nikdy nevrací. Sken a discovery posílají dotazy jen do lokální sítě. Aplikace neposílá žádná data na internet kromě kontroly aktualizací na GitHubu; instalační balíček aktualizace je ověřen podpisem. Aplikace si při startu přidá příchozí UDP pravidlo Windows Firewallu (`NetScout discovery`) výhradně pro svůj program, aby discovery fungovalo; pravidlo lze kdykoli smazat. Release build běží s právy správce, proto vstup z paketů nikdy neprochází do příkazů.
