# Podíl na vývoji NetScoutu

Díky za zájem. Projekt vede a spravuje autor, Tomáš Nesrsta; o začlenění změn rozhoduje on.

## Než začnete
- U větší změny nejdřív založte *Issue* a domluvte se, ať se zbytečně nepracuje. Drobné opravy můžete poslat rovnou.
- Bezpečnostní problémy neposílejte veřejně, viz [`SECURITY.md`](SECURITY.md).
- Aplikace nikdy sama nemění síťové nastavení (IP adresu) bez výslovného pokynu uživatele a nikam neposílá data bez jeho vědomí (žádná telemetrie). Změny, které to porušují, se nepřijímají.
- Sken a discovery jsou pro správu vlastních sítí. Funkce určené k narušování cizích sítí se nepřijímají.

## Pravidla pro změny
- Sestavení a testy: `cargo test --workspace` a `npm --prefix ui run build` musí projít.
- Nový parser protokolu patří s testem na ukázkovém paketu (viz `src-tauri/src/proto.rs`). Pokud paket pochází z reálného zařízení, anonymizujte MAC a IP adresy.
- Texty rozhraní jsou zatím česky. Komentáře a názvy v kódu anglicky nebo česky, jako v okolním kódu.
- Žádná reálná osobní data, adresy ani hesla v testech a ukázkových datech.
- Styl: držte se stylu okolního kódu. Žádné nové závislosti bez důvodu; licence závislosti musí být slučitelná s AGPL-3.0 (MIT, Apache-2.0, BSD, ISC, MPL-2.0…).

## Licence příspěvků
Odesláním změny souhlasíte, že ji lze šířit pod licencí projektu, **GNU AGPL-3.0-only**, a že k ní máte práva. Autorství vašeho příspěvku zůstává vaše; commity podepisujte `git commit -s` (*Developer Certificate of Origin*, <https://developercertificate.org>).
Autorská poznámka v souborech (`Copyright (C) 2026 Tomáš Nesrsta`) a soubor [`NOTICE`](NOTICE) se neodstraňují.
