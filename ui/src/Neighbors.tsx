// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Tomáš Nesrsta
import { memo, useMemo, useState } from "react";
import {
  Button, DrawerBody, DrawerHeader, DrawerHeaderTitle, MessageBar, MessageBarBody, OverlayDrawer, Select, Text, mergeClasses,
} from "@fluentui/react-components";
import { Copy20Regular, Delete20Regular, Dismiss24Regular, Globe20Regular, Play20Regular, Search20Regular, Stop20Regular } from "@fluentui/react-icons";
import { api } from "./api";
import { Card, KeyValues, NARROW, Page, copyText, useCommon, useMediaQuery } from "./common";
import { clearNeighbors, restartNeighbors, stopNeighbors, useStore, type SeenNeighbor } from "./store";
import { ColumnMenu, InfoItem, InfoTip, SearchBox, matches, useColumns, type Col } from "./tableTools";
import { cmpIp } from "./util";

const COLS: Col[] = [
  { id: "mac", label: "MAC" },
  { id: "vendor", label: "Výrobce" },
  { id: "identity", label: "Identita" },
  { id: "model", label: "Model" },
  { id: "version", label: "Verze" },
  { id: "iface", label: "Rozhraní" },
];

export default memo(function Neighbors() {
  const c = useCommon();
  const { neighbors: items, hosts, metas, nb } = useStore("neighbors");
  const narrow = useMediaQuery(NARROW);
  const [selected, setSelected] = useState<string | null>(null);
  const [proto, setProto] = useState("");
  const [query, setQuery] = useState("");
  const [col, shownCols, setCols] = useColumns("neighbors", COLS);

  // Výrobce, který zná sken nebo uložený inventář, se doplní i sousedům, kteří ho sami neuvedou.
  const vendorOf = useMemo(() => {
    const byMac = new Map<string, string>();
    const byIp = new Map<string, string>();
    for (const h of Object.values(hosts)) {
      if (!h.vendor) continue;
      byMac.set(h.mac.toLowerCase(), h.vendor);
      byIp.set(h.ip, h.vendor);
    }
    return (n: SeenNeighbor) => n.vendor || byMac.get(n.mac.toLowerCase()) || metas[n.mac]?.vendor || byIp.get(n.ip) || "";
  }, [hosts, metas]);

  const list = useMemo(
    () =>
      Object.values(items)
        .filter((n) => !proto || n.protocol === proto)
        .filter((n) => matches(query, n.protocol, n.ip, n.mac, vendorOf(n), n.identity, n.model, n.version, n.local_iface))
        .sort((a, b) => cmpIp(a.ip, b.ip) || a.protocol.localeCompare(b.protocol)),
    [items, proto, query, vendorOf],
  );
  const protocols = useMemo(() => [...new Set(Object.values(items).map((n) => n.protocol))].sort(), [items]);
  const sel = selected ? items[selected] : null;
  const detail = sel && <Detail n={sel} vendor={vendorOf(sel)} />;

  return (
    <Page
      fill
      title="Neighbors"
      subtitle={`${nb.running ? (nb.active ? "Aktivně hledám a poslouchám" : "Jen poslouchám (nic neodesílám)") : "Zastaveno"} · ${list.length} zařízení`}
      actions={
        <>
          <Button icon={<Delete20Regular />} onClick={() => { clearNeighbors(); setSelected(null); }}>Vyčistit</Button>
          {nb.running ? (
            <Button icon={<Stop20Regular />} onClick={stopNeighbors}>Zastavit</Button>
          ) : (
            <Button icon={<Play20Regular />} onClick={() => restartNeighbors(false)}>Poslouchat</Button>
          )}
          <Button appearance="primary" icon={<Search20Regular />} disabled={nb.running && nb.active} onClick={() => restartNeighbors(true)}>
            Hledat aktivně
          </Button>
          <InfoTip label="Poslech a aktivní hledání">
            <InfoItem title="Poslouchat (výchozí, spouští se samo)">Aplikace nic neodesílá. Zachytává jen to, co zařízení vysílají sama: MikroTik MNDP a (s Npcap) CDP a LLDP. Zařízení se ozývají podle svého časovače, často po desítkách sekund až minutách.</InfoItem>
            <InfoItem title="Hledat aktivně">Třikrát po 3 s odešle dotazy MNDP, Ubiquiti, Hikvision SADP a ONVIF a pak dál jen poslouchá. Zařízení se ozvou hned, ale jsou to broadcasty a multicasty, které může síť s ochranou proti skenování zaznamenat.</InfoItem>
          </InfoTip>
        </>
      }
    >
      {nb.error && <MessageBar intent="error"><MessageBarBody>{nb.error}</MessageBarBody></MessageBar>}
      {nb.warn && <MessageBar intent="warning"><MessageBarBody>{nb.warn}</MessageBarBody></MessageBar>}

      <div className={c.actions}>
        <SearchBox value={query} onChange={setQuery} placeholder="Hledat (protokol, IP, MAC, výrobce, identita, model…)" />
        <Select value={proto} onChange={(_, d) => setProto(d.value)} aria-label="Protokol">
          <option value="">Všechny protokoly</option>
          {protocols.map((p) => <option key={p}>{p}</option>)}
        </Select>
        <ColumnMenu cols={COLS} shown={shownCols} onChange={setCols} />
      </div>

      <div className={mergeClasses(c.split, c.splitFill)}>
        <Card className={c.scroll}>
          <table className="ns-table" aria-label="Sousedé">
            <thead>
              <tr>
                <th>Protokol</th>
                <th>IP</th>
                {col("mac") && <th className={c.hideXNarrow}>MAC</th>}
                {col("vendor") && <th className={c.hideNarrow}>Výrobce</th>}
                {col("identity") && <th>Identita</th>}
                {col("model") && <th className={c.hideNarrow}>Model</th>}
                {col("version") && <th className={c.hideNarrow}>Verze</th>}
                {col("iface") && <th className={c.hideNarrow}>Rozhraní</th>}
              </tr>
            </thead>
            <tbody>
              {list.map((n) => (
                <tr key={n.key} className={selected === n.key ? "sel" : ""} onClick={() => setSelected(n.key)}>
                  <td>{n.protocol}</td>
                  <td className={c.mono}>{n.ip || "—"}</td>
                  {col("mac") && <td className={mergeClasses(c.mono, c.hideXNarrow)}>{n.mac || "—"}</td>}
                  {col("vendor") && <td className={c.hideNarrow}>{vendorOf(n) || "—"}</td>}
                  {col("identity") && <td>{n.identity || "—"}</td>}
                  {col("model") && <td className={c.hideNarrow}>{n.model || "—"}</td>}
                  {col("version") && <td className={c.hideNarrow}>{n.version || "—"}</td>}
                  {col("iface") && <td className={c.hideNarrow}>{n.local_iface || "—"}</td>}
                </tr>
              ))}
              {list.length === 0 && (
                <tr>
                  <td colSpan={8}>
                    <Text className={c.muted}>{nb.running ? (nb.active ? "Zatím nic nenalezeno. Zařízení se ozývají obvykle do několika sekund." : "Zatím nic neslyším. Zařízení se ozývají podle svého časovače; zkus Hledat aktivně.") : "Spusť poslech nebo hledání."}</Text>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </Card>

        {narrow ? (
          <OverlayDrawer open={!!sel} position="end" style={{ width: "min(440px, 100vw)" }} onOpenChange={(_, d) => !d.open && setSelected(null)}>
            <DrawerHeader>
              <DrawerHeaderTitle action={<Button appearance="subtle" aria-label="Zavřít" icon={<Dismiss24Regular />} onClick={() => setSelected(null)} />}>
                Soused
              </DrawerHeaderTitle>
            </DrawerHeader>
            <DrawerBody>{detail}</DrawerBody>
          </OverlayDrawer>
        ) : (
          <Card className={mergeClasses(c.pad, c.sideCard)}>{detail ?? <Text className={c.muted}>Vyber zařízení v seznamu a uvidíš všechna pole, která vysílá.</Text>}</Card>
        )}
      </div>
    </Page>
  );
});

function Detail({ n, vendor }: { n: SeenNeighbor; vendor: string }) {
  const c = useCommon();
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
      <div>
        <Text as="h2" weight="semibold" size={500} block>{n.identity || n.model || n.ip}</Text>
        <Text className={c.muted}>{n.protocol}{vendor ? ` · ${vendor}` : ""}</Text>
      </div>
      <div className={c.actions}>
        {n.ip && <Button icon={<Globe20Regular />} onClick={() => api.openWeb(n.ip, 80).catch(() => {})}>Web</Button>}
        {n.ip && <Button icon={<Copy20Regular />} onClick={() => copyText(n.ip)}>Kopírovat IP</Button>}
      </div>
      <KeyValues rows={n.fields} />
      <details>
        <summary className={c.muted}>Surový paket</summary>
        <pre className={c.raw}>{n.raw}</pre>
      </details>
    </div>
  );
}
