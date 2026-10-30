// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Tomáš Nesrsta
import { memo, useMemo, useState } from "react";
import {
  Button, DrawerBody, DrawerHeader, DrawerHeaderTitle, Input, MessageBar, MessageBarBody, OverlayDrawer, ProgressBar,
  Select, Switch, Text, mergeClasses,
} from "@fluentui/react-components";
import {
  ArrowDownload20Regular, Copy20Regular, DatabaseSearch20Regular, Desktop20Regular, Dismiss24Regular, Globe20Regular,
  Play20Regular, Stop20Regular,
} from "@fluentui/react-icons";
import { api, type Host, type Iface, type ScanMode } from "./api";
import { Card, IconBtn, Page, copyText, useCommon } from "./common";
import DeviceDetail from "./DeviceDetail";
import { buildDevices, first } from "./devices";
import SourcesDialog from "./SourcesDialog";
import { cancelScan, startScan, useStore } from "./store";
import { ColumnMenu, InfoItem, InfoTip, SearchBox, matches, useColumns, usePersisted, type Col } from "./tableTools";
import { cmpIp, downloadCsv, ipNum } from "./util";

interface Subnet {
  label: string;
  cidr: string;
}

function subnetsOf(ifaces: Iface[]): Subnet[] {
  const out: Subnet[] = [];
  for (const i of ifaces) {
    if (i.status !== "Up") continue;
    for (const a of i.addresses) {
      if (a.ip.startsWith("169.254.") || a.prefix < 16 || a.prefix > 30) continue;
      const mask = (0xffffffff << (32 - a.prefix)) >>> 0;
      const net = (ipNum(a.ip) & mask) >>> 0;
      const ip = [24, 16, 8, 0].map((s) => (net >>> s) & 255).join(".");
      out.push({ label: `${i.name} – ${ip}/${a.prefix}`, cidr: `${ip}/${a.prefix}` });
    }
  }
  return out;
}

const COLS: Col[] = [
  { id: "mac", label: "MAC" },
  { id: "vendor", label: "Výrobce" },
  { id: "name", label: "Jméno" },
  { id: "model", label: "Model" },
  { id: "kind", label: "Typ" },
  { id: "ports", label: "Porty" },
  { id: "ms", label: "Odezva" },
];

const MODES: { id: ScanMode; label: string }[] = [
  { id: "quiet", label: "Tichý" },
  { id: "careful", label: "Opatrný" },
  { id: "normal", label: "Běžný" },
  { id: "thorough", label: "Důkladný" },
];

const webPort = (h: Host) => [443, 80, 8080].find((p) => h.ports.includes(p));

export default memo(function Scan() {
  const c = useCommon();
  const { hosts: hostMap, neighbors, metas, leases, mikrotik, ifaces, admin, scan } = useStore("scan");
  const subnets = useMemo(() => subnetsOf(ifaces ?? []), [ifaces]);
  const [range, setRange] = useState("");
  const [mode, setMode] = usePersisted<ScanMode>("scan.mode", "careful");
  const [ports, setPorts] = usePersisted("scan.ports", false);
  const [query, setQuery] = useState("");
  const [col, shownCols, setCols] = useColumns("scan", COLS);
  const canPorts = mode === "normal" || mode === "thorough";
  const pickMode = (m: ScanMode) => {
    setMode(m);
    setPorts(m === "normal" || m === "thorough");
  };
  const go = () => startScan(effective, mode, canPorts && ports);
  const [actionError, setActionError] = useState<string | null>(null);
  const [sources, setSources] = useState(false);
  const [selected, setSelected] = useState<string | null>(null);
  const effective = range || subnets[0]?.cidr || "";
  const allHosts = useMemo(() => Object.values(hostMap).sort((a, b) => cmpIp(a.ip, b.ip)), [hostMap]);
  const hosts = useMemo(
    () => allHosts.filter((h) => matches(query, h.ip, h.mac, h.vendor, h.name, h.hostname, h.model, h.kind, h.services, leases[h.mac]?.host_name, h.private_mac ? "soukromá" : "")),
    [allHosts, query, leases],
  );
  const devices = useMemo(() => buildDevices(Object.values(hostMap), Object.values(neighbors), metas, leases), [hostMap, neighbors, metas, leases]);
  const sel = selected ? devices.find((d) => d.id === selected) ?? null : null;
  const pct = scan.progress ? scan.progress.done / scan.progress.total : 0;
  const error = scan.error ?? actionError;
  const fail = (e: unknown) => setActionError(String(e));

  /** Nejlepší jméno: DHCP z routeru, pak mDNS / UPnP / titulek webu / reverzní DNS. */
  const nameOf = (h: Host) => first(leases[h.mac]?.host_name, h.name, h.hostname);

  function exportCsv() {
    downloadCsv(
      "sken",
      ["IP", "MAC", "Výrobce", "Jméno", "Model", "Typ", "Služby", "Class ID", "Porty", "Odezva ms"],
      hosts.map((h) => [
        h.ip, h.mac, h.vendor ?? (h.private_mac ? "Soukromá MAC" : ""), nameOf(h), h.model, h.kind, h.services.join(" "),
        leases[h.mac]?.class_id, h.ports.join(" "), h.latency_ms || "",
      ]),
    );
  }

  return (
    <Page
      fill
      title="Sken sítě"
      subtitle="ARP + mDNS + UPnP: MAC, výrobce, jméno, model, služby, porty; jména a Class ID z DHCP routeru"
      actions={
        <>
          <Button appearance="subtle" icon={<DatabaseSearch20Regular />} onClick={() => setSources(true)}>
            Router (volitelné){mikrotik?.has_password ? " ✓" : ""}
          </Button>
          <Button icon={<ArrowDownload20Regular />} onClick={exportCsv} disabled={hosts.length === 0}>Export CSV</Button>
        </>
      }
    >
      <Card className={c.pad}>
        <div className={c.actions}>
          <Select value="" onChange={(_, d) => d.value && setRange(d.value)} disabled={scan.running}>
            <option value="">Lokální podsítě…</option>
            {subnets.map((s) => <option key={s.cidr} value={s.cidr}>{s.label}</option>)}
          </Select>
          <Input
            className={c.grow}
            value={effective}
            placeholder="192.168.1.0/24 nebo 192.168.1.10-50"
            disabled={scan.running}
            onChange={(_, d) => setRange(d.value)}
            onKeyDown={(e) => e.key === "Enter" && !scan.running && effective.trim() && go()}
          />
          <Select value={mode} onChange={(_, d) => pickMode(d.value as ScanMode)} disabled={scan.running} aria-label="Režim skenu">
            {MODES.map((m) => <option key={m.id} value={m.id}>Režim: {m.label}</option>)}
          </Select>
          <InfoTip label="Co který režim dělá">
            <InfoItem title="Tichý (cca 12 s)">Nic neodesílá. Přečte ARP tabulku Windows (zařízení, se kterými počítač už komunikoval) a poslouchá mDNS oznámení. Najde nejméně zařízení, ale v síti ho nikdo nepozná.</InfoItem>
            <InfoItem title="Opatrný (cca 1 minuta, výchozí)">Posílá jen ARP dotazy, což je běžný provoz každé sítě: nejvýš 12 najednou, v náhodném pořadí. K tomu poslouchá mDNS. Žádné UDP pakety, žádné porty ani multicastové dotazy.</InfoItem>
            <InfoItem title="Běžný (cca 7 s)">Pošle UDP paket na každou adresu, aby systém provedl ARP, a aktivně se ptá přes mDNS a UPnP. Rychlý a spolehlivý, ale na síti s ochranou proti skenování je vidět.</InfoItem>
            <InfoItem title="Důkladný (cca 20 s)">Jako Běžný, ale čeká déle a opakuje dotazy, aby se ozvala i zařízení v úsporném režimu. Vytvoří nejvíc provozu.</InfoItem>
          </InfoTip>
          <Switch
            label="Porty"
            checked={canPorts && ports}
            disabled={scan.running || !canPorts}
            onChange={(_, d) => setPorts(d.checked)}
          />
          <InfoTip label="Co dělá skenování portů">
            <InfoItem title="Porty">Zkusí navázat TCP spojení na 16 běžných portů každého nalezeného zařízení (web, SSH, RDP, tiskárna, kamera…). Pomáhá poznat typ zařízení a ukáže odezvu, ale je to přesně to, co firewally a systémy IDS hlásí jako port scan. V režimech Tichý a Opatrný je vypnuto.</InfoItem>
          </InfoTip>
          {scan.running ? (
            <Button icon={<Stop20Regular />} onClick={cancelScan}>Zastavit</Button>
          ) : (
            <Button appearance="primary" icon={<Play20Regular />} disabled={!effective.trim()} onClick={go}>Skenovat</Button>
          )}
        </div>
        {(scan.running || scan.progress) && (
          <div style={{ marginTop: 12 }}>
            <ProgressBar value={pct} />
            <Text size={200} className={c.muted}>
              {scan.progress ? `${scan.progress.done} / ${scan.progress.total}` : "Spouštím…"} · nalezeno {hosts.length}
            </Text>
          </div>
        )}
        {error && <MessageBar intent="error" style={{ marginTop: 12 }}><MessageBarBody>{error}</MessageBarBody></MessageBar>}
        {admin === false && (
          <MessageBar intent="warning" style={{ marginTop: 12 }}><MessageBarBody>Bez práv správce nemusí sken fungovat spolehlivě.</MessageBarBody></MessageBar>
        )}
      </Card>

      <div className={c.actions}>
        <SearchBox value={query} onChange={setQuery} placeholder="Hledat (IP, MAC, výrobce, jméno, model, typ…)" />
        <ColumnMenu cols={COLS} shown={shownCols} onChange={setCols} />
        {query && <Text size={200} className={c.muted}>{hosts.length} z {allHosts.length}</Text>}
      </div>

      <Card className={c.scroll}>
        <table className="ns-table" aria-label="Výsledky skenu">
          <thead>
            <tr>
              <th>IP</th>
              {col("mac") && <th className={c.hideXNarrow}>MAC</th>}
              {col("vendor") && <th>Výrobce</th>}
              {col("name") && <th>Jméno</th>}
              {col("model") && <th className={c.hideNarrow}>Model</th>}
              {col("kind") && <th className={c.hideXNarrow}>Typ</th>}
              {col("ports") && <th className={c.hideNarrow}>Porty</th>}
              {col("ms") && <th className={c.hideNarrow}>ms</th>}
              <th />
            </tr>
          </thead>
          <tbody>
            {hosts.map((h) => (
              <tr key={h.ip} className={selected === h.mac ? "sel" : ""} onClick={() => setSelected(h.mac)}>
                <td className={c.mono}>{h.ip}</td>
                {col("mac") && <td className={mergeClasses(c.mono, c.hideXNarrow)}>{h.mac}</td>}
                {col("vendor") && (
                  <td title={h.private_mac ? "Soukromá (náhodná) MAC adresa: telefony a tablety ji používají místo skutečné, výrobce nelze určit" : undefined}>
                    {h.vendor ?? (h.private_mac ? "Soukromá MAC" : "—")}
                  </td>
                )}
                {col("name") && <td>{nameOf(h) || "—"}</td>}
                {col("model") && <td className={c.hideNarrow}>{h.model ?? "—"}</td>}
                {col("kind") && <td className={c.hideXNarrow}>{h.kind ?? "—"}</td>}
                {col("ports") && <td className={mergeClasses(c.mono, c.hideNarrow)}>{h.ports.join(", ") || "—"}</td>}
                {col("ms") && <td className={c.hideNarrow}>{h.latency_ms || "—"}</td>}
                <td>
                  <div className={c.actions} style={{ flexWrap: "nowrap", gap: 2 }}>
                    {webPort(h) && <IconBtn label="Otevřít web" onClick={(e) => { e.stopPropagation(); api.openWeb(h.ip, webPort(h)!).catch(fail); }}><Globe20Regular /></IconBtn>}
                    {h.ports.includes(3389) && <IconBtn label="RDP" onClick={(e) => { e.stopPropagation(); api.openRdp(h.ip).catch(fail); }}><Desktop20Regular /></IconBtn>}
                    <IconBtn label="Kopírovat IP" onClick={(e) => { e.stopPropagation(); copyText(h.ip); }}><Copy20Regular /></IconBtn>
                  </div>
                </td>
              </tr>
            ))}
            {hosts.length === 0 && (
              <tr>
                <td colSpan={9}><Text className={c.muted}>{allHosts.length ? "Hledání nic nenašlo." : scan.running ? "Hledám zařízení…" : "Žádné výsledky. Vyber podsíť a spusť sken."}</Text></td>
              </tr>
            )}
          </tbody>
        </table>
      </Card>

      <OverlayDrawer open={!!sel} position="end" style={{ width: "min(440px, 100vw)" }} onOpenChange={(_, d) => !d.open && setSelected(null)}>
        <DrawerHeader>
          <DrawerHeaderTitle action={<Button appearance="subtle" aria-label="Zavřít" icon={<Dismiss24Regular />} onClick={() => setSelected(null)} />}>
            Zařízení
          </DrawerHeaderTitle>
        </DrawerHeader>
        <DrawerBody>{sel && <DeviceDetail key={sel.id} d={sel} onError={fail} />}</DrawerBody>
      </OverlayDrawer>

      <SourcesDialog open={sources} onClose={() => setSources(false)} />
    </Page>
  );
});
