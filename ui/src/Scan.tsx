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
import { api, type Host, type Iface } from "./api";
import { Card, IconBtn, Page, copyText, useCommon } from "./common";
import DeviceDetail from "./DeviceDetail";
import { buildDevices, first } from "./devices";
import SourcesDialog from "./SourcesDialog";
import { cancelScan, startScan, useStore } from "./store";
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

const webPort = (h: Host) => [443, 80, 8080].find((p) => h.ports.includes(p));

export default memo(function Scan() {
  const c = useCommon();
  const { hosts: hostMap, neighbors, metas, leases, mikrotik, ifaces, admin, scan } = useStore("scan");
  const subnets = useMemo(() => subnetsOf(ifaces ?? []), [ifaces]);
  const [range, setRange] = useState("");
  const [thorough, setThorough] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [sources, setSources] = useState(false);
  const [selected, setSelected] = useState<string | null>(null);
  const effective = range || subnets[0]?.cidr || "";
  const hosts = useMemo(() => Object.values(hostMap).sort((a, b) => cmpIp(a.ip, b.ip)), [hostMap]);
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
      title="Sken sítě"
      subtitle="ARP + mDNS + UPnP: MAC, výrobce, jméno, model, služby, porty; jména a Class ID z DHCP routeru"
      actions={
        <>
          <Button icon={<DatabaseSearch20Regular />} onClick={() => setSources(true)}>
            Zdroje dat{mikrotik?.has_password ? " ✓" : ""}
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
            onKeyDown={(e) => e.key === "Enter" && !scan.running && effective.trim() && startScan(effective, thorough)}
          />
          <Switch
            label="Důkladný (cca 20 s)"
            checked={thorough}
            disabled={scan.running}
            onChange={(_, d) => setThorough(d.checked)}
          />
          {scan.running ? (
            <Button icon={<Stop20Regular />} onClick={cancelScan}>Zastavit</Button>
          ) : (
            <Button appearance="primary" icon={<Play20Regular />} disabled={!effective.trim()} onClick={() => startScan(effective, thorough)}>Skenovat</Button>
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

      <Card className={c.scroll}>
        <table className="ns-table" aria-label="Výsledky skenu">
          <thead>
            <tr>
              <th>IP</th>
              <th className={c.hideXNarrow}>MAC</th>
              <th>Výrobce</th>
              <th>Jméno</th>
              <th className={c.hideNarrow}>Model</th>
              <th className={c.hideXNarrow}>Typ</th>
              <th className={c.hideNarrow}>Porty</th>
              <th className={c.hideNarrow}>ms</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {hosts.map((h) => (
              <tr key={h.ip} className={selected === h.mac ? "sel" : ""} onClick={() => setSelected(h.mac)}>
                <td className={c.mono}>{h.ip}</td>
                <td className={mergeClasses(c.mono, c.hideXNarrow)}>{h.mac}</td>
                <td title={h.private_mac ? "Soukromá (náhodná) MAC adresa: telefony a tablety ji používají místo skutečné, výrobce nelze určit" : undefined}>
                  {h.vendor ?? (h.private_mac ? "Soukromá MAC" : "—")}
                </td>
                <td>{nameOf(h) || "—"}</td>
                <td className={c.hideNarrow}>{h.model ?? "—"}</td>
                <td className={c.hideXNarrow}>{h.kind ?? "—"}</td>
                <td className={mergeClasses(c.mono, c.hideNarrow)}>{h.ports.join(", ") || "—"}</td>
                <td className={c.hideNarrow}>{h.latency_ms || "—"}</td>
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
                <td colSpan={9}><Text className={c.muted}>{scan.running ? "Hledám zařízení…" : "Žádné výsledky. Vyber podsíť a spusť sken."}</Text></td>
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
