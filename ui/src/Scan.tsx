// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Tomáš Nesrsta
import { useEffect, useMemo, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { api, type Host, type Iface } from "./api";
import { clearHosts, useStore } from "./store";
import { cmpIp, downloadCsv } from "./util";

interface Subnet {
  label: string;
  cidr: string;
}

const ipToNum = (ip: string) => ip.split(".").reduce((a, o) => ((a << 8) | Number(o)) >>> 0, 0);

function subnetsOf(ifaces: Iface[]): Subnet[] {
  const out: Subnet[] = [];
  for (const i of ifaces) {
    if (i.status !== "Up") continue;
    for (const a of i.addresses) {
      if (a.ip.startsWith("169.254.") || a.prefix < 16 || a.prefix > 30) continue;
      const mask = (0xffffffff << (32 - a.prefix)) >>> 0;
      const net = (ipToNum(a.ip) & mask) >>> 0;
      const ip = [24, 16, 8, 0].map((s) => (net >>> s) & 255).join(".");
      out.push({ label: `${i.name} – ${ip}/${a.prefix}`, cidr: `${ip}/${a.prefix}` });
    }
  }
  return out;
}

export default function Scan({ admin }: { admin: boolean }) {
  const [subnets, setSubnets] = useState<Subnet[]>([]);
  const [range, setRange] = useState("");
  const { hosts: hostMap } = useStore();
  const hosts = useMemo(() => Object.values(hostMap), [hostMap]);
  const [progress, setProgress] = useState<{ done: number; total: number } | null>(null);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [ouiCount, setOuiCount] = useState<[number, string] | null>(null);

  useEffect(() => {
    api.listInterfaces().then((l) => {
      const s = subnetsOf(l);
      setSubnets(s);
      setRange((cur) => cur || s[0]?.cidr || "");
    }, (e) => setError(String(e)));
    api.ouiInfo().then(setOuiCount, () => {});

    const un = [
      listen<{ done: number; total: number }>("scan-progress", (e) => setProgress(e.payload)),
      listen<boolean>("scan-done", () => setRunning(false)),
    ];
    return () => un.forEach((p) => p.then((f) => f()));
  }, []);

  async function start() {
    setError(null);
    clearHosts();
    setProgress(null);
    try {
      await api.startScan(range);
      setRunning(true);
    } catch (e) {
      setError(String(e));
    }
  }

  const sorted = useMemo(() => [...hosts].sort((a, b) => cmpIp(a.ip, b.ip)), [hosts]);

  function exportCsv() {
    downloadCsv(
      "sken",
      ["IP", "MAC", "Výrobce", "Hostname", "Typ", "Porty", "Latence ms"],
      sorted.map((h) => [h.ip, h.mac, h.vendor, h.hostname, h.kind, h.ports.join(" "), h.latency_ms]),
    );
  }

  const webPort = (h: Host) => [443, 80, 8080].find((p) => h.ports.includes(p));
  const pct = progress ? Math.round((progress.done / progress.total) * 100) : 0;

  return (
    <div>
      <section className="panel">
        <div className="scanbar">
          <select value="" onChange={(e) => e.target.value && setRange(e.target.value)} disabled={running}>
            <option value="">Lokální podsítě…</option>
            {subnets.map((s) => (
              <option key={s.cidr} value={s.cidr}>{s.label}</option>
            ))}
          </select>
          <input
            value={range}
            onChange={(e) => setRange(e.target.value)}
            placeholder="192.168.1.0/24 nebo 192.168.1.10-50"
            disabled={running}
            onKeyDown={(e) => e.key === "Enter" && !running && start()}
          />
          {running ? (
            <button onClick={() => api.cancelScan()}>Zastavit</button>
          ) : (
            <button className="primary" onClick={start} disabled={!range.trim()}>Skenovat</button>
          )}
          <button onClick={exportCsv} disabled={hosts.length === 0}>Export CSV</button>
        </div>
        {(running || progress) && (
          <div className="progress">
            <div style={{ width: `${pct}%` }} />
            <span>{progress ? `${progress.done} / ${progress.total}` : "…"} · nalezeno {hosts.length}</span>
          </div>
        )}
        {error && <div className="banner err">{error}</div>}
        {!admin && <div className="banner warn" style={{ borderRadius: 6 }}>Bez práv správce nemusí sken fungovat spolehlivě.</div>}
        {ouiCount && ouiCount[0] === 0 && (
          <div className="banner warn" style={{ borderRadius: 6 }}>
            Databáze výrobců se nenačetla (soubor oui.csv: {ouiCount[1]}).
          </div>
        )}
      </section>

      <section className="panel" style={{ marginTop: 16, padding: 0, overflowX: "auto" }}>
        <table>
          <thead>
            <tr><th>IP</th><th>MAC</th><th>Výrobce</th><th>Hostname</th><th>Typ</th><th>Porty</th><th>ms</th><th></th></tr>
          </thead>
          <tbody>
            {sorted.map((h) => (
              <tr key={h.ip}>
                <td className="mono">{h.ip}</td>
                <td className="mono">{h.mac}</td>
                <td>{h.vendor ?? "—"}</td>
                <td>{h.hostname ?? "—"}</td>
                <td>{h.kind ?? "—"}</td>
                <td className="mono">{h.ports.join(", ") || "—"}</td>
                <td>{h.latency_ms}</td>
                <td className="actions">
                  {webPort(h) && <button onClick={() => api.openWeb(h.ip, webPort(h)!)}>Web</button>}
                  {h.ports.includes(3389) && <button onClick={() => api.openRdp(h.ip)}>RDP</button>}
                  <button onClick={() => navigator.clipboard?.writeText(h.ip)}>Kopírovat</button>
                </td>
              </tr>
            ))}
            {sorted.length === 0 && (
              <tr><td colSpan={8} className="muted" style={{ padding: 16 }}>{running ? "Hledám zařízení…" : "Žádné výsledky. Vyber podsíť a spusť sken."}</td></tr>
            )}
          </tbody>
        </table>
      </section>
    </div>
  );
}
