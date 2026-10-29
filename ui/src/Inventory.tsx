// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Tomáš Nesrsta
import { useEffect, useMemo, useRef, useState } from "react";
import { api, type Meta } from "./api";
import { useStore, type SeenHost, type SeenNeighbor } from "./store";
import { ago, cmpIp, downloadCsv } from "./util";

interface Device {
  id: string;
  mac: string;
  ip: string;
  vendor: string;
  kind: string;
  name: string;
  ports: number[];
  sources: string[];
  /** Čas posledního spatření v této relaci; null = jen z uloženého inventáře. */
  seen: number | null;
  host?: SeenHost;
  neighbors: SeenNeighbor[];
  meta?: Meta;
}

type Filter = "all" | "fav" | "live" | "offline";

const first = (...v: (string | null | undefined)[]) => v.find((x) => x && x.trim()) ?? "";

function buildDevices(hosts: SeenHost[], neighbors: SeenNeighbor[], metas: Record<string, Meta>): Device[] {
  const map = new Map<string, Device>();
  const blank = (id: string, mac: string): Device => ({
    id, mac, ip: "", vendor: "", kind: "", name: "", ports: [], sources: [], seen: null, neighbors: [], meta: metas[mac],
  });
  const touch = (d: Device, seen: number) => {
    d.seen = Math.max(d.seen ?? 0, seen);
  };

  for (const h of hosts) {
    const d = map.get(h.mac) ?? blank(h.mac, h.mac);
    d.host = h;
    d.ip = h.ip;
    d.ports = h.ports;
    d.vendor = first(d.vendor, h.vendor);
    d.kind = first(d.kind, h.kind);
    d.name = first(d.name, h.hostname);
    if (!d.sources.includes("Sken")) d.sources.push("Sken");
    touch(d, h.seen);
    map.set(h.mac, d);
  }
  for (const n of neighbors) {
    // Soused bez MAC (např. ONVIF) se spáruje se skenem podle IP.
    let key = n.mac;
    if (!key) key = [...map.values()].find((d) => d.ip && d.ip === n.ip)?.id ?? `ip:${n.ip}`;
    const d = map.get(key) ?? blank(key, n.mac);
    d.neighbors.push(n);
    d.ip = first(d.ip, n.ip);
    d.vendor = first(d.vendor, n.vendor);
    d.kind = first(d.kind, n.model);
    d.name = first(n.identity, d.name);
    if (!d.sources.includes(n.protocol)) d.sources.push(n.protocol);
    touch(d, n.seen);
    map.set(key, d);
  }
  // Uložená zařízení, která teď nejsou vidět.
  for (const [mac, m] of Object.entries(metas)) {
    if (map.has(mac)) continue;
    map.set(mac, { ...blank(mac, mac), ip: m.last_ip, vendor: m.vendor, kind: m.kind, name: m.name, seen: null, meta: m });
  }
  return [...map.values()];
}

export default function Inventory() {
  const { hosts, neighbors } = useStore();
  const [metas, setMetas] = useState<Record<string, Meta>>({});
  const [selected, setSelected] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState<Filter>("all");
  const [error, setError] = useState<string | null>(null);
  const [now, setNow] = useState(Date.now());

  useEffect(() => {
    api.inventoryLoad().then(setMetas, (e) => setError(String(e)));
    const t = setInterval(() => setNow(Date.now()), 15000);
    return () => clearInterval(t);
  }, []);

  const devices = useMemo(
    () => buildDevices(Object.values(hosts), Object.values(neighbors), metas),
    [hosts, neighbors, metas],
  );

  // Průběžně ukládej, co je vidět (jen při změně údajů, zpožděně).
  const lastSig = useRef("");
  useEffect(() => {
    const entries = devices
      .filter((d) => d.mac && d.seen !== null)
      .map((d) => ({ mac: d.mac, ip: d.ip, vendor: d.vendor, name: first(d.neighbors[0]?.identity, d.host?.hostname), kind: d.kind }))
      .sort((a, b) => a.mac.localeCompare(b.mac));
    const sig = JSON.stringify(entries);
    if (!entries.length || sig === lastSig.current) return;
    const t = setTimeout(() => {
      lastSig.current = sig;
      api.inventorySeen(entries).then(setMetas, (e) => setError(String(e)));
    }, 2000);
    return () => clearTimeout(t);
  }, [devices]);

  const shown = useMemo(() => {
    const q = query.trim().toLowerCase();
    return devices
      .filter((d) => {
        if (filter === "fav" && !d.meta?.favorite) return false;
        if (filter === "live" && d.seen === null) return false;
        if (filter === "offline" && d.seen !== null) return false;
        if (!q) return true;
        const hay = [d.ip, d.mac, d.vendor, d.kind, d.name, d.meta?.label, d.meta?.note, ...d.sources].join(" ").toLowerCase();
        return hay.includes(q);
      })
      .sort((a, b) => Number(!!b.meta?.favorite) - Number(!!a.meta?.favorite) || cmpIp(a.ip, b.ip) || a.mac.localeCompare(b.mac));
  }, [devices, query, filter]);

  const sel = devices.find((d) => d.id === selected) ?? null;
  const liveCount = devices.filter((d) => d.seen !== null).length;

  function exportCsv() {
    downloadCsv(
      "inventar",
      ["Název", "IP", "MAC", "Výrobce", "Typ / model", "Zdroje", "Oblíbené", "Poznámka", "Naposledy"],
      shown.map((d) => [
        first(d.meta?.label, d.name), d.ip, d.mac, d.vendor, d.kind, d.sources.join(" "),
        d.meta?.favorite ? "ano" : "", d.meta?.note, d.seen ? new Date(d.seen).toLocaleString() : d.meta ? new Date(d.meta.last_seen * 1000).toLocaleString() : "",
      ]),
    );
  }

  async function toggleFav(d: Device) {
    if (!d.mac) return;
    try {
      setMetas(await api.inventoryUpdate(d.mac, d.meta?.label ?? "", d.meta?.note ?? "", !d.meta?.favorite));
    } catch (e) {
      setError(String(e));
    }
  }

  return (
    <div className="cols neighbors">
      <section className="panel" style={{ padding: 0, overflowX: "auto" }}>
        <div className="scanbar" style={{ padding: 12 }}>
          <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Hledat (IP, MAC, výrobce, název, poznámka…)" />
          <select value={filter} onChange={(e) => setFilter(e.target.value as Filter)} style={{ width: 150 }}>
            <option value="all">Všechna</option>
            <option value="fav">Oblíbená</option>
            <option value="live">Viděná teď</option>
            <option value="offline">Jen uložená</option>
          </select>
          <button onClick={exportCsv} disabled={shown.length === 0}>Export CSV</button>
        </div>
        <div className="muted" style={{ padding: "0 12px 8px" }}>
          {devices.length} zařízení · {liveCount} viděno v této relaci · data ze skenu a neighbours se sloučí podle MAC
        </div>
        {error && <div className="banner err" style={{ margin: 12 }}>{error}</div>}
        <table>
          <thead>
            <tr><th></th><th>Název</th><th>IP</th><th>MAC</th><th>Výrobce</th><th>Typ / model</th><th>Zdroje</th><th>Naposledy</th></tr>
          </thead>
          <tbody>
            {shown.map((d) => (
              <tr key={d.id} className={`${selected === d.id ? "sel" : ""} ${d.seen === null ? "stale" : ""}`} onClick={() => setSelected(d.id)}>
                <td>
                  <button className="star" title={d.mac ? "Oblíbené" : "Bez MAC nelze uložit"} disabled={!d.mac}
                    onClick={(e) => { e.stopPropagation(); toggleFav(d); }}>
                    {d.meta?.favorite ? "★" : "☆"}
                  </button>
                </td>
                <td>{first(d.meta?.label, d.name) || "—"}</td>
                <td className="mono">{d.ip || "—"}</td>
                <td className="mono">{d.mac || "—"}</td>
                <td>{d.vendor || "—"}</td>
                <td>{d.kind || "—"}</td>
                <td>{d.sources.map((s) => <span key={s} className="badge">{s}</span>)}</td>
                <td>{d.seen ? ago(d.seen, now) : d.meta ? ago(d.meta.last_seen * 1000, now) : "—"}</td>
              </tr>
            ))}
            {shown.length === 0 && (
              <tr><td colSpan={8} className="muted" style={{ padding: 16 }}>
                Zatím žádná zařízení. Spusť sken sítě nebo nech běžet Neighbors; nalezená zařízení se sem sloučí a uloží.
              </td></tr>
            )}
          </tbody>
        </table>
      </section>

      <section className="panel">
        {sel ? <Detail key={sel.id} d={sel} onMetas={setMetas} onError={setError} /> : <p className="muted">Vyber zařízení v seznamu.</p>}
      </section>
    </div>
  );
}

function Detail({ d, onMetas, onError }: { d: Device; onMetas: (m: Record<string, Meta>) => void; onError: (e: string) => void }) {
  const [label, setLabel] = useState(d.meta?.label ?? "");
  const [note, setNote] = useState(d.meta?.note ?? "");
  const dirty = label !== (d.meta?.label ?? "") || note !== (d.meta?.note ?? "");
  const webPort = d.ports.find((p) => [443, 80, 8080].includes(p)) ?? (d.neighbors.length ? 80 : undefined);

  async function save() {
    try {
      onMetas(await api.inventoryUpdate(d.mac, label, note, d.meta?.favorite ?? false));
    } catch (e) {
      onError(String(e));
    }
  }

  async function forget() {
    if (!confirm("Odstranit zařízení z uloženého inventáře (název i poznámku)?")) return;
    try {
      onMetas(await api.inventoryForget(d.mac));
    } catch (e) {
      onError(String(e));
    }
  }

  return (
    <>
      <div className="row between">
        <h2>{first(d.meta?.label, d.name, d.ip, d.mac)}</h2>
        <div className="row" style={{ margin: 0 }}>
          {d.ip && webPort && <button onClick={() => api.openWeb(d.ip, webPort)}>Web</button>}
          {d.ip && d.ports.includes(3389) && <button onClick={() => api.openRdp(d.ip)}>RDP</button>}
          {d.ip && <button onClick={() => navigator.clipboard?.writeText(d.ip)}>Kopírovat IP</button>}
        </div>
      </div>
      <p className="muted">{[d.vendor, d.kind].filter(Boolean).join(" · ") || "Neznámé zařízení"}</p>

      {d.mac ? (
        <div className="form" style={{ borderTop: 0, marginTop: 0 }}>
          <label>Vlastní název<input value={label} onChange={(e) => setLabel(e.target.value)} placeholder="např. Kamera vjezd" /></label>
          <label>Poznámka<textarea value={note} onChange={(e) => setNote(e.target.value)} rows={3} /></label>
          <div className="row">
            <button className="primary" onClick={save} disabled={!dirty}>Uložit</button>
            {d.meta && <button onClick={forget}>Zapomenout</button>}
          </div>
        </div>
      ) : (
        <p className="muted">Zařízení nemá známou MAC adresu, proto se nedá uložit do inventáře.</p>
      )}

      <dl className="state" style={{ gridTemplateColumns: "130px 1fr" }}>
        <dt>IP</dt><dd className="mono">{d.ip || "—"}</dd>
        <dt>MAC</dt><dd className="mono">{d.mac || "—"}</dd>
        {d.host && <><dt>Hostname</dt><dd>{d.host.hostname ?? "—"}</dd><dt>Porty</dt><dd className="mono">{d.ports.join(", ") || "—"}</dd><dt>Latence</dt><dd>{d.host.latency_ms} ms</dd></>}
        {d.meta && <><dt>První spatření</dt><dd>{new Date(d.meta.first_seen * 1000).toLocaleString()}</dd><dt>Naposledy uloženo</dt><dd>{new Date(d.meta.last_seen * 1000).toLocaleString()}</dd></>}
      </dl>

      {d.neighbors.map((n) => (
        <details key={n.key} open>
          <summary><strong>{n.protocol}</strong> <span className="muted">{n.local_iface ? `· ${n.local_iface}` : ""}</span></summary>
          <dl className="state" style={{ gridTemplateColumns: "130px 1fr" }}>
            {n.fields.map(([k, v], i) => (
              <div key={i} style={{ display: "contents" }}>
                <dt>{k}</dt>
                <dd className="mono" style={{ whiteSpace: "pre-wrap" }}>{v}</dd>
              </div>
            ))}
          </dl>
        </details>
      ))}
    </>
  );
}
