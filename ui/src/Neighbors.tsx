// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Tomáš Nesrsta
import { useEffect, useMemo, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { api } from "./api";
import { clearNeighbors, useStore } from "./store";
import { cmpIp } from "./util";

const STALE_MS = 90_000;

export default function Neighbors() {
  const { neighbors: items } = useStore();
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [proto, setProto] = useState("");
  const [now, setNow] = useState(Date.now());
  const [warn, setWarn] = useState<string | null>(null);

  useEffect(() => {
    const un = [
      listen("neighbors-done", () => setRunning(false)),
      listen<string>("neighbors-warn", (e) => setWarn(e.payload)),
    ];
    api.neighborsRunning().then(setRunning, () => {});
    const t = setInterval(() => setNow(Date.now()), 5000);
    return () => {
      un.forEach((p) => p.then((f) => f()));
      clearInterval(t);
    };
  }, []);

  async function start() {
    setError(null);
    setWarn(null);
    try {
      await api.startNeighbors();
      setRunning(true);
    } catch (e) {
      setError(String(e));
    }
  }

  // Při prvním zobrazení hned začni hledat.
  useEffect(() => {
    api.neighborsRunning().then((r) => { if (!r) start(); }, () => {});
  }, []);

  const list = useMemo(
    () =>
      Object.values(items)
        .filter((n) => !proto || n.protocol === proto)
        .sort((a, b) => (cmpIp(a.ip, b.ip) || a.protocol.localeCompare(b.protocol))),
    [items, proto],
  );
  const protocols = useMemo(() => [...new Set(Object.values(items).map((n) => n.protocol))].sort(), [items]);
  const sel = selected ? items[selected] : null;

  return (
    <div className="cols neighbors">
      <section className="panel" style={{ padding: 0, overflowX: "auto" }}>
        <div className="scanbar" style={{ padding: 12 }}>
          {running ? (
            <button onClick={() => api.stopNeighbors()}>Zastavit</button>
          ) : (
            <button className="primary" onClick={start}>Hledat</button>
          )}
          <select value={proto} onChange={(e) => setProto(e.target.value)} style={{ width: 160 }}>
            <option value="">Všechny protokoly</option>
            {protocols.map((p) => <option key={p}>{p}</option>)}
          </select>
          <button onClick={() => { clearNeighbors(); setSelected(null); }}>Vyčistit</button>
          <span className="muted" style={{ alignSelf: "center" }}>
            {running ? "Poslouchám (MNDP, Ubiquiti, SADP, ONVIF, CDP, LLDP)…" : "Zastaveno"} · {list.length} zařízení
          </span>
        </div>
        {error && <div className="banner err" style={{ margin: 12 }}>{error}</div>}
        {warn && <div className="banner warn" style={{ margin: 12, borderRadius: 6 }}>{warn}</div>}
        <table>
          <thead>
            <tr><th>Protokol</th><th>IP</th><th>MAC</th><th>Identita</th><th>Model</th><th>Verze</th><th>Rozhraní</th></tr>
          </thead>
          <tbody>
            {list.map((n) => (
              <tr key={n.key} className={`${selected === n.key ? "sel" : ""} ${now - n.seen > STALE_MS ? "stale" : ""}`} onClick={() => setSelected(n.key)}>
                <td>{n.protocol}</td>
                <td className="mono">{n.ip}</td>
                <td className="mono">{n.mac || "—"}</td>
                <td>{n.identity || "—"}</td>
                <td>{n.model || "—"}</td>
                <td>{n.version || "—"}</td>
                <td>{n.local_iface || "—"}</td>
              </tr>
            ))}
            {list.length === 0 && (
              <tr><td colSpan={7} className="muted" style={{ padding: 16 }}>
                {running ? "Zatím nic nenalezeno. Zařízení se ozývají obvykle do několika sekund." : "Spusť hledání."}
              </td></tr>
            )}
          </tbody>
        </table>
      </section>

      <section className="panel">
        {sel ? (
          <>
            <div className="row between">
              <h2>{sel.identity || sel.model || sel.ip}</h2>
              <div className="row" style={{ margin: 0 }}>
                {sel.ip && <button onClick={() => api.openWeb(sel.ip, 80)}>Web</button>}
                {sel.ip && <button onClick={() => navigator.clipboard?.writeText(sel.ip)}>Kopírovat IP</button>}
              </div>
            </div>
            <p className="muted">{sel.protocol}{sel.vendor ? ` · ${sel.vendor}` : ""}</p>
            <dl className="state" style={{ gridTemplateColumns: "130px 1fr" }}>
              {sel.fields.map(([k, v], i) => (
                <div key={i} style={{ display: "contents" }}>
                  <dt>{k}</dt>
                  <dd className="mono" style={{ whiteSpace: "pre-wrap" }}>{v}</dd>
                </div>
              ))}
            </dl>
            <details>
              <summary className="muted">Surový paket</summary>
              <pre className="raw">{sel.raw}</pre>
            </details>
          </>
        ) : (
          <p className="muted">Vyber zařízení v seznamu a uvidíš všechna pole, která vysílá.</p>
        )}
      </section>
    </div>
  );
}
