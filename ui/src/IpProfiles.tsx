// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Tomáš Nesrsta
import { useCallback, useEffect, useState } from "react";
import { api, parsePrefix, prefixToMask, type Iface, type Profile } from "./api";

interface Draft {
  id: string;
  name: string;
  interface: string;
  mode: "static" | "dhcp";
  ip: string;
  mask: string;
  gateway: string;
  dns: string;
}

const emptyDraft = (iface: string): Draft => ({
  id: "", name: "", interface: iface, mode: "static", ip: "", mask: "255.255.255.0", gateway: "", dns: "",
});

function toDraft(p: Profile): Draft {
  // Formulář podporuje první adresu; další adresy z profilu se při úpravě zachovají přes extra.
  const a = p.addresses[0];
  return {
    id: p.id, name: p.name, interface: p.interface, mode: p.mode,
    ip: a?.ip ?? "", mask: a ? prefixToMask(a.prefix) : "255.255.255.0",
    gateway: p.gateway, dns: p.dns.join(", "),
  };
}

function summary(p: Profile): string {
  if (p.mode === "dhcp") return "DHCP";
  return p.addresses.map((a) => `${a.ip}/${a.prefix}`).join(", ") + (p.gateway ? ` · GW ${p.gateway}` : "");
}

export default function IpProfiles({ admin }: { admin: boolean }) {
  const [ifaces, setIfaces] = useState<Iface[]>([]);
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [selected, setSelected] = useState("");
  const [draft, setDraft] = useState<Draft | null>(null);
  const [canRevert, setCanRevert] = useState(false);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);

  const refresh = useCallback(async () => {
    try {
      const list = await api.listInterfaces();
      setIfaces(list);
      setSelected((cur) => (list.some((i) => i.name === cur) ? cur : (list.find((i) => i.status === "Up") ?? list[0])?.name ?? ""));
      setCanRevert(await api.hasSnapshot());
    } catch (e) {
      setMsg({ ok: false, text: String(e) });
    }
  }, []);

  useEffect(() => {
    refresh();
    api.listProfiles().then(setProfiles, (e) => setMsg({ ok: false, text: String(e) }));
  }, [refresh]);

  const current = ifaces.find((i) => i.name === selected);

  async function run(action: () => Promise<unknown>, okText: string) {
    setBusy(true);
    setMsg(null);
    try {
      await action();
      setMsg({ ok: true, text: okText });
    } catch (e) {
      setMsg({ ok: false, text: String(e) });
    } finally {
      setBusy(false);
      refresh();
    }
  }

  async function save() {
    if (!draft) return;
    let addresses: Profile["addresses"] = [];
    if (draft.mode === "static") {
      const prefix = parsePrefix(draft.mask);
      if (prefix === null) return setMsg({ ok: false, text: "Neplatná maska / prefix" });
      const old = profiles.find((p) => p.id === draft.id);
      addresses = [{ ip: draft.ip.trim(), prefix }, ...(old?.addresses.slice(1) ?? [])];
    }
    const profile: Profile = {
      id: draft.id, name: draft.name.trim(), interface: draft.interface, mode: draft.mode, addresses,
      gateway: draft.mode === "static" ? draft.gateway.trim() : "",
      dns: draft.mode === "static" ? draft.dns.split(/[,;\s]+/).filter(Boolean) : [],
    };
    try {
      setProfiles(await api.saveProfile(profile));
      setDraft(null);
      setMsg({ ok: true, text: "Profil uložen" });
    } catch (e) {
      setMsg({ ok: false, text: String(e) });
    }
  }

  const set = (patch: Partial<Draft>) => setDraft((d) => (d ? { ...d, ...patch } : d));

  return (
    <div className="cols">
      <section className="panel">
        <h2>Síťové rozhraní</h2>
        <select value={selected} onChange={(e) => setSelected(e.target.value)}>
          {ifaces.map((i) => (
            <option key={i.index} value={i.name}>{i.name} ({i.status})</option>
          ))}
        </select>
        {current && (
          <dl className="state">
            <dt>Adaptér</dt><dd>{current.description}</dd>
            <dt>MAC</dt><dd>{current.mac}</dd>
            <dt>Režim</dt><dd>{current.dhcp ? "DHCP" : "Statická"}</dd>
            <dt>IP</dt><dd>{current.addresses.map((a) => `${a.ip}/${a.prefix}`).join(", ") || "—"}</dd>
            <dt>Brána</dt><dd>{current.gateway ?? "—"}</dd>
            <dt>DNS</dt><dd>{current.dns.join(", ") || "—"}</dd>
          </dl>
        )}
        <div className="row">
          <button onClick={refresh} disabled={busy}>Obnovit</button>
          <button
            disabled={busy || !canRevert || !admin}
            onClick={() => run(async () => { const n = await api.revertLast(); setSelected(n); }, "Vráceno předchozí nastavení")}
          >
            Zpět na předchozí
          </button>
        </div>
        {msg && <div className={msg.ok ? "banner ok" : "banner err"}>{msg.text}</div>}
      </section>

      <section className="panel">
        <div className="row between">
          <h2>Profily</h2>
          <button onClick={() => setDraft(emptyDraft(selected))}>+ Nový</button>
        </div>
        {profiles.length === 0 && !draft && <p className="muted">Zatím žádné profily.</p>}
        <ul className="profiles">
          {profiles.map((p) => (
            <li key={p.id}>
              <div>
                <strong>{p.name}</strong>
                <div className="muted">{summary(p)}</div>
              </div>
              <div className="row">
                <button className="primary" disabled={busy || !admin || !selected}
                  onClick={() => run(() => api.applyProfile(p.id, selected), `Profil „${p.name}“ použit na ${selected}`)}>
                  Použít
                </button>
                <button onClick={() => setDraft(toDraft(p))}>Upravit</button>
                <button onClick={async () => { if (confirm(`Smazat profil „${p.name}“?`)) setProfiles(await api.deleteProfile(p.id)); }}>
                  Smazat
                </button>
              </div>
            </li>
          ))}
        </ul>

        {draft && (
          <form className="form" onSubmit={(e) => { e.preventDefault(); save(); }}>
            <h3>{draft.id ? "Upravit profil" : "Nový profil"}</h3>
            <label>Název<input value={draft.name} onChange={(e) => set({ name: e.target.value })} required /></label>
            <label>Režim
              <select value={draft.mode} onChange={(e) => set({ mode: e.target.value as Draft["mode"] })}>
                <option value="static">Statická IP</option>
                <option value="dhcp">DHCP klient</option>
              </select>
            </label>
            {draft.mode === "static" && (
              <>
                <label>IP adresa<input value={draft.ip} placeholder="192.168.1.10" onChange={(e) => set({ ip: e.target.value })} required /></label>
                <label>Maska / prefix<input value={draft.mask} placeholder="255.255.255.0 nebo 24" onChange={(e) => set({ mask: e.target.value })} required /></label>
                <label>Brána<input value={draft.gateway} placeholder="volitelné" onChange={(e) => set({ gateway: e.target.value })} /></label>
                <label>DNS<input value={draft.dns} placeholder="8.8.8.8, 1.1.1.1" onChange={(e) => set({ dns: e.target.value })} /></label>
              </>
            )}
            <div className="row">
              <button className="primary" type="submit">Uložit</button>
              <button type="button" onClick={() => setDraft(null)}>Zrušit</button>
            </div>
          </form>
        )}
      </section>
    </div>
  );
}
