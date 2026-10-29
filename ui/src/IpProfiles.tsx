// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Tomáš Nesrsta
import { memo, useEffect, useState } from "react";
import {
  Button, Dialog, DialogActions, DialogBody, DialogContent, DialogSurface, DialogTitle, Field, Input, MessageBar,
  MessageBarBody, Select, Text,
} from "@fluentui/react-components";
import { Add20Regular, ArrowClockwise20Regular, ArrowUndo20Regular, Delete20Regular, Edit20Regular, Play20Regular } from "@fluentui/react-icons";
import { api, parsePrefix, prefixToMask, type Profile } from "./api";
import { Card, KeyValues, Page, useCommon } from "./common";
import { refreshIfaces, useStore } from "./store";

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

const emptyDraft = (iface: string): Draft => ({ id: "", name: "", interface: iface, mode: "static", ip: "", mask: "255.255.255.0", gateway: "", dns: "" });

function toDraft(p: Profile): Draft {
  const a = p.addresses[0];
  return {
    id: p.id, name: p.name, interface: p.interface, mode: p.mode,
    ip: a?.ip ?? "", mask: a ? prefixToMask(a.prefix) : "255.255.255.0", gateway: p.gateway, dns: p.dns.join(", "),
  };
}

function summary(p: Profile): string {
  if (p.mode === "dhcp") return "DHCP klient";
  return p.addresses.map((a) => `${a.ip}/${a.prefix}`).join(", ") + (p.gateway ? ` · brána ${p.gateway}` : "");
}

export default memo(function IpProfiles() {
  const c = useCommon();
  const { ifaces, ifacesError, admin: adminState } = useStore("profiles");
  const admin = adminState !== false;
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [chosen, setChosen] = useState("");
  const [draft, setDraft] = useState<Draft | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [canRevert, setCanRevert] = useState(false);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);

  useEffect(() => {
    api.listProfiles().then(setProfiles, (e) => setMsg({ ok: false, text: String(e) }));
    api.hasSnapshot().then(setCanRevert, () => {});
  }, []);

  const list = ifaces ?? [];
  const selected = list.some((i) => i.name === chosen) ? chosen : (list.find((i) => i.status === "Up") ?? list[0])?.name ?? "";
  const current = list.find((i) => i.name === selected);

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
      refreshIfaces();
      api.hasSnapshot().then(setCanRevert, () => {});
    }
  }

  async function save() {
    if (!draft) return;
    let addresses: Profile["addresses"] = [];
    if (draft.mode === "static") {
      const prefix = parsePrefix(draft.mask);
      if (prefix === null) return setFormError("Neplatná maska / prefix");
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
      setFormError(null);
      setMsg({ ok: true, text: "Profil uložen" });
    } catch (e) {
      setFormError(String(e));
    }
  }

  const set = (patch: Partial<Draft>) => setDraft((d) => (d ? { ...d, ...patch } : d));

  return (
    <Page title="IP profily" subtitle="Uložené konfigurace IPv4 pro síťové karty, použití jedním kliknutím">
      {ifacesError && <MessageBar intent="error"><MessageBarBody>{ifacesError}</MessageBarBody></MessageBar>}
      {msg && <MessageBar intent={msg.ok ? "success" : "error"}><MessageBarBody>{msg.text}</MessageBarBody></MessageBar>}

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(340px, 1fr))", gap: 16, alignItems: "start" }}>
        <Card className={c.pad}>
          <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
            <Text weight="semibold" size={400}>Síťové rozhraní</Text>
            <Select value={selected} onChange={(_, d) => setChosen(d.value)}>
              {list.map((i) => <option key={i.index} value={i.name}>{i.name} ({i.status})</option>)}
            </Select>
            {current && (
              <KeyValues mono={false} rows={[
                ["Adaptér", current.description],
                ["MAC", current.mac],
                ["Režim", current.dhcp ? "DHCP" : "Statická"],
                ["IP", current.addresses.map((a) => `${a.ip}/${a.prefix}`).join(", ") || "—"],
                ["Brána", current.gateway ?? "—"],
                ["DNS", current.dns.join(", ") || "—"],
              ]} />
            )}
            <div className={c.actions}>
              <Button icon={<ArrowClockwise20Regular />} onClick={() => refreshIfaces()} disabled={busy}>Obnovit</Button>
              <Button icon={<ArrowUndo20Regular />} disabled={busy || !canRevert || !admin}
                onClick={() => run(async () => { setChosen(await api.revertLast()); }, "Vráceno předchozí nastavení")}>
                Zpět na předchozí
              </Button>
            </div>
          </div>
        </Card>

        <Card className={c.pad}>
          <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
            <div className={c.head}>
              <Text weight="semibold" size={400}>Profily</Text>
              <Button icon={<Add20Regular />} onClick={() => { setFormError(null); setDraft(emptyDraft(selected)); }}>Nový profil</Button>
            </div>
            {profiles.length === 0 && <Text className={c.muted}>Zatím žádné profily.</Text>}
            {profiles.map((p) => (
              <div key={p.id} className={c.head} style={{ padding: "8px 0", borderTop: "1px solid var(--colorNeutralStroke2)" }}>
                <div style={{ minWidth: 0 }}>
                  <Text weight="semibold" block>{p.name}</Text>
                  <Text size={200} className={c.muted}>{summary(p)}</Text>
                </div>
                <div className={c.actions} style={{ flexWrap: "nowrap" }}>
                  <Button appearance="primary" icon={<Play20Regular />} disabled={busy || !admin || !selected}
                    onClick={() => run(() => api.applyProfile(p.id, selected), `Profil „${p.name}“ použit na ${selected}`)}>
                    Použít
                  </Button>
                  <Button appearance="subtle" aria-label="Upravit" icon={<Edit20Regular />} onClick={() => { setFormError(null); setDraft(toDraft(p)); }} />
                  <Button appearance="subtle" aria-label="Smazat" icon={<Delete20Regular />}
                    onClick={async () => { if (confirm(`Smazat profil „${p.name}“?`)) setProfiles(await api.deleteProfile(p.id)); }} />
                </div>
              </div>
            ))}
          </div>
        </Card>
      </div>

      <Dialog open={!!draft} onOpenChange={(_, d) => !d.open && setDraft(null)}>
        <DialogSurface>
          <form onSubmit={(e) => { e.preventDefault(); save(); }}>
            <DialogBody>
              <DialogTitle>{draft?.id ? "Upravit profil" : "Nový profil"}</DialogTitle>
              <DialogContent>
                {draft && (
                  <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
                    {formError && <MessageBar intent="error"><MessageBarBody>{formError}</MessageBarBody></MessageBar>}
                    <Field label="Název" required><Input value={draft.name} onChange={(_, d) => set({ name: d.value })} /></Field>
                    <Field label="Režim">
                      <Select value={draft.mode} onChange={(_, d) => set({ mode: d.value as Draft["mode"] })}>
                        <option value="static">Statická IP</option>
                        <option value="dhcp">DHCP klient</option>
                      </Select>
                    </Field>
                    {draft.mode === "static" && (
                      <>
                        <Field label="IP adresa" required><Input value={draft.ip} placeholder="192.168.1.10" onChange={(_, d) => set({ ip: d.value })} /></Field>
                        <Field label="Maska / prefix" required><Input value={draft.mask} placeholder="255.255.255.0 nebo 24" onChange={(_, d) => set({ mask: d.value })} /></Field>
                        <Field label="Brána"><Input value={draft.gateway} placeholder="volitelné" onChange={(_, d) => set({ gateway: d.value })} /></Field>
                        <Field label="DNS"><Input value={draft.dns} placeholder="8.8.8.8, 1.1.1.1" onChange={(_, d) => set({ dns: d.value })} /></Field>
                      </>
                    )}
                  </div>
                )}
              </DialogContent>
              <DialogActions>
                <Button appearance="secondary" type="button" onClick={() => setDraft(null)}>Zrušit</Button>
                <Button appearance="primary" type="submit">Uložit</Button>
              </DialogActions>
            </DialogBody>
          </form>
        </DialogSurface>
      </Dialog>
    </Page>
  );
});
