// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Tomáš Nesrsta
import { useEffect, useState } from "react";
import {
  Button, Dialog, DialogActions, DialogBody, DialogContent, DialogSurface, DialogTitle, Field, Input, MessageBar,
  MessageBarBody, Text,
} from "@fluentui/react-components";
import { api } from "./api";
import { useCommon } from "./common";
import { refreshLeases, useStore } from "./store";

/** Nastavení zdroje dat z routeru MikroTik (DHCP leasy: jméno hostitele, Class ID, Client ID, komentář). */
export default function SourcesDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const c = useCommon();
  const { mikrotik, ifaces, leases, leasesError } = useStore("scan");
  const [host, setHost] = useState("");
  const [user, setUser] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);

  useEffect(() => {
    if (!open) return;
    setMsg(null);
    setPassword("");
    // Výchozí adresa: uložená, jinak brána aktivního rozhraní (MikroTik bývá bránou sítě).
    setHost(mikrotik?.host || ifaces?.find((i) => i.status === "Up" && i.gateway)?.gateway || "");
    setUser(mikrotik?.user ?? "");
  }, [open]);

  async function run(action: () => Promise<string>) {
    setBusy(true);
    setMsg(null);
    try {
      setMsg({ ok: true, text: await action() });
    } catch (e) {
      setMsg({ ok: false, text: String(e) });
    } finally {
      setBusy(false);
    }
  }

  const pw = password || null;
  return (
    <Dialog open={open} onOpenChange={(_, d) => !d.open && onClose()}>
      <DialogSurface>
        <DialogBody>
          <DialogTitle>Zdroje dat: router MikroTik</DialogTitle>
          <DialogContent>
            <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
              <Text>
                Router zná jména a DHCP údaje zařízení (host-name, Class ID, Client ID, komentář), i těch, která se na sken nehlásí.
                Aplikace čte jen DHCP leasy přes API (port 8728).
              </Text>
              <MessageBar intent="warning">
                <MessageBarBody>
                  API na portu 8728 posílá heslo po síti nešifrovaně. Vytvoř na routeru samostatného uživatele jen s právem čtení
                  (skupina <b>read</b>) a použij ho tady. Heslo se ukládá šifrovaně přes Windows DPAPI jen pro tvůj účet.
                </MessageBarBody>
              </MessageBar>
              <Field label="Adresa routeru"><Input value={host} placeholder="192.168.88.1" onChange={(_, d) => setHost(d.value)} /></Field>
              <Field label="Uživatel"><Input value={user} onChange={(_, d) => setUser(d.value)} /></Field>
              <Field label="Heslo" hint={mikrotik?.has_password ? "Uloženo; nech prázdné, aby se zachovalo." : undefined}>
                <Input type="password" value={password} onChange={(_, d) => setPassword(d.value)} />
              </Field>
              {msg && <MessageBar intent={msg.ok ? "success" : "error"}><MessageBarBody>{msg.text}</MessageBarBody></MessageBar>}
              {!msg && leasesError && <MessageBar intent="error"><MessageBarBody>{leasesError}</MessageBarBody></MessageBar>}
              {!msg && mikrotik?.has_password && !leasesError && (
                <Text className={c.muted}>Načteno leasů z routeru: {Object.keys(leases).length}</Text>
              )}
            </div>
          </DialogContent>
          <DialogActions>
            {mikrotik?.has_password && (
              <Button disabled={busy} onClick={() => run(async () => { await api.mikrotikClear(); await refreshLeases(); return "Údaje smazány"; })}>Smazat údaje</Button>
            )}
            <Button
              disabled={busy || !host.trim() || !user.trim() || (!password && !mikrotik?.has_password)}
              onClick={() => run(async () => `Přihlášení v pořádku, leasů: ${await api.mikrotikTest(host, user, pw)}`)}
            >
              Vyzkoušet
            </Button>
            <Button
              appearance="primary"
              disabled={busy || !host.trim() || !user.trim()}
              onClick={() => run(async () => { await api.mikrotikSave(host, user, pw); await refreshLeases(); setPassword(""); return "Uloženo"; })}
            >
              Uložit
            </Button>
            <Button appearance="secondary" onClick={onClose}>Zavřít</Button>
          </DialogActions>
        </DialogBody>
      </DialogSurface>
    </Dialog>
  );
}
