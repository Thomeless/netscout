// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Tomáš Nesrsta
import { useState } from "react";
import { Accordion, AccordionHeader, AccordionItem, AccordionPanel, Button, Field, Input, Text, Textarea } from "@fluentui/react-components";
import { Copy20Regular, Desktop20Regular, Globe20Regular } from "@fluentui/react-icons";
import { api } from "./api";
import { KeyValues, copyText, useCommon } from "./common";
import { first, type Device } from "./devices";
import { forgetMeta, updateMeta } from "./store";

/** Podrobnosti zařízení (inventář i sken): název a poznámka, údaje ze skenu, DHCP z routeru, neighbours. */
export default function DeviceDetail({ d, onError }: { d: Device; onError: (e: unknown) => void }) {
  const c = useCommon();
  const [label, setLabel] = useState(d.meta?.label ?? "");
  const [note, setNote] = useState(d.meta?.note ?? "");
  const dirty = label !== (d.meta?.label ?? "") || note !== (d.meta?.note ?? "");
  const webPort = d.ports.find((p) => [443, 80, 8080].includes(p)) ?? (d.neighbors.length ? 80 : undefined);

  const rows: [string, string][] = [["IP", d.ip || "—"], ["MAC", d.mac ? d.mac + (d.privateMac ? " (soukromá / náhodná)" : "") : "—"]];
  if (d.name) rows.push(["Jméno", d.name]);
  if (d.model) rows.push(["Model", d.model]);
  if (d.host) {
    if (d.host.hostname) rows.push(["Reverzní DNS", d.host.hostname]);
    if (d.host.web_title) rows.push(["Titulek webu", d.host.web_title]);
    if (d.host.web_server) rows.push(["HTTP Server", d.host.web_server]);
    rows.push(["Porty", d.ports.join(", ") || "—"]);
    if (d.host.latency_ms) rows.push(["Odezva (TCP)", `${d.host.latency_ms} ms`]);
  }
  if (d.services.length) rows.push(["Služby", d.services.join(", ")]);
  if (d.meta) rows.push(["První spatření", new Date(d.meta.first_seen * 1000).toLocaleString()], ["Naposledy uloženo", new Date(d.meta.last_seen * 1000).toLocaleString()]);

  const l = d.lease;
  const dhcp: [string, string][] = l
    ? ([
        ["Jméno hostitele (host-name)", l.host_name],
        ["Class ID", l.class_id],
        ["Client ID", l.client_id],
        ["Adresa z DHCP", l.address],
        ["Stav leasu", l.status],
        ["Naposledy viděno (router)", l.last_seen],
        ["DHCP server", l.server],
        ["Komentář na routeru", l.comment],
      ] as [string, string][]).filter(([, v]) => v)
    : [];

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
      <div>
        <Text as="h2" weight="semibold" size={500} block>{first(d.meta?.label, d.name, d.ip, d.mac)}</Text>
        <Text className={c.muted}>{[d.vendor || (d.privateMac ? "Soukromá MAC" : ""), d.kind].filter(Boolean).join(" · ") || "Neznámé zařízení"}</Text>
      </div>
      <div className={c.actions}>
        {d.ip && webPort && <Button icon={<Globe20Regular />} onClick={() => api.openWeb(d.ip, webPort).catch(onError)}>Web</Button>}
        {d.ip && d.ports.includes(3389) && <Button icon={<Desktop20Regular />} onClick={() => api.openRdp(d.ip).catch(onError)}>RDP</Button>}
        {d.ip && <Button icon={<Copy20Regular />} onClick={() => copyText(d.ip)}>Kopírovat IP</Button>}
      </div>

      {d.mac ? (
        <>
          <Field label="Vlastní název"><Input value={label} placeholder="např. Kamera vjezd" onChange={(_, v) => setLabel(v.value)} /></Field>
          <Field label="Poznámka"><Textarea value={note} rows={3} resize="vertical" onChange={(_, v) => setNote(v.value)} /></Field>
          <div className={c.actions}>
            <Button appearance="primary" disabled={!dirty} onClick={() => updateMeta(d.mac, label, note, d.meta?.favorite ?? false).catch(onError)}>Uložit</Button>
            {d.meta && (
              <Button onClick={() => confirm("Odstranit zařízení z uloženého inventáře (název i poznámku)?") && forgetMeta(d.mac).catch(onError)}>Zapomenout</Button>
            )}
          </div>
        </>
      ) : (
        <Text className={c.muted}>Zařízení nemá známou MAC adresu, proto se nedá uložit do inventáře.</Text>
      )}

      <KeyValues rows={rows} />

      {dhcp.length > 0 && (
        <>
          <Text weight="semibold">DHCP (router MikroTik)</Text>
          <KeyValues rows={dhcp} />
        </>
      )}

      {d.neighbors.length > 0 && (
        <Accordion multiple collapsible defaultOpenItems={d.neighbors.map((n) => n.key)}>
          {d.neighbors.map((n) => (
            <AccordionItem key={n.key} value={n.key}>
              <AccordionHeader>{n.protocol}{n.local_iface ? ` · ${n.local_iface}` : ""}</AccordionHeader>
              <AccordionPanel><KeyValues rows={n.fields} /></AccordionPanel>
            </AccordionItem>
          ))}
        </Accordion>
      )}
    </div>
  );
}
