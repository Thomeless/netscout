// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Tomáš Nesrsta
import type { Meta } from "./api";
import type { SeenHost, SeenNeighbor } from "./store";

export interface Device {
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

export const first = (...v: (string | null | undefined)[]) => v.find((x) => x && x.trim()) ?? "";

/** Sloučí sken, neighbours a uložený inventář do jednoho seznamu podle MAC (soused bez MAC podle IP). */
export function buildDevices(hosts: SeenHost[], neighbors: SeenNeighbor[], metas: Record<string, Meta>): Device[] {
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
  for (const [mac, m] of Object.entries(metas)) {
    if (map.has(mac)) continue;
    map.set(mac, { ...blank(mac, mac), ip: m.last_ip, vendor: m.vendor, kind: m.kind, name: m.name, meta: m });
  }
  return [...map.values()];
}
