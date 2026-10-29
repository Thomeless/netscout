// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Tomáš Nesrsta
import type { Lease, Meta } from "./api";
import type { SeenHost, SeenNeighbor } from "./store";

export interface Device {
  id: string;
  mac: string;
  ip: string;
  vendor: string;
  kind: string;
  name: string;
  model: string;
  services: string[];
  ports: number[];
  sources: string[];
  /** Soukromá (náhodná) MAC adresa. */
  privateMac: boolean;
  /** Čas posledního spatření v této relaci; null = jen z uloženého inventáře nebo z routeru. */
  seen: number | null;
  host?: SeenHost;
  neighbors: SeenNeighbor[];
  meta?: Meta;
  lease?: Lease;
}

export const first = (...v: (string | null | undefined)[]) => v.find((x) => x && x.trim()) ?? "";

/** MAC se soukromou (lokálně spravovanou) adresou: druhý nejnižší bit prvního bajtu. */
export const isPrivateMac = (mac: string) => {
  const b = parseInt(mac.slice(0, 2), 16);
  return Number.isFinite(b) && (b & 2) !== 0;
};

/** Sloučí sken, neighbours, DHCP leasy z routeru a uložený inventář do jednoho seznamu podle MAC (soused bez MAC podle IP). */
export function buildDevices(
  hosts: SeenHost[],
  neighbors: SeenNeighbor[],
  metas: Record<string, Meta>,
  leases: Record<string, Lease> = {},
): Device[] {
  const map = new Map<string, Device>();
  const blank = (id: string, mac: string): Device => ({
    id, mac, ip: "", vendor: "", kind: "", name: "", model: "", services: [], ports: [], sources: [],
    privateMac: !!mac && isPrivateMac(mac), seen: null, neighbors: [], meta: metas[mac], lease: leases[mac],
  });
  const touch = (d: Device, seen: number) => {
    d.seen = Math.max(d.seen ?? 0, seen);
  };
  const addSource = (d: Device, s: string) => {
    if (!d.sources.includes(s)) d.sources.push(s);
  };

  for (const h of hosts) {
    const d = map.get(h.mac) ?? blank(h.mac, h.mac);
    d.host = h;
    d.ip = h.ip;
    d.ports = h.ports;
    d.vendor = first(d.vendor, h.vendor);
    d.kind = first(d.kind, h.kind);
    d.model = first(d.model, h.model);
    d.services = h.services;
    d.name = first(d.lease?.host_name, d.name, h.name, h.hostname);
    addSource(d, "Sken");
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
    d.name = first(n.identity, d.lease?.host_name, d.name);
    addSource(d, n.protocol);
    touch(d, n.seen);
    map.set(key, d);
  }
  // Zařízení, která zná jen router (DHCP) nebo uložený inventář.
  for (const [mac, l] of Object.entries(leases)) {
    if (map.has(mac)) continue;
    map.set(mac, { ...blank(mac, mac), ip: l.address, name: l.host_name, kind: l.class_id, sources: ["DHCP"] });
  }
  for (const [mac, m] of Object.entries(metas)) {
    const existing = map.get(mac);
    if (existing) {
      if (!existing.ip) existing.ip = m.last_ip;
      continue;
    }
    map.set(mac, { ...blank(mac, mac), ip: m.last_ip, vendor: m.vendor, kind: m.kind, name: m.name });
  }
  for (const d of map.values()) {
    if (d.lease) addSource(d, "DHCP");
    d.vendor = d.vendor || "";
  }
  return [...map.values()];
}
