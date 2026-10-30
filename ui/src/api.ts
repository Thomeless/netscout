// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Tomáš Nesrsta
import { invoke } from "@tauri-apps/api/core";

export interface Addr {
  ip: string;
  prefix: number;
}

export interface Iface {
  name: string;
  description: string;
  mac: string;
  status: string;
  index: number;
  dhcp: boolean;
  addresses: Addr[];
  gateway: string | null;
  dns: string[];
}

export interface Profile {
  id: string;
  name: string;
  interface: string;
  mode: "static" | "dhcp";
  addresses: Addr[];
  gateway: string;
  dns: string[];
}

export interface Host {
  ip: string;
  mac: string;
  vendor: string | null;
  hostname: string | null;
  /** Nejlepší dostupné jméno (mDNS, UPnP, titulek webu, reverzní DNS). */
  name: string | null;
  model: string | null;
  services: string[];
  web_title: string | null;
  web_server: string | null;
  /** Soukromá (náhodná) MAC, výrobce nelze určit. */
  private_mac: boolean;
  kind: string | null;
  ports: number[];
  latency_ms: number;
}

export interface Neighbor {
  key: string;
  protocol: string;
  vendor: string;
  ip: string;
  mac: string;
  identity: string;
  model: string;
  version: string;
  local_iface: string;
  fields: [string, string][];
  raw: string;
}

export interface Meta {
  label: string;
  note: string;
  favorite: boolean;
  first_seen: number;
  last_seen: number;
  last_ip: string;
  vendor: string;
  name: string;
  kind: string;
}

export interface SeenEntry {
  mac: string;
  ip: string;
  vendor: string;
  name: string;
  kind: string;
}

export interface Lease {
  mac: string;
  address: string;
  host_name: string;
  class_id: string;
  client_id: string;
  status: string;
  server: string;
  comment: string;
  last_seen: string;
  dynamic: boolean;
}

export interface MikrotikSettings {
  host: string;
  user: string;
  has_password: boolean;
}

export type ScanMode = "quiet" | "careful" | "normal" | "thorough";

export const api = {
  mikrotikSettings: () => invoke<MikrotikSettings>("mikrotik_settings"),
  mikrotikSave: (host: string, user: string, password: string | null) => invoke<void>("mikrotik_save", { host, user, password }),
  mikrotikClear: () => invoke<void>("mikrotik_clear"),
  mikrotikTest: (host: string, user: string, password: string | null) => invoke<number>("mikrotik_test", { host, user, password }),
  mikrotikLeases: () => invoke<Lease[]>("mikrotik_leases"),
  inventoryLoad: () => invoke<Record<string, Meta>>("inventory_load"),
  inventorySeen: (seen: SeenEntry[]) => invoke<Record<string, Meta>>("inventory_seen", { seen }),
  inventoryUpdate: (mac: string, label: string, note: string, favorite: boolean) =>
    invoke<Record<string, Meta>>("inventory_update", { mac, label, note, favorite }),
  inventoryForget: (mac: string) => invoke<Record<string, Meta>>("inventory_forget", { mac }),
  startNeighbors: (active: boolean) => invoke<void>("start_neighbors", { active }),
  stopNeighbors: () => invoke<void>("stop_neighbors"),
  neighborsRunning: () => invoke<boolean>("neighbors_running"),
  startScan: (range: string, mode: ScanMode, ports: boolean) => invoke<void>("start_scan", { range, mode, ports }),
  cancelScan: () => invoke<void>("cancel_scan"),
  ouiInfo: () => invoke<[number, string]>("oui_info"),
  openWeb: (ip: string, port: number) => invoke<void>("open_web", { ip, port }),
  openRdp: (ip: string) => invoke<void>("open_rdp", { ip }),
  isPortable: () => invoke<boolean>("is_portable"),
  openReleases: () => invoke<void>("open_releases"),
  isAdmin: () => invoke<boolean>("is_admin"),
  listInterfaces: () => invoke<Iface[]>("list_interfaces"),
  listProfiles: () => invoke<Profile[]>("list_profiles"),
  saveProfile: (profile: Profile) => invoke<Profile[]>("save_profile", { profile }),
  deleteProfile: (id: string) => invoke<Profile[]>("delete_profile", { id }),
  applyProfile: (id: string, interfaceName: string) =>
    invoke<void>("apply_profile", { id, interface: interfaceName }),
  revertLast: () => invoke<string>("revert_last"),
  hasSnapshot: () => invoke<boolean>("has_snapshot"),
};

/** Délka prefixu → maska (24 → 255.255.255.0). */
export function prefixToMask(p: number): string {
  const bits = p <= 0 ? 0 : p >= 32 ? 0xffffffff : (0xffffffff << (32 - p)) >>> 0;
  return [24, 16, 8, 0].map((s) => (bits >>> s) & 255).join(".");
}

/** Maska nebo prefix ("255.255.255.0", "24", "/24") → délka prefixu, nebo null při chybě. */
export function parsePrefix(text: string): number | null {
  const t = text.trim().replace(/^\//, "");
  if (/^\d{1,2}$/.test(t)) {
    const n = Number(t);
    return n >= 1 && n <= 32 ? n : null;
  }
  const m = t.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return null;
  let bits = 0;
  for (let i = 1; i <= 4; i++) {
    const o = Number(m[i]);
    if (o > 255) return null;
    bits = ((bits << 8) | o) >>> 0;
  }
  const bin = bits.toString(2).padStart(32, "0");
  if (!/^1+0*$/.test(bin)) return null;
  return bin.indexOf("0") === -1 ? 32 : bin.indexOf("0");
}
