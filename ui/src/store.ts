// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Tomáš Nesrsta
import { useEffect, useReducer, useRef, useSyncExternalStore } from "react";
import { listen } from "@tauri-apps/api/event";
import { api, type Host, type Iface, type Meta, type Neighbor, type SeenEntry } from "./api";

export type SeenHost = Host & { seen: number };
export type SeenNeighbor = Neighbor & { seen: number };

export type Page = "inventory" | "profiles" | "scan" | "neighbors";

export interface State {
  /** Aktuální čas, obnovuje se každých 5 s (pro „před X min“ a zešednutí starých záznamů). */
  now: number;
  hosts: Record<string, SeenHost>;
  neighbors: Record<string, SeenNeighbor>;
  metas: Record<string, Meta>;
  ifaces: Iface[] | null;
  ifacesError: string | null;
  admin: boolean | null;
  scan: { running: boolean; progress: { done: number; total: number } | null; error: string | null };
  nb: { running: boolean; warn: string | null; error: string | null };
}

let state: State = {
  now: Date.now(),
  hosts: {},
  neighbors: {},
  metas: {},
  ifaces: null,
  ifacesError: null,
  admin: null,
  scan: { running: false, progress: null, error: null },
  nb: { running: false, warn: null, error: null },
};

const subs = new Set<() => void>();
let version = 0;
let notifyTimer: number | undefined;

/** Stav se mění hned, zobrazení se obnovuje nejvýše ~20× za sekundu (dávky událostí ze skenu). */
function set(patch: Partial<State>) {
  state = { ...state, ...patch };
  version++;
  if (notifyTimer !== undefined) return;
  notifyTimer = window.setTimeout(() => {
    notifyTimer = undefined;
    subs.forEach((f) => f());
  }, 50);
}

let currentPage: Page = "inventory";

/** Aplikace říká, která stránka je vidět; skryté stránky se při změnách stavu nepřekreslují. */
export function setPage(page: Page) {
  currentPage = page;
  subs.forEach((f) => f());
}

/**
 * Odběr stavu pro stránku `page`. Skrytá stránka se nepřekresluje, takže přepínání záložek
 * je levné i při stovkách zařízení; po zobrazení se překreslí jen tehdy, když se stav změnil.
 */
export function useStore(page: Page): State {
  const [, bump] = useReducer((n: number) => n + 1, 0);
  const rendered = useRef(version);
  rendered.current = version;
  useEffect(() => {
    const f = () => {
      if (currentPage === page && rendered.current !== version) bump();
    };
    subs.add(f);
    return () => {
      subs.delete(f);
    };
  }, [page]);
  return state;
}

/** Jen příznak práv správce; překresluje se pouze při jeho změně. */
export function useAdmin(): boolean | null {
  return useSyncExternalStore(
    (f) => {
      subs.add(f);
      return () => {
        subs.delete(f);
      };
    },
    () => state.admin,
  );
}

// ---------------------------------------------------------------- trvalý inventář

let saveTimer: number | undefined;
let lastSig = "";

function entries(): SeenEntry[] {
  const m = new Map<string, SeenEntry>();
  const get = (mac: string) => m.get(mac) ?? { mac, ip: "", vendor: "", name: "", kind: "" };
  for (const h of Object.values(state.hosts)) {
    const e = get(h.mac);
    m.set(h.mac, { mac: h.mac, ip: h.ip, vendor: h.vendor ?? e.vendor, name: h.hostname ?? e.name, kind: h.kind ?? e.kind });
  }
  for (const n of Object.values(state.neighbors)) {
    if (!n.mac) continue;
    const e = get(n.mac);
    m.set(n.mac, {
      mac: n.mac,
      ip: e.ip || n.ip,
      vendor: e.vendor || n.vendor,
      name: n.identity || e.name,
      kind: e.kind || n.model,
    });
  }
  return [...m.values()].sort((a, b) => a.mac.localeCompare(b.mac));
}

function scheduleSave() {
  window.clearTimeout(saveTimer);
  saveTimer = window.setTimeout(() => {
    const list = entries();
    const sig = JSON.stringify(list);
    if (!list.length || sig === lastSig) return;
    lastSig = sig;
    api.inventorySeen(list).then((metas) => set({ metas }), () => {});
  }, 2000);
}

// ---------------------------------------------------------------- akce

let ifacesInFlight: Promise<void> | null = null;

export function refreshIfaces(): Promise<void> {
  ifacesInFlight ??= api
    .listInterfaces()
    .then((ifaces) => set({ ifaces, ifacesError: null }))
    .catch((e) => set({ ifacesError: String(e) }))
    .finally(() => {
      ifacesInFlight = null;
    });
  return ifacesInFlight;
}

export async function startScan(range: string) {
  set({ hosts: {}, scan: { running: false, progress: null, error: null } });
  try {
    await api.startScan(range);
    set({ scan: { ...state.scan, running: true } });
  } catch (e) {
    set({ scan: { ...state.scan, error: String(e) } });
  }
}

export const cancelScan = () => api.cancelScan();
export const clearHosts = () => set({ hosts: {} });
export const clearNeighbors = () => set({ neighbors: {} });

export async function startNeighbors() {
  set({ nb: { running: false, warn: null, error: null } });
  try {
    await api.startNeighbors();
    set({ nb: { ...state.nb, running: true } });
  } catch (e) {
    set({ nb: { ...state.nb, error: String(e) } });
  }
}

export const stopNeighbors = () => api.stopNeighbors();

export async function updateMeta(mac: string, label: string, note: string, favorite: boolean) {
  set({ metas: await api.inventoryUpdate(mac, label, note, favorite) });
}

export async function forgetMeta(mac: string) {
  set({ metas: await api.inventoryForget(mac) });
}

// ---------------------------------------------------------------- start

let started = false;

/** Zaregistruje události z backendu a načte počáteční data; volá se jednou při startu aplikace. */
export function initStore() {
  if (started) return;
  started = true;
  window.setInterval(() => set({ now: Date.now() }), 5000);
  listen<Host>("scan-host", (e) => {
    set({ hosts: { ...state.hosts, [e.payload.ip]: { ...e.payload, seen: Date.now() } } });
    scheduleSave();
  });
  listen<Neighbor>("neighbor", (e) => {
    set({ neighbors: { ...state.neighbors, [e.payload.key]: { ...e.payload, seen: Date.now() } } });
    scheduleSave();
  });
  listen<{ done: number; total: number }>("scan-progress", (e) =>
    set({ scan: { ...state.scan, progress: e.payload } }),
  );
  listen<boolean>("scan-done", () => set({ scan: { ...state.scan, running: false } }));
  listen("neighbors-done", () => set({ nb: { ...state.nb, running: false } }));
  listen<string>("neighbors-warn", (e) => set({ nb: { ...state.nb, warn: e.payload } }));

  api.isAdmin().then((admin) => set({ admin }), () => {});
  api.inventoryLoad().then((metas) => set({ metas }), () => {});
  refreshIfaces();
  // Discovery běží od startu aplikace.
  api.neighborsRunning().then((r) => (r ? set({ nb: { ...state.nb, running: true } }) : startNeighbors()), () => {});
}
