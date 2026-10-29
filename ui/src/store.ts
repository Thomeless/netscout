// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Tomáš Nesrsta
import { useSyncExternalStore } from "react";
import { listen } from "@tauri-apps/api/event";
import type { Host, Neighbor } from "./api";

export type SeenHost = Host & { seen: number };
export type SeenNeighbor = Neighbor & { seen: number };

interface State {
  hosts: Record<string, SeenHost>;
  neighbors: Record<string, SeenNeighbor>;
}

let state: State = { hosts: {}, neighbors: {} };
const subs = new Set<() => void>();

function set(next: State) {
  state = next;
  subs.forEach((f) => f());
}

let started = false;

/** Zaregistruje poslech událostí ze skenu a neighbour discovery; volá se jednou při startu aplikace. */
export function initStore() {
  if (started) return;
  started = true;
  listen<Host>("scan-host", (e) =>
    set({ ...state, hosts: { ...state.hosts, [e.payload.ip]: { ...e.payload, seen: Date.now() } } }),
  );
  listen<Neighbor>("neighbor", (e) =>
    set({ ...state, neighbors: { ...state.neighbors, [e.payload.key]: { ...e.payload, seen: Date.now() } } }),
  );
}

export const clearHosts = () => set({ ...state, hosts: {} });
export const clearNeighbors = () => set({ ...state, neighbors: {} });

export function useStore(): State {
  return useSyncExternalStore(
    (f) => {
      subs.add(f);
      return () => subs.delete(f);
    },
    () => state,
  );
}
