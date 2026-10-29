// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Tomáš Nesrsta
import { useEffect, useState } from "react";
import { api } from "./api";
import Inventory from "./Inventory";
import IpProfiles from "./IpProfiles";
import Neighbors from "./Neighbors";
import Scan from "./Scan";
import { initStore } from "./store";
import Updater from "./Updater";

initStore();

type Tab = "inventory" | "profiles" | "scan" | "neighbors";

const TABS: { id: Tab; label: string }[] = [
  { id: "inventory", label: "Inventář" },
  { id: "profiles", label: "IP profily" },
  { id: "scan", label: "Sken sítě" },
  { id: "neighbors", label: "Neighbors" },
];

export default function App() {
  const [tab, setTab] = useState<Tab>("inventory");
  const [admin, setAdmin] = useState<boolean | null>(null);

  useEffect(() => {
    api.isAdmin().then(setAdmin, () => setAdmin(null));
  }, []);

  return (
    <div className="app">
      <header>
        <h1>NetScout</h1>
        <nav>
          {TABS.map((t) => (
            <button key={t.id} className={tab === t.id ? "tab active" : "tab"} onClick={() => setTab(t.id)}>
              {t.label}
            </button>
          ))}
        </nav>
        <Updater />
      </header>
      {admin === false && (
        <div className="banner warn">
          Aplikace neběží jako správce – změna IP adresy nebude fungovat. Spusť ji jako správce.
        </div>
      )}
      <main>
        {/* Záložky zůstávají připojené, aby se neztratil stav skenu a nalezení sousedé. */}
        <div hidden={tab !== "inventory"}><Inventory /></div>
        <div hidden={tab !== "profiles"}><IpProfiles admin={admin !== false} /></div>
        <div hidden={tab !== "scan"}><Scan admin={admin !== false} /></div>
        <div hidden={tab !== "neighbors"}><Neighbors /></div>
      </main>
    </div>
  );
}
