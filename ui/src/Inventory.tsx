// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Tomáš Nesrsta
import { memo, useMemo, useState } from "react";
import {
  Button, DrawerBody, DrawerHeader, DrawerHeaderTitle, MessageBar, MessageBarBody, OverlayDrawer, Select, Text, mergeClasses,
} from "@fluentui/react-components";
import { ArrowDownload20Regular, Dismiss24Regular, Star20Filled, Star20Regular } from "@fluentui/react-icons";
import DeviceDetail from "./DeviceDetail";
import { Card, IconBtn, NARROW, Page, useCommon, useMediaQuery } from "./common";
import { buildDevices, first } from "./devices";
import { updateMeta, useStore } from "./store";
import { ColumnMenu, SearchBox, matches, useColumns, type Col } from "./tableTools";
import { ago, cmpIp, downloadCsv } from "./util";

const COLS: Col[] = [
  { id: "mac", label: "MAC" },
  { id: "vendor", label: "Výrobce" },
  { id: "kind", label: "Typ / model" },
  { id: "sources", label: "Zdroje" },
  { id: "seen", label: "Naposledy" },
];

type Filter = "all" | "fav" | "live" | "offline";

export default memo(function Inventory() {
  const c = useCommon();
  const { hosts, neighbors, metas, leases, now } = useStore("inventory");
  const narrow = useMediaQuery(NARROW);
  const [selected, setSelected] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState<Filter>("all");
  const [error, setError] = useState<string | null>(null);
  const [col, shownCols, setCols] = useColumns("inventory", COLS);

  const devices = useMemo(() => buildDevices(Object.values(hosts), Object.values(neighbors), metas, leases), [hosts, neighbors, metas, leases]);

  const shown = useMemo(() => {
    return devices
      .filter((d) => {
        if (filter === "fav" && !d.meta?.favorite) return false;
        if (filter === "live" && d.seen === null) return false;
        if (filter === "offline" && d.seen !== null) return false;
        return matches(query, d.ip, d.mac, d.vendor, d.kind, d.name, d.model, d.meta?.label, d.meta?.note, d.sources, d.privateMac ? "soukromá" : "");
      })
      .sort((a, b) => Number(!!b.meta?.favorite) - Number(!!a.meta?.favorite) || cmpIp(a.ip, b.ip) || a.mac.localeCompare(b.mac));
  }, [devices, query, filter]);

  const sel = devices.find((d) => d.id === selected) ?? null;
  const liveCount = devices.filter((d) => d.seen !== null).length;

  function exportCsv() {
    downloadCsv(
      "inventar",
      ["Název", "IP", "MAC", "Výrobce", "Typ / model", "Zdroje", "Oblíbené", "Poznámka", "Naposledy"],
      shown.map((d) => [
        first(d.meta?.label, d.name), d.ip, d.mac, d.vendor, d.kind, d.sources.join(" "), d.meta?.favorite ? "ano" : "", d.meta?.note,
        d.seen ? new Date(d.seen).toLocaleString() : d.meta ? new Date(d.meta.last_seen * 1000).toLocaleString() : "",
      ]),
    );
  }

  const fail = (e: unknown) => setError(String(e));
  const detail = sel && <DeviceDetail key={sel.id} d={sel} onError={fail} />;

  return (
    <Page
      fill
      title="Inventář"
      subtitle={`${devices.length} zařízení · ${liveCount} viděno v této relaci · sken a neighbours se slučují podle MAC`}
      actions={<Button icon={<ArrowDownload20Regular />} onClick={exportCsv} disabled={shown.length === 0}>Export CSV</Button>}
    >
      <div className={c.actions}>
        <SearchBox value={query} onChange={setQuery} placeholder="Hledat (IP, MAC, výrobce, název, poznámka…)" />
        <Select value={filter} onChange={(_, d) => setFilter(d.value as Filter)}>
          <option value="all">Všechna</option>
          <option value="fav">Oblíbená</option>
          <option value="live">Viděná teď</option>
          <option value="offline">Jen uložená</option>
        </Select>
        <ColumnMenu cols={COLS} shown={shownCols} onChange={setCols} />
      </div>
      {error && <MessageBar intent="error"><MessageBarBody>{error}</MessageBarBody></MessageBar>}

      <div className={mergeClasses(c.split, c.splitFill)}>
        <Card className={c.scroll}>
          <table className="ns-table" aria-label="Zařízení">
            <thead>
              <tr>
                <th style={{ width: 44 }} />
                <th>Název</th>
                <th>IP</th>
                {col("mac") && <th className={c.hideNarrow}>MAC</th>}
                {col("vendor") && <th className={c.hideNarrow}>Výrobce</th>}
                {col("kind") && <th className={c.hideXNarrow}>Typ / model</th>}
                {col("sources") && <th className={c.hideNarrow}>Zdroje</th>}
                {col("seen") && <th>Naposledy</th>}
              </tr>
            </thead>
            <tbody>
              {shown.map((d) => (
                <tr key={d.id} className={selected === d.id ? "sel" : ""} onClick={() => setSelected(d.id)}>
                  <td>
                    <IconBtn
                      label="Oblíbené" disabled={!d.mac}
                      onClick={(e) => {
                        e.stopPropagation();
                        updateMeta(d.mac, d.meta?.label ?? "", d.meta?.note ?? "", !d.meta?.favorite).catch(fail);
                      }}
                    >
                      {d.meta?.favorite ? <Star20Filled color="#d4a017" /> : <Star20Regular />}
                    </IconBtn>
                  </td>
                  <td>{first(d.meta?.label, d.name) || "—"}</td>
                  <td className={c.mono}>{d.ip || "—"}</td>
                  {col("mac") && <td className={mergeClasses(c.mono, c.hideNarrow)}>{d.mac || "—"}</td>}
                  {col("vendor") && <td className={c.hideNarrow}>{d.vendor || (d.privateMac ? "Soukromá MAC" : "—")}</td>}
                  {col("kind") && <td className={c.hideXNarrow}>{d.kind || "—"}</td>}
                  {col("sources") && (
                    <td className={c.hideNarrow}>
                      {d.sources.map((s) => <span key={s} className="ns-badge">{s}</span>)}
                    </td>
                  )}
                  {col("seen") && <td>{d.seen ? ago(d.seen, now) : d.meta ? ago(d.meta.last_seen * 1000, now) : "—"}</td>}
                </tr>
              ))}
              {shown.length === 0 && (
                <tr>
                  <td colSpan={8}>
                    <Text className={c.muted}>Zatím žádná zařízení. Spusť sken sítě nebo nech běžet Neighbors; nalezená zařízení se sem sloučí a uloží.</Text>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </Card>

        {narrow ? (
          <OverlayDrawer open={!!sel} position="end" style={{ width: "min(440px, 100vw)" }} onOpenChange={(_, d) => !d.open && setSelected(null)}>
            <DrawerHeader>
              <DrawerHeaderTitle action={<Button appearance="subtle" aria-label="Zavřít" icon={<Dismiss24Regular />} onClick={() => setSelected(null)} />}>
                Zařízení
              </DrawerHeaderTitle>
            </DrawerHeader>
            <DrawerBody>{detail}</DrawerBody>
          </OverlayDrawer>
        ) : (
          <Card className={mergeClasses(c.pad, c.sideCard)}>{detail ?? <Text className={c.muted}>Vyber zařízení v seznamu.</Text>}</Card>
        )}
      </div>
    </Page>
  );
});
