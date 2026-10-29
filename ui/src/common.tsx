// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Tomáš Nesrsta
import { useEffect, useState, type MouseEvent, type ReactNode } from "react";
import { makeStyles, mergeClasses, tokens, Subtitle1, Text } from "@fluentui/react-components";

/** Šířka okna pod níž se rozložení zjednoduší (detail jako boční panel místo vedle seznamu). */
export function useMediaQuery(query: string): boolean {
  const [match, setMatch] = useState(() => window.matchMedia(query).matches);
  useEffect(() => {
    const m = window.matchMedia(query);
    const f = () => setMatch(m.matches);
    m.addEventListener("change", f);
    f();
    return () => m.removeEventListener("change", f);
  }, [query]);
  return match;
}

export const NARROW = "(max-width: 1100px)";

export const useCommon = makeStyles({
  page: { display: "flex", flexDirection: "column", gap: "16px", padding: "20px 24px 24px", minWidth: 0 },
  head: { display: "flex", alignItems: "center", flexWrap: "wrap", gap: "12px", justifyContent: "space-between" },
  actions: { display: "flex", alignItems: "center", flexWrap: "wrap", gap: "8px" },
  card: {
    backgroundColor: tokens.colorNeutralBackground1,
    border: `1px solid ${tokens.colorNeutralStroke2}`,
    borderRadius: tokens.borderRadiusXLarge,
    boxShadow: tokens.shadow2,
    minWidth: 0,
  },
  pad: { padding: "16px" },
  scroll: { overflowX: "auto", overflowY: "visible" },
  split: {
    display: "grid",
    gridTemplateColumns: "minmax(0, 1fr) 380px",
    gap: "16px",
    alignItems: "start",
    "@media (max-width: 1100px)": { gridTemplateColumns: "minmax(0, 1fr)" },
  },
  grow: { flex: "1 1 220px", minWidth: "160px" },
  kv: { display: "grid", gridTemplateColumns: "120px minmax(0, 1fr)", gap: "6px 12px", margin: 0 },
  kvKey: { color: tokens.colorNeutralForeground3 },
  kvVal: { margin: 0, wordBreak: "break-word", whiteSpace: "pre-wrap" },
  mono: { fontFamily: "Consolas, 'Cascadia Mono', monospace", fontSize: tokens.fontSizeBase200 },
  muted: { color: tokens.colorNeutralForeground3 },
  hideNarrow: { "@media (max-width: 900px)": { display: "none" } },
  hideXNarrow: { "@media (max-width: 640px)": { display: "none" } },
  stale: { opacity: 0.55 },
  raw: {
    maxHeight: "220px",
    overflow: "auto",
    whiteSpace: "pre-wrap",
    wordBreak: "break-all",
    fontFamily: "Consolas, monospace",
    fontSize: "11px",
    backgroundColor: tokens.colorNeutralBackground3,
    padding: "8px",
    borderRadius: tokens.borderRadiusMedium,
  },
});

export function Page({ title, subtitle, actions, children }: { title: string; subtitle?: string; actions?: ReactNode; children: ReactNode }) {
  const c = useCommon();
  return (
    <div className={c.page}>
      <div className={c.head}>
        <div>
          <Subtitle1 as="h1" block>{title}</Subtitle1>
          {subtitle && <Text className={c.muted}>{subtitle}</Text>}
        </div>
        {actions && <div className={c.actions}>{actions}</div>}
      </div>
      {children}
    </div>
  );
}

export function Card({ children, className }: { children: ReactNode; className?: string }) {
  const c = useCommon();
  return <div className={mergeClasses(c.card, className)}>{children}</div>;
}

/** Dvojice název/hodnota v mřížce. */
export function KeyValues({ rows, mono = true }: { rows: [string, ReactNode][]; mono?: boolean }) {
  const c = useCommon();
  return (
    <dl className={c.kv}>
      {rows.map(([k, v], i) => (
        <div key={i} style={{ display: "contents" }}>
          <dt className={c.kvKey}>{k}</dt>
          <dd className={mergeClasses(c.kvVal, mono && c.mono)}>{v}</dd>
        </div>
      ))}
    </dl>
  );
}

export const copyText = (t: string) => navigator.clipboard?.writeText(t).catch(() => {});

/** Lehké tlačítko s ikonou pro řádky tabulek (Fluent Button by se v každém řádku zbytečně draze vykresloval). */
export function IconBtn({ label, onClick, disabled, children }: { label: string; onClick: (e: MouseEvent) => void; disabled?: boolean; children: ReactNode }) {
  return (
    <button type="button" className="ns-icon-btn" aria-label={label} title={label} disabled={disabled} onClick={onClick}>
      {children}
    </button>
  );
}
