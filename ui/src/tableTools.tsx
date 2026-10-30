// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Tomáš Nesrsta
import { useCallback, useState, type ReactNode } from "react";
import {
  Button, Input, Menu, MenuItemCheckbox, MenuList, MenuPopover, MenuTrigger, Popover, PopoverSurface, PopoverTrigger, Text,
} from "@fluentui/react-components";
import { Dismiss16Regular, Info16Regular, Search20Regular, TableSettings20Regular } from "@fluentui/react-icons";

export interface Col {
  id: string;
  label: string;
}

function load<T>(key: string, fallback: T): T {
  try {
    const raw = localStorage.getItem("netscout." + key);
    return raw === null ? fallback : (JSON.parse(raw) as T);
  } catch {
    return fallback;
  }
}

function save(key: string, value: unknown) {
  try {
    localStorage.setItem("netscout." + key, JSON.stringify(value));
  } catch {
    /* úložiště nemusí být dostupné; nastavení se jen nezapamatuje */
  }
}

/** Hodnota zapamatovaná v prohlížeči (poslední režim, filtry…). */
export function usePersisted<T>(key: string, fallback: T): [T, (v: T) => void] {
  const [value, setValue] = useState<T>(() => load(key, fallback));
  const set = useCallback(
    (v: T) => {
      setValue(v);
      save(key, v);
    },
    [key],
  );
  return [value, set];
}

/** Které sloupce tabulky jsou vidět; volba se pamatuje. */
export function useColumns(key: string, cols: Col[]): [(id: string) => boolean, string[], (ids: string[]) => void] {
  const all = cols.map((c) => c.id);
  const [shown, setShown] = usePersisted<string[]>("cols." + key, all);
  const valid = shown.filter((id) => all.includes(id));
  return [(id) => valid.includes(id), valid, setShown];
}

export function ColumnMenu({ cols, shown, onChange }: { cols: Col[]; shown: string[]; onChange: (ids: string[]) => void }) {
  return (
    <Menu checkedValues={{ cols: shown }} onCheckedValueChange={(_, d) => onChange(d.checkedItems)}>
      <MenuTrigger disableButtonEnhancement>
        <Button icon={<TableSettings20Regular />}>Sloupce</Button>
      </MenuTrigger>
      <MenuPopover>
        <MenuList>
          {cols.map((c) => <MenuItemCheckbox key={c.id} name="cols" value={c.id}>{c.label}</MenuItemCheckbox>)}
        </MenuList>
      </MenuPopover>
    </Menu>
  );
}

export function SearchBox({ value, onChange, placeholder }: { value: string; onChange: (v: string) => void; placeholder: string }) {
  return (
    <Input
      style={{ flex: "1 1 220px", minWidth: 160 }}
      contentBefore={<Search20Regular />}
      contentAfter={value ? <Button appearance="transparent" size="small" aria-label="Vymazat hledání" icon={<Dismiss16Regular />} onClick={() => onChange("")} /> : undefined}
      placeholder={placeholder}
      value={value}
      onChange={(_, d) => onChange(d.value)}
    />
  );
}

/** Malé „i“, které po kliknutí vysvětlí volbu. */
export function InfoTip({ label, children }: { label: string; children: ReactNode }) {
  return (
    <Popover positioning="below-end" withArrow>
      <PopoverTrigger disableButtonEnhancement>
        <Button appearance="subtle" size="small" aria-label={label} title={label} icon={<Info16Regular />} />
      </PopoverTrigger>
      <PopoverSurface style={{ maxWidth: 400 }}>
        <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>{children}</div>
      </PopoverSurface>
    </Popover>
  );
}

export function InfoItem({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div>
      <Text weight="semibold" block>{title}</Text>
      <Text size={200}>{children}</Text>
    </div>
  );
}

export const matches = (query: string, ...fields: (string | number | null | undefined | string[])[]) => {
  const q = query.trim().toLowerCase();
  if (!q) return true;
  const hay = fields.map((f) => (Array.isArray(f) ? f.join(" ") : String(f ?? ""))).join(" ").toLowerCase();
  return q.split(/\s+/).every((t) => hay.includes(t));
};
