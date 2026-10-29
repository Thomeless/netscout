// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Tomáš Nesrsta
export function ipNum(ip: string): number {
  const p = ip.split(".").map(Number);
  return p.length === 4 && p.every((x) => x >= 0 && x <= 255) ? p.reduce((a, o) => ((a << 8) | o) >>> 0, 0) : Infinity;
}

/** Porovnání IP adres pro řazení; adresy bez platného formátu jdou na konec. */
export function cmpIp(a: string, b: string): number {
  const x = ipNum(a);
  const y = ipNum(b);
  return x === y ? 0 : x < y ? -1 : 1;
}

export function csvCell(v: string | number | null | undefined): string {
  const s = v === null || v === undefined ? "" : String(v);
  return /[",;\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

/** Stáhne CSV (středník, UTF-8 s BOM kvůli Excelu). */
export function downloadCsv(prefix: string, head: string[], rows: (string | number | null | undefined)[][]) {
  const body = [head.join(";"), ...rows.map((r) => r.map(csvCell).join(";"))].join("\r\n");
  const blob = new Blob(["﻿" + body], { type: "text/csv;charset=utf-8" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `${prefix}-${new Date().toISOString().slice(0, 16).replace(/[:T]/g, "-")}.csv`;
  a.click();
  URL.revokeObjectURL(a.href);
}

export function ago(ts: number, now = Date.now()): string {
  const s = Math.max(0, Math.round((now - ts) / 1000));
  if (s < 60) return "právě teď";
  if (s < 3600) return `před ${Math.floor(s / 60)} min`;
  if (s < 86400) return `před ${Math.floor(s / 3600)} h`;
  return `před ${Math.floor(s / 86400)} d`;
}
