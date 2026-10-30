// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Tomáš Nesrsta
import { useEffect, useState } from "react";
import { Button, Caption1, Tooltip } from "@fluentui/react-components";
import { ArrowSync20Regular, ArrowDownload20Regular } from "@fluentui/react-icons";
import { api } from "./api";
import { getVersion } from "@tauri-apps/api/app";
import { check, type Update } from "@tauri-apps/plugin-updater";
import { relaunch } from "@tauri-apps/plugin-process";

type Status =
  | { kind: "idle" }
  | { kind: "checking" }
  | { kind: "uptodate" }
  | { kind: "available"; update: Update }
  | { kind: "downloading"; done: number; total: number }
  | { kind: "error"; message: string };

/** Verze a kontrola aktualizací (GitHub Releases) v navigaci. Při startu se kontroluje potichu. */
export default function Updater({ compact }: { compact: boolean }) {
  const [version, setVersion] = useState("");
  const [status, setStatus] = useState<Status>({ kind: "idle" });
  const [manual, setManual] = useState(false);
  const [portable, setPortable] = useState(false);

  async function run(isManual: boolean) {
    setManual(isManual);
    setStatus({ kind: "checking" });
    try {
      const update = await check();
      setStatus(update ? { kind: "available", update } : { kind: "uptodate" });
    } catch (e) {
      // Při automatické kontrole (bez internetu, před prvním vydáním) neobtěžuj.
      setStatus(isManual ? { kind: "error", message: String(e) } : { kind: "idle" });
    }
  }

  useEffect(() => {
    getVersion().then(setVersion, () => {});
    api.isPortable().then(setPortable, () => {});
    run(false);
  }, []);

  async function install(update: Update) {
    let total = 0;
    let done = 0;
    setStatus({ kind: "downloading", done, total });
    try {
      await update.downloadAndInstall((ev) => {
        if (ev.event === "Started") total = ev.data.contentLength ?? 0;
        if (ev.event === "Progress") done += ev.data.chunkLength;
        setStatus({ kind: "downloading", done, total });
      });
      await relaunch();
    } catch (e) {
      setStatus({ kind: "error", message: String(e) });
    }
  }

  const s = status;
  const text =
    s.kind === "available" ? (portable ? `Nová verze ${s.update.version}: stáhnout` : `Nová verze ${s.update.version}`)
    : s.kind === "downloading" ? `Stahuji… ${s.total ? Math.round((s.done / s.total) * 100) + " %" : ""}`
    : s.kind === "checking" ? "Kontroluji…"
    : s.kind === "uptodate" && manual ? "Máš nejnovější verzi"
    : s.kind === "error" ? "Kontrola selhala"
    : "";

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 4, alignItems: compact ? "center" : "stretch" }}>
      {s.kind === "available" ? (
        <Tooltip content={text} relationship="label">
          <Button appearance="primary" icon={<ArrowDownload20Regular />} onClick={() => (portable ? api.openReleases().catch(() => {}) : install(s.update))}>{compact ? "" : text}</Button>
        </Tooltip>
      ) : (
        <Tooltip content={s.kind === "error" ? s.message : "Zkontrolovat aktualizace"} relationship="label">
          <Button appearance="subtle" icon={<ArrowSync20Regular />} disabled={s.kind === "checking" || s.kind === "downloading"} onClick={() => run(true)}>
            {compact ? "" : "Aktualizace"}
          </Button>
        </Tooltip>
      )}
      {!compact && text && s.kind !== "available" && <Caption1>{text}</Caption1>}
      {!compact && version && <Caption1>NetScout v{version}</Caption1>}
    </div>
  );
}
