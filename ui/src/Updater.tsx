// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Tomáš Nesrsta
import { useEffect, useRef, useState } from "react";
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

/** Verze v záhlaví + kontrola aktualizací (GitHub Releases). Při startu se kontroluje potichu. */
export default function Updater() {
  const [version, setVersion] = useState("");
  const [status, setStatus] = useState<Status>({ kind: "idle" });
  const manual = useRef(false);

  async function run(isManual: boolean) {
    manual.current = isManual;
    setStatus({ kind: "checking" });
    try {
      const update = await check();
      setStatus(update ? { kind: "available", update } : { kind: "uptodate" });
    } catch (e) {
      // Při automatické kontrole (např. bez internetu nebo před prvním vydáním) neobtěžuj.
      setStatus(isManual ? { kind: "error", message: String(e) } : { kind: "idle" });
    }
  }

  useEffect(() => {
    getVersion().then(setVersion, () => {});
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
  return (
    <div className="updater">
      {s.kind === "available" && (
        <>
          <span>Nová verze {s.update.version}</span>
          <button className="primary" onClick={() => install(s.update)}>Aktualizovat</button>
        </>
      )}
      {s.kind === "downloading" && (
        <span>Stahuji… {s.total ? `${Math.round((s.done / s.total) * 100)} %` : ""}</span>
      )}
      {s.kind === "uptodate" && manual.current && <span className="muted">Máš nejnovější verzi</span>}
      {s.kind === "error" && <span className="err-text" title={s.message}>Kontrola selhala</span>}
      {s.kind !== "available" && s.kind !== "downloading" && (
        <button onClick={() => run(true)} disabled={s.kind === "checking"}>
          {s.kind === "checking" ? "Kontroluji…" : "Zkontrolovat aktualizace"}
        </button>
      )}
      {version && <span className="muted">v{version}</span>}
    </div>
  );
}
