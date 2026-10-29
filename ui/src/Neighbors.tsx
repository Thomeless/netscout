// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Tomáš Nesrsta
import { memo, useMemo, useState } from "react";
import {
  Button, DrawerBody, DrawerHeader, DrawerHeaderTitle, MessageBar, MessageBarBody, OverlayDrawer, Select, Text, mergeClasses,
} from "@fluentui/react-components";
import { Copy20Regular, Delete20Regular, Dismiss24Regular, Globe20Regular, Play20Regular, Stop20Regular } from "@fluentui/react-icons";
import { api } from "./api";
import { Card, KeyValues, NARROW, Page, copyText, useCommon, useMediaQuery } from "./common";
import { clearNeighbors, startNeighbors, stopNeighbors, useStore, type SeenNeighbor } from "./store";
import { cmpIp } from "./util";

const STALE_MS = 90_000;

export default memo(function Neighbors() {
  const c = useCommon();
  const { neighbors: items, nb, now } = useStore("neighbors");
  const narrow = useMediaQuery(NARROW);
  const [selected, setSelected] = useState<string | null>(null);
  const [proto, setProto] = useState("");

  const list = useMemo(
    () =>
      Object.values(items)
        .filter((n) => !proto || n.protocol === proto)
        .sort((a, b) => cmpIp(a.ip, b.ip) || a.protocol.localeCompare(b.protocol)),
    [items, proto],
  );
  const protocols = useMemo(() => [...new Set(Object.values(items).map((n) => n.protocol))].sort(), [items]);
  const sel = selected ? items[selected] : null;
  const detail = sel && <Detail n={sel} />;

  return (
    <Page
      title="Neighbors"
      subtitle={`${nb.running ? "Poslouchám: MNDP, Ubiquiti, SADP, ONVIF, CDP, LLDP" : "Zastaveno"} · ${list.length} zařízení`}
      actions={
        <>
          <Select value={proto} onChange={(_, d) => setProto(d.value)}>
            <option value="">Všechny protokoly</option>
            {protocols.map((p) => <option key={p}>{p}</option>)}
          </Select>
          <Button icon={<Delete20Regular />} onClick={() => { clearNeighbors(); setSelected(null); }}>Vyčistit</Button>
          {nb.running ? (
            <Button icon={<Stop20Regular />} onClick={stopNeighbors}>Zastavit</Button>
          ) : (
            <Button appearance="primary" icon={<Play20Regular />} onClick={startNeighbors}>Hledat</Button>
          )}
        </>
      }
    >
      {nb.error && <MessageBar intent="error"><MessageBarBody>{nb.error}</MessageBarBody></MessageBar>}
      {nb.warn && <MessageBar intent="warning"><MessageBarBody>{nb.warn}</MessageBarBody></MessageBar>}

      <div className={c.split}>
        <Card className={c.scroll}>
          <table className="ns-table" aria-label="Sousedé">
            <thead>
              <tr>
                <th>Protokol</th>
                <th>IP</th>
                <th className={c.hideXNarrow}>MAC</th>
                <th>Identita</th>
                <th className={c.hideNarrow}>Model</th>
                <th className={c.hideNarrow}>Verze</th>
                <th className={c.hideNarrow}>Rozhraní</th>
              </tr>
            </thead>
            <tbody>
              {list.map((n) => (
                <tr key={n.key} className={`${selected === n.key ? "sel" : ""} ${now - n.seen > STALE_MS && false ? "" : ""}`} onClick={() => setSelected(n.key)}>
                  <td>{n.protocol}</td>
                  <td className={c.mono}>{n.ip || "—"}</td>
                  <td className={mergeClasses(c.mono, c.hideXNarrow)}>{n.mac || "—"}</td>
                  <td>{n.identity || "—"}</td>
                  <td className={c.hideNarrow}>{n.model || "—"}</td>
                  <td className={c.hideNarrow}>{n.version || "—"}</td>
                  <td className={c.hideNarrow}>{n.local_iface || "—"}</td>
                </tr>
              ))}
              {list.length === 0 && (
                <tr>
                  <td colSpan={7}>
                    <Text className={c.muted}>{nb.running ? "Zatím nic nenalezeno. Zařízení se ozývají obvykle do několika sekund." : "Spusť hledání."}</Text>
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
                Soused
              </DrawerHeaderTitle>
            </DrawerHeader>
            <DrawerBody>{detail}</DrawerBody>
          </OverlayDrawer>
        ) : (
          <Card className={c.pad}>{detail ?? <Text className={c.muted}>Vyber zařízení v seznamu a uvidíš všechna pole, která vysílá.</Text>}</Card>
        )}
      </div>
    </Page>
  );
});

function Detail({ n }: { n: SeenNeighbor }) {
  const c = useCommon();
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
      <div>
        <Text as="h2" weight="semibold" size={500} block>{n.identity || n.model || n.ip}</Text>
        <Text className={c.muted}>{n.protocol}{n.vendor ? ` · ${n.vendor}` : ""}</Text>
      </div>
      <div className={c.actions}>
        {n.ip && <Button icon={<Globe20Regular />} onClick={() => api.openWeb(n.ip, 80).catch(() => {})}>Web</Button>}
        {n.ip && <Button icon={<Copy20Regular />} onClick={() => copyText(n.ip)}>Kopírovat IP</Button>}
      </div>
      <KeyValues rows={n.fields} />
      <details>
        <summary className={c.muted}>Surový paket</summary>
        <pre className={c.raw}>{n.raw}</pre>
      </details>
    </div>
  );
}
