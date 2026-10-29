// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Tomáš Nesrsta
import { useEffect, useState, type ReactElement, type ReactNode } from "react";
import {
  FluentProvider, MessageBar, MessageBarBody, Tab, TabList, Text, makeStyles, mergeClasses, tokens, webDarkTheme, webLightTheme,
} from "@fluentui/react-components";
import { Apps24Regular, PlugConnected24Regular, Search24Regular, Share24Regular } from "@fluentui/react-icons";
import logo from "./assets/logo.png";
import { useMediaQuery } from "./common";
import Inventory from "./Inventory";
import IpProfiles from "./IpProfiles";
import Neighbors from "./Neighbors";
import Scan from "./Scan";
import { initStore, setPage, useAdmin } from "./store";
import Updater from "./Updater";

initStore();

type Tab = "inventory" | "profiles" | "scan" | "neighbors";

const TABS: { id: Tab; label: string; icon: ReactElement }[] = [
  { id: "inventory", label: "Inventář", icon: <Apps24Regular /> },
  { id: "profiles", label: "IP profily", icon: <PlugConnected24Regular /> },
  { id: "scan", label: "Sken sítě", icon: <Search24Regular /> },
  { id: "neighbors", label: "Neighbors", icon: <Share24Regular /> },
];

const useStyles = makeStyles({
  root: {
    display: "flex",
    height: "100vh",
    backgroundColor: tokens.colorNeutralBackground3,
    color: tokens.colorNeutralForeground1,
  },
  rootBottom: { flexDirection: "column-reverse" },
  nav: {
    width: "220px",
    flexShrink: 0,
    display: "flex",
    flexDirection: "column",
    gap: "12px",
    padding: "12px 8px",
  },
  navCompact: { width: "64px", alignItems: "center", padding: "12px 4px" },
  navBottom: { width: "100%", flexDirection: "row", justifyContent: "space-around", padding: "4px 8px", alignItems: "center" },
  brand: { display: "flex", alignItems: "center", gap: "10px", padding: "4px 12px" },
  logo: { width: "28px", height: "28px", borderRadius: "6px" },
  tabs: { flexGrow: 1 },
  tabsBottom: { flexGrow: 1, justifyContent: "space-around" },
  main: {
    flex: 1,
    minWidth: 0,
    overflowY: "auto",
    backgroundColor: tokens.colorNeutralBackground2,
    borderTopLeftRadius: tokens.borderRadiusXLarge,
    borderLeft: `1px solid ${tokens.colorNeutralStroke2}`,
    borderTop: `1px solid ${tokens.colorNeutralStroke2}`,
  },
  mainBottom: { borderTopLeftRadius: 0, borderLeft: "none", borderTopRightRadius: tokens.borderRadiusXLarge, borderTop: "none" },
});

export default function App() {
  const s = useStyles();
  const dark = useMediaQuery("(prefers-color-scheme: dark)");
  const compact = useMediaQuery("(max-width: 900px)");
  const bottom = useMediaQuery("(max-width: 600px)");
  const [tab, setTab] = useState<Tab>("inventory");
  const admin = useAdmin();
  useEffect(() => setPage(tab), [tab]);

  const pages: Record<Tab, ReactNode> = {
    inventory: <Inventory />,
    profiles: <IpProfiles />,
    scan: <Scan />,
    neighbors: <Neighbors />,
  };

  return (
    <FluentProvider theme={dark ? webDarkTheme : webLightTheme} style={{ height: "100%", background: "transparent" }}>
      <div className={mergeClasses(s.root, bottom && s.rootBottom)}>
        <nav className={mergeClasses(s.nav, compact && s.navCompact, bottom && s.navBottom)} aria-label="Hlavní navigace">
          {!bottom && (
            <div className={s.brand}>
              <img className={s.logo} src={logo} alt="" />
              {!compact && <Text weight="semibold" size={400}>NetScout</Text>}
            </div>
          )}
          <TabList
            className={bottom ? s.tabsBottom : s.tabs}
            vertical={!bottom}
            size="large"
            selectedValue={tab}
            onTabSelect={(_, d) => setTab(d.value as Tab)}
          >
            {TABS.map((t) => (
              <Tab key={t.id} value={t.id} icon={t.icon} aria-label={t.label}>
                {!compact && t.label}
              </Tab>
            ))}
          </TabList>
          {!bottom && <Updater compact={compact} />}
        </nav>
        <main className={mergeClasses(s.main, bottom && s.mainBottom)}>
          {admin === false && (
            <MessageBar intent="warning" shape="square">
              <MessageBarBody>Aplikace neběží jako správce – změna IP adresy nebude fungovat. Spusť ji jako správce.</MessageBarBody>
            </MessageBar>
          )}
          {TABS.map((t) => (
            <div
              key={t.id}
              // content-visibility: hidden zachová vykreslený stav skryté stránky, takže návrat na ni je okamžitý (display: none by ho zahodil).
              style={tab === t.id ? undefined : { contentVisibility: "hidden", height: 0, overflow: "hidden" }}
              aria-hidden={tab !== t.id}
            >
              {pages[t.id]}
            </div>
          ))}
        </main>
      </div>
    </FluentProvider>
  );
}
