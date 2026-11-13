import { useEffect, useRef, useState } from "react";
import { api, errorMessage, getSession, onForbidden, onUnauthorized, type Session } from "./api/client";
import { BottomDock } from "./components/BottomDock";
import { DetailsDrawer } from "./components/DetailsDrawer";
import { Login } from "./components/Login";
import { NavRail } from "./components/NavRail";
import { Notices } from "./components/Notices";
import { Sidebar } from "./components/Sidebar";
import { TopBar } from "./components/TopBar";
import { GraphCanvas } from "./graph/GraphCanvas";
import { readLocal, writeLocal } from "./hooks/localStore";
import { navigate, useRoute } from "./hooks/useRoute";
import { SettingsDialog } from "./settings/SettingsDialog";
import { SettingsProvider } from "./settings/SettingsContext";
import { AppProvider, useApp } from "./state/AppContext";
import { CatalogProvider } from "./state/CatalogContext";
import { FixListProvider } from "./state/FixListContext";
import { SessionProvider } from "./state/SessionContext";
import { ZonesProvider } from "./state/ZonesContext";
import { ZoneDialogs } from "./views/zones/AddToZoneDialog";
import { AccountView } from "./views/AccountView";
import { AdminView } from "./views/admin/AdminView";
import { AlertsView } from "./views/AlertsView";
import { FilterView } from "./views/filter/FilterView";
import { ReportsView } from "./views/ReportsView";
import { DataView } from "./views/DataView";
import { UploadOnlyView } from "./views/UploadOnlyView";
import { FindingsView } from "./views/findings/FindingsView";
import { PostureView } from "./views/posture/PostureView";
import { RemediationView } from "./views/remediation/RemediationView";
import { ZonesView } from "./views/zones/ZonesView";

const NODES_TABLE_KEY = "copperhound.canvasTableOpen";

function Workspace({ onLogout, onSignedOut }: { onLogout: () => void; onSignedOut: (notice: string) => void }) {
  const { openSettings, notify } = useApp();
  const route = useRoute();
  const [nodesTable, setNodesTable] = useState(() => readLocal(NODES_TABLE_KEY, false));
  const toggleNodesTable = (open: boolean) => {
    setNodesTable(open);
    writeLocal(NODES_TABLE_KEY, open);
  };

  // Any 403 (role too low) shows the server's message, wherever it came from.
  useEffect(() => {
    onForbidden((message) => notify(message, "error"));
    return () => onForbidden(null);
  }, [notify]);

  // #/settings or #/settings/<section> opens the settings dialog over Explore.
  useEffect(() => {
    const m = /^#\/settings(?:\/(appearance|filters|layout|behaviour))?/.exec(window.location.hash);
    if (m) {
      openSettings((m[1] as "appearance" | "filters" | "layout" | "behaviour" | undefined) ?? "appearance");
      navigate("explore");
    }
  }, [route, openSettings]);
  const explore = route.view === "explore";
  return (
    <div className="app">
      <TopBar onLogout={onLogout} />
      <div className="shell">
        <NavRail route={route} />
        {/* Explore stays mounted (canvas, tabs, editor state) while other views are open. */}
        <div className="workspace" hidden={!explore}>
          <Sidebar />
          <main className="center">
            <GraphCanvas active={explore} tableOpen={nodesTable} onToggleTable={toggleNodesTable} />
            <BottomDock nodesOpen={nodesTable} onCloseNodes={() => toggleNodesTable(false)} />
          </main>
          <DetailsDrawer />
        </div>
        {!explore && (
          <main className="view" aria-label={route.view}>
            {route.view === "filter" && <FilterView />}
            {route.view === "findings" && <FindingsView findingId={route.id} />}
            {route.view === "remediation" && <RemediationView />}
            {route.view === "posture" && <PostureView route={route} />}
            {route.view === "zones" && <ZonesView zoneId={route.id} />}
            {route.view === "data" && <DataView />}
            {route.view === "reports" && <ReportsView />}
            {route.view === "alerts" && <AlertsView />}
            {route.view === "account" && <AccountView onSignedOut={onSignedOut} />}
            {route.view === "admin" && <AdminView section={route.id} params={route.params} />}
          </main>
        )}
      </div>
      <Notices />
      <SettingsDialog />
    </div>
  );
}

export function App() {
  const [user, setUser] = useState<Pick<Session, "username" | "role"> | null>(() => getSession());
  const [loginNotice, setLoginNotice] = useState<string | null>(null);

  const [ssoPending, setSsoPending] = useState(false);
  const redeemed = useRef(new Set<string>());

  useEffect(() => {
    onUnauthorized(() => {
      setUser(null);
      setLoginNotice("Your session has expired. Please sign in again.");
    });
  }, []);

  // SSO callback: the server redirects to /#/sso?code=… after the IdP sign-in. The code is
  // single-use and short-lived, so redeem it at once and drop it from the URL and history.
  useEffect(() => {
    const handle = () => {
      const m = /^#\/sso(?:\?(.*))?$/.exec(window.location.hash);
      if (!m) return;
      const code = new URLSearchParams(m[1] ?? "").get("code");
      window.history.replaceState(null, "", window.location.pathname + window.location.search);
      if (!code || redeemed.current.has(code)) return;
      redeemed.current.add(code);
      setSsoPending(true);
      api.oidcExchange(code).then(
        (res) => {
          const target = typeof res.return_to === "string" && /^\/(?![/\\])/.test(res.return_to) ? res.return_to : "/";
          window.history.replaceState(null, "", target);
          window.dispatchEvent(new HashChangeEvent("hashchange"));
          setUser({ username: res.username, role: res.role });
          setLoginNotice(null);
        },
        (e: unknown) => {
          setUser(null);
          setLoginNotice(`Single sign-on failed: ${errorMessage(e)}. Please try again.`);
        },
      ).finally(() => setSsoPending(false));
    };
    handle();
    window.addEventListener("hashchange", handle);
    return () => window.removeEventListener("hashchange", handle);
  }, []);

  const logout = () => {
    void api.logout().finally(() => {
      setUser(null);
      setLoginNotice(null);
    });
  };

  return (
    <SettingsProvider>
      {user === null || ssoPending ? (
        <Login
          notice={loginNotice}
          ssoPending={ssoPending}
          onLoggedIn={(username, role) => {
            setUser({ username, role });
            setLoginNotice(null);
          }}
        />
      ) : user.role === "uploader" ? (
        <UploadOnlyView username={user.username} onLogout={logout} />
      ) : (
        <CatalogProvider key={user.username}>
          <SessionProvider username={user.username} role={user.role}>
            <ZonesProvider>
              <FixListProvider>
                <AppProvider>
                  <Workspace
                    onLogout={logout}
                    onSignedOut={(notice) => {
                      setUser(null);
                      setLoginNotice(notice);
                    }}
                  />
                  <ZoneDialogs />
                </AppProvider>
              </FixListProvider>
            </ZonesProvider>
          </SessionProvider>
        </CatalogProvider>
      )}
    </SettingsProvider>
  );
}
