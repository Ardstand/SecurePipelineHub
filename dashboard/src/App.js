import React, { useEffect, useRef, useState, useCallback } from "react";
import {
  NavLink,
  BrowserRouter,
  Routes,
  Route,
  useNavigate,
  useLocation,
} from "react-router-dom";
import Dashboard from "./components/Dashboard";
import FindingsTable from "./components/FindingsTable";
import FindingDetail from "./components/FindingDetail";
import ComplianceView from "./components/ComplianceView";
import TrendsView from "./components/TrendsView";
import { getStats } from "./api";

const FRONTEND_POLL_MS = 30_000; // check API for new data every 30s
const SYNC_STATUS_MS = 30_000; // check git sync status every 30s

async function fetchSyncStatus() {
  try {
    const res = await fetch("http://localhost:5000/api/sync-status");
    const data = await res.json();
    return data?.data ?? null;
  } catch {
    return null;
  }
}

async function triggerSyncNow() {
  try {
    const res = await fetch("http://localhost:5000/api/sync-now", {
      method: "POST",
    });
    const data = await res.json();
    return data?.data ?? null;
  } catch {
    return null;
  }
}

function ShieldIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
      <path
        d="M12 2L4 6v6c0 5.25 3.5 10.15 8 11.35C16.5 22.15 20 17.25 20 12V6l-8-4z"
        fill="rgba(79,142,247,0.18)"
        stroke="#4f8ef7"
        strokeWidth="1.5"
        strokeLinejoin="round"
      />
      <path
        d="M9 12l2 2 4-4"
        stroke="#4f8ef7"
        strokeWidth="1.75"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

function RefreshIcon({ spinning }) {
  return (
    <svg
      width="13"
      height="13"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2.2"
      strokeLinecap="round"
      strokeLinejoin="round"
      className={spinning ? "animate-spin" : ""}
    >
      <polyline points="23 4 23 10 17 10" />
      <path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10" />
    </svg>
  );
}

function SyncIndicator({ syncStatus, totalFindings, onSyncNow, syncing }) {
  const isPulling = syncStatus?.status === "pulling" || syncing;
  const wasUpdated = syncStatus?.status === "updated";

  const dotColor = isPulling
    ? "#fbbf24"
    : wasUpdated
      ? "#06d6a0"
      : syncStatus?.status === "error"
        ? "#ff4d6a"
        : "var(--text-muted)";

  const label = isPulling
    ? "Syncing…"
    : wasUpdated
      ? `Updated · ${syncStatus?.last_commit ?? ""}`
      : syncStatus?.status === "error"
        ? "Sync error"
        : syncStatus?.last_commit
          ? `${syncStatus.last_commit}`
          : "Watching…";

  return (
    <div className="flex items-center gap-2">
      {/* Finding count */}
      <div
        style={{
          color: "var(--text-muted)",
          border: "1px solid var(--border)",
          backgroundColor: "var(--bg-hover)",
          fontSize: 11,
          borderRadius: 6,
          padding: "3px 8px",
          fontVariantNumeric: "tabular-nums",
        }}
        className="hidden sm:block"
      >
        {totalFindings ?? "—"} findings
      </div>

      {/* Sync status pill */}
      <div
        style={{
          border: "1px solid var(--border)",
          backgroundColor: "var(--bg-hover)",
          borderRadius: 6,
          padding: "3px 8px",
          fontSize: 11,
          color: "var(--text-muted)",
        }}
        className="hidden sm:flex items-center gap-1.5"
        title={
          syncStatus?.last_checked
            ? `Last checked: ${syncStatus.last_checked}`
            : ""
        }
      >
        <span
          style={{
            width: 6,
            height: 6,
            borderRadius: "50%",
            backgroundColor: dotColor,
            display: "inline-block",
            transition: "background-color 0.3s",
          }}
        />
        {label}
      </div>

      {/* Manual sync button */}
      <button
        onClick={onSyncNow}
        disabled={isPulling}
        title="Pull latest findings now"
        style={{
          border: "1px solid var(--border)",
          backgroundColor: "var(--bg-hover)",
          color: isPulling ? "var(--accent)" : "var(--text-muted)",
          borderRadius: 6,
          padding: "5px 8px",
          cursor: isPulling ? "not-allowed" : "pointer",
          transition: "color 0.2s",
        }}
        className="hover:text-[#c8d4f0] transition-colors"
      >
        <RefreshIcon spinning={isPulling} />
      </button>
    </div>
  );
}

function NavItem({ to, end, children }) {
  return (
    <NavLink
      to={to}
      end={end}
      className={({ isActive }) =>
        `relative px-3.5 py-1.5 rounded-lg text-[13px] font-medium transition-all duration-200 ${
          isActive
            ? "text-[#f0f4ff] bg-[#1a2948] border border-[#2a4070]"
            : "text-[#7e8fa8] hover:text-[#c8d4f0] hover:bg-[#121c2e]"
        }`
      }
    >
      {children}
    </NavLink>
  );
}

// ─── Auto-refresh context ─────────────────────────────────────────────────────
// Passed down so child pages know when to re-fetch
export const RefreshContext = React.createContext({ refreshKey: 0 });

function AppShell() {
  const location = useLocation();
  const [syncStatus, setSyncStatus] = useState(null);
  const [totalFindings, setTotalFindings] = useState(null);
  const [syncing, setSyncing] = useState(false);
  const [refreshKey, setRefreshKey] = useState(0);
  const prevTotalRef = useRef(null);

  // Bump refreshKey to tell child pages to re-fetch data
  const triggerRefresh = useCallback(() => {
    setRefreshKey((k) => k + 1);
  }, []);

  // Poll /api/sync-status to know if Flask pulled new commits
  useEffect(() => {
    let alive = true;
    async function checkSync() {
      const status = await fetchSyncStatus();
      if (!alive) return;
      setSyncStatus(status);
    }
    checkSync();
    const id = setInterval(checkSync, SYNC_STATUS_MS);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, []);

  // Poll /api/stats every 30s — if total changes, trigger page refresh
  useEffect(() => {
    let alive = true;
    async function checkStats() {
      try {
        const stats = await getStats();
        if (!alive) return;
        const newTotal = stats?.total_findings ?? null;
        setTotalFindings(newTotal);
        if (
          prevTotalRef.current !== null &&
          newTotal !== null &&
          newTotal !== prevTotalRef.current
        ) {
          console.log(
            `[AutoRefresh] Findings changed ${prevTotalRef.current} → ${newTotal}`,
          );
          triggerRefresh();
        }
        prevTotalRef.current = newTotal;
      } catch {
        // API not reachable — ignore
      }
    }
    checkStats();
    const id = setInterval(checkStats, FRONTEND_POLL_MS);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, [triggerRefresh]);

  const handleSyncNow = async () => {
    setSyncing(true);
    const result = await triggerSyncNow();
    setSyncing(false);
    if (result?.pulled) {
      // Give Flask a moment to read the new files, then refresh
      setTimeout(triggerRefresh, 800);
    }
  };

  return (
    <div className="min-h-screen" style={{ backgroundColor: "var(--bg-base)" }}>
      <header
        style={{
          backgroundColor: "var(--bg-surface)",
          borderBottom: "1px solid var(--border)",
        }}
        className="sticky top-0 z-10"
      >
        <div className="accent-line" />
        <div className="mx-auto flex max-w-7xl items-center justify-between px-6 py-3">
          <div className="flex items-center gap-2.5">
            <ShieldIcon />
            <NavLink to="/" className="flex items-baseline gap-1.5">
              <span
                style={{
                  fontFamily: "var(--font-sans)",
                  letterSpacing: "-0.02em",
                }}
                className="font-semibold text-[15px] text-[#f0f4ff]"
              >
                SecurePipeline
              </span>
              <span
                style={{ color: "var(--accent)" }}
                className="text-[13px] font-medium"
              >
                Hub
              </span>
            </NavLink>
          </div>

          <nav className="flex items-center gap-1">
            <NavItem to="/" end>
              Dashboard
            </NavItem>
            <NavItem to="/findings">Findings</NavItem>
            <NavItem to="/compliance">OWASP Coverage</NavItem>
            <NavItem to="/trends">Trends</NavItem>
          </nav>

          <SyncIndicator
            syncStatus={syncStatus}
            totalFindings={totalFindings}
            onSyncNow={handleSyncNow}
            syncing={syncing}
          />
        </div>
      </header>

      <main className="mx-auto max-w-7xl px-6 py-7">
        <RefreshContext.Provider value={{ refreshKey }}>
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/findings" element={<FindingsTable />} />
            <Route path="/findings/:id" element={<FindingDetail />} />
            <Route path="/compliance" element={<ComplianceView />} />
            <Route path="/trends" element={<TrendsView />} />
          </Routes>
        </RefreshContext.Provider>
      </main>
    </div>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <AppShell />
    </BrowserRouter>
  );
}
