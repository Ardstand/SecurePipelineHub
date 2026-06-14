import React, { useEffect, useRef, useState, useCallback } from "react";
import {
  NavLink,
  BrowserRouter,
  Routes,
  Route,
  Outlet,
  Navigate,
  useNavigate,
  useLocation,
} from "react-router-dom";
import Dashboard from "./components/Dashboard";
import FindingsTable from "./components/FindingsTable";
import FindingDetail from "./components/FindingDetail";
import ComplianceView from "./components/ComplianceView";
import TrendsView from "./components/TrendsView";
import LoginPage from "./components/LoginPage";
import AdminUsersPage from "./components/AdminUsersPage";
import { getCurrentUser, getStats } from "./api";

const POLL_STATS_MS = 30_000;
const POLL_SYNC_MS = 30_000;

async function fetchSyncStatus() {
  try {
    const token = localStorage.getItem("authToken");
    const res = await fetch("http://localhost:5000/api/sync-status", {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    });
    return (await res.json())?.data ?? null;
  } catch {
    return null;
  }
}

async function triggerSyncNow() {
  try {
    const token = localStorage.getItem("authToken");
    const res = await fetch("http://localhost:5000/api/sync-now", {
      method: "POST",
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    });
    return (await res.json())?.data ?? null;
  } catch {
    return null;
  }
}

// ── Auto-refresh context ──────────────────────────────────────────────────────
export const RefreshContext = React.createContext({ refreshKey: 0 });

// ── Icons ─────────────────────────────────────────────────────────────────────
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
function LogoutIcon() {
  return (
    <svg
      width="13"
      height="13"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" />
      <polyline points="16 17 21 12 16 7" />
      <line x1="21" y1="12" x2="9" y2="12" />
    </svg>
  );
}
function UsersIcon() {
  return (
    <svg
      width="13"
      height="13"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" />
      <circle cx="9" cy="7" r="4" />
      <path d="M23 21v-2a4 4 0 0 0-3-3.87" />
      <path d="M16 3.13a4 4 0 0 1 0 7.75" />
    </svg>
  );
}
function KeyIcon() {
  return (
    <svg
      width="13"
      height="13"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4" />
    </svg>
  );
}

// ── Nav item ──────────────────────────────────────────────────────────────────
function NavItem({ to, end, children }) {
  return (
    <NavLink
      to={to}
      end={end}
      className={({ isActive }) =>
        `px-3.5 py-1.5 rounded-lg text-[13px] font-medium transition-all duration-200 ${
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

// ── Sync indicator ────────────────────────────────────────────────────────────
function SyncIndicator({ syncStatus, totalFindings, onSyncNow, syncing }) {
  const isPulling = syncStatus?.status === "pulling" || syncing;
  const wasUpdated = syncStatus?.status === "updated";
  const isError = syncStatus?.status === "error";

  const dotColor = isPulling
    ? "#fbbf24"
    : wasUpdated
      ? "#06d6a0"
      : isError
        ? "#ff4d6a"
        : "var(--text-muted)";

  const label = isPulling
    ? "Syncing…"
    : wasUpdated
      ? `Updated · ${syncStatus?.last_commit ?? ""}`
      : isError
        ? "Sync error"
        : syncStatus?.last_commit
          ? syncStatus.last_commit
          : "Watching…";

  return (
    <div className="flex items-center gap-1.5">
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
        className="hidden md:block"
      >
        {totalFindings ?? "—"} findings
      </div>
      <div
        style={{
          border: "1px solid var(--border)",
          backgroundColor: "var(--bg-hover)",
          borderRadius: 6,
          padding: "3px 8px",
          fontSize: 11,
          color: "var(--text-muted)",
        }}
        className="hidden lg:flex items-center gap-1.5"
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
        }}
        className="hover:text-[#c8d4f0] transition-colors"
      >
        <RefreshIcon spinning={isPulling} />
      </button>
    </div>
  );
}

// ── User menu (avatar + dropdown) ─────────────────────────────────────────────
function UserMenu({ user, onLogout }) {
  const [open, setOpen] = useState(false);
  const [showPw, setShowPw] = useState(false);
  const [pwForm, setPwForm] = useState({ current: "", next: "" });
  const [pwErr, setPwErr] = useState("");
  const [pwOk, setPwOk] = useState(false);
  const [pwSaving, setPwSaving] = useState(false);
  const navigate = useNavigate();
  const ref = useRef(null);

  useEffect(() => {
    const fn = (e) => {
      if (ref.current && !ref.current.contains(e.target)) setOpen(false);
    };
    document.addEventListener("mousedown", fn);
    return () => document.removeEventListener("mousedown", fn);
  }, []);

  const handleChangePw = async (e) => {
    e.preventDefault();
    setPwErr("");
    setPwOk(false);
    setPwSaving(true);
    try {
      const { changePassword } = await import("./api");
      await changePassword(pwForm.current, pwForm.next);
      setPwOk(true);
      setPwForm({ current: "", next: "" });
      setTimeout(() => {
        setPwOk(false);
        setShowPw(false);
      }, 2000);
    } catch (err) {
      setPwErr(err?.response?.data?.message ?? "Failed to change password");
    } finally {
      setPwSaving(false);
    }
  };

  const initials = (user?.name ?? user?.email ?? "?")[0].toUpperCase();
  const display = user?.name || user?.email || "User";

  return (
    <div className="relative" ref={ref}>
      <button
        onClick={() => {
          setOpen((o) => !o);
          setShowPw(false);
        }}
        style={{
          border: "1px solid var(--border)",
          backgroundColor: "var(--bg-hover)",
          borderRadius: 8,
          padding: "4px 10px 4px 6px",
          fontFamily: "var(--font-sans)",
        }}
        className="inline-flex items-center gap-2 hover:border-[#2a4070] transition-all"
      >
        <span
          style={{
            width: 26,
            height: 26,
            borderRadius: "50%",
            backgroundColor: "rgba(79,142,247,0.15)",
            color: "var(--accent)",
            border: "1px solid rgba(79,142,247,0.3)",
            display: "inline-flex",
            alignItems: "center",
            justifyContent: "center",
            fontSize: 11,
            fontWeight: 700,
            flexShrink: 0,
          }}
        >
          {initials}
        </span>
        <div className="text-left hidden sm:block">
          <div
            style={{ color: "var(--text-primary)" }}
            className="text-[12px] font-medium leading-tight"
          >
            {display.length > 18 ? display.slice(0, 18) + "…" : display}
          </div>
          <div
            style={{ color: "var(--text-muted)" }}
            className="text-[10px] leading-tight capitalize"
          >
            {user?.role === "admin" ? "Admin" : "Developer"}
          </div>
        </div>
      </button>

      {open && (
        <div
          style={{
            backgroundColor: "var(--bg-card)",
            border: "1px solid var(--border)",
            borderRadius: 10,
            minWidth: 220,
            zIndex: 50,
            top: "calc(100% + 6px)",
            right: 0,
            boxShadow: "0 8px 32px rgba(0,0,0,0.5)",
          }}
          className="absolute"
        >
          {/* User info */}
          <div
            style={{ borderBottom: "1px solid var(--border)" }}
            className="px-3.5 py-3"
          >
            <div
              style={{ color: "var(--text-primary)" }}
              className="text-[13px] font-semibold"
            >
              {user?.name || "—"}
            </div>
            <div
              style={{ color: "var(--text-muted)" }}
              className="text-[11px] mt-0.5 font-mono"
            >
              {user?.email}
            </div>
            {user?.team && (
              <div
                style={{ color: "var(--text-muted)" }}
                className="text-[11px] mt-0.5"
              >
                Team: {user.team}
              </div>
            )}
          </div>

          {/* Menu items */}
          {user?.role === "admin" && (
            <button
              onClick={() => {
                setOpen(false);
                navigate("/admin/users");
              }}
              style={{
                color: "var(--text-secondary)",
                fontFamily: "var(--font-sans)",
              }}
              className="w-full flex items-center gap-2.5 px-3.5 py-2.5 text-[13px] hover:bg-[#1a2236] transition-colors"
            >
              <UsersIcon /> User Management
            </button>
          )}

          <button
            onClick={() => setShowPw((v) => !v)}
            style={{
              color: "var(--text-secondary)",
              fontFamily: "var(--font-sans)",
            }}
            className="w-full flex items-center gap-2.5 px-3.5 py-2.5 text-[13px] hover:bg-[#1a2236] transition-colors"
          >
            <KeyIcon /> Change Password
          </button>

          {/* Inline change password form */}
          {showPw && (
            <form
              onSubmit={handleChangePw}
              style={{ borderTop: "1px solid var(--border-subtle)" }}
              className="px-3.5 py-3 space-y-2"
            >
              {[
                { key: "current", label: "Current password", ph: "••••••••" },
                { key: "next", label: "New password", ph: "Min 8 chars" },
              ].map(({ key, label, ph }) => (
                <div key={key}>
                  <div
                    style={{
                      color: "var(--text-muted)",
                      fontSize: 10,
                      letterSpacing: "0.06em",
                    }}
                    className="uppercase font-medium mb-1"
                  >
                    {label}
                  </div>
                  <input
                    type="password"
                    placeholder={ph}
                    value={pwForm[key]}
                    onChange={(e) =>
                      setPwForm((f) => ({ ...f, [key]: e.target.value }))
                    }
                    style={{
                      backgroundColor: "var(--bg-hover)",
                      border: "1px solid var(--border)",
                      color: "var(--text-primary)",
                      borderRadius: 6,
                      fontSize: 12,
                      outline: "none",
                      fontFamily: "var(--font-sans)",
                      width: "100%",
                      padding: "6px 8px",
                    }}
                  />
                </div>
              ))}
              {pwErr && <p className="text-rose-400 text-[11px]">{pwErr}</p>}
              {pwOk && (
                <p className="text-emerald-400 text-[11px]">
                  Password changed!
                </p>
              )}
              <button
                type="submit"
                disabled={pwSaving}
                style={{
                  backgroundColor: "var(--bg-hover)",
                  border: "1px solid var(--border)",
                  color: "var(--text-secondary)",
                  borderRadius: 6,
                  fontSize: 12,
                  fontFamily: "var(--font-sans)",
                  width: "100%",
                  padding: "6px 8px",
                  opacity: pwSaving ? 0.6 : 1,
                }}
                className="hover:border-[#2a4070] hover:text-[#c8d4f0] transition-all"
              >
                {pwSaving ? "Saving…" : "Update password"}
              </button>
            </form>
          )}

          <div style={{ borderTop: "1px solid var(--border)" }}>
            <button
              onClick={() => {
                setOpen(false);
                onLogout();
              }}
              style={{ color: "#f87171", fontFamily: "var(--font-sans)" }}
              className="w-full flex items-center gap-2.5 px-3.5 py-2.5 text-[13px] hover:bg-rose-500/8 transition-colors"
            >
              <LogoutIcon /> Sign out
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

// ── Route guards ──────────────────────────────────────────────────────────────
function ProtectedRoute({ user, children }) {
  if (!user) return <Navigate to="/login" replace />;
  return children;
}
function AdminRoute({ user, children }) {
  if (!user) return <Navigate to="/login" replace />;
  if (user.role !== "admin") return <Navigate to="/" replace />;
  return children;
}

// ── Main shell (rendered when logged in) ──────────────────────────────────────
function AppShell({ user, onLogout }) {
  const [syncStatus, setSyncStatus] = useState(null);
  const [totalFindings, setTotalFindings] = useState(null);
  const [syncing, setSyncing] = useState(false);
  const [refreshKey, setRefreshKey] = useState(0);
  const prevTotalRef = useRef(null);

  const triggerRefresh = useCallback(() => setRefreshKey((k) => k + 1), []);

  // Poll sync status
  useEffect(() => {
    let alive = true;
    const check = async () => {
      const s = await fetchSyncStatus();
      if (alive) setSyncStatus(s);
    };
    check();
    const id = setInterval(check, POLL_SYNC_MS);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, []);

  // Poll stats — auto-refresh on change
  useEffect(() => {
    let alive = true;
    const check = async () => {
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
          triggerRefresh();
        }
        prevTotalRef.current = newTotal;
      } catch {}
    };
    check();
    const id = setInterval(check, POLL_STATS_MS);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, [triggerRefresh]);

  const handleSyncNow = async () => {
    setSyncing(true);
    const result = await triggerSyncNow();
    setSyncing(false);
    if (result?.pulled) setTimeout(triggerRefresh, 800);
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
        <div className="mx-auto flex max-w-7xl items-center gap-4 px-6 py-3">
          {/* Logo */}
          <div className="flex items-center gap-2.5 shrink-0">
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

          {/* Nav — centred */}
          <nav className="flex items-center gap-1 flex-1 justify-center">
            <NavItem to="/" end>
              Dashboard
            </NavItem>
            <NavItem to="/findings">Findings</NavItem>
            <NavItem to="/compliance">OWASP Coverage</NavItem>
            <NavItem to="/trends">Trends</NavItem>
            {user?.role === "admin" && (
              <NavItem to="/admin/users">Users</NavItem>
            )}
          </nav>

          {/* Right side */}
          <div className="flex items-center gap-2 shrink-0">
            <SyncIndicator
              syncStatus={syncStatus}
              totalFindings={totalFindings}
              onSyncNow={handleSyncNow}
              syncing={syncing}
            />
            <UserMenu user={user} onLogout={onLogout} />
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-7xl px-6 py-7">
        <RefreshContext.Provider value={{ refreshKey }}>
          <Outlet />
        </RefreshContext.Provider>
      </main>
    </div>
  );
}

// ── Root ──────────────────────────────────────────────────────────────────────
export default function App() {
  const [user, setUser] = useState(null);
  const [authLoading, setAuthLoading] = useState(true);

  // On mount — verify stored token is still valid
  useEffect(() => {
    const token = localStorage.getItem("authToken");
    if (!token) {
      setAuthLoading(false);
      return;
    }
    getCurrentUser()
      .then((u) => setUser(u))
      .catch(() => {
        localStorage.removeItem("authToken");
        localStorage.removeItem("authUser");
      })
      .finally(() => setAuthLoading(false));
  }, []);

  const handleLogin = ({ token, user: u }) => {
    localStorage.setItem("authToken", token);
    localStorage.setItem("authUser", JSON.stringify(u));
    setUser(u);
  };

  const handleLogout = () => {
    localStorage.removeItem("authToken");
    localStorage.removeItem("authUser");
    setUser(null);
  };

  if (authLoading) {
    return (
      <div
        className="min-h-screen flex items-center justify-center"
        style={{ backgroundColor: "var(--bg-base)" }}
      >
        <div style={{ color: "var(--text-muted)" }} className="text-sm">
          Loading…
        </div>
      </div>
    );
  }

  return (
    <BrowserRouter>
      <Routes>
        <Route
          path="/login"
          element={
            user ? (
              <Navigate to="/" replace />
            ) : (
              <LoginPage onLogin={handleLogin} />
            )
          }
        />
        <Route
          path="/"
          element={
            <ProtectedRoute user={user}>
              <AppShell user={user} onLogout={handleLogout} />
            </ProtectedRoute>
          }
        >
          <Route index element={<Dashboard />} />
          <Route path="findings" element={<FindingsTable />} />
          <Route path="findings/:id" element={<FindingDetail />} />
          <Route path="compliance" element={<ComplianceView />} />
          <Route path="trends" element={<TrendsView />} />
          <Route
            path="admin/users"
            element={
              <AdminRoute user={user}>
                <AdminUsersPage user={user} />
              </AdminRoute>
            }
          />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
