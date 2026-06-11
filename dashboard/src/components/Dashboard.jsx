import React, { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { getFindings, getStats } from "../api";
import RiskChart from "./RiskChart";
import SLAStatus from "./SLAStatus";

const PRIORITY_STYLES = {
  CRITICAL: "bg-rose-500/10 text-rose-400 border border-rose-500/25 ring-1 ring-inset ring-rose-500/10",
  HIGH:     "bg-orange-500/10 text-orange-400 border border-orange-500/25",
  MEDIUM:   "bg-yellow-500/10 text-yellow-400 border border-yellow-500/25",
  LOW:      "bg-emerald-500/10 text-emerald-400 border border-emerald-500/25",
  INFO:     "bg-slate-500/10 text-slate-400 border border-slate-500/25",
};

function badge(priority) {
  return PRIORITY_STYLES[(priority ?? "").toUpperCase()] ?? PRIORITY_STYLES.INFO;
}

function SearchIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/>
    </svg>
  );
}
function AlertIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/>
      <line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
    </svg>
  );
}
function ClockIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>
    </svg>
  );
}
function ShieldCheckIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/>
    </svg>
  );
}

function StatCard({ label, value, color, icon: Icon, accent }) {
  return (
    <div
      className="card fade-up relative overflow-hidden p-5 group hover:border-[#253550] transition-all duration-200"
    >
      <div
        className="absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity duration-300"
        style={{ background: `radial-gradient(circle at 0% 0%, ${accent}08 0%, transparent 60%)` }}
      />
      <div className="flex items-center justify-between mb-4">
        <span
          style={{ color: "var(--text-secondary)", letterSpacing: "0.07em" }}
          className="text-[11px] font-medium uppercase"
        >
          {label}
        </span>
        <span style={{ color: accent }} className="opacity-70">
          <Icon />
        </span>
      </div>
      <div className={`text-[32px] font-semibold leading-none ${color}`}
        style={{ fontVariantNumeric: "tabular-nums", letterSpacing: "-0.02em" }}>
        {value}
      </div>
    </div>
  );
}

function SectionLabel({ children }) {
  return (
    <div
      style={{ color: "var(--text-muted)", letterSpacing: "0.08em" }}
      className="text-[11px] font-semibold uppercase mb-4"
    >
      {children}
    </div>
  );
}

export default function Dashboard() {
  const navigate = useNavigate();
  const [stats, setStats] = useState(null);
  const [topFindings, setTopFindings] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    let alive = true;
    async function load() {
      setLoading(true); setError("");
      try {
        const [s, top] = await Promise.all([getStats(), getFindings({ limit: 5 })]);
        if (!alive) return;
        setStats(s);
        setTopFindings(top?.findings ?? []);
      } catch (e) {
        if (!alive) return;
        setError(e?.message ?? "Failed to load dashboard data.");
      } finally {
        if (alive) setLoading(false);
      }
    }
    load();
    return () => { alive = false; };
  }, []);

  const overview = useMemo(() => {
    const byPriority = stats?.by_priority ?? {};
    const bySla = stats?.by_sla_status ?? {};
    return {
      total: stats?.total_findings ?? 0,
      highPriority: (byPriority?.CRITICAL ?? 0) + (byPriority?.HIGH ?? 0),
      overdue: bySla?.OVERDUE ?? 0,
      sentinelFlagged: stats?.sentinel_flagged ?? 0,
    };
  }, [stats]);

  if (loading)
    return (
      <div className="card p-10 text-center">
        <div className="inline-flex items-center gap-2" style={{ color: "var(--text-muted)" }}>
          <svg className="animate-spin" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M21 12a9 9 0 1 1-6.219-8.56" strokeLinecap="round"/>
          </svg>
          <span className="text-sm">Loading dashboard…</span>
        </div>
      </div>
    );

  if (error)
    return (
      <div className="rounded-xl p-5 bg-rose-500/8 border border-rose-500/20">
        <p className="text-rose-400 text-sm">{error}</p>
      </div>
    );

  return (
    <div className="space-y-6">
      {/* Stat cards */}
      <section className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
        <StatCard label="Total Findings"  value={overview.total}          color="text-[#f0f4ff]"   icon={SearchIcon}     accent="#4f8ef7" />
        <StatCard label="Critical + High" value={overview.highPriority}   color="text-rose-400"    icon={AlertIcon}      accent="#ff4d6a" />
        <StatCard label="Overdue"         value={overview.overdue}        color="text-orange-400"  icon={ClockIcon}      accent="#ff8c42" />
        <StatCard label="Sentinel Flagged" value={overview.sentinelFlagged} color="text-blue-400"  icon={ShieldCheckIcon} accent="#4f8ef7" />
      </section>

      {/* Main grid */}
      <section className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        {/* Donut chart */}
        <div className="card p-5 lg:col-span-1">
          <SectionLabel>Risk Distribution</SectionLabel>
          <RiskChart byPriority={stats?.by_priority ?? {}} />
        </div>

        {/* Top findings + SLA */}
        <div className="lg:col-span-2 grid grid-cols-1 gap-6 xl:grid-cols-2">
          {/* Top 5 */}
          <div className="card p-5">
            <SectionLabel>Top 5 Highest Risk</SectionLabel>
            <div className="space-y-2">
              {topFindings.map((f) => (
                <button
                  key={f.id}
                  style={{ backgroundColor: "var(--bg-hover)", border: "1px solid var(--border)" }}
                  className="w-full rounded-lg p-3 text-left hover:border-[#2a4070] hover:bg-[#141c2e] transition-all duration-150"
                  onClick={() => navigate(`/findings/${f.id}`)}
                >
                  <div className="flex items-start justify-between gap-2">
                    <div className="min-w-0">
                      <div style={{ color: "var(--text-primary)" }} className="truncate text-[13px] font-medium">
                        {f.title}
                      </div>
                      <div style={{ color: "var(--text-muted)" }} className="mt-0.5 text-xs truncate font-mono">
                        {f.file_path}:{f.line_number}
                      </div>
                    </div>
                    <div className="flex flex-col items-end gap-1.5 shrink-0">
                      <span className={`rounded-md px-2 py-0.5 text-[11px] font-semibold tracking-wide ${badge(f.priority)}`}>
                        {f.priority}
                      </span>
                      <span style={{ color: "var(--text-muted)" }} className="text-[11px]">
                        Score <span style={{ color: "var(--text-secondary)" }} className="font-semibold">{f.risk_score}</span>
                      </span>
                    </div>
                  </div>
                </button>
              ))}
            </div>
          </div>

          {/* SLA status */}
          <div className="card p-5">
            <SectionLabel>SLA Status</SectionLabel>
            <SLAStatus
              openCount={stats?.by_sla_status?.OPEN ?? 0}
              overdueCount={stats?.by_sla_status?.OVERDUE ?? 0}
              noSlaCount={stats?.by_sla_status?.NO_SLA ?? 0}
            />
          </div>
        </div>
      </section>
    </div>
  );
}
