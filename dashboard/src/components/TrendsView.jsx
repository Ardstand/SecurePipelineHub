import React, { useEffect, useState } from "react";
import { getTrends } from "../api";
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid,
  Tooltip, Legend, ResponsiveContainer,
} from "recharts";

const COLORS = {
  CRITICAL: "#ff4d6a",
  HIGH:     "#ff8c42",
  MEDIUM:   "#ffd166",
  LOW:      "#06d6a0",
  INFO:     "#6b7fa3",
  total:    "#4f8ef7",
};

const TOOLTIP_STYLE = {
  backgroundColor: "#111827",
  border: "1px solid #1e2d45",
  borderRadius: 10,
  color: "#f0f4ff",
  fontSize: 12,
  fontFamily: "'DM Sans', system-ui, sans-serif",
  boxShadow: "0 8px 24px rgba(0,0,0,0.4)",
};

const GRID_COLOR  = "#1e2d45";
const TICK_COLOR  = "#3d5068";

function MetricCard({ label, value, color, accent }) {
  return (
    <div className="card p-5 relative overflow-hidden group hover:border-[#253550] transition-all duration-200">
      <div
        className="absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity duration-300"
        style={{ background: `radial-gradient(circle at 0% 100%, ${accent}08 0%, transparent 60%)` }}
      />
      <div style={{ color: "var(--text-muted)", letterSpacing: "0.07em" }} className="text-[11px] font-medium uppercase mb-3">
        {label}
      </div>
      <div className={`text-[30px] font-semibold leading-none ${color}`}
        style={{ letterSpacing: "-0.02em", fontVariantNumeric: "tabular-nums" }}>
        {value}
      </div>
    </div>
  );
}

export default function TrendsView() {
  const [trends, setTrends] = useState([]);
  const [days, setDays]     = useState(30);
  const [loading, setLoading] = useState(true);
  const [error, setError]     = useState("");

  useEffect(() => {
    let alive = true;
    async function load() {
      setLoading(true); setError("");
      try {
        const data = await getTrends(days);
        if (!alive) return;
        setTrends(data?.trends ?? []);
      } catch (e) {
        if (!alive) return;
        setError(e?.message ?? "Failed to load trends.");
      } finally {
        if (alive) setLoading(false);
      }
    }
    load();
    return () => { alive = false; };
  }, [days]);

  const totalFindings    = trends.reduce((s, d) => s + d.total, 0);
  const daysWithFindings = trends.filter(d => d.total > 0).length;
  const avgPerDay = daysWithFindings > 0 ? (totalFindings / daysWithFindings).toFixed(1) : "0";
  const peakDay   = trends.reduce((max, d) => d.total > max.total ? d : max, { total: 0, date: "—" });

  const formatDate = (dateStr) => {
    if (!dateStr) return "";
    const [, month, day] = dateStr.split("-");
    return `${day}/${month}`;
  };

  if (loading)
    return (
      <div className="card p-10 text-center">
        <span style={{ color: "var(--text-muted)" }} className="inline-flex items-center gap-2 text-sm">
          <svg className="animate-spin" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 12a9 9 0 1 1-6.219-8.56" strokeLinecap="round"/></svg>
          Loading trends…
        </span>
      </div>
    );

  if (error)
    return (
      <div className="card p-5 bg-rose-500/8 border-rose-500/20">
        <div className="text-rose-400 text-sm">{error}</div>
      </div>
    );

  return (
    <div className="space-y-6 fade-up">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h2 style={{ color: "var(--text-primary)", letterSpacing: "-0.02em" }} className="text-lg font-semibold">
          Security Trends
        </h2>
        <div className="flex items-center gap-1">
          <span style={{ color: "var(--text-muted)" }} className="text-xs mr-2">Last</span>
          {[7, 14, 30, 60].map(d => (
            <button
              key={d}
              onClick={() => setDays(d)}
              style={
                days === d
                  ? { backgroundColor: "#1a2948", color: "var(--accent)", border: "1px solid #2a4070" }
                  : { backgroundColor: "var(--bg-hover)", color: "var(--text-secondary)", border: "1px solid var(--border)" }
              }
              className="rounded-lg px-3 py-1.5 text-xs font-medium transition-all duration-150 hover:border-[#2a4070]"
            >
              {d}d
            </button>
          ))}
        </div>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
        <MetricCard label={`Total Findings (${days}d)`}      value={totalFindings}  color="text-[#f0f4ff]"  accent="#4f8ef7" />
        <MetricCard label="Avg per Active Day"               value={avgPerDay}      color="text-blue-400"   accent="#4f8ef7" />
        <MetricCard label="Peak Day"
          value={peakDay.total > 0 ? `${peakDay.total} on ${peakDay.date}` : "—"}
          color="text-rose-400" accent="#ff4d6a" />
      </div>

      {/* Total over time */}
      <div className="card p-5">
        <div style={{ color: "var(--text-muted)", letterSpacing: "0.07em" }} className="text-[11px] font-medium uppercase mb-5">
          Total Findings Over Time
        </div>
        <ResponsiveContainer width="100%" height={250}>
          <LineChart data={trends} margin={{ top: 4, right: 16, left: 0, bottom: 4 }}>
            <CartesianGrid strokeDasharray="3 3" stroke={GRID_COLOR} />
            <XAxis dataKey="date" tickFormatter={formatDate} tick={{ fontSize: 11, fill: TICK_COLOR }} interval="preserveStartEnd" />
            <YAxis allowDecimals={false} tick={{ fontSize: 11, fill: TICK_COLOR }} width={32} />
            <Tooltip labelFormatter={l => `Date: ${l}`} contentStyle={TOOLTIP_STYLE} />
            <Line type="monotone" dataKey="total" name="Total" stroke={COLORS.total} strokeWidth={2.5} dot={false} activeDot={{ r: 4, fill: COLORS.total }} />
          </LineChart>
        </ResponsiveContainer>
      </div>

      {/* By severity */}
      <div className="card p-5">
        <div style={{ color: "var(--text-muted)", letterSpacing: "0.07em" }} className="text-[11px] font-medium uppercase mb-5">
          Findings by Severity Over Time
        </div>
        <ResponsiveContainer width="100%" height={250}>
          <LineChart data={trends} margin={{ top: 4, right: 16, left: 0, bottom: 4 }}>
            <CartesianGrid strokeDasharray="3 3" stroke={GRID_COLOR} />
            <XAxis dataKey="date" tickFormatter={formatDate} tick={{ fontSize: 11, fill: TICK_COLOR }} interval="preserveStartEnd" />
            <YAxis allowDecimals={false} tick={{ fontSize: 11, fill: TICK_COLOR }} width={32} />
            <Tooltip labelFormatter={l => `Date: ${l}`} contentStyle={TOOLTIP_STYLE} />
            <Legend wrapperStyle={{ fontSize: 12, color: "#7e8fa8", paddingTop: 8 }} />
            {["CRITICAL","HIGH","MEDIUM","LOW","INFO"].map(key => (
              <Line key={key} type="monotone" dataKey={key} stroke={COLORS[key]} strokeWidth={2} dot={false} activeDot={{ r: 3 }} />
            ))}
          </LineChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
