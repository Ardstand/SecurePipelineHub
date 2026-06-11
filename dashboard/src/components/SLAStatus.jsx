import React, { useEffect, useState } from "react";
import { getFindings } from "../api";

function slaBadge(slaStatus) {
  const s = (slaStatus ?? "").toUpperCase();
  if (s === "OVERDUE")  return "bg-rose-500/10 text-rose-400 border border-rose-500/25";
  if (s === "OPEN")     return "bg-emerald-500/10 text-emerald-400 border border-emerald-500/25";
  if (s === "NO_SLA")   return "bg-slate-500/10 text-slate-400 border border-slate-500/25";
  if (s === "RESOLVED") return "bg-blue-500/10 text-blue-400 border border-blue-500/25";
  if (s === "WARNING")  return "bg-yellow-500/10 text-yellow-400 border border-yellow-500/25";
  return "bg-slate-500/10 text-slate-400";
}

export default function SLAStatus({ openCount, overdueCount, noSlaCount }) {
  const [overdueFindings, setOverdueFindings] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError]     = useState("");

  useEffect(() => {
    let alive = true;
    async function load() {
      setLoading(true); setError("");
      try {
        const res = await getFindings({ sla_status: "OVERDUE", limit: 5 });
        if (!alive) return;
        setOverdueFindings(res?.findings ?? []);
      } catch (e) {
        if (!alive) return;
        setError(e?.message ?? "Failed to load SLA details.");
      } finally {
        if (alive) setLoading(false);
      }
    }
    load();
    return () => { alive = false; };
  }, []);

  return (
    <div className="space-y-4">
      {/* Counters */}
      <div className="grid grid-cols-3 gap-2">
        {[
          { label: "Open",    value: openCount,    colorText: "text-emerald-400", colorBg: "bg-emerald-500/8 border-emerald-500/15" },
          { label: "Overdue", value: overdueCount, colorText: "text-rose-400",    colorBg: "bg-rose-500/8 border-rose-500/15" },
          { label: "No SLA",  value: noSlaCount,   colorText: "text-slate-400",   colorBg: "bg-slate-500/8 border-slate-500/15" },
        ].map(({ label, value, colorText, colorBg }) => (
          <div key={label} className={`rounded-lg border p-3 text-center ${colorBg}`}>
            <div style={{ letterSpacing: "0.06em" }} className={`text-[10px] font-semibold uppercase ${colorText} mb-1`}>{label}</div>
            <div className={`text-[22px] font-bold leading-none ${colorText}`} style={{ fontVariantNumeric: "tabular-nums" }}>
              {value ?? 0}
            </div>
          </div>
        ))}
      </div>

      {/* Overdue list */}
      <div>
        <div style={{ color: "var(--text-muted)", letterSpacing: "0.07em" }} className="mb-2.5 text-[11px] font-medium uppercase">
          Top Overdue
        </div>

        {loading && (
          <div style={{ color: "var(--text-muted)" }} className="text-xs animate-pulse">Loading…</div>
        )}
        {error && <div className="text-xs text-rose-400">{error}</div>}

        {!loading && !error && (
          <div className="space-y-1.5">
            {overdueFindings.length === 0 && (
              <div style={{ color: "var(--text-muted)" }} className="text-xs">No overdue findings.</div>
            )}
            {overdueFindings.map(f => {
              const raw = Number(f.days_remaining ?? 0);
              const overdueDays = Number.isFinite(raw) ? Math.abs(raw) : undefined;
              return (
                <div
                  key={f.id}
                  style={{ backgroundColor: "var(--bg-hover)", border: "1px solid var(--border)" }}
                  className="rounded-lg p-2.5 flex items-start justify-between gap-2"
                >
                  <div className="min-w-0">
                    <div style={{ color: "var(--text-primary)" }} className="truncate text-[12px] font-medium">{f.title}</div>
                    <div style={{ color: "var(--text-muted)" }} className="mt-0.5 text-[11px] truncate font-mono">{f.file_path}:{f.line_number}</div>
                  </div>
                  <div className="flex flex-col items-end gap-1 shrink-0">
                    <span className={`rounded-md px-1.5 py-0.5 text-[10px] font-semibold ${slaBadge(f.sla_status)}`}>
                      {f.sla_status}
                    </span>
                    {overdueDays !== undefined && (
                      <div className="text-[11px] text-rose-400">{overdueDays.toFixed(1)}d</div>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
