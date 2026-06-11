import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { getCompliance } from "../api";

function CheckIcon() {
  return (
    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="20 6 9 17 4 12"/>
    </svg>
  );
}
function DashIcon() {
  return (
    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round">
      <line x1="5" y1="12" x2="19" y2="12"/>
    </svg>
  );
}
function ArrowRightIcon() {
  return (
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="9 18 15 12 9 6"/>
    </svg>
  );
}

export default function ComplianceView() {
  const navigate = useNavigate();
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    let alive = true;
    async function load() {
      setLoading(true); setError("");
      try {
        const res = await getCompliance();
        if (!alive) return;
        setData(res);
      } catch (e) {
        if (!alive) return;
        setError(e?.message ?? "Failed to load compliance data.");
      } finally {
        if (alive) setLoading(false);
      }
    }
    load();
    return () => { alive = false; };
  }, []);

  if (loading)
    return (
      <div className="card p-8 text-center">
        <span style={{ color: "var(--text-muted)" }} className="text-sm">Loading OWASP coverage…</span>
      </div>
    );

  if (error)
    return (
      <div className="card p-5 bg-rose-500/8 border-rose-500/20">
        <div className="text-rose-400 text-sm">{error}</div>
      </div>
    );

  const categories  = data?.categories ?? [];
  const covered     = data?.covered ?? 0;
  const total       = data?.total ?? 10;
  const coveragePct = data?.coverage_pct ?? 0;

  return (
    <div className="space-y-5 fade-up">
      {/* Coverage summary */}
      <div className="card p-5">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
          <div>
            <h2 style={{ color: "var(--text-primary)", letterSpacing: "-0.01em" }} className="text-[15px] font-semibold mb-1">
              OWASP Top 10 Coverage
            </h2>
            <p style={{ color: "var(--text-secondary)" }} className="text-sm">
              {covered} of {total} categories have active findings
            </p>
          </div>
          <div className="sm:text-right">
            <div style={{ color: "var(--accent)", letterSpacing: "-0.02em" }} className="text-3xl font-semibold">
              {coveragePct}%
            </div>
            <div style={{ color: "var(--text-muted)" }} className="text-xs">coverage</div>
          </div>
        </div>

        <div className="mt-5">
          <div className="h-2 w-full overflow-hidden rounded-full" style={{ backgroundColor: "var(--bg-hover)" }}>
            <div
              className="h-full rounded-full transition-all duration-700"
              style={{
                width: `${coveragePct}%`,
                background: "linear-gradient(90deg, var(--accent) 0%, #7c3aed 100%)",
              }}
            />
          </div>
        </div>
      </div>

      {/* Categories list */}
      <div className="card p-5">
        <h3 style={{ color: "var(--text-muted)", letterSpacing: "0.07em" }} className="text-[11px] font-medium uppercase mb-4">
          OWASP Categories
        </h3>
        <div className="space-y-2">
          {categories.map((c) => {
            const isCovered = c.status === "FINDINGS_PRESENT";
            return (
              <button
                key={c.category}
                style={{
                  backgroundColor: isCovered ? "var(--bg-hover)" : "transparent",
                  border: `1px solid ${isCovered ? "var(--border)" : "var(--border-subtle)"}`,
                }}
                className={`w-full rounded-lg px-4 py-3 text-left transition-all duration-150 group
                  ${isCovered ? "hover:border-[#2a4070] hover:bg-[#141c2e]" : "hover:border-[#1e2d45]"}`}
                onClick={() => navigate(`/findings?tag=${encodeURIComponent(c.category)}`)}
                type="button"
              >
                <div className="flex items-center justify-between gap-3">
                  <div className="flex items-center gap-3 min-w-0">
                    <span
                      className={`inline-flex h-6 w-6 items-center justify-center rounded-md text-[11px] font-bold shrink-0
                        ${isCovered
                          ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/25"
                          : "bg-[#1a1f2e] text-[var(--text-muted)] border border-[var(--border-subtle)]"}`}
                    >
                      {isCovered ? <CheckIcon /> : <DashIcon />}
                    </span>
                    <span style={{ color: isCovered ? "var(--text-primary)" : "var(--text-secondary)" }}
                      className="truncate text-[13px] font-medium">
                      {c.category}
                    </span>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    <span className={`text-xs font-semibold ${isCovered ? "text-emerald-400" : "text-[var(--text-muted)]"}`}>
                      {isCovered ? `${c.finding_count} findings` : "Not covered"}
                    </span>
                    <span style={{ color: "var(--text-muted)" }} className="opacity-0 group-hover:opacity-100 transition-opacity">
                      <ArrowRightIcon />
                    </span>
                  </div>
                </div>
              </button>
            );
          })}
        </div>
      </div>
    </div>
  );
}
