import React, { useEffect, useMemo, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { getFindings, getStats } from "../api";

const PAGE_SIZE = 20;

const SEVERITY_BADGE = {
  CRITICAL: "bg-rose-500/10 text-rose-400 border border-rose-500/25",
  HIGH: "bg-orange-500/10 text-orange-400 border border-orange-500/25",
  MEDIUM: "bg-yellow-500/10 text-yellow-400 border border-yellow-500/25",
  LOW: "bg-emerald-500/10 text-emerald-400 border border-emerald-500/25",
  INFO: "bg-slate-500/10 text-slate-400 border border-slate-500/25",
};

const SLA_BADGE = {
  OVERDUE: "bg-rose-500/10 text-rose-400 border border-rose-500/25",
  OPEN: "bg-emerald-500/10 text-emerald-400 border border-emerald-500/25",
  NO_SLA: "bg-slate-500/10 text-slate-400 border border-slate-500/25",
  RESOLVED: "bg-blue-500/10 text-blue-400 border border-blue-500/25",
  WARNING: "bg-yellow-500/10 text-yellow-400 border border-yellow-500/25",
};

function sevBadge(s) {
  return SEVERITY_BADGE[(s ?? "").toUpperCase()] ?? SEVERITY_BADGE.INFO;
}
function slaBadge(s) {
  return SLA_BADGE[(s ?? "").toUpperCase()] ?? SLA_BADGE.NO_SLA;
}

function formatDate(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  return Number.isNaN(d.getTime())
    ? "—"
    : d.toLocaleDateString("en-IE", {
        day: "2-digit",
        month: "short",
        year: "numeric",
      });
}

function ChevronLeftIcon() {
  return (
    <svg
      width="14"
      height="14"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <polyline points="15 18 9 12 15 6" />
    </svg>
  );
}
function ChevronRightIcon() {
  return (
    <svg
      width="14"
      height="14"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <polyline points="9 18 15 12 9 6" />
    </svg>
  );
}
function XIcon() {
  return (
    <svg
      width="11"
      height="11"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2.5"
      strokeLinecap="round"
    >
      <line x1="18" y1="6" x2="6" y2="18" />
      <line x1="6" y1="6" x2="18" y2="18" />
    </svg>
  );
}
function SearchIcon() {
  return (
    <svg
      width="14"
      height="14"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <circle cx="11" cy="11" r="8" />
      <path d="m21 21-4.35-4.35" />
    </svg>
  );
}
function FPIcon() {
  return (
    <svg
      width="12"
      height="12"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <circle cx="12" cy="12" r="10" />
      <line x1="4.93" y1="4.93" x2="19.07" y2="19.07" />
    </svg>
  );
}
function GitIcon() {
  return (
    <svg
      width="11"
      height="11"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <circle cx="12" cy="12" r="3" />
      <line x1="3" y1="12" x2="9" y2="12" />
      <line x1="15" y1="12" x2="21" y2="12" />
    </svg>
  );
}

const fieldStyle = {
  backgroundColor: "var(--bg-hover)",
  border: "1px solid var(--border)",
  color: "var(--text-primary)",
  borderRadius: 8,
  fontSize: 13,
  outline: "none",
  fontFamily: "var(--font-sans)",
};

export default function FindingsTable() {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const complianceTag = searchParams.get("tag") ?? "";

  const [stats, setStats] = useState(null);
  const [statsLoading, setStatsLoading] = useState(true);
  const [statsError, setStatsError] = useState("");
  const [severity, setSeverity] = useState("");
  const [source, setSource] = useState("");
  const [priority, setPriority] = useState("");
  const [slaStatus, setSlaStatus] = useState("");
  const [query, setQuery] = useState("");
  const [showFP, setShowFP] = useState(false);
  const [page, setPage] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [findings, setFindings] = useState([]);
  const [total, setTotal] = useState(0);

  useEffect(() => {
    let alive = true;
    async function loadStats() {
      setStatsLoading(true);
      setStatsError("");
      try {
        const s = await getStats();
        if (!alive) return;
        setStats(s);
      } catch (e) {
        if (!alive) return;
        setStatsError(e?.message ?? "Failed to load filter options.");
      } finally {
        if (alive) setStatsLoading(false);
      }
    }
    loadStats();
    return () => {
      alive = false;
    };
  }, []);

  const filterOptions = useMemo(() => {
    const bySeverity = stats?.by_severity ?? {};
    const bySource = stats?.by_source ?? {};
    const byPriority = stats?.by_priority ?? {};
    const bySla = stats?.by_sla_status ?? {};
    return {
      severities: Object.keys(bySeverity).sort(),
      priorities: Object.keys(byPriority).sort(),
      sources: Object.keys(bySource).sort(),
      slaStatuses: Object.keys(bySla).sort(),
    };
  }, [stats]);

  useEffect(() => {
    let alive = true;
    async function load() {
      setLoading(true);
      setError("");
      try {
        const res = await getFindings({
          severity: severity || undefined,
          source: source || undefined,
          priority: priority || undefined,
          sla_status: slaStatus || undefined,
          compliance_tag: complianceTag || undefined,
          show_false_positives: showFP || undefined,
          limit: PAGE_SIZE,
          offset: page * PAGE_SIZE,
        });
        let rows = res?.findings ?? [];

        // Client-side text search (title / file path)
        if (query.trim()) {
          const q = query.trim().toLowerCase();
          rows = rows.filter(
            (f) =>
              (f.title ?? "").toLowerCase().includes(q) ||
              (f.file_path ?? "").toLowerCase().includes(q),
          );
        }

        if (!alive) return;
        setFindings(rows);
        setTotal(res?.total ?? 0);
      } catch (e) {
        if (!alive) return;
        setError(e?.message ?? "Failed to load findings.");
      } finally {
        if (alive) setLoading(false);
      }
    }
    load();
    return () => {
      alive = false;
    };
  }, [
    severity,
    source,
    priority,
    slaStatus,
    page,
    query,
    complianceTag,
    showFP,
  ]);

  useEffect(() => {
    setPage(0);
  }, [severity, source, priority, slaStatus, query, complianceTag, showFP]);

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const clearTag = () => {
    const n = new URLSearchParams(searchParams);
    n.delete("tag");
    setSearchParams(n);
  };

  return (
    <div className="space-y-4 fade-up">
      {/* Filter bar */}
      <div className="card p-5">
        <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between mb-5">
          <div>
            <h2
              style={{ color: "var(--text-primary)", letterSpacing: "-0.01em" }}
              className="text-[15px] font-semibold"
            >
              Vulnerability Findings
            </h2>
            {complianceTag && (
              <div className="mt-2 inline-flex items-center gap-1.5 rounded-full bg-blue-500/10 border border-blue-500/25 px-2.5 py-1 text-[11px] text-blue-400">
                OWASP: {complianceTag}
                <button
                  onClick={clearTag}
                  className="hover:text-blue-300 transition-colors"
                >
                  <XIcon />
                </button>
              </div>
            )}
          </div>

          <div className="flex items-center gap-3">
            {/* False positive toggle */}
            <button
              onClick={() => setShowFP((v) => !v)}
              style={{
                backgroundColor: showFP
                  ? "rgba(250,204,21,0.08)"
                  : "var(--bg-hover)",
                border: `1px solid ${showFP ? "rgba(250,204,21,0.3)" : "var(--border)"}`,
                color: showFP ? "#fbbf24" : "var(--text-muted)",
              }}
              className="inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-[12px] font-medium transition-all duration-150 whitespace-nowrap"
            >
              <FPIcon />
              {showFP ? "Hiding False Positives" : "Show False Positives"}
            </button>

            {/* Search */}
            <div className="relative md:w-72">
              <span
                className="absolute left-3 top-1/2 -translate-y-1/2"
                style={{ color: "var(--text-muted)" }}
              >
                <SearchIcon />
              </span>
              <input
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Search title or file path…"
                style={{
                  ...fieldStyle,
                  padding: "7px 12px 7px 34px",
                  width: "100%",
                }}
              />
            </div>
          </div>
        </div>

        <div className="grid grid-cols-1 gap-3 md:grid-cols-4">
          {[
            {
              label: "Severity",
              value: severity,
              set: setSeverity,
              opts: filterOptions.severities,
            },
            {
              label: "Source",
              value: source,
              set: setSource,
              opts: filterOptions.sources,
            },
            {
              label: "Priority",
              value: priority,
              set: setPriority,
              opts: filterOptions.priorities,
            },
            {
              label: "SLA Status",
              value: slaStatus,
              set: setSlaStatus,
              opts: filterOptions.slaStatuses,
            },
          ].map(({ label, value, set, opts }) => (
            <div key={label}>
              <div
                style={{ color: "var(--text-muted)", letterSpacing: "0.07em" }}
                className="mb-1.5 text-[11px] font-medium uppercase"
              >
                {label}
              </div>
              <select
                key={opts.join(",")}
                value={value}
                onChange={(e) => set(e.target.value)}
                style={{ ...fieldStyle, padding: "7px 10px", width: "100%" }}
              >
                <option value="">All</option>
                {opts.map((o) => (
                  <option key={o} value={o}>
                    {o}
                  </option>
                ))}
              </select>
            </div>
          ))}
        </div>
        {statsError && (
          <div className="mt-2 text-xs text-rose-400">{statsError}</div>
        )}
      </div>

      {/* Table */}
      <div className="card overflow-hidden">
        <div
          style={{ borderBottom: "1px solid var(--border)" }}
          className="flex items-center justify-between px-5 py-3.5"
        >
          <div
            style={{ color: "var(--text-primary)" }}
            className="text-[13px] font-semibold"
          >
            Findings{" "}
            <span
              style={{ color: "var(--text-muted)" }}
              className="font-normal ml-1"
            >
              ({total})
            </span>
          </div>
          <div style={{ color: "var(--text-muted)" }} className="text-[12px]">
            Page {page + 1} of {totalPages}
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full table-auto text-[13px]">
            <thead>
              <tr
                style={{
                  borderBottom: "1px solid var(--border)",
                  backgroundColor: "var(--bg-hover)",
                }}
              >
                {[
                  "Score",
                  "Severity",
                  "Title / Path",
                  "Source",
                  "Assignee",
                  "SLA",
                  "Due",
                  "Commit",
                ].map((h) => (
                  <th
                    key={h}
                    style={{
                      color: "var(--text-muted)",
                      letterSpacing: "0.06em",
                    }}
                    className="px-4 py-3 text-left text-[11px] font-medium uppercase"
                  >
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td
                    colSpan={8}
                    style={{ color: "var(--text-muted)" }}
                    className="px-4 py-10 text-center text-sm"
                  >
                    <span className="inline-flex items-center gap-2">
                      <svg
                        className="animate-spin"
                        width="13"
                        height="13"
                        viewBox="0 0 24 24"
                        fill="none"
                        stroke="currentColor"
                        strokeWidth="2"
                      >
                        <path
                          d="M21 12a9 9 0 1 1-6.219-8.56"
                          strokeLinecap="round"
                        />
                      </svg>
                      Loading…
                    </span>
                  </td>
                </tr>
              ) : findings.length === 0 ? (
                <tr>
                  <td
                    colSpan={8}
                    style={{ color: "var(--text-muted)" }}
                    className="px-4 py-10 text-center text-sm"
                  >
                    No findings match your filters.
                  </td>
                </tr>
              ) : (
                findings.map((f, i) => {
                  const isFP = f.false_positive === true;
                  return (
                    <tr
                      key={f.id}
                      style={{
                        borderTop: "1px solid var(--border-subtle)",
                        backgroundColor: isFP
                          ? "rgba(250,204,21,0.03)"
                          : i % 2 === 0
                            ? "transparent"
                            : "rgba(255,255,255,0.012)",
                        opacity: isFP ? 0.55 : 1,
                      }}
                      className="cursor-pointer transition-colors duration-100 hover:bg-[#111d30]"
                      onClick={() => navigate(`/findings/${f.id}`)}
                    >
                      <td className="px-4 py-3">
                        <span
                          style={{
                            color: isFP ? "var(--text-muted)" : "#f0f4ff",
                            fontVariantNumeric: "tabular-nums",
                            letterSpacing: "-0.01em",
                          }}
                          className="font-bold text-[15px]"
                        >
                          {f.risk_score}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <span
                          className={`rounded-md px-2 py-0.5 text-[11px] font-semibold tracking-wide ${sevBadge(f.severity)}`}
                        >
                          {f.severity}
                        </span>
                      </td>
                      <td className="px-4 py-3 max-w-xs">
                        <div className="flex items-center gap-1.5">
                          {isFP && (
                            <span
                              title="Marked as false positive"
                              style={{ color: "#fbbf24" }}
                              className="shrink-0"
                            >
                              <FPIcon />
                            </span>
                          )}
                          <div
                            style={{
                              color: isFP
                                ? "var(--text-muted)"
                                : "var(--text-primary)",
                            }}
                            className={`font-medium truncate ${isFP ? "line-through" : ""}`}
                          >
                            {f.title}
                          </div>
                        </div>
                        <div
                          style={{ color: "var(--text-muted)" }}
                          className="mt-0.5 text-[11px] truncate font-mono"
                        >
                          {f.file_path}:{f.line_number}
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <span
                          style={{ color: "var(--text-secondary)" }}
                          className="text-xs"
                        >
                          {f.source}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <div
                          style={{ color: "var(--text-secondary)" }}
                          className="text-xs truncate"
                        >
                          {f.ci_author ?? f.assignee}
                        </div>
                        <div
                          style={{ color: "var(--text-muted)" }}
                          className="text-[11px]"
                        >
                          {f.ci_author
                            ? f.ci_author.split("@")[0]
                            : f.assignee_team}
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <span
                          className={`rounded-md px-2 py-0.5 text-[11px] font-semibold ${slaBadge(f.sla_status)}`}
                        >
                          {f.sla_status}
                        </span>
                        {typeof f.days_remaining === "number" &&
                          (f.days_remaining < 0 ? (
                            <div className="mt-0.5 text-[11px] text-rose-400">
                              {Math.abs(f.days_remaining).toFixed(1)}d overdue
                            </div>
                          ) : (
                            <div
                              style={{ color: "var(--text-muted)" }}
                              className="mt-0.5 text-[11px]"
                            >
                              {f.days_remaining.toFixed(1)}d left
                            </div>
                          ))}
                      </td>
                      <td
                        style={{ color: "var(--text-secondary)" }}
                        className="px-4 py-3 text-xs whitespace-nowrap"
                      >
                        {formatDate(f.due_date)}
                      </td>
                      <td className="px-4 py-3">
                        {f.ci_short_sha ? (
                          <div>
                            <a
                              href={`https://github.com/${process.env.REACT_APP_TARGET_REPO}/commit/${f.ci_commit_sha}`}
                              target="_blank"
                              rel="noopener noreferrer"
                              onClick={(e) => e.stopPropagation()}
                              style={{ color: "var(--accent)" }}
                              className="inline-flex items-center gap-1 font-mono text-[11px] hover:underline"
                            >
                              <GitIcon />
                              {f.ci_short_sha}
                            </a>
                            <div
                              style={{ color: "var(--text-muted)" }}
                              className="text-[11px] mt-0.5 truncate max-w-[120px]"
                              title={f.ci_message}
                            >
                              {f.ci_message
                                ? f.ci_message.slice(0, 40) +
                                  (f.ci_message.length > 40 ? "…" : "")
                                : ""}
                            </div>
                            <div
                              style={{ color: "var(--text-muted)" }}
                              className="text-[10px] mt-0.5 truncate max-w-[120px]"
                            >
                              {f.ci_author ? f.ci_author.split("@")[0] : ""}
                            </div>
                          </div>
                        ) : (
                          <span
                            style={{ color: "var(--text-muted)" }}
                            className="text-[11px]"
                          >
                            —
                          </span>
                        )}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        <div
          style={{ borderTop: "1px solid var(--border)" }}
          className="flex items-center justify-between px-5 py-3"
        >
          <button
            style={{
              backgroundColor: "var(--bg-hover)",
              border: "1px solid var(--border)",
              color: "var(--text-secondary)",
            }}
            className="inline-flex items-center gap-1.5 rounded-lg px-3.5 py-1.5 text-xs font-medium disabled:opacity-30 hover:border-[#2a4070] hover:text-[#c8d4f0] transition-all"
            disabled={page === 0}
            onClick={() => setPage((p) => Math.max(0, p - 1))}
          >
            <ChevronLeftIcon /> Prev
          </button>
          <div style={{ color: "var(--text-muted)" }} className="text-xs">
            {findings.length} of {total} results
          </div>
          <button
            style={{
              backgroundColor: "var(--bg-hover)",
              border: "1px solid var(--border)",
              color: "var(--text-secondary)",
            }}
            className="inline-flex items-center gap-1.5 rounded-lg px-3.5 py-1.5 text-xs font-medium disabled:opacity-30 hover:border-[#2a4070] hover:text-[#c8d4f0] transition-all"
            disabled={(page + 1) * PAGE_SIZE >= total}
            onClick={() => setPage((p) => p + 1)}
          >
            Next <ChevronRightIcon />
          </button>
        </div>
      </div>
    </div>
  );
}
