import React, { useEffect, useMemo, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { getFinding, updateFinding } from "../api";

function sevBadgeClass(severity) {
  const s = (severity ?? "").toUpperCase();
  if (s === "CRITICAL")
    return "bg-rose-500/10 text-rose-400 border border-rose-500/25 ring-1 ring-inset ring-rose-500/10";
  if (s === "HIGH")
    return "bg-orange-500/10 text-orange-400 border border-orange-500/25";
  if (s === "MEDIUM")
    return "bg-yellow-500/10 text-yellow-400 border border-yellow-500/25";
  if (s === "LOW")
    return "bg-emerald-500/10 text-emerald-400 border border-emerald-500/25";
  return "bg-slate-500/10 text-slate-400 border border-slate-500/25";
}

function slaBadgeClass(slaStatus) {
  const s = (slaStatus ?? "").toUpperCase();
  if (s === "OVERDUE")
    return "bg-rose-500/10 text-rose-400 border border-rose-500/25";
  if (s === "OPEN")
    return "bg-emerald-500/10 text-emerald-400 border border-emerald-500/25";
  if (s === "RESOLVED")
    return "bg-blue-500/10 text-blue-400 border border-blue-500/25";
  if (s === "WARNING")
    return "bg-yellow-500/10 text-yellow-400 border border-yellow-500/25";
  return "bg-slate-500/10 text-slate-400 border border-slate-500/25";
}

function formatDate(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleString("en-IE", { dateStyle: "medium", timeStyle: "short" });
}

function BackIcon() {
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
function CheckIcon() {
  return (
    <svg
      width="14"
      height="14"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2.2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <polyline points="20 6 9 17 4 12" />
    </svg>
  );
}
function FPIcon() {
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
      <circle cx="12" cy="12" r="10" />
      <line x1="4.93" y1="4.93" x2="19.07" y2="19.07" />
    </svg>
  );
}
function SpinnerIcon() {
  return (
    <svg
      className="animate-spin"
      width="13"
      height="13"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
    >
      <path d="M21 12a9 9 0 1 1-6.219-8.56" strokeLinecap="round" />
    </svg>
  );
}

function FieldLabel({ children }) {
  return (
    <div
      style={{ color: "var(--text-muted)", letterSpacing: "0.07em" }}
      className="text-[11px] font-medium uppercase mb-1"
    >
      {children}
    </div>
  );
}

function SectionTitle({ children }) {
  return (
    <h3
      style={{ color: "var(--text-primary)", letterSpacing: "-0.01em" }}
      className="text-[13px] font-semibold mb-3"
    >
      {children}
    </h3>
  );
}

export default function FindingDetail() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [finding, setFinding] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [savingResolved, setSavingResolved] = useState(false);
  const [savingFP, setSavingFP] = useState(false);

  useEffect(() => {
    let alive = true;
    async function load() {
      setLoading(true);
      setError("");
      try {
        const f = await getFinding(id);
        if (!alive) return;
        setFinding(f);
      } catch (e) {
        if (!alive) return;
        setError(e?.message ?? "Failed to load finding.");
      } finally {
        if (alive) setLoading(false);
      }
    }
    load();
    return () => {
      alive = false;
    };
  }, [id]);

  const riskFactorRows = useMemo(() => {
    const rf = finding?.risk_factors ?? {};
    return Object.entries(rf).map(([k, v]) => ({ key: k, value: v }));
  }, [finding]);

  const markResolved = async () => {
    if (!finding) return;
    setSavingResolved(true);
    setError("");
    try {
      const updated = await updateFinding(id, { sla_status: "RESOLVED" });
      setFinding(updated);
    } catch (e) {
      setError(e?.message ?? "Failed to mark as resolved.");
    } finally {
      setSavingResolved(false);
    }
  };

  const toggleFalsePositive = async () => {
    if (!finding) return;
    setSavingFP(true);
    setError("");
    try {
      const updated = await updateFinding(id, {
        false_positive: !finding.false_positive,
      });
      setFinding(updated);
    } catch (e) {
      setError(e?.message ?? "Failed to update false positive status.");
    } finally {
      setSavingFP(false);
    }
  };

  if (loading)
    return (
      <div className="card p-8 text-center">
        <span
          style={{ color: "var(--text-muted)" }}
          className="inline-flex items-center gap-2 text-sm"
        >
          <SpinnerIcon /> Loading finding…
        </span>
      </div>
    );

  if (error && !finding)
    return (
      <div className="card p-5 bg-rose-500/8 border-rose-500/20">
        <p className="text-rose-400 text-sm">{error}</p>
      </div>
    );

  if (!finding)
    return (
      <div className="card p-8 text-center">
        <span style={{ color: "var(--text-muted)" }} className="text-sm">
          Finding not found.
        </span>
      </div>
    );

  const isResolved = (finding.sla_status ?? "").toUpperCase() === "RESOLVED";
  const isFP = finding.false_positive === true;

  return (
    <div className="space-y-5 fade-up">
      {/* Back button */}
      <button
        onClick={() => navigate(-1)}
        style={{
          color: "var(--text-secondary)",
          border: "1px solid var(--border)",
        }}
        className="inline-flex items-center gap-1.5 rounded-lg bg-transparent px-3 py-1.5 text-xs font-medium hover:text-[#c8d4f0] hover:border-[#2a4070] transition-all"
      >
        <BackIcon /> Back
      </button>

      {/* False positive banner */}
      {isFP && (
        <div className="rounded-xl border border-yellow-500/25 bg-yellow-500/8 px-4 py-3 flex items-center gap-2.5">
          <span style={{ color: "#fbbf24" }}>
            <FPIcon />
          </span>
          <div>
            <div className="text-[13px] font-semibold text-yellow-400">
              Marked as False Positive
            </div>
            {finding.false_positive_at && (
              <div className="text-[11px] text-yellow-400/60 mt-0.5">
                Flagged on {formatDate(finding.false_positive_at)}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Header card */}
      <div
        className="card p-5"
        style={
          isFP ? { opacity: 0.7, borderColor: "rgba(251,191,36,0.2)" } : {}
        }
      >
        <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
          <div className="min-w-0 flex-1">
            <h1
              style={{ color: "var(--text-primary)", letterSpacing: "-0.02em" }}
              className={`text-xl font-semibold leading-snug ${isFP ? "line-through opacity-60" : ""}`}
            >
              {finding.title}
            </h1>
            <div className="mt-3 flex flex-wrap items-center gap-2">
              <span
                className={`inline-flex items-center rounded-md px-2.5 py-1 text-[12px] font-semibold tracking-wide ${sevBadgeClass(finding.severity)}`}
              >
                {finding.severity}
              </span>
              <span style={{ color: "var(--text-muted)" }} className="text-xs">
                Risk Score{" "}
                <span
                  style={{
                    color: "var(--text-primary)",
                    fontVariantNumeric: "tabular-nums",
                  }}
                  className="font-bold text-[15px]"
                >
                  {finding.risk_score}
                </span>
              </span>
            </div>
          </div>

          <div className="flex flex-col gap-2 sm:items-end shrink-0">
            <span
              className={`inline-flex items-center rounded-md px-2.5 py-1 text-[12px] font-semibold ${slaBadgeClass(finding.sla_status)}`}
            >
              {finding.sla_status}
            </span>
            <div style={{ color: "var(--text-muted)" }} className="text-xs">
              Due:{" "}
              <span
                style={{ color: "var(--text-secondary)" }}
                className="font-medium"
              >
                {formatDate(finding.due_date)}
              </span>
            </div>
            {typeof finding.days_remaining === "number" && (
              <div
                className={`text-xs ${finding.days_remaining < 0 ? "text-rose-400" : "text-emerald-400"}`}
              >
                {finding.days_remaining < 0
                  ? `${Math.abs(finding.days_remaining).toFixed(1)} days overdue`
                  : `${finding.days_remaining.toFixed(1)} days remaining`}
              </div>
            )}

            {error && (
              <div className="text-xs text-rose-400 mt-1 max-w-[200px] text-right">
                {error}
              </div>
            )}

            {/* Action buttons */}
            <div className="flex flex-col gap-2 mt-1 w-full sm:items-end">
              {/* Mark Resolved */}
              <button
                style={{
                  background: isResolved
                    ? "var(--bg-hover)"
                    : "linear-gradient(135deg, #16a34a, #15803d)",
                  border: isResolved
                    ? "1px solid var(--border)"
                    : "1px solid #16a34a",
                  color: isResolved ? "var(--text-muted)" : "#fff",
                }}
                className="inline-flex items-center gap-1.5 rounded-lg px-4 py-2 text-[13px] font-semibold disabled:opacity-50 transition-all hover:opacity-90 w-full justify-center sm:w-auto"
                disabled={savingResolved || isResolved || isFP}
                onClick={markResolved}
                title={isFP ? "Cannot resolve a false positive" : undefined}
              >
                {savingResolved ? (
                  <>
                    <SpinnerIcon /> Updating…
                  </>
                ) : (
                  <>
                    <CheckIcon /> {isResolved ? "Resolved" : "Mark as Resolved"}
                  </>
                )}
              </button>

              {/* False Positive toggle */}
              <button
                style={{
                  backgroundColor: isFP
                    ? "rgba(250,204,21,0.08)"
                    : "var(--bg-hover)",
                  border: `1px solid ${isFP ? "rgba(250,204,21,0.3)" : "var(--border)"}`,
                  color: isFP ? "#fbbf24" : "var(--text-secondary)",
                }}
                className="inline-flex items-center gap-1.5 rounded-lg px-4 py-2 text-[13px] font-semibold disabled:opacity-50 transition-all hover:opacity-90 w-full justify-center sm:w-auto"
                disabled={savingFP || isResolved}
                onClick={toggleFalsePositive}
                title={
                  isResolved
                    ? "Cannot flag a resolved finding as false positive"
                    : undefined
                }
              >
                {savingFP ? (
                  <>
                    <SpinnerIcon /> Updating…
                  </>
                ) : (
                  <>
                    <FPIcon />{" "}
                    {isFP ? "Unmark False Positive" : "Mark as False Positive"}
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Body grid */}
      <div className="grid grid-cols-1 gap-5 lg:grid-cols-3">
        {/* Main content */}
        <div className="card p-5 lg:col-span-2 space-y-5">
          <div>
            <SectionTitle>Location</SectionTitle>
            <code
              style={{
                color: "var(--text-secondary)",
                backgroundColor: "var(--bg-hover)",
                border: "1px solid var(--border)",
              }}
              className="inline-block rounded-md px-3 py-1.5 text-xs font-mono"
            >
              {finding.file_path}:{finding.line_number}
            </code>
          </div>

          <div>
            <SectionTitle>Description</SectionTitle>
            <p
              style={{ color: "var(--text-secondary)" }}
              className="text-sm leading-relaxed whitespace-pre-wrap"
            >
              {finding.description}
            </p>
          </div>

          {finding.code_snippet && (
            <div>
              <SectionTitle>Code Snippet</SectionTitle>
              <pre
                style={{
                  backgroundColor: "var(--bg-hover)",
                  border: "1px solid var(--border)",
                  color: "#c8d4f0",
                }}
                className="rounded-lg p-4 text-xs overflow-x-auto leading-relaxed font-mono"
              >
                {finding.code_snippet}
              </pre>
            </div>
          )}

          <div>
            <SectionTitle>Remediation</SectionTitle>
            <p
              style={{ color: "var(--text-secondary)" }}
              className="text-sm leading-relaxed whitespace-pre-wrap"
            >
              {finding.remediation}
            </p>
          </div>

          <div>
            <SectionTitle>Risk Score Breakdown</SectionTitle>
            <div
              className="overflow-x-auto rounded-lg"
              style={{ border: "1px solid var(--border)" }}
            >
              <table className="w-full text-sm">
                <thead>
                  <tr
                    style={{
                      borderBottom: "1px solid var(--border)",
                      backgroundColor: "var(--bg-hover)",
                    }}
                  >
                    <th
                      style={{
                        color: "var(--text-muted)",
                        letterSpacing: "0.06em",
                      }}
                      className="px-4 py-2.5 text-left text-[11px] uppercase font-medium"
                    >
                      Factor
                    </th>
                    <th
                      style={{
                        color: "var(--text-muted)",
                        letterSpacing: "0.06em",
                      }}
                      className="px-4 py-2.5 text-left text-[11px] uppercase font-medium"
                    >
                      Value
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {riskFactorRows.length === 0 ? (
                    <tr>
                      <td
                        colSpan={2}
                        style={{ color: "var(--text-muted)" }}
                        className="px-4 py-4 text-sm"
                      >
                        No risk factors available.
                      </td>
                    </tr>
                  ) : (
                    riskFactorRows.map((row) => (
                      <tr
                        key={row.key}
                        style={{ borderTop: "1px solid var(--border-subtle)" }}
                      >
                        <td
                          style={{ color: "var(--text-primary)" }}
                          className="px-4 py-2.5 font-medium text-[13px]"
                        >
                          {row.key}
                        </td>
                        <td
                          style={{ color: "var(--text-secondary)" }}
                          className="px-4 py-2.5 text-[13px] font-mono"
                        >
                          {typeof row.value === "object"
                            ? JSON.stringify(row.value)
                            : String(row.value)}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        {/* Sidebar */}
        <div className="space-y-4">
          {/* Compliance Tags */}
          <div className="card p-5">
            <SectionTitle>Compliance Tags</SectionTitle>
            <div className="flex flex-wrap gap-2">
              {(finding.compliance_tags ?? []).length === 0 ? (
                <div style={{ color: "var(--text-muted)" }} className="text-sm">
                  None
                </div>
              ) : (
                finding.compliance_tags.map((t) => (
                  <span
                    key={t}
                    className="rounded-md bg-blue-500/10 border border-blue-500/25 px-2.5 py-1 text-[12px] font-medium text-blue-400"
                  >
                    {t}
                  </span>
                ))
              )}
            </div>
          </div>

          {/* Assignment */}
          <div className="card p-5 space-y-3">
            <SectionTitle>Assignment</SectionTitle>
            {[
              finding.ci_author
                ? { label: "Author", value: finding.ci_author }
                : { label: "Assignee", value: finding.assignee },
              finding.ci_author
                ? { label: "Team", value: finding.ci_author.split("@")[0] }
                : { label: "Team", value: finding.assignee_team },
              finding.ci_short_sha && {
                label: "Commit",
                value: finding.ci_short_sha,
              },
              finding.ci_message && {
                label: "Message",
                value: finding.ci_message,
              },
              finding.ci_date && {
                label: "Date",
                value: finding.ci_date?.slice(0, 10),
              },
              !finding.ci_author &&
                finding.assignment_method && {
                  label: "Method",
                  value: finding.assignment_method,
                },
              !finding.ci_author &&
                finding.codeowners_pattern && {
                  label: "Codeowners",
                  value: finding.codeowners_pattern,
                },
            ]
              .filter(Boolean)
              .map(({ label, value }) => (
                <div key={label}>
                  <FieldLabel>{label}</FieldLabel>
                  <div
                    style={{ color: "var(--text-primary)" }}
                    className="text-[13px] font-medium"
                  >
                    {value ?? "—"}
                  </div>
                </div>
              ))}
          </div>

          {/* Metadata */}
          <div className="card p-5 space-y-3">
            <SectionTitle>Metadata</SectionTitle>
            {[
              { label: "Source", value: finding.source },
              { label: "Detected At", value: formatDate(finding.detected_at) },
              {
                label: "Sentinel Escalate",
                value: finding.sentinel_escalate ? "Yes" : "No",
              },
              {
                label: "False Positive",
                value: isFP
                  ? `Yes — ${formatDate(finding.false_positive_at)}`
                  : "No",
              },
            ].map(({ label, value }) => (
              <div key={label}>
                <FieldLabel>{label}</FieldLabel>
                <div
                  style={{
                    color:
                      label === "False Positive" && isFP
                        ? "#fbbf24"
                        : "var(--text-primary)",
                  }}
                  className="text-[13px] font-medium"
                >
                  {value ?? "—"}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
