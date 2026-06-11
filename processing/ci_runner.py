# processing/ci_runner.py
# CI entry point for GitHub Actions security scan.
# Runs the full processing pipeline on fresh scanner outputs,
# saves findings tagged with the git commit SHA, and exits
# with code 1 if any CRITICAL findings are found (blocking the PR).
#
# Usage:
#   python processing/ci_runner.py \
#     --semgrep  scanner-outputs/semgrep.json  \
#     --gitleaks scanner-outputs/gitleaks.json \
#     --trivy    scanner-outputs/trivy.json    \
#     --sha      <git-commit-sha>

import argparse
import json
import os
import sys
import tempfile

# Make sure project root is on the path regardless of working directory
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from processing.normalizer import parse_semgrep, parse_gitleaks, parse_trivy
from processing.risk_engine import run_risk_engine
from processing.ownership_engine import run_ownership_engine
from processing.sla_engine import run_sla_engine
from processing.compliance_mapper import run_compliance_mapper
from processing.storage import save_findings


def run_ci_pipeline(semgrep_path, gitleaks_path, trivy_path, commit_sha):
    """
    Run the full processing chain on fresh scanner outputs.
    Returns (findings, critical_count).
    """
    print("\n" + "=" * 55)
    print("SECUREPIPELINE HUB - CI RUNNER")
    print("=" * 55)
    print(f"Commit SHA : {commit_sha}")
    print(f"Semgrep    : {semgrep_path}")
    print(f"Gitleaks   : {gitleaks_path}")
    print(f"Trivy      : {trivy_path}")
    print("=" * 55)

    # ── Step 1: Parse scanner outputs ────────────────────────
    findings = []

    if semgrep_path and os.path.exists(semgrep_path):
        sg = parse_semgrep(semgrep_path)
        print(f"[INFO] Semgrep   : {len(sg)} findings")
        findings.extend(sg)
    else:
        print(f"[WARN] Semgrep output not found: {semgrep_path}")

    if gitleaks_path and os.path.exists(gitleaks_path):
        gl = parse_gitleaks(gitleaks_path)
        print(f"[INFO] Gitleaks  : {len(gl)} findings")
        findings.extend(gl)
    else:
        print(f"[WARN] Gitleaks output not found: {gitleaks_path}")

    if trivy_path and os.path.exists(trivy_path):
        tv = parse_trivy(trivy_path)
        print(f"[INFO] Trivy     : {len(tv)} findings")
        findings.extend(tv)
    else:
        print(f"[WARN] Trivy output not found: {trivy_path}")

    if not findings:
        print("[INFO] No findings from any scanner — nothing to process.")
        return [], 0

    print(f"[INFO] Total raw : {len(findings)}")

    # Tag every finding with the commit SHA and source context
    short_sha = commit_sha[:8] if commit_sha else "unknown"
    for f in findings:
        f['pipeline_run_id'] = f"ci_{short_sha}"
        f['target_app']      = "src"
        f['ci_commit_sha']   = commit_sha

    # ── Step 2: Run processing chain via temp files ───────────
    # Use a temp directory so we don't litter the project root
    with tempfile.TemporaryDirectory() as tmpdir:
        p_normalized = os.path.join(tmpdir, "normalized.json")
        p_scored     = os.path.join(tmpdir, "scored.json")
        p_owned      = os.path.join(tmpdir, "owned.json")
        p_sla        = os.path.join(tmpdir, "sla.json")
        p_final      = os.path.join(tmpdir, "final.json")

        with open(p_normalized, 'w') as fp:
            json.dump(findings, fp, indent=2)

        print("\n[INFO] Running risk engine...")
        run_risk_engine(p_normalized, p_scored)

        print("[INFO] Running ownership engine...")
        codeowners_path = os.path.join(PROJECT_ROOT, "CODEOWNERS")
        run_ownership_engine(p_scored, p_owned, codeowners_path)

        print("[INFO] Running SLA engine...")
        run_sla_engine(p_owned, p_sla)

        print("[INFO] Running compliance mapper...")
        run_compliance_mapper(p_sla, p_final)

        with open(p_final) as fp:
            final_findings = json.load(fp)

    # ── Step 3: Save to storage ───────────────────────────────
    run_id   = f"ci_{short_sha}"
    filepath = save_findings(final_findings, pipeline_run_id=run_id)
    print(f"\n[INFO] Saved to: {filepath}")

    # ── Step 4: Count by priority ─────────────────────────────
    by_priority = {}
    for f in final_findings:
        p = f.get('priority', 'UNKNOWN')
        by_priority[p] = by_priority.get(p, 0) + 1

    critical_count = by_priority.get('CRITICAL', 0)

    # ── Step 5: Print summary ─────────────────────────────────
    print("\n" + "=" * 55)
    print("SCAN SUMMARY")
    print("=" * 55)
    print(f"Total findings : {len(final_findings)}")
    print()
    for priority in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
        count = by_priority.get(priority, 0)
        if count:
            flag = "  <-- PR BLOCKED" if priority == 'CRITICAL' else ""
            print(f"  {priority:<10} {count}{flag}")

    print("=" * 55)

    # Write a machine-readable summary for the PR comment script
    summary_path = os.path.join(
        os.path.dirname(filepath), f"ci_summary_{short_sha}.json"
    )
    with open(summary_path, 'w') as fp:
        json.dump({
            "commit_sha":   commit_sha,
            "short_sha":    short_sha,
            "total":        len(final_findings),
            "by_priority":  by_priority,
            "findings_file": os.path.basename(filepath),
            "blocked":      critical_count > 0
        }, fp, indent=2)
    print(f"[INFO] Summary  : {summary_path}")

    return final_findings, critical_count


def main():
    parser = argparse.ArgumentParser(
        description="SecurePipeline Hub - CI runner for GitHub Actions"
    )
    parser.add_argument('--semgrep',  help="Path to Semgrep JSON output")
    parser.add_argument('--gitleaks', help="Path to Gitleaks JSON output")
    parser.add_argument('--trivy',    help="Path to Trivy JSON output")
    parser.add_argument('--sha',      default="unknown", help="Git commit SHA")
    args = parser.parse_args()

    findings, critical_count = run_ci_pipeline(
        semgrep_path  = args.semgrep,
        gitleaks_path = args.gitleaks,
        trivy_path    = args.trivy,
        commit_sha    = args.sha
    )

    if critical_count > 0:
        print(f"\n[BLOCK] {critical_count} CRITICAL finding(s) detected.")
        print("[BLOCK] Fix all CRITICAL findings and push again to unblock the PR.")
        sys.exit(1)
    else:
        print("\n[PASS] No CRITICAL findings. PR is clear to merge.")
        sys.exit(0)


if __name__ == "__main__":
    main()