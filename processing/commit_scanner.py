# processing/commit_scanner.py
# Clones a target GitHub repo, iterates its commit history,
# checks out each commit, runs the three scanners, passes
# findings through the full processing chain, and saves
# per-commit findings files.
#
# Used by:
#   - GitHub Actions workflow (new commits only)
#   - backfill_commits.py (full history)
#
# Usage:
#   python processing/commit_scanner.py --sha <commit-sha>
#   python processing/commit_scanner.py --sha <commit-sha> --repo-dir /path/to/cloned/repo

import argparse
import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from processing.normalizer import parse_semgrep, parse_gitleaks, parse_trivy
from processing.risk_engine import run_risk_engine
from processing.ownership_engine import run_ownership_engine
from processing.sla_engine import run_sla_engine
from processing.compliance_mapper import run_compliance_mapper
from processing.storage import save_findings, get_storage_dir


def run_cmd(cmd, cwd=None, check=True):
    """Run a shell command, return (stdout, returncode)."""
    result = subprocess.run(
        cmd, shell=True, cwd=cwd,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True
    )
    if check and result.returncode != 0:
        print(f"[WARN] Command failed: {cmd}")
        print(f"       stderr: {result.stderr[:300]}")
    return result.stdout.strip(), result.returncode


def get_commit_metadata(repo_dir, sha):
    """Extract author, date, and message for a given commit SHA."""
    fmt = "%H|%ae|%ai|%s"
    out, _ = run_cmd(f'git log -1 --format="{fmt}" {sha}', cwd=repo_dir, check=False)
    out = out.strip('"')
    parts = out.split("|", 3)
    if len(parts) == 4:
        return {
            "sha":     parts[0],
            "author":  parts[1],
            "date":    parts[2],
            "message": parts[3]
        }
    return {"sha": sha, "author": "unknown", "date": "", "message": ""}


def already_scanned(sha):
    """Return True if findings_ci_<sha[:8]>.json already exists in storage."""
    short = sha[:8]
    storage_dir = get_storage_dir()
    return os.path.exists(os.path.join(storage_dir, f"findings_ci_{short}.json"))


def scan_commit(sha, repo_dir, codeowners_path=None):
    """
    Checkout repo_dir at `sha`, run all three scanners,
    run the full pipeline, save findings.
    Returns (findings, critical_count) or ([], 0) on failure.
    """
    short = sha[:8]
    print(f"\n{'─'*55}")
    print(f"Scanning commit {short}")

    # Get commit metadata before checkout
    meta = get_commit_metadata(repo_dir, sha)
    print(f"  Author  : {meta['author']}")
    print(f"  Date    : {meta['date']}")
    print(f"  Message : {meta['message'][:60]}")

    # Checkout this commit (detached HEAD)
    _, rc = run_cmd(f"git checkout {sha} --quiet", cwd=repo_dir, check=False)
    if rc != 0:
        print(f"[ERROR] Could not checkout {short} — skipping")
        return [], 0

    with tempfile.TemporaryDirectory() as tmpdir:
        sg_out  = os.path.join(tmpdir, "semgrep.json")
        gl_out  = os.path.join(tmpdir, "gitleaks.json")
        tv_out  = os.path.join(tmpdir, "trivy.json")

        # ── Semgrep ──────────────────────────────────────────
        print(f"  [1/3] Semgrep...")
        run_cmd(
            f"semgrep scan . "
            f"--config p/python --config p/secrets --config p/owasp-top-ten "
            f"--json --output {sg_out} --quiet",
            cwd=repo_dir, check=False
        )

        # ── Gitleaks ─────────────────────────────────────────
        # Run in git-history mode (not working-directory mode) so that
        # secrets committed in older commits and later "deleted" are still
        # caught. --log-opts restricts the scan to commits reachable from
        # HEAD that are not older than 90 days, keeping CI fast while
        # covering the realistic window of exposure. Remove --since if you
        # want a full history scan (slower on large repos).
        print(f"  [2/3] Gitleaks (full history)...")
        gl_config = os.path.join(PROJECT_ROOT, "scanners", "gitleaks.toml")
        gl_config_flag = f"--config {gl_config}" if os.path.exists(gl_config) else ""
        history_days = int(os.environ.get('GITLEAKS_HISTORY_DAYS', '90'))
        run_cmd(
            f'gitleaks detect --source . {gl_config_flag} '
            f'--log-opts="--since={history_days}.days.ago --all" '
            f'--report-format json --report-path {gl_out} --exit-code 0',
            cwd=repo_dir, check=False
        )
        print(f"       (scanned git history: last {history_days} days)")

        # ── Trivy ────────────────────────────────────────────
        print(f"  [3/3] Trivy...")
        run_cmd(
            f"trivy fs . --format json --output {tv_out} --quiet",
            cwd=repo_dir, check=False
        )

        # ── Parse scanner outputs ─────────────────────────────
        findings = []
        for parser, path, name in [
            (parse_semgrep,  sg_out, "semgrep"),
            (parse_gitleaks, gl_out, "gitleaks"),
            (parse_trivy,    tv_out, "trivy"),
        ]:
            if os.path.exists(path):
                parsed = parser(path)
                print(f"       {name}: {len(parsed)} findings")
                findings.extend(parsed)
            else:
                print(f"       {name}: no output")

        if not findings:
            print(f"  [INFO] No findings at {short}")
            return [], 0

        # ── Tag every finding with commit metadata ────────────
        for f in findings:
            f['pipeline_run_id'] = f"ci_{short}"
            f['ci_commit_sha']   = sha
            f['ci_short_sha']    = short
            f['ci_author']       = meta['author']
            f['ci_date']         = meta['date']
            f['ci_message']      = meta['message']
            # commit_introduced is populated by parse_gitleaks from the
            # "Commit" field in Gitleaks history-mode output. For non-
            # Gitleaks findings it stays None (set in normalizer).
            # Do not overwrite if already set by the parser.
            f.setdefault('commit_introduced', None)

        # ── Run processing chain ──────────────────────────────
        p_normalized = os.path.join(tmpdir, "normalized.json")
        p_scored     = os.path.join(tmpdir, "scored.json")
        p_owned      = os.path.join(tmpdir, "owned.json")
        p_sla        = os.path.join(tmpdir, "sla.json")
        p_final      = os.path.join(tmpdir, "final.json")

        with open(p_normalized, 'w') as fp:
            json.dump(findings, fp, indent=2)

        co_path = codeowners_path or os.path.join(PROJECT_ROOT, "CODEOWNERS")
        run_risk_engine(p_normalized, p_scored)
        run_ownership_engine(p_scored, p_owned, co_path)
        run_sla_engine(p_owned, p_sla)
        run_compliance_mapper(p_sla, p_final)

        with open(p_final) as fp:
            final_findings = json.load(fp)

        # ── Override assignee with commit author ──────────────
        # The ownership engine uses CODEOWNERS/gitblame which gives
        # generic results. For CI findings, the commit author is the
        # person who actually introduced the code, so use them instead.
        commit_author  = meta['author']
        commit_team    = commit_author.split('@')[0] if '@' in commit_author else commit_author
        for f in final_findings:
            if f.get('ci_author'):
                f['assignee']          = commit_author
                f['assignee_team']     = commit_team
                f['assignment_method'] = 'commit_author'

        # ── Save ─────────────────────────────────────────────
        run_id   = f"ci_{short}"
        filepath = save_findings(final_findings, pipeline_run_id=run_id)

        by_priority = {}
        for f in final_findings:
            p = f.get('priority', 'UNKNOWN')
            by_priority[p] = by_priority.get(p, 0) + 1

        critical = by_priority.get('CRITICAL', 0)
        print(f"  Saved  : {os.path.basename(filepath)}")
        print(f"  Total  : {len(final_findings)} "
              f"(C:{by_priority.get('CRITICAL',0)} "
              f"H:{by_priority.get('HIGH',0)} "
              f"M:{by_priority.get('MEDIUM',0)} "
              f"L:{by_priority.get('LOW',0)})")

        # Write summary for PR comments
        summary_path = os.path.join(
            get_storage_dir(), f"ci_summary_{short}.json"
        )
        with open(summary_path, 'w') as fp:
            json.dump({
                "commit_sha":    sha,
                "short_sha":     short,
                "author":        meta['author'],
                "date":          meta['date'],
                "message":       meta['message'],
                "total":         len(final_findings),
                "by_priority":   by_priority,
                "findings_file": os.path.basename(filepath),
                "blocked":       critical > 0
            }, fp, indent=2)

        return final_findings, critical


def clone_or_update_repo(repo_url, clone_dir):
    """Clone repo_url into clone_dir, or pull if it already exists."""
    if os.path.exists(os.path.join(clone_dir, ".git")):
        print(f"[INFO] Updating existing clone at {clone_dir}")
        run_cmd("git fetch --all --quiet", cwd=clone_dir, check=False)
    else:
        # Mask the PAT in logs so it never prints to console
        safe_url = repo_url
        if "@" in repo_url:
            parts = repo_url.split("@")
            safe_url = parts[0].split("//")[0] + "//<PAT_REDACTED>@" + parts[1]
        print(f"[INFO] Cloning {safe_url} into {clone_dir}")
        os.makedirs(clone_dir, exist_ok=True)

        result = subprocess.run(
            f'git clone "{repo_url}" "{clone_dir}"',
            shell=True, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        if result.returncode != 0:
            print(f"[ERROR] Failed to clone repository.")
            print(f"[ERROR] Git said: {result.stderr.strip()}")
            print()
            print("Common causes:")
            print("  1. PAT is wrong or expired — regenerate at github.com/settings/tokens")
            print("  2. Repo URL is wrong — check TARGET_REPO_URL in .env")
            print("  3. PAT does not have 'repo' scope for private repos")
            print("  4. Repo name has a typo")
            sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Scan a single commit from the target repo"
    )
    parser.add_argument('--sha',      required=True, help="Commit SHA to scan")
    parser.add_argument('--repo-dir', help="Path to already-cloned repo (skips clone)")
    args = parser.parse_args()

    # Load env
    from dotenv import load_dotenv
    load_dotenv(os.path.join(PROJECT_ROOT, '.env'))

    repo_url  = os.environ.get('TARGET_REPO_URL', '')
    clone_dir = os.path.join(PROJECT_ROOT, '.repo_cache')

    if args.repo_dir:
        repo_dir = args.repo_dir
    else:
        if not repo_url:
            print("[ERROR] TARGET_REPO_URL not set in .env")
            sys.exit(1)
        clone_or_update_repo(repo_url, clone_dir)
        repo_dir = clone_dir

    findings, critical = scan_commit(args.sha, repo_dir)

    # Restore repo to HEAD after scanning
    run_cmd("git checkout main --quiet || git checkout master --quiet",
            cwd=repo_dir, check=False)

    if critical > 0:
        print(f"\n[BLOCK] {critical} CRITICAL finding(s) in {args.sha[:8]}")
        sys.exit(1)
    else:
        print(f"\n[PASS] No CRITICAL findings in {args.sha[:8]}")
        sys.exit(0)


if __name__ == "__main__":
    main()