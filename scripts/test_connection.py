# scripts/test_connection.py
# Tests the connection to the target repo and lists commits.
# Run this before the full backfill to verify everything is set up correctly.
#
# Usage:
#   python scripts/test_connection.py

import os
import sys
import subprocess

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)


def run(cmd, cwd=None):
    result = subprocess.run(
        cmd, shell=True, cwd=cwd,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    return result.stdout.strip(), result.stderr.strip(), result.returncode


def main():
    # ── Load .env ─────────────────────────────────────────────
    try:
        from dotenv import load_dotenv
        load_dotenv(os.path.join(PROJECT_ROOT, '.env'))
    except ImportError:
        print("[WARN] python-dotenv not installed — reading .env manually")
        env_path = os.path.join(PROJECT_ROOT, '.env')
        if os.path.exists(env_path):
            with open(env_path) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        k, v = line.split('=', 1)
                        os.environ[k.strip()] = v.strip()

    repo_url = os.environ.get('TARGET_REPO_URL', '')
    limit    = int(os.environ.get('BACKFILL_LIMIT', '50'))

    print("=" * 55)
    print("SECUREPIPELINE HUB — CONNECTION TEST")
    print("=" * 55)

    # ── Check .env ────────────────────────────────────────────
    if not repo_url:
        print("[ERROR] TARGET_REPO_URL is not set in your .env file")
        print("        Add: TARGET_REPO_URL=https://<PAT>@github.com/user/repo.git")
        sys.exit(1)

    safe_url = repo_url
    if "@" in repo_url:
        parts    = repo_url.split("@")
        safe_url = parts[0].split("//")[0] + "//<PAT_REDACTED>@" + parts[1]

    print(f"Target repo  : {safe_url}")
    print(f"Backfill limit: {limit} commits")
    print()

    # ── Check scanners are installed ──────────────────────────
    print("Checking scanners...")
    scanners = {
        "semgrep":  "semgrep --version",
        "gitleaks": "gitleaks version",
        "trivy":    "trivy --version",
    }
    all_ok = True
    for name, cmd in scanners.items():
        out, err, rc = run(cmd)
        if rc == 0:
            version = out.splitlines()[0] if out else "ok"
            print(f"  {name:<12} installed ({version})")
        else:
            print(f"  {name:<12} NOT FOUND — install before running backfill")
            all_ok = False

    if not all_ok:
        print()
        print("[WARN] Some scanners are missing. The backfill will skip their outputs.")
        print("       Install guides:")
        print("         semgrep  : pip install semgrep")
        print("         gitleaks : https://github.com/gitleaks/gitleaks/releases")
        print("         trivy    : https://aquasecurity.github.io/trivy/latest/getting-started/installation/")

    print()

    # ── Clone or update repo ──────────────────────────────────
    clone_dir = os.path.join(PROJECT_ROOT, '.repo_cache')
    if os.path.exists(os.path.join(clone_dir, '.git')):
        print(f"Repo already cloned at .repo_cache — fetching latest...")
        out, err, rc = run("git fetch --all --quiet", cwd=clone_dir)
        if rc != 0:
            print(f"[ERROR] git fetch failed: {err}")
            sys.exit(1)
        print("Fetch complete.")
    else:
        print(f"Cloning repository...")
        out, err, rc = run(f'git clone "{repo_url}" "{clone_dir}" --quiet')
        if rc != 0:
            print(f"[ERROR] Clone failed: {err}")
            print()
            print("Common causes:")
            print("  - PAT is wrong or expired")
            print("  - PAT is missing 'repo' scope (for private repos)")
            print("  - Repo URL has a typo")
            sys.exit(1)
        print("Clone successful.")

    print()

    # ── Show repo info ────────────────────────────────────────
    name_out, _, _ = run("git remote get-url origin", cwd=clone_dir)
    branch_out, _, _ = run("git branch -r", cwd=clone_dir)
    total_out, _, _ = run("git log --oneline | wc -l", cwd=clone_dir)

    print(f"Repository info:")
    print(f"  Remote branches:")
    for b in branch_out.splitlines():
        print(f"    {b.strip()}")
    print(f"  Total commits : {total_out.strip()}")
    print()

    # ── List commits ──────────────────────────────────────────
    print(f"Last {limit} commits (newest first):")
    print(f"{'─'*55}")

    log_out, _, _ = run(
        f'git log -n {limit} --format="%H|%ae|%ai|%s"',
        cwd=clone_dir
    )

    from processing.storage import get_storage_dir, load_all_findings
    storage_dir = get_storage_dir()

    already_scanned = set()
    for fname in os.listdir(storage_dir):
        if fname.startswith('findings_ci_') and fname.endswith('.json'):
            short = fname.replace('findings_ci_', '').replace('.json', '')
            already_scanned.add(short)

    commits = []
    for line in log_out.splitlines():
        parts = line.strip().split('|', 3)
        if len(parts) == 4:
            commits.append({
                'sha':     parts[0],
                'short':   parts[0][:8],
                'author':  parts[1],
                'date':    parts[2][:10],
                'message': parts[3]
            })

    for c in commits:
        scanned = "already scanned" if c['short'] in already_scanned else "not yet scanned"
        status  = "✓" if c['short'] in already_scanned else "○"
        msg     = c['message'][:45] + "…" if len(c['message']) > 45 else c['message']
        print(f"  {status} {c['short']}  {c['date']}  {msg}")
        print(f"              {c['author']}  [{scanned}]")

    print(f"{'─'*55}")
    to_scan = len([c for c in commits if c['short'] not in already_scanned])
    print(f"\nSummary:")
    print(f"  Total commits shown : {len(commits)}")
    print(f"  Already scanned     : {len(commits) - to_scan}")
    print(f"  Will be scanned     : {to_scan}")
    print()
    print("If this looks correct, run:")
    print(f"  python processing/backfill_commits.py --limit {limit}")
    print("=" * 55)


if __name__ == "__main__":
    main()