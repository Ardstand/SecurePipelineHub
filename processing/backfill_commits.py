# processing/backfill_commits.py
# Scans the full commit history of the target repo.
# Idempotent — skips commits that already have findings files.
# Run this once to populate historical data, then let CI
# handle new commits going forward.
#
# Usage:
#   python processing/backfill_commits.py
#   python processing/backfill_commits.py --limit 20
#   python processing/backfill_commits.py --limit 0   # all commits

import argparse
import os
import sys
import subprocess

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from processing.commit_scanner import (
    clone_or_update_repo,
    scan_commit,
    already_scanned,
    run_cmd
)


def get_all_commits(repo_dir, limit=50):
    """Return list of commit SHAs, newest first."""
    limit_flag = f"-n {limit}" if limit and limit > 0 else ""
    out, _ = run_cmd(
        f"git log {limit_flag} --format=%H",
        cwd=repo_dir, check=False
    )
    return [sha.strip() for sha in out.splitlines() if sha.strip()]


def main():
    parser = argparse.ArgumentParser(
        description="Backfill security findings for all commits in target repo"
    )
    parser.add_argument(
        '--limit', type=int, default=None,
        help="Max commits to scan (default: use BACKFILL_LIMIT from .env, or 50)"
    )
    parser.add_argument(
        '--force', action='store_true',
        help="Re-scan commits that already have findings files"
    )
    parser.add_argument(
        '--repo-dir',
        help="Path to already-cloned repo (skips clone step)"
    )
    args = parser.parse_args()

    # Load env
    from dotenv import load_dotenv
    load_dotenv(os.path.join(PROJECT_ROOT, '.env'))

    repo_url  = os.environ.get('TARGET_REPO_URL', '')
    clone_dir = os.path.join(PROJECT_ROOT, '.repo_cache')

    # Resolve limit: CLI arg > .env > default 50
    if args.limit is not None:
        limit = args.limit
    else:
        env_limit = os.environ.get('BACKFILL_LIMIT', '50')
        limit = int(env_limit) if env_limit else 50

    if args.repo_dir:
        repo_dir = args.repo_dir
    else:
        if not repo_url:
            print("[ERROR] TARGET_REPO_URL not set in .env")
            sys.exit(1)
        clone_or_update_repo(repo_url, clone_dir)
        repo_dir = clone_dir

    # Get commit list
    commits = get_all_commits(repo_dir, limit=limit)
    if not commits:
        print("[ERROR] No commits found in repo")
        sys.exit(1)

    limit_label = f"(limit: {limit})" if limit else "(all commits)"
    print(f"\n{'='*55}")
    print(f"SECUREPIPELINE HUB - BACKFILL")
    print(f"{'='*55}")
    print(f"Repo      : {repo_url or repo_dir}")
    print(f"Commits   : {len(commits)} {limit_label}")
    print(f"Force     : {args.force}")
    print(f"{'='*55}")

    skipped  = 0
    scanned  = 0
    errors   = 0
    blocked  = []

    for i, sha in enumerate(commits, 1):
        short = sha[:8]
        print(f"\n[{i}/{len(commits)}] {short}")

        if not args.force and already_scanned(sha):
            print(f"  Already scanned — skipping (use --force to re-scan)")
            skipped += 1
            continue

        try:
            findings, critical = scan_commit(sha, repo_dir)
            scanned += 1
            if critical > 0:
                blocked.append(short)
        except Exception as e:
            print(f"  [ERROR] Exception scanning {short}: {e}")
            errors += 1

    # Restore repo to HEAD
    run_cmd(
        "git checkout main --quiet || git checkout master --quiet",
        cwd=repo_dir, check=False
    )

    print(f"\n{'='*55}")
    print(f"BACKFILL COMPLETE")
    print(f"{'='*55}")
    print(f"Scanned  : {scanned}")
    print(f"Skipped  : {skipped} (already done)")
    print(f"Errors   : {errors}")
    if blocked:
        print(f"Blocked  : {len(blocked)} commits had CRITICAL findings")
        for sha in blocked:
            print(f"           {sha}")
    print(f"{'='*55}")
    print(f"Run 'git pull' on your server and restart Flask to see results.")


if __name__ == "__main__":
    main()