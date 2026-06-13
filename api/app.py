# api/app.py
# SecurePipeline Hub - Flask REST API
# Serves enriched findings to the React dashboard

from flask import Flask, jsonify, request
from flask_cors import CORS
import json
import os
import sys
import subprocess
import threading
import time
from datetime import datetime, timezone

# Add project root to path so we can import storage module
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from processing.storage import (
    query_findings,
    get_stats,
    get_compliance_status,
    load_all_findings,
    save_findings
)

app = Flask(__name__)
CORS(app)


# ─────────────────────────────────────────────
# HELPER
# ─────────────────────────────────────────────

def success(data, status=200):
    return jsonify({"status": "success", "data": data}), status


def error(message, status=400):
    return jsonify({"status": "error", "message": message}), status


def find_and_save(finding_id, mutate_fn):
    all_findings = load_all_findings()
    updated = None
    for f in all_findings:
        if f.get('id') == finding_id:
            mutate_fn(f)
            updated = f
            break
    if not updated:
        return None, f"Finding {finding_id} not found"
    run_id = f"update_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"
    save_findings(all_findings, run_id)
    return updated, None


# ─────────────────────────────────────────────
# GIT POLLER
# Runs in a background thread. Every POLL_INTERVAL
# seconds it checks if the remote has new commits.
# If so, runs git pull so new findings files land
# on disk immediately — no Flask restart needed.
# ─────────────────────────────────────────────

POLL_INTERVAL = int(os.environ.get('POLL_INTERVAL', 60))  # seconds
PROJECT_ROOT  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Shared state — read by /api/sync-status
_poller_state = {
    "last_checked":   None,   # ISO string
    "last_pulled":    None,   # ISO string of most recent pull
    "last_commit":    None,   # SHA of latest local commit
    "status":         "idle", # idle | pulling | up_to_date | updated | error
    "message":        "",
    "pull_count":     0,
}
_poller_lock = threading.Lock()


def _run(cmd, cwd=None):
    result = subprocess.run(
        cmd, shell=True, cwd=cwd,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    return result.stdout.strip(), result.stderr.strip(), result.returncode


def _get_local_sha():
    out, _, _ = _run("git rev-parse HEAD", cwd=PROJECT_ROOT)
    return out


def _get_remote_sha():
    _run("git fetch origin main --quiet", cwd=PROJECT_ROOT)
    out, _, _ = _run("git rev-parse origin/main", cwd=PROJECT_ROOT)
    return out


def _do_pull():
    out, err, rc = _run("git pull origin main --quiet", cwd=PROJECT_ROOT)
    return rc == 0, err


def _poll_loop():
    print(f"[Poller] Started — checking for new commits every {POLL_INTERVAL}s")
    # Track the last SHA we successfully pulled to, so we don't re-detect
    # the same commit as new on the next iteration.
    _last_pulled_sha = None

    while True:
        try:
            now = datetime.now(timezone.utc).isoformat()
            local_sha  = _get_local_sha()
            remote_sha = _get_remote_sha()

            with _poller_lock:
                _poller_state["last_checked"] = now
                _poller_state["last_commit"]  = local_sha[:8] if local_sha else None

            # Only pull if remote differs from local AND we haven't already
            # successfully pulled this exact SHA (prevents re-pulling on
            # Windows where HEAD may lag behind one cycle after a pull)
            already_done = (_last_pulled_sha is not None and
                            remote_sha and
                            remote_sha.startswith(_last_pulled_sha))

            if local_sha and remote_sha and local_sha != remote_sha and not already_done:
                print(f"[Poller] New commit detected: {remote_sha[:8]} — pulling...")

                with _poller_lock:
                    _poller_state["status"] = "pulling"

                ok, err_msg = _do_pull()

                # Re-read local SHA after pull to confirm HEAD moved
                new_local_sha = _get_local_sha()

                with _poller_lock:
                    if ok and new_local_sha == remote_sha:
                        _last_pulled_sha = remote_sha
                        _poller_state["status"]      = "updated"
                        _poller_state["last_pulled"] = now
                        _poller_state["last_commit"] = remote_sha[:8]
                        _poller_state["pull_count"] += 1
                        _poller_state["message"]     = f"Pulled {remote_sha[:8]}"
                        print(f"[Poller] Pull successful — {remote_sha[:8]}")
                    elif ok and new_local_sha != remote_sha:
                        # Pull claimed success but HEAD didn't move —
                        # likely a dirty working tree or merge conflict
                        _poller_state["status"]  = "error"
                        _poller_state["message"] = "Pull succeeded but HEAD did not advance. Check for uncommitted local changes."
                        print(f"[Poller] Pull did not advance HEAD — possible dirty working tree")
                    else:
                        _poller_state["status"]  = "error"
                        _poller_state["message"] = err_msg[:200]
                        print(f"[Poller] Pull failed: {err_msg[:200]}")
            else:
                with _poller_lock:
                    _poller_state["status"]  = "up_to_date"
                    _poller_state["message"] = ""

        except Exception as e:
            with _poller_lock:
                _poller_state["status"]  = "error"
                _poller_state["message"] = str(e)[:200]
            print(f"[Poller] Error: {e}")

        time.sleep(POLL_INTERVAL)


# Start background poller thread when Flask starts
# (not during testing or reloader child process)
if os.environ.get('WERKZEUG_RUN_MAIN') != 'false':
    _poller_thread = threading.Thread(target=_poll_loop, daemon=True)
    _poller_thread.start()


# ─────────────────────────────────────────────
# GET /api/sync-status
# Returns current poller state so the dashboard
# knows when new findings have landed.
# ─────────────────────────────────────────────

@app.route('/api/sync-status', methods=['GET'])
def sync_status():
    with _poller_lock:
        state = dict(_poller_state)
    return success(state)


# ─────────────────────────────────────────────
# POST /api/sync-now
# Manually triggers an immediate git pull.
# Useful for testing without waiting 60s.
# ─────────────────────────────────────────────

@app.route('/api/sync-now', methods=['POST'])
def sync_now():
    try:
        now = datetime.now(timezone.utc).isoformat()
        local_sha  = _get_local_sha()
        remote_sha = _get_remote_sha()

        if local_sha == remote_sha:
            return success({
                "pulled":  False,
                "message": "Already up to date",
                "commit":  local_sha[:8] if local_sha else None
            })

        ok, err_msg = _do_pull()
        if ok:
            new_sha = _get_local_sha()
            with _poller_lock:
                _poller_state["status"]      = "updated"
                _poller_state["last_pulled"] = now
                _poller_state["last_commit"] = new_sha[:8] if new_sha else None
                _poller_state["pull_count"] += 1
                _poller_state["message"]     = f"Manually pulled {new_sha[:8] if new_sha else ''}"
            return success({
                "pulled":  True,
                "message": f"Pulled new commit {new_sha[:8] if new_sha else ''}",
                "commit":  new_sha[:8] if new_sha else None
            })
        else:
            return error(f"git pull failed: {err_msg}", 500)

    except Exception as e:
        return error(str(e), 500)


# ─────────────────────────────────────────────
# GET /api/findings
# ─────────────────────────────────────────────

@app.route('/api/findings', methods=['GET'])
def get_findings():
    try:
        severity       = request.args.get('severity')
        source         = request.args.get('source')
        priority       = request.args.get('priority')
        assignee       = request.args.get('assignee')
        sla_status     = request.args.get('sla_status')
        compliance_tag = request.args.get('compliance_tag')
        show_fp        = request.args.get('show_false_positives', 'false').lower() == 'true'
        limit          = int(request.args.get('limit', 100))
        offset         = int(request.args.get('offset', 0))

        if compliance_tag:
            all_matching, _ = query_findings(
                severity=severity,
                source=source,
                priority=None,
                assignee=assignee,
                sla_status=sla_status,
                include_false_positives=show_fp,
                limit=100_000,
                offset=0
            )
            filtered = [
                f for f in all_matching
                if compliance_tag in (f.get('compliance_tags') or [])
            ]
            if priority:
                filtered = [
                    f for f in filtered
                    if (f.get('priority') or '').upper() == priority.upper()
                ]
            total    = len(filtered)
            findings = filtered[offset: offset + limit]
        else:
            findings, total = query_findings(
                severity=severity,
                source=source,
                priority=priority,
                assignee=assignee,
                sla_status=sla_status,
                include_false_positives=show_fp,
                limit=limit,
                offset=offset
            )

        return success({
            "findings": findings,
            "total":    total,
            "limit":    limit,
            "offset":   offset,
            "returned": len(findings)
        })

    except Exception as e:
        return error(str(e), 500)


# ─────────────────────────────────────────────
# GET /api/findings/<id>
# ─────────────────────────────────────────────

@app.route('/api/findings/<finding_id>', methods=['GET'])
def get_finding(finding_id):
    try:
        all_findings = load_all_findings()
        finding = next(
            (f for f in all_findings if f.get('id') == finding_id),
            None
        )
        if not finding:
            return error(f"Finding {finding_id} not found", 404)
        return success(finding)
    except Exception as e:
        return error(str(e), 500)


# ─────────────────────────────────────────────
# PATCH /api/findings/<id>
# ─────────────────────────────────────────────

@app.route('/api/findings/<finding_id>', methods=['PATCH'])
def update_finding(finding_id):
    try:
        body = request.get_json()
        if not body:
            return error("Request body required")

        allowed_fields = {'sla_status', 'false_positive'}
        unknown = set(body.keys()) - allowed_fields
        if unknown:
            return error(f"Unknown fields: {list(unknown)}. Allowed: {list(allowed_fields)}")

        if 'sla_status' in body:
            new_status = body['sla_status'].upper()
            valid_statuses = ['OPEN', 'WARNING', 'OVERDUE', 'RESOLVED']
            if new_status not in valid_statuses:
                return error(f"sla_status must be one of: {valid_statuses}")

        if 'false_positive' in body:
            if not isinstance(body['false_positive'], bool):
                return error("false_positive must be a boolean (true or false)")

        def mutate(f):
            now = datetime.now(timezone.utc).isoformat()
            if 'sla_status' in body:
                f['sla_status'] = body['sla_status'].upper()
                if f['sla_status'] == 'RESOLVED':
                    f['resolved_at'] = now
            if 'false_positive' in body:
                f['false_positive'] = body['false_positive']
                if body['false_positive']:
                    f['false_positive_at'] = now
                else:
                    f.pop('false_positive_at', None)

        updated, err = find_and_save(finding_id, mutate)
        if err:
            return error(err, 404)
        return success(updated)

    except Exception as e:
        return error(str(e), 500)


# ─────────────────────────────────────────────
# POST /api/findings/<id>/comments
# ─────────────────────────────────────────────

@app.route('/api/findings/<finding_id>/comments', methods=['POST'])
def add_comment(finding_id):
    try:
        import uuid as uuid_lib
        body = request.get_json()
        if not body:
            return error("Request body required")

        text   = (body.get('text')   or '').strip()
        author = (body.get('author') or '').strip()
        if not text:
            return error("Comment text is required")
        if not author:
            return error("Author is required")
        if len(text) > 2000:
            return error("Comment must be 2000 characters or fewer")

        new_comment = {
            "id":         str(uuid_lib.uuid4()),
            "text":       text,
            "author":     author,
            "created_at": datetime.now(timezone.utc).isoformat()
        }

        def mutate(f):
            if not isinstance(f.get('comments'), list):
                f['comments'] = []
            f['comments'].append(new_comment)

        updated, err = find_and_save(finding_id, mutate)
        if err:
            return error(err, 404)
        return success(new_comment, 201)

    except Exception as e:
        return error(str(e), 500)


# ─────────────────────────────────────────────
# GET /api/stats
# ─────────────────────────────────────────────

@app.route('/api/stats', methods=['GET'])
def get_statistics():
    try:
        stats = get_stats()
        return success(stats)
    except Exception as e:
        return error(str(e), 500)


# ─────────────────────────────────────────────
# GET /api/compliance
# ─────────────────────────────────────────────

@app.route('/api/compliance', methods=['GET'])
def get_compliance():
    try:
        compliance = get_compliance_status()
        covered = sum(1 for c in compliance if c['status'] == 'FINDINGS_PRESENT')
        return success({
            "categories":   compliance,
            "covered":      covered,
            "total":        10,
            "coverage_pct": round((covered / 10) * 100, 1)
        })
    except Exception as e:
        return error(str(e), 500)


# ─────────────────────────────────────────────
# GET /api/trends
# ─────────────────────────────────────────────

@app.route('/api/trends', methods=['GET'])
def get_trends():
    try:
        days         = int(request.args.get('days', 30))
        all_findings = load_all_findings()

        from datetime import timedelta
        now   = datetime.now(timezone.utc)
        daily = {}

        for i in range(days):
            day = (now - timedelta(days=i)).strftime('%Y-%m-%d')
            daily[day] = {"date": day, "total": 0,
                          "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

        for f in all_findings:
            if f.get('false_positive', False):
                continue
            detected = f.get('detected_at', '')
            if not detected:
                continue
            try:
                dt  = datetime.fromisoformat(detected.replace('Z', '+00:00'))
                day = dt.strftime('%Y-%m-%d')
                if day in daily:
                    daily[day]['total'] += 1
                    priority = f.get('priority', 'INFO')
                    if priority in daily[day]:
                        daily[day][priority] += 1
            except Exception:
                continue

        trend_list = sorted(daily.values(), key=lambda x: x['date'])
        return success({"trends": trend_list, "days": days})

    except Exception as e:
        return error(str(e), 500)


# ─────────────────────────────────────────────
# GET /api/health
# ─────────────────────────────────────────────

@app.route('/api/health', methods=['GET'])
def health():
    all_findings = load_all_findings()
    with _poller_lock:
        poller = dict(_poller_state)
    return success({
        "status":              "healthy",
        "findings_in_storage": len(all_findings),
        "version":             "1.0.0",
        "poller":              poller
    })


# ─────────────────────────────────────────────
# ROOT
# ─────────────────────────────────────────────

@app.route('/', methods=['GET'])
def root():
    return success({
        "name":    "SecurePipeline Hub API",
        "version": "1.0.0",
        "endpoints": [
            "GET  /api/health",
            "GET  /api/sync-status",
            "POST /api/sync-now",
            "GET  /api/findings",
            "GET  /api/findings/<id>",
            "PATCH /api/findings/<id>",
            "POST /api/findings/<id>/comments",
            "GET  /api/stats",
            "GET  /api/compliance",
            "GET  /api/trends"
        ]
    })


if __name__ == '__main__':
    print("=" * 50)
    print("SecurePipeline Hub - Flask API")
    print("=" * 50)
    print(f"Running at: http://localhost:5000")
    print(f"Git poller: every {POLL_INTERVAL}s (set POLL_INTERVAL env var to change)")
    print("=" * 50)
    app.run(debug=True, host='0.0.0.0', port=5000)