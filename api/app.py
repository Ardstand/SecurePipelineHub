# api/app.py
# SecurePipeline Hub - Flask REST API
# Serves enriched findings to the React dashboard

from flask import Flask, jsonify, request, g
from flask_cors import CORS
import json
import os
import sys
import sqlite3
import subprocess
import threading
import time
from datetime import datetime, timezone
from functools import wraps

from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from werkzeug.security import check_password_hash, generate_password_hash

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
# AUTH + USER MANAGEMENT
# Uses SQLite, salted password hashes, and admin-only user signup.

AUTH_DB_PATH = os.environ.get(
    'AUTH_DB_PATH',
    os.path.join(os.path.dirname(__file__), 'auth.db')
)
SECRET_KEY = os.environ.get('SECRET_KEY', 'change-me-in-production')
TOKEN_EXPIRATION_SECONDS = int(os.environ.get('AUTH_TOKEN_EXPIRATION', 3600 * 8))
TOKEN_SALT = 'securepipeline-auth-token'

auth_serializer = URLSafeTimedSerializer(SECRET_KEY, salt=TOKEN_SALT)


def get_db_connection():
    conn = sqlite3.connect(AUTH_DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            '''CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                github_email TEXT,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL,
                created_at TEXT NOT NULL
            )'''
        )
        conn.commit()
    finally:
        conn.close()


def get_user_by_email(email):
    if not email:
        return None
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE email = ?', (email.lower(),))
        row = cursor.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def get_user_by_github_email(github_email):
    if not github_email:
        return None
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE github_email = ?', (github_email.lower(),))
        row = cursor.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def count_users():
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(1) AS count FROM users')
        row = cursor.fetchone()
        return row['count'] if row else 0
    finally:
        conn.close()


def create_user(email, github_email, password, role='user'):
    if not email or not password:
        raise ValueError('Email and password are required')
    normalized_email = email.strip().lower()
    normalized_github_email = (github_email or '').strip().lower() or None
    if get_user_by_email(normalized_email):
        raise ValueError('A user with that email already exists')
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO users (email, github_email, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)',
            (
                normalized_email,
                normalized_github_email,
                generate_password_hash(password),
                role,
                datetime.now(timezone.utc).isoformat(),
            )
        )
        conn.commit()
        user_id = cursor.lastrowid
        return get_user_by_email(normalized_email)
    finally:
        conn.close()


def verify_auth_token(token):
    if not token:
        return None
    try:
        payload = auth_serializer.loads(token, max_age=TOKEN_EXPIRATION_SECONDS)
        return get_user_by_email(payload.get('email'))
    except (BadSignature, SignatureExpired):
        return None


def generate_auth_token(user):
    return auth_serializer.dumps({
        'id': user['id'],
        'email': user['email'],
        'role': user['role'],
    })


def auth_required(role=None):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            auth_header = request.headers.get('Authorization', '')
            if not auth_header.startswith('Bearer '):
                return error('Authorization header with Bearer token required', 401)
            token = auth_header.split(' ', 1)[1].strip()
            user = verify_auth_token(token)
            if not user:
                return error('Invalid or expired token', 401)
            if role and user.get('role') != role:
                return error('Forbidden: admin access required', 403)
            g.current_user = user
            return fn(*args, **kwargs)
        return wrapper
    return decorator


def enrich_finding_with_user(finding):
    if not isinstance(finding, dict):
        return finding
    user = None
    ci_author = (finding.get('ci_author') or '').strip().lower()
    assignee = (finding.get('assignee') or '').strip().lower()
    if ci_author and '@' in ci_author:
        user = get_user_by_github_email(ci_author) or get_user_by_email(ci_author)
    if not user and assignee and '@' in assignee:
        user = get_user_by_github_email(assignee) or get_user_by_email(assignee)
    if not user:
        return finding
    enriched = dict(finding)
    enriched['assigned_user'] = {
        'id': user['id'],
        'email': user['email'],
        'github_email': user['github_email'],
        'role': user['role'],
    }
    return enriched


def get_current_user_from_request():
    """Extract current user from Authorization header. Returns None if no valid token."""
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return None
    token = auth_header.split(' ', 1)[1].strip()
    return verify_auth_token(token)


def filter_findings_for_user(findings, user):
    """Filter findings based on user role and github_email. Admins see all findings."""
    if not user or user.get('role') == 'admin' or not user.get('github_email'):
        return findings
    
    user_github_email = user['github_email'].lower()
    return [
        f for f in findings
        if user_github_email in (
            (f.get('ci_author') or '').lower(),
            (f.get('assignee') or '').lower()
        )
    ]


def init_auth_system():
    init_db()
    if count_users() == 0:
        admin_email = os.environ.get('ADMIN_EMAIL', 'admin')
        admin_password = os.environ.get('ADMIN_PASSWORD', 'admin')
        print('[AUTH] Creating initial admin user from configuration or defaults')
        try:
            create_user(admin_email, admin_email, admin_password, role='admin')
        except ValueError:
            pass


@app.route('/api/auth/login', methods=['POST'])
def login():
    body = request.get_json() or {}
    email = (body.get('email') or '').strip().lower()
    password = body.get('password')
    if not email or not password:
        return error('Email and password are required', 400)
    user = get_user_by_email(email)
    if not user or not check_password_hash(user['password_hash'], password):
        return error('Invalid email or password', 401)
    token = generate_auth_token(user)
    return success({
        'token': token,
        'user': {
            'id': user['id'],
            'email': user['email'],
            'github_email': user['github_email'],
            'role': user['role'],
        }
    })


@app.route('/api/auth/signup', methods=['POST'])
@auth_required(role='admin')
def signup():
    body = request.get_json() or {}
    email = (body.get('email') or '').strip().lower()
    password = body.get('password')
    github_email = (body.get('github_email') or '').strip().lower()
    role = (body.get('role') or 'user').strip().lower()
    if role not in ('user', 'admin'):
        return error('Role must be user or admin', 400)
    if not email or not password:
        return error('Email and password are required', 400)
    try:
        user = create_user(email, github_email, password, role=role)
    except ValueError as exc:
        return error(str(exc), 400)
    return success({
        'id': user['id'],
        'email': user['email'],
        'github_email': user['github_email'],
        'role': user['role'],
    }, 201)


@app.route('/api/auth/me', methods=['GET'])
@auth_required()
def auth_me():
    user = g.current_user
    return success({
        'id': user['id'],
        'email': user['email'],
        'github_email': user['github_email'],
        'role': user['role'],
    })


@app.route('/api/users', methods=['GET'])
@auth_required(role='admin')
def list_users():
    github_email = request.args.get('github_email', '').strip().lower()
    email = request.args.get('email', '').strip().lower()
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        if github_email:
            cursor.execute('SELECT * FROM users WHERE github_email = ?', (github_email,))
        elif email:
            cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
        else:
            cursor.execute('SELECT * FROM users ORDER BY id ASC')
        rows = cursor.fetchall()
        users = [
            {
                'id': row['id'],
                'email': row['email'],
                'github_email': row['github_email'],
                'role': row['role'],
                'created_at': row['created_at'],
            }
            for row in rows
        ]
        return success(users)
    finally:
        conn.close()


init_auth_system()


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
        current_user = get_current_user_from_request()
        
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
            # Apply user-level filtering before pagination
            filtered = filter_findings_for_user(filtered, current_user)
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
                limit=limit + offset,  # Get extra to account for filtering
                offset=0
            )
            # Apply user-level filtering
            findings = filter_findings_for_user(findings, current_user)
            total = len(findings)
            findings = findings[offset: offset + limit]
        
        findings = [enrich_finding_with_user(f) for f in findings]
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
        current_user = get_current_user_from_request()
        
        all_findings = load_all_findings()
        finding = next(
            (f for f in all_findings if f.get('id') == finding_id),
            None
        )
        if not finding:
            return error(f"Finding {finding_id} not found", 404)
        
        # Check access control
        if not filter_findings_for_user([finding], current_user):
            return error(f"Forbidden: You do not have access to this finding", 403)
        
        return success(enrich_finding_with_user(finding))
    except Exception as e:
        return error(str(e), 500)


# ─────────────────────────────────────────────
# GET /api/findings/<id>/assignee
# Returns the linked user for a finding, if one exists.

@app.route('/api/findings/<finding_id>/assignee', methods=['GET'])
def get_finding_assignee(finding_id):
    try:
        all_findings = load_all_findings()
        finding = next(
            (f for f in all_findings if f.get('id') == finding_id),
            None
        )
        if not finding:
            return error(f"Finding {finding_id} not found", 404)
        enriched = enrich_finding_with_user(finding)
        return success({'assigned_user': enriched.get('assigned_user')})
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
        current_user = get_current_user_from_request()
        all_findings, _ = query_findings(limit=100_000)
        findings = filter_findings_for_user(all_findings, current_user)
        
        if not findings:
            return success({
                "total_findings": 0,
                "by_severity": {},
                "by_source": {},
                "by_priority": {},
                "by_sla_status": {},
                "avg_risk_score": 0,
                "sentinel_flagged": 0
            })
        
        by_severity = {}
        by_source = {}
        by_priority = {}
        by_sla_status = {}
        total_score = 0
        sentinel_count = 0
        
        for f in findings:
            sev = f.get('severity', 'UNKNOWN')
            src = f.get('source', 'unknown')
            pri = f.get('priority', 'UNKNOWN')
            sla = f.get('sla_status', 'UNKNOWN')
            score = f.get('risk_score', 0)
            
            by_severity[sev] = by_severity.get(sev, 0) + 1
            by_source[src] = by_source.get(src, 0) + 1
            by_priority[pri] = by_priority.get(pri, 0) + 1
            by_sla_status[sla] = by_sla_status.get(sla, 0) + 1
            total_score += score
            if f.get('sentinel_flagged'):
                sentinel_count += 1
        
        avg_score = total_score / len(findings) if findings else 0
        
        return success({
            "total_findings": len(findings),
            "by_severity": by_severity,
            "by_source": by_source,
            "by_priority": by_priority,
            "by_sla_status": by_sla_status,
            "avg_risk_score": round(avg_score, 2),
            "sentinel_flagged": sentinel_count
        })
    except Exception as e:
        return error(str(e), 500)


# ─────────────────────────────────────────────
# GET /api/compliance
# ─────────────────────────────────────────────

@app.route('/api/compliance', methods=['GET'])
def get_compliance():
    try:
        current_user = get_current_user_from_request()
        all_findings, _ = query_findings(limit=100_000)
        findings = filter_findings_for_user(all_findings, current_user)
        
        all_categories = [
            "A01:2021 - Broken Access Control",
            "A02:2021 - Cryptographic Failures",
            "A03:2021 - Injection",
            "A04:2021 - Insecure Design",
            "A05:2021 - Security Misconfiguration",
            "A06:2021 - Vulnerable and Outdated Components",
            "A07:2021 - Identification and Authentication Failures",
            "A08:2021 - Software and Data Integrity Failures",
            "A09:2021 - Security Logging and Monitoring Failures",
            "A10:2021 - Server-Side Request Forgery",
        ]
        
        category_counts = {cat: 0 for cat in all_categories}
        
        for f in findings:
            for tag in f.get('compliance_tags', []):
                if tag in category_counts:
                    category_counts[tag] += 1
        
        result = []
        for cat in all_categories:
            count = category_counts[cat]
            result.append({
                "category": cat,
                "finding_count": count,
                "status": "FINDINGS_PRESENT" if count > 0 else "NOT_COVERED"
            })
        
        covered = sum(1 for c in result if c['status'] == 'FINDINGS_PRESENT')
        return success({
            "categories":   result,
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
        current_user = get_current_user_from_request()
        all_findings = load_all_findings()
        findings = filter_findings_for_user(all_findings, current_user)

        from datetime import timedelta
        now   = datetime.now(timezone.utc)
        daily = {}

        for i in range(days):
            day = (now - timedelta(days=i)).strftime('%Y-%m-%d')
            daily[day] = {"date": day, "total": 0,
                          "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

        for f in findings:
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
            "GET  /api/findings/<id>/assignee",
            "POST /api/auth/login",
            "POST /api/auth/signup",
            "GET  /api/auth/me",
            "GET  /api/users",
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