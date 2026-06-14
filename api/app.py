# api/app.py
# SecurePipeline Hub - Flask REST API

from flask import Flask, jsonify, request, g
from flask_cors import CORS
import json
import os
import sys
import sqlite3
import sqlite3
import subprocess
import threading
import time
import uuid as uuid_lib
from datetime import datetime, timezone, timedelta
from functools import wraps

from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from werkzeug.security import check_password_hash, generate_password_hash

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from processing.storage import (
    query_findings, get_stats,
    get_compliance_status, load_all_findings, save_findings
    query_findings, get_stats,
    get_compliance_status, load_all_findings, save_findings
)
 
app = Flask(__name__)
CORS(app, resources={r"/api/*": {
    "origins": ["http://localhost:3000", "http://127.0.0.1:3000"],
    "methods": ["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    "allow_headers": ["Content-Type", "Authorization"],
    "supports_credentials": True,
}})

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ─────────────────────────────────────────────
# HELPERS
# HELPERS
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
# ─────────────────────────────────────────────

AUTH_DB_PATH             = os.environ.get('AUTH_DB_PATH', os.path.join(os.path.dirname(__file__), 'auth.db'))
SECRET_KEY               = os.environ.get('SECRET_KEY', 'change-me-in-production')
TOKEN_EXPIRATION_SECONDS = int(os.environ.get('AUTH_TOKEN_EXPIRATION', 3600 * 8))
TOKEN_SALT               = 'securepipeline-auth-token'

auth_serializer = URLSafeTimedSerializer(SECRET_KEY, salt=TOKEN_SALT)


def get_db():
    conn = sqlite3.connect(AUTH_DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    try:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                email        TEXT NOT NULL UNIQUE,
                github_email TEXT,
                password_hash TEXT NOT NULL,
                name         TEXT,
                team         TEXT,
                role         TEXT NOT NULL DEFAULT 'user',
                is_active    INTEGER NOT NULL DEFAULT 1,
                created_at   TEXT NOT NULL,
                last_login   TEXT
            )
        ''')
        # Add columns that may not exist in older DBs
        for col, defn in [
            ("name",       "TEXT"),
            ("team",       "TEXT"),
            ("is_active",  "INTEGER NOT NULL DEFAULT 1"),
            ("last_login", "TEXT"),
        ]:
            try:
                conn.execute(f"ALTER TABLE users ADD COLUMN {col} {defn}")
            except Exception:
                pass
        conn.commit()
    finally:
        conn.close()


def _row_to_dict(row):
    if not row:
        return None
    d = dict(row)
    d['is_active'] = bool(d.get('is_active', 1))
    return d


def get_user_by_email(email):
    if not email:
        return None
    conn = get_db()
    try:
        row = conn.execute('SELECT * FROM users WHERE email = ?', (email.lower(),)).fetchone()
        return _row_to_dict(row)
    finally:
        conn.close()


def get_all_users():
    conn = get_db()
    try:
        rows = conn.execute('SELECT * FROM users ORDER BY id ASC').fetchall()
        return [_row_to_dict(r) for r in rows]
    finally:
        conn.close()


def count_users():
    conn = get_db()
    try:
        row = conn.execute('SELECT COUNT(1) AS c FROM users').fetchone()
        return row['c'] if row else 0
    finally:
        conn.close()


def db_create_user(email, password, role='user', name=None, team=None, github_email=None):
    email = email.strip().lower()
    if get_user_by_email(email):
        raise ValueError('A user with that email already exists')
    conn = get_db()
    try:
        conn.execute(
            'INSERT INTO users (email, github_email, password_hash, name, team, role, is_active, created_at) VALUES (?,?,?,?,?,?,1,?)',
            (email, (github_email or '').strip().lower() or None,
             generate_password_hash(password),
             (name or '').strip() or None,
             (team or '').strip() or None,
             role,
             datetime.now(timezone.utc).isoformat())
        )
        conn.commit()
        return get_user_by_email(email)
    finally:
        conn.close()


def db_update_user(user_id, **fields):
    allowed = {'name', 'team', 'github_email', 'role', 'is_active', 'password_hash', 'last_login'}
    updates = {k: v for k, v in fields.items() if k in allowed}
    if not updates:
        return
    conn = get_db()
    try:
        sets = ', '.join(f"{k} = ?" for k in updates)
        vals = list(updates.values()) + [user_id]
        conn.execute(f"UPDATE users SET {sets} WHERE id = ?", vals)
        conn.commit()
    finally:
        conn.close()


def db_delete_user(user_id):
    conn = get_db()
    try:
        conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
        conn.commit()
    finally:
        conn.close()


def count_active_admins():
    conn = get_db()
    try:
        row = conn.execute("SELECT COUNT(1) AS c FROM users WHERE role='admin' AND is_active=1").fetchone()
        return row['c'] if row else 0
    finally:
        conn.close()


def generate_token(user):
    return auth_serializer.dumps({'id': user['id'], 'email': user['email'], 'role': user['role']})


def verify_token(token):
    if not token:
        return None
    try:
        payload = auth_serializer.loads(token, max_age=TOKEN_EXPIRATION_SECONDS)
        return get_user_by_email(payload.get('email'))
    except (BadSignature, SignatureExpired):
        return None


def auth_required(role=None):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            hdr = request.headers.get('Authorization', '')
            if not hdr.startswith('Bearer '):
                return error('Authorization required', 401)
            user = verify_token(hdr.split(' ', 1)[1].strip())
            if not user:
                return error('Invalid or expired token', 401)
            if not user.get('is_active', True):
                return error('Account is disabled', 403)
            if role and user.get('role') != role:
                return error('Admin access required', 403)
            g.current_user = user
            return fn(*args, **kwargs)
        return wrapper
    return decorator


def get_current_user():
    hdr = request.headers.get('Authorization', '')
    if not hdr.startswith('Bearer '):
        return None
    return verify_token(hdr.split(' ', 1)[1].strip())


def safe_user(u):
    """Public-safe user dict — no password hash."""
    if not u:
        return None
    return {
        'id':           u['id'],
        'email':        u['email'],
        'github_email': u.get('github_email'),
        'name':         u.get('name'),
        'team':         u.get('team'),
        'role':         u['role'],
        'is_active':    u.get('is_active', True),
        'created_at':   u.get('created_at'),
        'last_login':   u.get('last_login'),
    }


def filter_findings_for_user(findings, user):
    """
    Admins see everything.
    Developers with a github_email see findings where they are the commit author or assignee.
    Developers without a github_email see everything (fallback — avoids blank dashboard).
    """
    if not user or user.get('role') == 'admin':
        return findings
    gh = (user.get('github_email') or '').lower()
    if not gh:
        return findings  # no github_email configured — show all so dashboard isn't empty
    return [
        f for f in findings
        if gh in ((f.get('ci_author') or '').lower(), (f.get('assignee') or '').lower())
    ]


def init_auth_system():
    init_db()
    if count_users() == 0:
        admin_email    = os.environ.get('ADMIN_EMAIL', 'admin@securepipeline.dev')
        admin_password = os.environ.get('ADMIN_PASSWORD', 'admin123!')
        print(f'[AUTH] Creating default admin: {admin_email}')
        try:
            db_create_user(admin_email, admin_password, role='admin', name='Admin', team='Security')
            print(f'[AUTH] Default password: {admin_password} — change this immediately!')
        except ValueError:
            pass


# ─── Auth routes ──────────────────────────────────────────────────────────────

@app.route('/api/auth/login', methods=['POST'])
def login():
    body     = request.get_json() or {}
    email    = (body.get('email') or '').strip().lower()
    password = body.get('password') or ''
    if not email or not password:
        return error('Email and password are required')
    user = get_user_by_email(email)
    if not user or not check_password_hash(user['password_hash'], password):
        return error('Invalid email or password', 401)
    if not user.get('is_active', True):
        return error('Account is disabled. Contact your admin.', 403)
    db_update_user(user['id'], last_login=datetime.now(timezone.utc).isoformat())
    return success({'token': generate_token(user), 'user': safe_user(user)})


@app.route('/api/auth/me', methods=['GET'])
@auth_required()
def auth_me():
    return success(safe_user(g.current_user))


@app.route('/api/auth/change-password', methods=['POST'])
@auth_required()
def change_password():
    body     = request.get_json() or {}
    current  = body.get('current_password') or ''
    new_pass = body.get('new_password') or ''
    if not current or not new_pass:
        return error('current_password and new_password are required')
    if not check_password_hash(g.current_user['password_hash'], current):
        return error('Current password is incorrect', 401)
    if len(new_pass) < 8:
        return error('New password must be at least 8 characters')
    db_update_user(g.current_user['id'], password_hash=generate_password_hash(new_pass))
    return success({'message': 'Password changed successfully'})


# ─── Admin user management routes ────────────────────────────────────────────

@app.route('/api/users', methods=['GET'])
@auth_required(role='admin')
def list_users():
    return success([safe_user(u) for u in get_all_users()])


@app.route('/api/users', methods=['POST'])
@auth_required(role='admin')
def create_user_route():
    body         = request.get_json() or {}
    email        = (body.get('email') or '').strip().lower()
    password     = body.get('password') or ''
    role         = (body.get('role') or 'user').strip().lower()
    name         = (body.get('name') or '').strip()
    team         = (body.get('team') or '').strip()
    github_email = (body.get('github_email') or '').strip().lower()

    if not email:
        return error('Email is required')
    if not password or len(password) < 8:
        return error('Password must be at least 8 characters')
    if role not in ('user', 'admin'):
        return error('Role must be user or admin')

    try:
        user = db_create_user(email, password, role=role, name=name or None,
                              team=team or None, github_email=github_email or None)
        return success(safe_user(user), 201)
    except ValueError as e:
        return error(str(e), 409)


@app.route('/api/users/<int:user_id>', methods=['PATCH'])
@auth_required(role='admin')
def update_user_route(user_id):
    conn = get_db()
    try:
        row = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    finally:
        conn.close()
    if not row:
        return error('User not found', 404)
    user = _row_to_dict(row)

    body    = request.get_json() or {}
    updates = {}

    if 'name' in body:
        updates['name'] = (body['name'] or '').strip() or None
    if 'team' in body:
        updates['team'] = (body['team'] or '').strip() or None
    if 'github_email' in body:
        updates['github_email'] = (body['github_email'] or '').strip().lower() or None
    if 'role' in body:
        role = body['role'].strip().lower()
        if role not in ('user', 'admin'):
            return error('Role must be user or admin')
        if role != 'admin' and user['role'] == 'admin' and count_active_admins() <= 1:
            return error('Cannot demote the last admin', 409)
        updates['role'] = role
    if 'is_active' in body:
        if not isinstance(body['is_active'], bool):
            return error('is_active must be a boolean')
        if not body['is_active'] and user['role'] == 'admin' and count_active_admins() <= 1:
            return error('Cannot deactivate the last admin', 409)
        updates['is_active'] = int(body['is_active'])
    if 'password' in body:
        pw = body['password'] or ''
        if len(pw) < 8:
            return error('Password must be at least 8 characters')
        updates['password_hash'] = generate_password_hash(pw)

    if updates:
        db_update_user(user_id, **updates)

    conn = get_db()
    try:
        row = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    finally:
        conn.close()
    return success(safe_user(_row_to_dict(row)))


@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@auth_required(role='admin')
def delete_user_route(user_id):
    if user_id == g.current_user['id']:
        return error('You cannot delete your own account', 409)
    conn = get_db()
    try:
        row = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    finally:
        conn.close()
    if not row:
        return error('User not found', 404)
    user = _row_to_dict(row)
    if user['role'] == 'admin' and count_active_admins() <= 1:
        return error('Cannot delete the last admin account', 409)
    db_delete_user(user_id)
    return success({'message': f"User {user['email']} deleted"})


# ─────────────────────────────────────────────
# GIT POLLER
# ─────────────────────────────────────────────

POLL_INTERVAL = int(os.environ.get('POLL_INTERVAL', 60))

_poller_state = {
    "last_checked": None, "last_pulled": None,
    "last_commit":  None, "status":      "idle",
    "message":      "",   "pull_count":  0,
    "last_checked": None, "last_pulled": None,
    "last_commit":  None, "status":      "idle",
    "message":      "",   "pull_count":  0,
}
_poller_lock = threading.Lock()
 
 
def _run(cmd, cwd=None):
    r = subprocess.run(cmd, shell=True, cwd=cwd,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return r.stdout.strip(), r.stderr.strip(), r.returncode


def _get_local_sha():
    out, _, _ = _run("git rev-parse HEAD", cwd=PROJECT_ROOT)
    return out
 
 
def _get_remote_sha():
    _run("git fetch origin main --quiet", cwd=PROJECT_ROOT)
    out, _, _ = _run("git rev-parse origin/main", cwd=PROJECT_ROOT)
    return out
 
 
def _do_pull():
    _run("git stash --quiet", cwd=PROJECT_ROOT)
    _, err_msg, rc = _run("git pull origin main --quiet", cwd=PROJECT_ROOT)
    _run("git stash pop --quiet", cwd=PROJECT_ROOT)
    return rc == 0, err_msg


def _poll_loop():
    print(f"[Poller] Started — checking every {POLL_INTERVAL}s")
    print(f"[Poller] Started — checking every {POLL_INTERVAL}s")
    _last_pulled_sha = None
    while True:
        try:
            now        = datetime.now(timezone.utc).isoformat()
            now        = datetime.now(timezone.utc).isoformat()
            local_sha  = _get_local_sha()
            remote_sha = _get_remote_sha()
            with _poller_lock:
                _poller_state["last_checked"] = now
                _poller_state["last_commit"]  = local_sha[:8] if local_sha else None

            already_done = (_last_pulled_sha is not None and
                            remote_sha and _last_pulled_sha == remote_sha)

            if local_sha and remote_sha and local_sha != remote_sha and not already_done:
                print(f"[Poller] New commit: {remote_sha[:8]} — pulling...")
                print(f"[Poller] New commit: {remote_sha[:8]} — pulling...")
                with _poller_lock:
                    _poller_state["status"] = "pulling"
                ok_pull, err_msg = _do_pull()
                new_local = _get_local_sha()
                ok_pull, err_msg = _do_pull()
                new_local = _get_local_sha()
                with _poller_lock:
                    if ok_pull and new_local == remote_sha:
                    if ok_pull and new_local == remote_sha:
                        _last_pulled_sha = remote_sha
                        _poller_state.update(status="updated", last_pulled=now,
                                             last_commit=remote_sha[:8],
                                             pull_count=_poller_state["pull_count"] + 1,
                                             message=f"Pulled {remote_sha[:8]}")
                        _poller_state.update(status="updated", last_pulled=now,
                                             last_commit=remote_sha[:8],
                                             pull_count=_poller_state["pull_count"] + 1,
                                             message=f"Pulled {remote_sha[:8]}")
                        print(f"[Poller] Pull successful — {remote_sha[:8]}")
                    else:
                        _last_pulled_sha = None
                        _poller_state.update(status="error",
                                             message=(err_msg or "HEAD did not advance")[:200])
                        print(f"[Poller] Pull failed: {err_msg[:100]}")
                        _last_pulled_sha = None
                        _poller_state.update(status="error",
                                             message=(err_msg or "HEAD did not advance")[:200])
                        print(f"[Poller] Pull failed: {err_msg[:100]}")
            else:
                with _poller_lock:
                    _poller_state.update(status="up_to_date", message="")
                    _poller_state.update(status="up_to_date", message="")
        except Exception as e:
            with _poller_lock:
                _poller_state.update(status="error", message=str(e)[:200])
                _poller_state.update(status="error", message=str(e)[:200])
            print(f"[Poller] Error: {e}")
        time.sleep(POLL_INTERVAL)


if os.environ.get('WERKZEUG_RUN_MAIN') != 'false':
    threading.Thread(target=_poll_loop, daemon=True).start()


# ─────────────────────────────────────────────
# SYNC ROUTES
# SYNC ROUTES
# ─────────────────────────────────────────────
 
@app.route('/api/sync-status', methods=['GET'])
def sync_status():
    with _poller_lock:
        return success(dict(_poller_state))


@app.route('/api/sync-now', methods=['POST'])
def sync_now():
    try:
        now        = datetime.now(timezone.utc).isoformat()
        now        = datetime.now(timezone.utc).isoformat()
        local_sha  = _get_local_sha()
        remote_sha = _get_remote_sha()
        if local_sha == remote_sha:
            return success({"pulled": False, "message": "Already up to date", "commit": local_sha[:8]})
        ok_pull, err_msg = _do_pull()
        if ok_pull:
            return success({"pulled": False, "message": "Already up to date", "commit": local_sha[:8]})
        ok_pull, err_msg = _do_pull()
        if ok_pull:
            new_sha = _get_local_sha()
            with _poller_lock:
                _poller_state.update(status="updated", last_pulled=now,
                                     last_commit=new_sha[:8] if new_sha else None,
                                     pull_count=_poller_state["pull_count"] + 1)
            return success({"pulled": True, "message": f"Pulled {new_sha[:8]}", "commit": new_sha[:8]})
        return error(f"git pull failed: {err_msg}", 500)
                _poller_state.update(status="updated", last_pulled=now,
                                     last_commit=new_sha[:8] if new_sha else None,
                                     pull_count=_poller_state["pull_count"] + 1)
            return success({"pulled": True, "message": f"Pulled {new_sha[:8]}", "commit": new_sha[:8]})
        return error(f"git pull failed: {err_msg}", 500)
    except Exception as e:
        return error(str(e), 500)
 
 
# ─────────────────────────────────────────────
# FINDINGS ROUTES
# FINDINGS ROUTES
# ─────────────────────────────────────────────
 
@app.route('/api/findings', methods=['GET'])
def get_findings():
    try:
        current_user   = get_current_user()
        current_user   = get_current_user()
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
                severity=severity, source=source, priority=None,
                assignee=assignee, sla_status=sla_status,
                include_false_positives=show_fp, limit=100_000, offset=0
                severity=severity, source=source, priority=None,
                assignee=assignee, sla_status=sla_status,
                include_false_positives=show_fp, limit=100_000, offset=0
            )
            filtered = [f for f in all_matching if compliance_tag in (f.get('compliance_tags') or [])]
            filtered = [f for f in all_matching if compliance_tag in (f.get('compliance_tags') or [])]
            if priority:
                filtered = [f for f in filtered if (f.get('priority') or '').upper() == priority.upper()]
            filtered = filter_findings_for_user(filtered, current_user)
                filtered = [f for f in filtered if (f.get('priority') or '').upper() == priority.upper()]
            filtered = filter_findings_for_user(filtered, current_user)
            total    = len(filtered)
            findings = filtered[offset: offset + limit]
        else:
            all_matching, _ = query_findings(
                severity=severity, source=source, priority=priority,
                assignee=assignee, sla_status=sla_status,
                include_false_positives=show_fp, limit=100_000, offset=0
            )
            filtered = filter_findings_for_user(all_matching, current_user)
            total    = len(filtered)
            findings = filtered[offset: offset + limit]

        return success({"findings": findings, "total": total,
                        "limit": limit, "offset": offset, "returned": len(findings)})
    except Exception as e:
        return error(str(e), 500)


@app.route('/api/findings/<finding_id>', methods=['GET'])
def get_finding(finding_id):
    try:
        all_f   = load_all_findings()
        finding = next((f for f in all_f if f.get('id') == finding_id), None)
        all_f   = load_all_findings()
        finding = next((f for f in all_f if f.get('id') == finding_id), None)
        if not finding:
            return error(f"Finding {finding_id} not found", 404)
        return success(finding)
    except Exception as e:
        return error(str(e), 500)


@app.route('/api/findings/<finding_id>', methods=['PATCH'])
def update_finding(finding_id):
    try:
        body = request.get_json()
        if not body:
            return error("Request body required")
        allowed = {'sla_status', 'false_positive'}
        unknown = set(body.keys()) - allowed
        allowed = {'sla_status', 'false_positive'}
        unknown = set(body.keys()) - allowed
        if unknown:
            return error(f"Unknown fields: {list(unknown)}")
            return error(f"Unknown fields: {list(unknown)}")
        if 'sla_status' in body:
            ns = body['sla_status'].upper()
            if ns not in ['OPEN', 'WARNING', 'OVERDUE', 'RESOLVED']:
                return error(f"Invalid sla_status: {ns}")
        if 'false_positive' in body and not isinstance(body['false_positive'], bool):
            return error("false_positive must be a boolean")

        current_user = get_current_user()
        actor_email  = (current_user or {}).get('email', 'unknown')

        def mutate(f):
            now = datetime.now(timezone.utc).isoformat()
            if 'sla_status' in body:
                f['sla_status'] = body['sla_status'].upper()
                if f['sla_status'] == 'RESOLVED':
                    f['resolved_at'] = now
                    f['resolved_by'] = actor_email
                    f['resolved_by'] = actor_email
            if 'false_positive' in body:
                f['false_positive'] = body['false_positive']
                if body['false_positive']:
                    f['false_positive_at'] = now
                    f['false_positive_by'] = actor_email
                    f['false_positive_by'] = actor_email
                else:
                    f.pop('false_positive_at', None)
                    f.pop('false_positive_by', None)

        updated, err = find_and_save(finding_id, mutate)
        if err:
            return error(err, 404)
        return success(updated)
    except Exception as e:
        return error(str(e), 500)


@app.route('/api/findings/<finding_id>/comments', methods=['POST'])
def add_comment(finding_id):
    try:
        body = request.get_json() or {}
        text = (body.get('text') or '').strip()
        body = request.get_json() or {}
        text = (body.get('text') or '').strip()
        if not text:
            return error("Comment text is required")
        if len(text) > 2000:
            return error("Comment must be 2000 characters or fewer")

        # Author from JWT if available, else from body (for backwards compat)
        current_user = get_current_user()
        if current_user:
            author = current_user.get('name') or current_user.get('email') or 'Unknown'
        else:
            author = (body.get('author') or '').strip() or 'Unknown'

        new_comment = {
            "id":         str(uuid_lib.uuid4()),
            "text":       text,
            "author":     author,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "created_at": datetime.now(timezone.utc).isoformat(),
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
# STATS / COMPLIANCE / TRENDS
# STATS / COMPLIANCE / TRENDS
# ─────────────────────────────────────────────
 
@app.route('/api/stats', methods=['GET'])
def get_statistics():
    try:
        current_user  = get_current_user()
        all_f, _      = query_findings(limit=100_000)
        findings      = filter_findings_for_user(all_f, current_user)
        if not findings:
            return success({"total_findings": 0, "by_severity": {}, "by_source": {},
                            "by_priority": {}, "by_sla_status": {},
                            "avg_risk_score": 0, "sentinel_flagged": 0})
        by_sev = {}; by_src = {}; by_pri = {}; by_sla = {}
        total_score = 0; sentinel = 0
        for f in findings:
            by_sev[f.get('severity','UNKNOWN')] = by_sev.get(f.get('severity','UNKNOWN'), 0) + 1
            by_src[f.get('source','unknown')]   = by_src.get(f.get('source','unknown'), 0) + 1
            by_pri[f.get('priority','UNKNOWN')] = by_pri.get(f.get('priority','UNKNOWN'), 0) + 1
            by_sla[f.get('sla_status','UNKNOWN')] = by_sla.get(f.get('sla_status','UNKNOWN'), 0) + 1
            total_score += f.get('risk_score', 0)
            if f.get('sentinel_flagged') or f.get('sentinel_escalate'):
                sentinel += 1
        return success({"total_findings": len(findings), "by_severity": by_sev,
                        "by_source": by_src, "by_priority": by_pri, "by_sla_status": by_sla,
                        "avg_risk_score": round(total_score / len(findings), 1),
                        "sentinel_flagged": sentinel})
        current_user  = get_current_user()
        all_f, _      = query_findings(limit=100_000)
        findings      = filter_findings_for_user(all_f, current_user)
        if not findings:
            return success({"total_findings": 0, "by_severity": {}, "by_source": {},
                            "by_priority": {}, "by_sla_status": {},
                            "avg_risk_score": 0, "sentinel_flagged": 0})
        by_sev = {}; by_src = {}; by_pri = {}; by_sla = {}
        total_score = 0; sentinel = 0
        for f in findings:
            by_sev[f.get('severity','UNKNOWN')] = by_sev.get(f.get('severity','UNKNOWN'), 0) + 1
            by_src[f.get('source','unknown')]   = by_src.get(f.get('source','unknown'), 0) + 1
            by_pri[f.get('priority','UNKNOWN')] = by_pri.get(f.get('priority','UNKNOWN'), 0) + 1
            by_sla[f.get('sla_status','UNKNOWN')] = by_sla.get(f.get('sla_status','UNKNOWN'), 0) + 1
            total_score += f.get('risk_score', 0)
            if f.get('sentinel_flagged') or f.get('sentinel_escalate'):
                sentinel += 1
        return success({"total_findings": len(findings), "by_severity": by_sev,
                        "by_source": by_src, "by_priority": by_pri, "by_sla_status": by_sla,
                        "avg_risk_score": round(total_score / len(findings), 1),
                        "sentinel_flagged": sentinel})
    except Exception as e:
        return error(str(e), 500)


@app.route('/api/compliance', methods=['GET'])
def get_compliance():
    try:
        current_user = get_current_user()
        all_f, _     = query_findings(limit=100_000)
        findings     = filter_findings_for_user(all_f, current_user)
        cats = [
            "A01:2021 - Broken Access Control", "A02:2021 - Cryptographic Failures",
            "A03:2021 - Injection", "A04:2021 - Insecure Design",
            "A05:2021 - Security Misconfiguration", "A06:2021 - Vulnerable and Outdated Components",
            "A07:2021 - Identification and Authentication Failures",
            "A08:2021 - Software and Data Integrity Failures",
            "A09:2021 - Security Logging and Monitoring Failures",
            "A10:2021 - Server-Side Request Forgery",
        ]
        counts = {c: 0 for c in cats}
        for f in findings:
            for tag in f.get('compliance_tags', []):
                if tag in counts:
                    counts[tag] += 1
        result  = [{"category": c, "finding_count": counts[c],
                    "status": "FINDINGS_PRESENT" if counts[c] > 0 else "NOT_COVERED"} for c in cats]
        covered = sum(1 for r in result if r['status'] == 'FINDINGS_PRESENT')
        return success({"categories": result, "covered": covered, "total": 10,
                        "coverage_pct": round((covered / 10) * 100, 1)})
        current_user = get_current_user()
        all_f, _     = query_findings(limit=100_000)
        findings     = filter_findings_for_user(all_f, current_user)
        cats = [
            "A01:2021 - Broken Access Control", "A02:2021 - Cryptographic Failures",
            "A03:2021 - Injection", "A04:2021 - Insecure Design",
            "A05:2021 - Security Misconfiguration", "A06:2021 - Vulnerable and Outdated Components",
            "A07:2021 - Identification and Authentication Failures",
            "A08:2021 - Software and Data Integrity Failures",
            "A09:2021 - Security Logging and Monitoring Failures",
            "A10:2021 - Server-Side Request Forgery",
        ]
        counts = {c: 0 for c in cats}
        for f in findings:
            for tag in f.get('compliance_tags', []):
                if tag in counts:
                    counts[tag] += 1
        result  = [{"category": c, "finding_count": counts[c],
                    "status": "FINDINGS_PRESENT" if counts[c] > 0 else "NOT_COVERED"} for c in cats]
        covered = sum(1 for r in result if r['status'] == 'FINDINGS_PRESENT')
        return success({"categories": result, "covered": covered, "total": 10,
                        "coverage_pct": round((covered / 10) * 100, 1)})
    except Exception as e:
        return error(str(e), 500)


@app.route('/api/trends', methods=['GET'])
def get_trends():
    try:
        days         = int(request.args.get('days', 30))
        current_user = get_current_user()
        all_f        = load_all_findings()
        findings     = filter_findings_for_user(all_f, current_user)
        current_user = get_current_user()
        all_f        = load_all_findings()
        findings     = filter_findings_for_user(all_f, current_user)
        now   = datetime.now(timezone.utc)
        daily = {}
        for i in range(days):
            day = (now - timedelta(days=i)).strftime('%Y-%m-%d')
            daily[day] = {"date": day, "total": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            if f.get('false_positive'):
            daily[day] = {"date": day, "total": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            if f.get('false_positive'):
                continue
            try:
                dt  = datetime.fromisoformat((f.get('detected_at') or '').replace('Z', '+00:00'))
                dt  = datetime.fromisoformat((f.get('detected_at') or '').replace('Z', '+00:00'))
                day = dt.strftime('%Y-%m-%d')
                if day in daily:
                    daily[day]['total'] += 1
                    p = f.get('priority', 'INFO')
                    if p in daily[day]:
                        daily[day][p] += 1
                    p = f.get('priority', 'INFO')
                    if p in daily[day]:
                        daily[day][p] += 1
            except Exception:
                continue
        return success({"trends": sorted(daily.values(), key=lambda x: x['date']), "days": days})
        return success({"trends": sorted(daily.values(), key=lambda x: x['date']), "days": days})
    except Exception as e:
        return error(str(e), 500)
 
 
# ─────────────────────────────────────────────
# HEALTH / ROOT
# HEALTH / ROOT
# ─────────────────────────────────────────────
 
@app.route('/api/health', methods=['GET'])
def health():
    with _poller_lock:
        poller = dict(_poller_state)
    return success({"status": "healthy", "findings_in_storage": len(load_all_findings()),
                    "version": "1.0.0", "poller": poller})


@app.route('/', methods=['GET'])
def root():
    return success({"name": "SecurePipeline Hub API", "version": "1.0.0"})


# ─────────────────────────────────────────────
# ENTRYPOINT
# ENTRYPOINT
# ─────────────────────────────────────────────

init_auth_system()

if __name__ == '__main__':
    print("=" * 50)
    print("SecurePipeline Hub - Flask API")
    print(f"Auth DB : {AUTH_DB_PATH}")
    print(f"Poller  : every {POLL_INTERVAL}s")
    print(f"Auth DB : {AUTH_DB_PATH}")
    print(f"Poller  : every {POLL_INTERVAL}s")
    print("=" * 50)
    app.run(debug=True, host='0.0.0.0', port=5000)