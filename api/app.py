# api/app.py
# SecurePipeline Hub - Flask REST API
# Serves enriched findings to the React dashboard

from flask import Flask, jsonify, request
from flask_cors import CORS
import json
import os
import sys
import uuid
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
CORS(app)  # Allow React dashboard to call this API


# ─────────────────────────────────────────────
# HELPER
# ─────────────────────────────────────────────

def success(data, status=200):
    return jsonify({"status": "success", "data": data}), status


def error(message, status=400):
    return jsonify({"status": "error", "message": message}), status


def find_and_save(finding_id, mutate_fn):
    """
    Load all findings, find the one with finding_id, call mutate_fn(finding)
    to apply changes in place, then persist and return the updated finding.
    Returns (updated_finding, error_message).
    """
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
# GET /api/findings
# List all findings with optional filters.
# By default false positives are excluded.
# Pass ?show_false_positives=true to include them.
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
            "total": total,
            "limit": limit,
            "offset": offset,
            "returned": len(findings)
        })

    except Exception as e:
        return error(str(e), 500)


# ─────────────────────────────────────────────
# GET /api/findings/<id>
# Single finding by UUID
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
# Update a finding. Supports:
#   {"sla_status": "RESOLVED"}
#   {"false_positive": true}
#   {"false_positive": false}
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
# Add a comment to a finding.
# Body: {"text": "...", "author": "..."}
# ─────────────────────────────────────────────

@app.route('/api/findings/<finding_id>/comments', methods=['POST'])
def add_comment(finding_id):
    try:
        body = request.get_json()
        if not body:
            return error("Request body required")

        text = (body.get('text') or '').strip()
        if not text:
            return error("Comment text is required")

        author = (body.get('author') or '').strip()
        if not author:
            return error("Author is required")

        if len(text) > 2000:
            return error("Comment must be 2000 characters or fewer")

        new_comment = {
            "id":         str(uuid.uuid4()),
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
# Aggregated statistics for dashboard cards.
# False positives are excluded from all counts.
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
# OWASP Top 10 coverage status
# ─────────────────────────────────────────────

@app.route('/api/compliance', methods=['GET'])
def get_compliance():
    try:
        compliance = get_compliance_status()
        covered = sum(1 for c in compliance if c['status'] == 'FINDINGS_PRESENT')
        return success({
            "categories": compliance,
            "covered": covered,
            "total": 10,
            "coverage_pct": round((covered / 10) * 100, 1)
        })
    except Exception as e:
        return error(str(e), 500)


# ─────────────────────────────────────────────
# GET /api/trends
# Daily finding counts for last N days
# ─────────────────────────────────────────────

@app.route('/api/trends', methods=['GET'])
def get_trends():
    try:
        days = int(request.args.get('days', 30))
        all_findings = load_all_findings()

        from datetime import timedelta
        now = datetime.now(timezone.utc)
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
                dt = datetime.fromisoformat(detected.replace('Z', '+00:00'))
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
    return success({
        "status": "healthy",
        "findings_in_storage": len(all_findings),
        "version": "1.0.0"
    })


# ─────────────────────────────────────────────
# ROOT
# ─────────────────────────────────────────────

@app.route('/', methods=['GET'])
def root():
    return success({
        "name": "SecurePipeline Hub API",
        "version": "1.0.0",
        "endpoints": [
            "GET  /api/health",
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
    print("Running at: http://localhost:5000")
    print("=" * 50)
    app.run(debug=True, host='0.0.0.0', port=5000)