# processing/storage.py
# Saves fully enriched findings to local JSON file storage
# Provides query functions for the Sprint 3 Flask API

import json
import os
from datetime import datetime, timezone


def get_timestamp():
    return datetime.now(timezone.utc).isoformat()


def get_storage_dir():
    """
    Returns the data/findings directory, creates it if needed.
    Respects FINDINGS_DIR env var so CI can override the path
    when running from a different working directory.
    """
    if os.environ.get('FINDINGS_DIR'):
        storage_dir = os.environ['FINDINGS_DIR']
    else:
        storage_dir = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), '..', 'data', 'findings'
        )
    os.makedirs(storage_dir, exist_ok=True)
    return storage_dir


def save_findings(findings, pipeline_run_id=None):
    """
    Save enriched findings to a timestamped JSON file.
    Each pipeline run creates one file.
    Returns the path of the saved file.
    """
    storage_dir = get_storage_dir()

    if not pipeline_run_id:
        pipeline_run_id = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')

    filename = f"findings_{pipeline_run_id}.json"
    filepath = os.path.join(storage_dir, filename)

    payload = {
        "pipeline_run_id": pipeline_run_id,
        "saved_at": get_timestamp(),
        "total_findings": len(findings),
        "findings": findings
    }

    with open(filepath, 'w') as f:
        json.dump(payload, f, indent=2)

    return filepath


def load_all_findings():
    """
    Load all findings from all pipeline runs.
    Deduplicates by finding ID — newest file wins, preserving the most
    recent state (resolved, false_positive, comments, etc).
    Returns a flat list sorted by risk_score descending.
    """
    storage_dir = get_storage_dir()

    if not os.path.exists(storage_dir):
        return []

    # Process files newest-first so the first time we see an ID it's
    # the most up-to-date copy. Older duplicates are skipped.
    seen_ids = set()
    all_findings = []

    for filename in sorted(os.listdir(storage_dir), reverse=True):
        if filename.startswith('findings_') and filename.endswith('.json'):
            filepath = os.path.join(storage_dir, filename)
            try:
                with open(filepath, encoding='utf-8') as f:
                    data = json.load(f)
                for finding in data.get('findings', []):
                    fid = finding.get('id')
                    if fid and fid not in seen_ids:
                        seen_ids.add(fid)
                        all_findings.append(finding)
            except Exception as e:
                print(f"[WARN] Could not load {filename}: {e}")

    # Sort by risk_score descending
    all_findings.sort(key=lambda x: x.get('risk_score', 0), reverse=True)
    return all_findings


def query_findings(
    severity=None,
    source=None,
    priority=None,
    assignee=None,
    sla_status=None,
    include_false_positives=False,
    limit=100,
    offset=0
):
    """
    Query findings with optional filters.
    False positives are excluded by default unless include_false_positives=True.
    Used by the Flask API.
    """
    findings = load_all_findings()

    # Exclude false positives by default
    if not include_false_positives:
        findings = [f for f in findings if not f.get('false_positive', False)]

    # Apply filters
    if severity:
        findings = [f for f in findings
                    if f.get('severity', '').upper() == severity.upper()]
    if source:
        findings = [f for f in findings
                    if f.get('source', '').lower() == source.lower()]
    if priority:
        findings = [f for f in findings
                    if f.get('priority', '').upper() == priority.upper()]
    if assignee:
        findings = [f for f in findings
                    if assignee.lower() in f.get('assignee', '').lower()]
    if sla_status:
        findings = [f for f in findings
                    if f.get('sla_status', '').upper() == sla_status.upper()]

    total = len(findings)
    paginated = findings[offset:offset + limit]
    return paginated, total


def get_stats():
    """
    Generate aggregated statistics for the Flask API /stats endpoint.
    False positives are excluded from all counts so dashboard numbers
    reflect only genuine findings.
    """
    # Reuse query_findings with no filters so FP exclusion is consistent
    findings, _ = query_findings(limit=100_000)

    if not findings:
        return {
            "total_findings": 0,
            "by_severity": {},
            "by_source": {},
            "by_priority": {},
            "by_sla_status": {},
            "avg_risk_score": 0,
            "sentinel_flagged": 0
        }

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

        if f.get('sentinel_escalate'):
            sentinel_count += 1

    return {
        "total_findings": len(findings),
        "by_severity": by_severity,
        "by_source": by_source,
        "by_priority": by_priority,
        "by_sla_status": by_sla_status,
        "avg_risk_score": round(total_score / len(findings), 1),
        "sentinel_flagged": sentinel_count
    }


def get_compliance_status():
    """
    Generate OWASP Top 10 compliance status for the /compliance endpoint.
    False positives are excluded so coverage reflects genuine findings only.
    """
    # Reuse query_findings so FP exclusion is consistent
    findings, _ = query_findings(limit=100_000)

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

    return result


def run_storage(
    input_path="final-findings.json",
    pipeline_run_id=None
):
    print("\n" + "=" * 50)
    print("SECUREPIPELINE HUB - STORAGE MODULE")
    print("=" * 50)

    if not os.path.exists(input_path):
        print(f"[ERROR] Input not found: {input_path}")
        return

    with open(input_path) as f:
        findings = json.load(f)

    print(f"[INFO] Saving {len(findings)} findings to storage...")

    filepath = save_findings(findings, pipeline_run_id)
    print(f"[INFO] Saved to: {filepath}")

    # Verify by loading back
    all_findings = load_all_findings()
    stats = get_stats()
    compliance = get_compliance_status()

    print(f"\n{'=' * 50}")
    print("STORAGE COMPLETE")
    print(f"{'=' * 50}")
    print(f"Total findings in storage: {stats['total_findings']}")
    print(f"Average risk score: {stats['avg_risk_score']}")
    print(f"Sentinel flagged: {stats['sentinel_flagged']}")

    print("\nBy priority:")
    for p in ['HIGH', 'MEDIUM', 'LOW', 'INFO', 'NO_SLA']:
        count = stats['by_priority'].get(p, 0)
        if count:
            print(f"  {p}: {count}")

    print("\nBy SLA status:")
    for s, count in stats['by_sla_status'].items():
        print(f"  {s}: {count}")

    print("\nOWASP coverage:")
    covered = sum(1 for c in compliance if c['status'] == 'FINDINGS_PRESENT')
    print(f"  {covered}/10 categories covered")

    print(f"\n✅ Storage complete: {filepath}")
    print("=" * 50)


if __name__ == "__main__":
    import sys
    run_id = sys.argv[1] if len(sys.argv) > 1 else None
    run_storage(pipeline_run_id=run_id)