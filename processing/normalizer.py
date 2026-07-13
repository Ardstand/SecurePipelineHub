# processing/normalizer.py
# Converts all 5 scanner outputs to unified finding schema

import json
import uuid
import os
from datetime import datetime, timezone


def get_timestamp():
    return datetime.now(timezone.utc).isoformat()


def normalize_severity(severity_str):
    """Normalize any severity string to CRITICAL/HIGH/MEDIUM/LOW/INFO"""
    s = str(severity_str).upper().strip()
    if s in ['CRITICAL', 'ERROR']:
        return 'CRITICAL'
    elif s in ['HIGH', 'WARNING', 'WARN']:
        return 'HIGH'
    elif s in ['MEDIUM', 'MODERATE', 'INFO']:
        return 'MEDIUM'
    elif s in ['LOW']:
        return 'LOW'
    else:
        return 'INFO'


def make_finding(source, title, description, severity,
                 file_path=None, line_number=None, code_snippet=None,
                 remediation=None, cve_id=None, cwe_id=None,
                 cvss_score=None, references=None, pipeline_run_id="local"):
    """Create a finding in unified schema"""
    return {
        "id": str(uuid.uuid4()),
        "source": source,
        "title": title,
        "description": description,
        "severity": normalize_severity(severity),
        "cvss_score": cvss_score,
        "cve_id": cve_id,
        "cwe_id": cwe_id,
        "file_path": file_path or "unknown",
        "line_number": line_number or 0,
        "code_snippet": code_snippet or "",
        "remediation": remediation or "Review and fix the identified issue",
        "references": references or [],
        "detected_at": get_timestamp(),
        "pipeline_run_id": pipeline_run_id
    }


# ─────────────────────────────────────────────
# PARSER 1: SEMGREP
# ─────────────────────────────────────────────
def parse_semgrep(filepath):
    findings = []
    if not os.path.exists(filepath):
        print(f"[WARN] Semgrep file not found: {filepath}")
        return findings

    with open(filepath, encoding='utf-8') as f:
        data = json.load(f)

    results = data.get('results', [])
    print(f"[INFO] Semgrep: {len(results)} raw results")

    for r in results:
        extra = r.get('extra', {})
        metadata = extra.get('metadata', {})

        # Extract severity
        severity = extra.get('severity', 'WARNING')

        # Map semgrep severity
        sev_map = {'ERROR': 'CRITICAL', 'WARNING': 'HIGH',
                   'INFO': 'MEDIUM', 'NOTE': 'LOW'}
        severity = sev_map.get(severity.upper(), 'MEDIUM')

        # Extract CWE
        cwe_raw = metadata.get('cwe', [])
        if isinstance(cwe_raw, list):
            cwe_id = cwe_raw[0] if cwe_raw else None
        else:
            cwe_id = cwe_raw or None

        findings.append(make_finding(
            source="semgrep",
            title=r.get('check_id', 'Semgrep Finding'),
            description=extra.get('message', 'No description'),
            severity=severity,
            file_path=r.get('path'),
            line_number=r.get('start', {}).get('line', 0),
            code_snippet=extra.get('lines', ''),
            remediation=metadata.get('fix', 'Review Semgrep rule for remediation guidance'),
            cwe_id=str(cwe_id) if cwe_id else None,
            references=metadata.get('references', [])
        ))

    return findings


# ─────────────────────────────────────────────
# PARSER 2: GITLEAKS
# ─────────────────────────────────────────────
def parse_gitleaks(filepath):
    findings = []
    if not os.path.exists(filepath):
        print(f"[WARN] GitLeaks file not found: {filepath}")
        return findings

    with open(filepath, encoding='utf-8') as f:
        data = json.load(f)

    # GitLeaks output is a list
    if not isinstance(data, list):
        print("[WARN] GitLeaks: unexpected format")
        return findings

    print(f"[INFO] GitLeaks: {len(data)} raw results")

    for r in data:
        secret_val = r.get('Secret', r.get('secret', ''))
        # Redact the actual secret value for safety
        if secret_val and len(secret_val) > 4:
            redacted = secret_val[:2] + '*' * (len(secret_val) - 4) + secret_val[-2:]
        else:
            redacted = '***REDACTED***'

        # In history-mode, Gitleaks includes the SHA of the commit that
        # introduced the secret. Capture it so the finding can be linked
        # back to the exact historical commit, not just the current CI run.
        commit_introduced = (
            r.get('Commit') or r.get('commit') or None
        )
        author_introduced = (
            r.get('Author') or r.get('author') or None
        )
        date_introduced = (
            r.get('Date') or r.get('date') or None
        )

        finding = make_finding(
            source="gitleaks",
            title=f"Secret Detected: {r.get('Description', r.get('description', 'Unknown Secret'))}",
            description=(
                f"Hardcoded secret found. Value (redacted): {redacted}. "
                f"Rule: {r.get('RuleID', r.get('ruleID', 'unknown'))}."
                + (f" Originally introduced in commit {commit_introduced[:8]}." if commit_introduced else "")
            ),
            severity="HIGH",  # Secrets are always HIGH
            file_path=r.get('File', r.get('file', 'unknown')),
            line_number=r.get('StartLine', r.get('startLine', 0)),
            code_snippet=f"Match: {r.get('Match', r.get('match', ''))}",
            remediation="Remove secret from code immediately. Rotate the credential. "
                       "Use environment variables or a secrets manager instead.",
            cwe_id="CWE-798"
        )

        # Attach history-mode metadata so the dashboard and API can surface
        # exactly when and by whom the secret was originally committed.
        finding['commit_introduced']  = commit_introduced
        finding['author_introduced']  = author_introduced
        finding['date_introduced']    = date_introduced

        findings.append(finding)

    return findings


# ─────────────────────────────────────────────
# PARSER 3: PIP-AUDIT / DEPENDENCY CHECK
# ─────────────────────────────────────────────
def parse_dependency_check(filepath):
    findings = []
    if not os.path.exists(filepath):
        print(f"[WARN] Dependency check file not found: {filepath}")
        return findings

    with open(filepath, encoding='utf-8') as f:
        data = json.load(f)

    # Handle pip-audit format (list of packages)
    if isinstance(data, list):
        print(f"[INFO] pip-audit: {len(data)} packages scanned")
        for pkg in data:
            for vuln in pkg.get('vulns', []):
                findings.append(make_finding(
                    source="dependency-check",
                    title=f"{vuln.get('id', 'Unknown CVE')} in "
                          f"{pkg.get('name', '?')}=={pkg.get('version', '?')}",
                    description=vuln.get('description', 'Vulnerable dependency detected'),
                    severity="HIGH",
                    file_path="src/requirements.txt",
                    remediation=f"Upgrade {pkg.get('name')} to a non-vulnerable version. "
                               f"Fixed in: {vuln.get('fix_versions', 'check PyPI')}",
                    cve_id=vuln.get('id'),
                    cwe_id="CWE-1035"
                ))
        return findings

    # Handle OWASP Dependency-Check JSON format
    deps = data.get('dependencies', [])
    print(f"[INFO] OWASP Dep-Check: {len(deps)} dependencies scanned")
    for dep in deps:
        for vuln in dep.get('vulnerabilities', []):
            cvss = vuln.get('cvssv3', {}).get('baseScore') or \
                   vuln.get('cvssv2', {}).get('score')
            findings.append(make_finding(
                source="dependency-check",
                title=f"{vuln.get('name', 'Unknown CVE')} in "
                      f"{dep.get('fileName', 'unknown')}",
                description=vuln.get('description', 'Vulnerable dependency'),
                severity=vuln.get('severity', 'MEDIUM'),
                file_path="src/requirements.txt",
                cvss_score=float(cvss) if cvss else None,
                cve_id=vuln.get('name'),
                cwe_id="CWE-1035",
                remediation="Update the vulnerable dependency to a patched version"
            ))

    return findings


# ─────────────────────────────────────────────
# PARSER 4: TRIVY
# ─────────────────────────────────────────────
def parse_trivy(filepath):
    findings = []
    if not os.path.exists(filepath):
        print(f"[WARN] Trivy file not found: {filepath}")
        return findings

    with open(filepath, encoding='utf-8') as f:
        data = json.load(f)

    results = data.get('Results', [])
    print(f"[INFO] Trivy: {len(results)} result sets")

    for result in results:
        vulns = result.get('Vulnerabilities') or []
        for v in vulns:
            cvss_data = v.get('CVSS', {})
            cvss_score = None
            for source_data in cvss_data.values():
                if isinstance(source_data, dict) and 'V3Score' in source_data:
                    cvss_score = source_data['V3Score']
                    break

            findings.append(make_finding(
                source="trivy",
                title=f"{v.get('VulnerabilityID', 'Unknown')} - "
                      f"{v.get('PkgName', 'unknown package')}",
                description=v.get('Description', v.get('Title', 'Container vulnerability')),
                severity=v.get('Severity', 'MEDIUM'),
                file_path=f"Docker: {result.get('Target', 'unknown')}",
                cvss_score=cvss_score,
                cve_id=v.get('VulnerabilityID'),
                cwe_id=None,
                remediation=f"Update {v.get('PkgName', 'package')} from "
                           f"{v.get('InstalledVersion', '?')} to "
                           f"{v.get('FixedVersion', 'latest')}",
                references=[v.get('PrimaryURL', '')] if v.get('PrimaryURL') else []
            ))

    return findings


# ─────────────────────────────────────────────
# PARSER 5: OWASP ZAP
# ─────────────────────────────────────────────
def parse_zap(filepath):
    findings = []
    if not os.path.exists(filepath):
        print(f"[WARN] ZAP file not found: {filepath}")
        return findings

    with open(filepath, encoding='utf-8') as f:
        data = json.load(f)

    sites = data.get('site', [])
    print(f"[INFO] ZAP: {len(sites)} sites scanned")

    # Map ZAP riskcode to severity
    risk_map = {'3': 'HIGH', '2': 'MEDIUM', '1': 'LOW', '0': 'INFO'}

    for site in sites:
        for alert in site.get('alerts', []):
            riskcode = str(alert.get('riskcode', '1'))
            severity = risk_map.get(riskcode, 'LOW')

            # Get first instance URL for file_path
            instances = alert.get('instances', [])
            url = instances[0].get('uri', site.get('@name', '')) if instances else ''

            cwe_raw = alert.get('cweid', '')
            cwe_id = f"CWE-{cwe_raw}" if cwe_raw and cwe_raw != '-1' else None

            findings.append(make_finding(
                source="zap",
                title=alert.get('name', 'ZAP Alert'),
                description=alert.get('desc', 'No description').replace('<p>', '').replace('</p>', ''),
                severity=severity,
                file_path=url,
                remediation=alert.get('solution', 'Review ZAP alert for remediation').replace('<p>', '').replace('</p>', ''),
                cwe_id=cwe_id,
                references=[alert.get('reference', '')] if alert.get('reference') else []
            ))

    return findings


# ─────────────────────────────────────────────
# MAIN NORMALIZER
# ─────────────────────────────────────────────
def normalize_all(
    semgrep_path="tests/sample_data/semgrep-results.json",
    gitleaks_path="tests/sample_data/gitleaks-results.json",
    depcheck_path="tests/sample_data/dependency-check-report.json",
    trivy_path="tests/sample_data/trivy-results.json",
    zap_path="tests/sample_data/zap-results.json",
    output_path="normalized-findings.json",
    pipeline_run_id="local"
):
    print("\n" + "="*50)
    print("SECUREPIPELINE HUB - NORMALIZER")
    print("="*50)

    all_findings = []

    # Parse each scanner
    all_findings.extend(parse_semgrep(semgrep_path))
    all_findings.extend(parse_gitleaks(gitleaks_path))
    all_findings.extend(parse_dependency_check(depcheck_path))
    all_findings.extend(parse_trivy(trivy_path))
    all_findings.extend(parse_zap(zap_path))

    # Add pipeline_run_id to all findings
    for f in all_findings:
        f['pipeline_run_id'] = pipeline_run_id

    # Summary
    print(f"\n{'='*50}")
    print(f"NORMALIZATION COMPLETE")
    print(f"{'='*50}")
    print(f"Total findings: {len(all_findings)}")

    by_source = {}
    by_severity = {}
    for f in all_findings:
        by_source[f['source']] = by_source.get(f['source'], 0) + 1
        by_severity[f['severity']] = by_severity.get(f['severity'], 0) + 1

    print("\nBy source:")
    for src, count in sorted(by_source.items()):
        print(f"  {src}: {count}")

    print("\nBy severity:")
    for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
        if sev in by_severity:
            print(f"  {sev}: {by_severity[sev]}")

    # Write output
    with open(output_path, 'w') as f:
        json.dump(all_findings, f, indent=2)

    print(f"\n✅ Output written to: {output_path}")
    print("="*50)
    return all_findings


if __name__ == "__main__":
    normalize_all()