#!/usr/bin/env python3
# scripts/zap_auth.py
# Logs into the app, retrieves a JWT token, and writes a ZAP
# automation config file that injects the Authorization header
# into every request ZAP makes. Run this before zap-baseline.py.

import json
import os
import sys
import urllib.request
import urllib.error

APP_URL   = os.environ.get("APP_URL", "http://host.docker.internal:3000")
EMAIL     = os.environ.get("ZAP_TEST_EMAIL", "")
PASSWORD  = os.environ.get("ZAP_TEST_PASSWORD", "")
# This file is written into the volume mount so ZAP can read it
OUT_FILE  = os.environ.get("ZAP_AUTH_PROP_FILE", "zap_auth.prop")

if not EMAIL or not PASSWORD:
    print("[zap_auth] ZAP_TEST_EMAIL or ZAP_TEST_PASSWORD not set — skipping auth")
    sys.exit(0)

print(f"[zap_auth] Logging in as {EMAIL} at {APP_URL}/api/auth/login")

payload = json.dumps({"email": EMAIL, "password": PASSWORD}).encode("utf-8")
req = urllib.request.Request(
    f"{APP_URL}/api/auth/login",
    data=payload,
    headers={"Content-Type": "application/json"},
    method="POST",
)

try:
    with urllib.request.urlopen(req, timeout=15) as resp:
        data = json.loads(resp.read().decode("utf-8"))
except urllib.error.HTTPError as e:
    body = e.read().decode("utf-8")
    print(f"[zap_auth] Login failed: HTTP {e.code} — {body}")
    sys.exit(1)
except Exception as e:
    print(f"[zap_auth] Login request failed: {e}")
    sys.exit(1)

token = data.get("token")
if not token:
    print(f"[zap_auth] No token in response: {data}")
    sys.exit(1)

print(f"[zap_auth] Token obtained: {token[:12]}...")

# Write a ZAP properties file that configures the replacer add-on
# to inject the Authorization header into every outgoing request.
# ZAP reads this via the -z flag (additional options).
prop_lines = [
    f"replacer.full_list(0).description=JWT Auth\n",
    f"replacer.full_list(0).enabled=true\n",
    f"replacer.full_list(0).matchtype=REQ_HEADER\n",
    f"replacer.full_list(0).matchstr=Authorization\n",
    f"replacer.full_list(0).replacement=Bearer {token}\n",
    f"replacer.full_list(0).initiators=\n",
]

with open(OUT_FILE, "w") as f:
    f.writelines(prop_lines)

print(f"[zap_auth] ZAP auth prop file written to {OUT_FILE}")
sys.exit(0)