#!/usr/bin/env python3
"""SecView v4.0 — web interface endpoint test script"""
import json
import urllib.request

BASE = "http://localhost:5000"


def test_api(name, url, data=None):
    """Test one API endpoint."""
    try:
        req = urllib.request.Request(
            url, data=data, headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=15) as r:
            result = json.loads(r.read().decode())
            ok = result.get("ok")
            print(f"  {'✓' if ok else '✗'} {name}: {'OK' if ok else result.get('error')}")
            return result
    except Exception as e:
        print(f"  ✗ {name}: ERROR - {e}")
        return None


print("=" * 50)
print("  SECVIEW v4.0 — WEB INTERFACE TEST")
print("=" * 50)

# API endpoints
test_api("CVE lookup", f"{BASE}/api/cve",
         json.dumps({"cve": "CVE-2021-44228"}).encode())
test_api("KEV feed", f"{BASE}/api/kev",
         json.dumps({"count": 5}).encode())
test_api("IPinfo", f"{BASE}/api/ipinfo",
         json.dumps({"ip": "8.8.8.8"}).encode())
test_api("Shodan host", f"{BASE}/api/shodan-host",
         json.dumps({"ip": "8.8.8.8"}).encode())
test_api("URLScan", f"{BASE}/api/urlscan",
         json.dumps({"domain": "example.com"}).encode())
test_api("DShield", f"{BASE}/api/dshield",
         json.dumps({"ip": "8.8.8.8"}).encode())

# Web pages
for name, path in [("Landing page", "/"), ("Tool console", "/app")]:
    try:
        req = urllib.request.Request(
            f"{BASE}{path}", headers={"User-Agent": "Mozilla/5.0"}
        )
        with urllib.request.urlopen(req, timeout=10) as r:
            html = r.read().decode()
            print(f"  ✓ {name}: OK (HTTP {r.status}, {len(html)} bytes)")
    except Exception as e:
        print(f"  ✗ {name}: ERROR - {e}")

print("=" * 50)
print("  ALL TESTS COMPLETE")
print("=" * 50)
