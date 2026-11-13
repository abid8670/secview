#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SECVIEW — Flask Web Interface v4.0
=============================================
Open SaaS for Security Experts.
Side-navigation UI, loading states, API info.

  Run:  python app.py
  URL:  http://localhost:<random>/
"""

import sys
import os
import json
import io
import datetime

from flask import Flask, render_template, request, jsonify, send_file

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from security_apis_tool import SecurityAPI, LOGO

api = SecurityAPI()

app = Flask(__name__)
app.config["SECRET_KEY"] = "security-api-tool-2026"


# ── Pages ─────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("landing.html")

@app.route("/app")
def tool():
    return render_template("app.html")

# ── API endpoints ─────────────────────────────────────────────────
@app.route("/api/cve", methods=["POST"])
def api_cve():
    d = request.get_json() or {}
    cve = (d.get("cve") or "").strip().upper()
    if not cve:
        return jsonify({"ok": False, "error": "CVE ID required"})
    if not cve.startswith("CVE-"):
        cve = "CVE-" + cve
    r = api.api_get(f"{api.E.CIRCL}/cna/cve/{cve}")
    if r["status"] == "ok":
        d = json.loads(r["data"])
        meta = d.get("cveMetadata", {})
        cna = d.get("containers", {}).get("cna", {})
        # Build a clean, readable summary
        descriptions = cna.get("descriptions", [])
        desc_text = descriptions[0].get("value", "?") if descriptions else "?"
        affected = cna.get("affected", [])
        affected_list = []
        for a in affected[:5]:
            vendor = a.get("vendor", "?")
            product = a.get("product", "?")
            versions = a.get("versions", [])
            ver_list = [v.get("version", "?") for v in versions[:3]]
            affected_list.append(f"{vendor}/{product} ({', '.join(ver_list)})")
        # CVSS: check CNA first, then ADP (CISA enrichment) containers
        metrics = cna.get("metrics", [])
        cvss_score = None
        cvss_sev = None
        for m in metrics:
            cvss_data = m.get("cvssV3_1", {}) or m.get("cvssV3_0", {}) or m.get("cvssV2_0", {})
            if cvss_data:
                cvss_score = cvss_data.get("baseScore", "?")
                cvss_sev = cvss_data.get("baseSeverity", "?")
                break
        if not cvss_score:
            for adp in d.get("containers", {}).get("adp", []):
                for m in adp.get("metrics", []):
                    cvss_data = m.get("cvssV3_1", {}) or m.get("cvssV3_0", {}) or m.get("cvssV2_0", {})
                    if cvss_data:
                        cvss_score = cvss_data.get("baseScore", "?")
                        cvss_sev = cvss_data.get("baseSeverity", "?")
                        break
                if cvss_score:
                    break
        refs = cna.get("references", [])
        ref_urls = [r.get("url", "") for r in refs[:5]]
        return jsonify({"ok": True, "data": {
            "cveId": meta.get("cveId", "?"),
            "title": cna.get("title", "?"),
            "description": desc_text,
            "published": meta.get("datePublished", "?"),
            "updated": meta.get("dateUpdated", "?"),
            "state": meta.get("state", "?"),
            "cvssScore": cvss_score,
            "cvssSeverity": cvss_sev,
            "affected": affected_list,
            "references": ref_urls,
        }})
    return jsonify({"ok": False, "error": f"HTTP {r.get('code', '?')}"})


@app.route("/api/kev", methods=["POST"])
def api_kev():
    d = request.get_json() or {}
    count = int(d.get("count", 20))
    r = api.api_get(f"{api.E.CIRCL_KEV}?per_page={count}")
    if r["status"] == "ok":
        return jsonify({"ok": True, "data": json.loads(r["data"])})
    return jsonify({"ok": False, "error": f"HTTP {r.get('code', '?')}"})


@app.route("/api/search", methods=["POST"])
def api_search():
    d = request.get_json() or {}
    vendor = (d.get("vendor") or "").strip()
    product = (d.get("product") or "").strip()
    if not vendor or not product:
        return jsonify({"ok": False, "error": "Vendor and product required"})
    import urllib.parse
    url = f"{api.E.CIRCL}/vulnerability/search/{urllib.parse.quote(vendor)}/{urllib.parse.quote(product)}"
    r = api.api_get(url)
    if r["status"] == "ok":
        return jsonify({"ok": True, "data": json.loads(r["data"])})
    return jsonify({"ok": False, "error": f"HTTP {r.get('code', '?')}"})


@app.route("/api/cpe", methods=["POST"])
def api_cpe():
    d = request.get_json() or {}
    cpe = (d.get("cpe") or "").strip()
    if not cpe:
        return jsonify({"ok": False, "error": "CPE required"})
    import urllib.parse
    url = f"{api.E.CIRCL}/vulnerability/cpesearch/{urllib.parse.quote(cpe)}"
    r = api.api_get(url)
    if r["status"] == "ok":
        return jsonify({"ok": True, "data": json.loads(r["data"])})
    return jsonify({"ok": False, "error": f"HTTP {r.get('code', '?')}"})


@app.route("/api/shodan-host", methods=["POST"])
def api_shodan_host():
    d = request.get_json() or {}
    ip = (d.get("ip") or "").strip()
    if not ip:
        return jsonify({"ok": False, "error": "IP required"})
    r = api.api_get(f"{api.E.SHODAN}/shodan/host/{ip}")
    if r["status"] == "ok":
        return jsonify({"ok": True, "data": json.loads(r["data"])})
    return jsonify({"ok": False, "error": f"HTTP {r.get('code', '?')}"})


@app.route("/api/urlscan", methods=["POST"])
def api_urlscan():
    d = request.get_json() or {}
    domain = (d.get("domain") or "").strip()
    if not domain:
        return jsonify({"ok": False, "error": "Domain required"})
    r = api.api_get(f"{api.E.URLSCAN}/search/", params={"q": f"domain:{domain}", "size": "10"})
    if r["status"] == "ok":
        return jsonify({"ok": True, "data": json.loads(r["data"])})
    return jsonify({"ok": False, "error": f"HTTP {r.get('code', '?')}"})


@app.route("/api/ipinfo", methods=["POST"])
def api_ipinfo():
    d = request.get_json() or {}
    ip = (d.get("ip") or "").strip()
    if not ip:
        return jsonify({"ok": False, "error": "IP required"})
    r = api.api_get(f"{api.E.IPINFO}/{ip}/json")
    if r["status"] == "ok":
        return jsonify({"ok": True, "data": json.loads(r["data"])})
    return jsonify({"ok": False, "error": f"HTTP {r.get('code', '?')}"})


@app.route("/api/dshield", methods=["POST"])
def api_dshield():
    d = request.get_json() or {}
    ip = (d.get("ip") or "").strip()
    if not ip:
        return jsonify({"ok": False, "error": "IP required"})
    r = api.api_get(api.E.DSHIELD, params={"response": "1", "timeout": "10", "ip": ip})
    if r["status"] == "ok":
        return jsonify({"ok": True, "data": r["data"][:500]})
    return jsonify({"ok": False, "error": f"HTTP {r.get('code', '?')}"})


@app.route("/api/email", methods=["POST"])
def api_email():
    d = request.get_json() or {}
    email = (d.get("email") or "").strip()
    if not email:
        return jsonify({"ok": False, "error": "Email required"})
    r = api.api_get(f"{api.E.EMAILREP}/{email}")
    if r["status"] == "ok":
        return jsonify({"ok": True, "data": json.loads(r["data"])})
    return jsonify({"ok": False, "error": f"HTTP {r.get('code', '?')}"})


@app.route("/api/export", methods=["POST"])
def api_export():
    d = request.get_json() or {}
    fmt = d.get("format", "json")
    filename = d.get("filename", "export")
    api.opt_export([], fmt, filename)
    files = [f for f in os.listdir(api.samples_dir) if f.startswith(filename)]
    if files:
        return jsonify({"ok": True, "file": files[-1]})
    return jsonify({"ok": False, "error": "Export failed"})


@app.route("/api/status", methods=["GET"])
def api_status():
    return jsonify({"ok": True, "status": api.status, "logo": LOGO})


# ── Run ───────────────────────────────────────────────────────────
if __name__ == "__main__":
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("", 0))
    port = s.getsockname()[1]
    s.close()
    print(f"\n  ╔══════════════════════════════════════════════╗")
    print(f"  ║   SECVIEW v4.0 — Security Intelligence SaaS   ║")
    print(f"  ╚══════════════════════════════════════════════╝")
    print(f"\n  → Open: http://localhost:{port}/")
    print(f"  → Press Ctrl+C to stop\n")
    app.run(host="127.0.0.1", port=port, debug=False)
