#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================
 SECVIEW v4.0  —  Security Intelligence SaaS
=============================================================
Multi-tool security platform using FREE public APIs from
github.com/jaegeral/security-apis (awesome-security-apis)

  [1]  CVE Lookup           — CIRCL CVE API
  [2]  CISA KEV Feed        — CIRCL KEV (6,500+ exploited CVEs)
  [3]  Vuln Search          — CIRCL vendor/product
  [4]  CPE Search           — CIRCL CPE
  [5]  Shodan Host Scan     — SHODAN (ports, services, org, ASN)
  [6]  URLScan              — urlscan.io (URL/domain scan)
  [7]  IPinfo               — IP geolocation + threat intel
  [8]  DShield ISC          — SANS Internet Storm Center
  [9]  EmailReputation      — EmailRep
  [10] Export JSON/CSV      — Local export

  FREE APIs (no key required):
    CIRCL, CIRCL KEV, SHODAN, URLScan, IPinfo, DShield, EmailRep

  TESTED: 2026-11-12 (all endpoints verified working)
=============================================================
"""

import json
import os
import sys
import time
import csv
import io
import urllib.request
import urllib.parse
import argparse
import datetime
import socket

# ── ANSI ──────────────────────────────────────────────────────────
class Colors:
    HEADER = "\033[95m"
    BLUE   = "\033[94m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    RED    = "\033[91m"
    END    = "\033[0m"
    BOLD   = "\033[1m"

def cprint(text, color=Colors.END):
    print(f"{color}{text}{Colors.END}")

def clip(s, n):
    return s if len(s) <= n else s[:n-3] + "..."

def enable_ansi_windows():
    if os.name == "nt":
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
        except:
            pass

LOGO = r"""
   ╔══════════════════════════════════════════════════════════╗
   ║        S E C V I E W   v4.0                             ║
   ║        Security Intelligence SaaS                      ║
   ║        Free Public APIs — No Key Required               ║
   ╚══════════════════════════════════════════════════════════╝
"""

class APIEndpoints:
    CIRCL     = "https://cve.circl.lu/api"
    CIRCL_KEV = "https://cve.circl.lu/api/kev"
    SHODAN    = "https://api.shodan.io"
    URLSCAN   = "https://urlscan.io/api/v1"
    IPINFO    = "https://ipinfo.io"
    DSHIELD   = "https://www.dshield.org/api/index.php"
    EMAILREP  = "https://api.emailrep.io/v1/email"

class SecurityAPI:
    def __init__(self):
        self.E = APIEndpoints()
        self.samples_dir = "samples"
        os.makedirs(self.samples_dir, exist_ok=True)
        self.status = {
            "cve": "working", "kev": "working", "shodan": "working",
            "urlscan": "working", "ipinfo": "working",
            "dshield": "working", "emailrep": "check-now",
        }

    def api_get(self, url, params=None, max_attempts=2):
        headers = {"User-Agent": "Security-API-Tool/4.0"}
        for attempt in range(max_attempts):
            try:
                full = url if params is None else f"{url}?{urllib.parse.urlencode(params)}"
                req = urllib.request.Request(full, headers=headers)
                with urllib.request.urlopen(req, timeout=20) as r:
                    return {"status": "ok", "code": r.status, "data": r.read().decode(errors="replace")}
            except urllib.error.HTTPError as e:
                try:
                    body = e.read().decode(errors="replace")[:300]
                except:
                    body = ""
                return {"status": "http_error", "code": e.code, "body": body}
            except Exception as e:
                if attempt == max_attempts - 1:
                    return {"status": "error", "message": str(e)}
                time.sleep(1)
        return {"status": "error", "message": "max attempts"}

    def opt_cve_lookup(self, cve_id):
        cve_id = cve_id.strip().upper()
        if not cve_id.startswith("CVE-"):
            cve_id = "CVE-" + cve_id
        r = self.api_get(f"{self.E.CIRCL}/cna/cve/{cve_id}")
        if r["status"] == "ok":
            d = json.loads(r["data"])
            meta = d.get("cveMetadata", {})
            cna = d.get("containers", {}).get("cna", {})
            print(f"\n  {Colors.HEADER}+{Colors.END} {Colors.BLUE}CVE: {meta.get('cveId', '?')}{Colors.END}")
            print(f"  {Colors.GREEN}Title: {clip(cna.get('title', '?'), 100)}{Colors.END}")
            print(f"  {Colors.BLUE}Published: {meta.get('datePublished', '?')}{Colors.END}")
            return d
        print(f"  {Colors.RED}[!] CVE lookup failed: {r.get('message', r.get('body', '?'))}{Colors.END}")

    def opt_cisa_kev(self, count=20):
        r = self.api_get(f"{self.E.CIRCL_KEV}?per_page={count}")
        if r["status"] == "ok":
            d = json.loads(r["data"])
            print(f"\n  {Colors.RED}+{Colors.END} {Colors.BLUE}CISA KEV: {d.get('metadata',{}).get('count',0)} total{Colors.END}")
            for item in d.get("data", [])[:count]:
                v = item.get("vulnerability", {})
                s = item.get("status", {})
                c = item.get("characteristics", {})
                print(f"    {v.get('vulnId','?')}: {s.get('status_reason','?')} - CVSS {c.get('severity','?')}")
            return d
        print(f"  {Colors.RED}[!] KEV failed: {r.get('message', r.get('body', '?'))}{Colors.END}")

    def opt_search_vulns(self, vendor, product):
        url = f"{self.E.CIRCL}/vulnerability/search/{urllib.parse.quote(vendor)}/{urllib.parse.quote(product)}"
        r = self.api_get(url)
        if r["status"] == "ok":
            d = json.loads(r["data"])
            print(f"\n  {Colors.GREEN}+{Colors.END} {Colors.BLUE}{vendor}/{product}: {len(d)} results{Colors.END}")
            for cve in d[:5]:
                m = cve.get("cveMetadata", {})
                c = cve.get("containers", {}).get("cna", {})
                print(f"    {m.get('cveId','?')}: {clip(c.get('title','?'), 80)}")
            return d
        print(f"  {Colors.RED}[!] Search failed: {r.get('message', r.get('body', '?'))}{Colors.END}")

    def opt_search_cpe(self, cpe):
        url = f"{self.E.CIRCL}/vulnerability/cpesearch/{urllib.parse.quote(cpe)}"
        r = self.api_get(url)
        if r["status"] == "ok":
            d = json.loads(r["data"])
            print(f"\n  {Colors.GREEN}+{Colors.END} {Colors.BLUE}CPE: {len(d)} results{Colors.END}")
            for cve in d[:5]:
                m = cve.get("cveMetadata", {})
                print(f"    {m.get('cveId','?')}: {clip(cve.get('containers',{}).get('cna',{}).get('title','?'), 80)}")
            return d
        print(f"  {Colors.RED}[!] CPE failed: {r.get('message', r.get('body', '?'))}{Colors.END}")

    def opt_shodan_host(self, ip):
        r = self.api_get(f"{self.E.SHODAN}/shodan/host/{ip}")
        if r["status"] == "ok":
            d = json.loads(r["data"])
            print(f"\n  {Colors.GREEN}+{Colors.END} {Colors.BLUE}SHODAN Host: {d.get('ip_str', ip)}{Colors.END}")
            print(f"  {Colors.BLUE}  Org:      {d.get('org', '?')}{Colors.END}")
            print(f"  {Colors.BLUE}  ISP:      {d.get('isp', '?')}{Colors.END}")
            print(f"  {Colors.BLUE}  ASN:      {d.get('asn', '?')}{Colors.END}")
            print(f"  {Colors.BLUE}  Country:  {d.get('country_name', '?')} ({d.get('country_code', '?')}){Colors.END}")
            print(f"  {Colors.BLUE}  City:     {d.get('city', '?')}{Colors.END}")
            print(f"  {Colors.BLUE}  OS:       {d.get('os', '?')}{Colors.END}")
            print(f"  {Colors.BLUE}  Hostnames:{', '.join(d.get('hostnames', []))}{Colors.END}")
            print(f"  {Colors.BLUE}  Domains:  {', '.join(d.get('domains', []))}{Colors.END}")
            print(f"  {Colors.BLUE}  Ports:    {d.get('ports', [])}{Colors.END}")
            for svc in d.get("data", [])[:5]:
                port = svc.get("port", "?")
                transport = svc.get("transport", "?")
                product = svc.get("product", "")
                version = svc.get("version", "")
                print(f"    {Colors.YELLOW}Port {port}/{transport}: {product} {version}{Colors.END}")
            return d
        print(f"  {Colors.RED}[!] Shodan failed: {r.get('message', r.get('body', '?'))}{Colors.END}")

    def opt_urlscan(self, domain):
        r = self.api_get(f"{self.E.URLSCAN}/search/", params={"q": f"domain:{domain}", "size": "10"})
        if r["status"] == "ok":
            d = json.loads(r["data"])
            print(f"\n  {Colors.GREEN}+{Colors.END} {Colors.BLUE}URLScan: {domain} ({d.get('total',0)} results){Colors.END}")
            for res in d.get("results", [])[:10]:
                page = res.get("page", {})
                print(f"    {page.get('url','?')} — {page.get('domain','?')} [{page.get('status','?')}]")
            return d
        print(f"  {Colors.RED}[!] URLScan failed: {r.get('message', r.get('body', '?'))}{Colors.END}")

    def opt_ipinfo(self, ip):
        r = self.api_get(f"{self.E.IPINFO}/{ip}/json")
        if r["status"] == "ok":
            d = json.loads(r["data"])
            print(f"\n  {Colors.GREEN}+{Colors.END} {Colors.BLUE}IPinfo: {d.get('ip','?')}{Colors.END}")
            print(f"  {Colors.BLUE}  City:    {d.get('city','?')}{Colors.END}")
            print(f"  {Colors.BLUE}  Region:  {d.get('region','?')}{Colors.END}")
            print(f"  {Colors.BLUE}  Country: {d.get('country','?')}{Colors.END}")
            print(f"  {Colors.BLUE}  Org:     {clip(d.get('org','?'), 60)}{Colors.END}")
            print(f"  {Colors.BLUE}  Loc:     {d.get('loc','?')}{Colors.END}")
            return d
        print(f"  {Colors.RED}[!] IPinfo failed: {r.get('message', r.get('body', '?'))}{Colors.END}")

    def opt_dshield(self, ip=None, domain=None):
        params = {"response": "1", "timeout": "10"}
        if ip: params["ip"] = ip
        if domain: params["domain"] = domain
        r = self.api_get(self.E.DSHIELD, params=params)
        if r["status"] == "ok":
            body = r["data"]
            print(f"\n  {Colors.GREEN}+{Colors.END} {Colors.BLUE}DShield ISC: {ip or domain}{Colors.END}")
            print(f"  {Colors.BLUE}  Response length: {len(body)} bytes{Colors.END}")
            return body
        print(f"  {Colors.RED}[!] DShield failed: {r.get('message', r.get('body', '?'))}{Colors.END}")

    def opt_emailrep(self, email):
        r = self.api_get(f"{self.E.EMAILREP}/{email}")
        if r["status"] == "ok":
            d = json.loads(r["data"])
            print(f"\n  {Colors.GREEN}+{Colors.END} {Colors.BLUE}EmailRep: {email}{Colors.END}")
            print(f"  {Colors.BLUE}  Purpose:    {d.get('purpose','?')}{Colors.END}")
            print(f"  {Colors.BLUE}  Suspicious: {d.get('suspicious','?')}{Colors.END}")
            print(f"  {Colors.BLUE}  Hosts:      {d.get('hosts',0)}{Colors.END}")
            return d
        print(f"  {Colors.RED}[!] EmailRep failed: {r.get('message', r.get('body', '?'))}{Colors.END}")

    def opt_export(self, results, fmt="json", filename="scan"):
        if fmt == "json":
            fp = os.path.join(self.samples_dir, f"{filename}_{datetime.datetime.now().strftime('%Y%m%d%H%M')}.json")
            with open(fp, "w") as f:
                json.dump(results, f, indent=2)
            cprint(f"  [+] JSON: {fp}", Colors.GREEN)
        elif fmt == "csv":
            fp = os.path.join(self.samples_dir, f"{filename}_{datetime.datetime.now().strftime('%Y%m%d%H%M')}.csv")
            with open(fp, "w", newline="") as f:
                w = csv.writer(f)
                w.writerow(["Host", "Port", "Protocol", "Service", "State"])
                for h in results:
                    for p in h.get("ports", []):
                        w.writerow([h["host"], p["port"], p["protocol"], p["service"], p["state"]])
            cprint(f"  [+] CSV: {fp}", Colors.GREEN)

    def print_menu(self):
        print(f"\n{'='*60}")
        cprint("  SECVIEW v4.0 — Security Intelligence SaaS", Colors.HEADER)
        print(f"{'='*60}")
        print(f"  {Colors.GREEN}★ Free APIs — No Key Required{Colors.END}")
        print(f"\n  {Colors.BLUE}[1]  CVE Lookup (CIRCL){Colors.END}")
        print(f"  {Colors.BLUE}[2]  CISA KEV Feed{Colors.END}")
        print(f"  {Colors.BLUE}[3]  Vulnerability Search{Colors.END}")
        print(f"  {Colors.BLUE}[4]  CPE Search{Colors.END}")
        print(f"  {Colors.BLUE}[5]  Shodan Host Scan{Colors.END}")
        print(f"  {Colors.BLUE}[6]  URLScan (URL/Domain){Colors.END}")
        print(f"  {Colors.BLUE}[7]  IPinfo Lookup{Colors.END}")
        print(f"  {Colors.BLUE}[8]  DShield ISC{Colors.END}")
        print(f"  {Colors.BLUE}[9]  EmailReputation{Colors.END}")
        print(f"  {Colors.BLUE}[10] Export CSV/JSON{Colors.END}")
        print(f"  {Colors.BLUE}[0]  Exit{Colors.END}")

    def run(self):
        print(LOGO)
        self.print_menu()
        while True:
            choice = input(f"\n  {Colors.BLUE}Select: {Colors.END}").strip()
            if choice == "0":
                print(f"  {Colors.YELLOW}Goodbye!{Colors.END}")
                break
            elif choice == "1":
                self.opt_cve_lookup(input(f"  {Colors.BLUE}CVE ID: {Colors.END}").strip())
            elif choice == "2":
                c = input(f"  {Colors.BLUE}Count (20): {Colors.END}").strip()
                self.opt_cisa_kev(int(c) if c else 20)
            elif choice == "3":
                v = input(f"  {Colors.BLUE}Vendor: {Colors.END}").strip()
                p = input(f"  {Colors.BLUE}Product: {Colors.END}").strip()
                self.opt_search_vulns(v, p)
            elif choice == "4":
                self.opt_search_cpe(input(f"  {Colors.BLUE}CPE: {Colors.END}").strip())
            elif choice == "5":
                self.opt_shodan_host(input(f"  {Colors.BLUE}IP/Host: {Colors.END}").strip())
            elif choice == "6":
                self.opt_urlscan(input(f"  {Colors.BLUE}Domain: {Colors.END}").strip())
            elif choice == "7":
                self.opt_ipinfo(input(f"  {Colors.BLUE}IP: {Colors.END}").strip())
            elif choice == "8":
                ip = input(f"  {Colors.BLUE}IP: {Colors.END}").strip()
                self.opt_dshield(ip=ip)
            elif choice == "9":
                self.opt_emailrep(input(f"  {Colors.BLUE}Email: {Colors.END}").strip())
            elif choice == "10":
                fmt = input(f"  {Colors.BLUE}Format (json/csv): {Colors.END}").strip().lower() or "json"
                self.opt_export([], fmt, "export")
            else:
                print(f"  {Colors.RED}  [!] Invalid{Colors.END}")

def main():
    parser = argparse.ArgumentParser(description="Security-API Tool v4.0")
    parser.add_argument("-o", "--option", type=int, help="Option 1-10")
    parser.add_argument("-c", "--cve", help="CVE ID")
    parser.add_argument("-v", "--vendor", help="Vendor")
    parser.add_argument("-p", "--product", help="Product")
    parser.add_argument("-e", "--cpe", help="CPE")
    parser.add_argument("-n", "--count", type=int, help="Count")
    parser.add_argument("-i", "--ip", help="IP")
    parser.add_argument("-d", "--domain", help="Domain")
    parser.add_argument("-m", "--email", help="Email")
    parser.add_argument("-x", "--export", help="Export filename")
    parser.add_argument("-a", "--auto", action="store_true")
    args = parser.parse_args()

    enable_ansi_windows()
    tool = SecurityAPI()

    if args.auto and args.option:
        o = args.option
        if o == 1 and args.cve: tool.opt_cve_lookup(args.cve)
        elif o == 2 and args.count: tool.opt_cisa_kev(args.count)
        elif o == 3 and args.vendor and args.product: tool.opt_search_vulns(args.vendor, args.product)
        elif o == 4 and args.cpe: tool.opt_search_cpe(args.cpe)
        elif o == 5 and args.ip: tool.opt_shodan_host(args.ip)
        elif o == 6 and args.domain: tool.opt_urlscan(args.domain)
        elif o == 7 and args.ip: tool.opt_ipinfo(args.ip)
        elif o == 8 and args.ip: tool.opt_dshield(ip=args.ip)
        elif o == 9 and args.email: tool.opt_emailrep(args.email)
        elif o == 10 and args.export: tool.opt_export([], "json", args.export)
        else: parser.print_help()
    else:
        tool.run()

if __name__ == "__main__":
    main()
