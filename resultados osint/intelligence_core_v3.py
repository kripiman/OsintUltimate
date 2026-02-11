#!/usr/bin/env python3
"""
INTELLIGENCE_CORE v3.0
Advanced Threat Triage & Passive Intelligence Engine (Academic / Authorized Use Only)

Características:
- Enriquecimiento: DNS concurrente, ASN validation, SSL cert parsing
- Identidad pasiva: favicon hashing (SHA256), header fingerprinting
- Scoring: Heurística + CVE local weighting (opcional)
- Correlación: clustering por ASN/tech/cert
- Output: HTML colorizado + final_targets.txt
- Plugins: arquitectura simple para añadir módulos de enriquecimiento
- Pipeline: invoca scanner.py si se solicita (opcional)

Aviso legal y ético:
USO EXCLUSIVO EN ENTORNOS AUTORIZADOS. No ejecutar en sistemas sin permiso.
"""

import argparse
import json
import os
import sys
import socket
import ssl
import hashlib
import subprocess
import time
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict, Counter
from dataclasses import dataclass, field
from typing import List, Dict, Optional

# -----------------------------
# Dependencias opcionales
# -----------------------------
try:
    # Prefer ipwhois for ASN lookups if available
    from ipwhois import IPWhois
    HAVE_IPWHOIS = True
except Exception:
    HAVE_IPWHOIS = False

# urllib for passive fetching (favicon)
try:
    from urllib.request import urlopen, Request
    from urllib.error import URLError, HTTPError
except Exception:
    print("[!] Error: urllib unavailable. This script requires Python stdlib urllib.")
    sys.exit(1)

# -----------------------------
# DATACLASS
# -----------------------------
@dataclass
class RiskProfile:
    score: int = 0
    severity: str = "INFO"
    vectors: List[str] = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)
    suggested_commands: List[str] = field(default_factory=list)

@dataclass
class Asset:
    url: str
    domain: str
    ip: Optional[str]
    asn: Optional[str]
    status: int
    title: str
    tech: List[str]
    size: int
    ssl_issuer: Optional[str]
    ssl_sans: List[str]
    favicon_hash: Optional[str]
    risk: RiskProfile

# -----------------------------
# CONFIG
# -----------------------------
DEFAULT_MAX_WORKERS = 20
HTML_TEMPLATE = """<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Intelligence Core v3.0 - Report</title>
  <style>
    body {{font-family: Inter, Roboto, Arial; padding: 20px; background:#f7fafc}}
    table {{border-collapse: collapse; width: 100%; background: white; box-shadow: 0 2px 6px rgba(0,0,0,0.06)}}
    th, td {{padding: 8px 10px; text-align: left; border-bottom: 1px solid #eee}}
    th {{background: #0f172a; color: #fff}}
    .CRITICAL {{background: #ffe6e6}}
    .HIGH {{background: #fff0e6}}
    .MEDIUM {{background: #fffbe6}}
    .LOW {{background: #f6ffed}}
    .INFO {{background: #eef2ff}}
    .badge {{display:inline-block; padding:2px 6px; border-radius:4px; font-size:12px}}
  </style>
</head>
<body>
  <h1>Intelligence Core v3.0 - Report</h1>
  <p>Generated: {ts}</p>
  <h2>Summary</h2>
  <ul>
    <li>Total assets processed: {total}</li>
    <li>By severity: {severity_counts}</li>
  </ul>
  <h2>Detailed Assets</h2>
  <table>
    <thead><tr>
      <th>Severity</th><th>Score</th><th>Domain (IP / ASN)</th><th>Title</th><th>Tech</th><th>Vectors & Reasons</th><th>Suggested</th>
    </tr></thead>
    <tbody>
      {rows}
    </tbody>
  </table>
</body>
</html>"""

# -----------------------------
# HELPERS
# -----------------------------
def safe_gethost(domain: str, timeout: float = 3.0) -> Optional[str]:
    """Resolve domain to IP address (simple, blocking)."""
    try:
        # set timeout on socket operations
        orig = socket.getdefaulttimeout()
        socket.setdefaulttimeout(timeout)
        ip = socket.gethostbyname(domain)
        socket.setdefaulttimeout(orig)
        return ip
    except Exception:
        return None

def fetch_favicon_hash(domain: str, scheme: str = "https", timeout: float = 4.0) -> Optional[str]:
    """Try to fetch /favicon.ico and return sha256 hash (hex)."""
    try:
        url = f"{scheme}://{domain}/favicon.ico"
        req = Request(url, headers={"User-Agent": "IntelligenceCore/3.0 (+academic)"})
        with urlopen(req, timeout=timeout) as resp:
            data = resp.read(200 * 1024)  # avoid huge files
            h = hashlib.sha256(data).hexdigest()
            return h
    except Exception:
        # try http fallback
        if scheme == "https":
            return fetch_favicon_hash(domain, scheme="http", timeout=timeout)
        return None

def get_ssl_cert_info(domain: str, timeout=3.0) -> Dict:
    """Obtain basic SSL SANs and issuer — non-verifying (best-effort)."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((domain, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                sans = []
                if 'subjectAltName' in cert:
                    sans = [x[1] for x in cert['subjectAltName'] if x[0] == 'DNS']
                issuer = cert.get('issuer', [])
                # issuer is list of tuples; extract CN-ish if possible
                issuer_str = None
                try:
                    issuer_str = dict(issuer[0])[0]
                except Exception:
                    issuer_str = str(issuer)[:80]
                return {'issuer': issuer_str, 'sans': sans}
    except Exception:
        return {'issuer': None, 'sans': []}

def whois_asn_lookup(ip: str) -> Optional[str]:
    """
    Try to get ASN/network owner.
    1) If ipwhois installed, use it.
    2) Else try 'whois' system command and parse 'origin' or 'originas' or 'origin:'.
    Returns a short ASN string like 'AS12345 (ORGNAME)' or None.
    """
    if not ip:
        return None
    if HAVE_IPWHOIS:
        try:
            obj = IPWhois(ip)
            res = obj.lookup_rdap(depth=1)
            asn = res.get('asn', None)
            asn_org = res.get('asn_description', None)
            if asn:
                return f"AS{asn} ({asn_org})" if asn_org else f"AS{asn}"
        except Exception:
            pass

    # fallback to whois command parsing
    try:
        p = subprocess.run(['whois', ip], capture_output=True, text=True, timeout=6)
        out = p.stdout.lower()
        for key in ('origin:', 'originas:', 'originas', 'originasn:'):
            idx = out.find(key)
            if idx != -1:
                # read until newline
                line = out[idx:idx+120].splitlines()[0]
                return line.strip()
        # try netname/org lines
        for key in ('netname:', 'org-name:', 'org:'):
            idx = out.find(key)
            if idx != -1:
                line = out[idx:idx+120].splitlines()[0]
                return line.strip()
    except Exception:
        pass
    return None

# -----------------------------
# RISK ENGINE (v3)
# -----------------------------
class RiskEngineV3:
    def __init__(self, cve_db: Optional[Dict] = None, mitre_map: Optional[Dict] = None):
        # base weights by technology
        self.tech_weights = {
            'WordPress': 9, 'Drupal': 8, 'Joomla': 7, 'Laravel': 7,
            'Tomcat': 8, 'JBoss': 9, 'IIS': 5, 'Apache': 3, 'Nginx': 3
        }
        # optional CVE DB: { "WordPress": [{"cve":"CVE-YYYY-XXXX","cvss":9.8}, ...], ...}
        self.cve_db = cve_db or {}
        # MITRE mapping: tech -> [ATT&CK IDs]
        self.mitre_map = mitre_map or {
            'WordPress': ['T1190'], 'Tomcat': ['T1190'], 'IIS': ['T1190'],
            'Laravel': ['T1190'], 'JBoss': ['T1190']
        }

    def evaluate(self, entry: Dict) -> RiskProfile:
        score = 0
        reasons = []
        vectors = []
        cmds = []

        status = entry.get('status', 0)
        techs = entry.get('tech', [])
        title = entry.get('title', '').lower()
        size = entry.get('size', 0)
        url = entry.get('url', '')

        # Tech weights & suggested commands
        for t in techs:
            w = self.tech_weights.get(t, 2)
            score += w
            reasons.append(f"Tech:{t}(w={w})")
            if t == 'WordPress':
                cmds.append(f"wpscan --url {url} --enumerate p,u")
            if t == 'Tomcat':
                cmds.append(f"nikto -host {url} -Tuning 1")
            # MITRE correlation
            if t in self.mitre_map:
                vectors += self.mitre_map[t]

            # CVE boosting
            if t in self.cve_db:
                # pick highest CVSS if present
                top = max((c.get('cvss', 0) for c in self.cve_db[t]), default=0)
                boost = int(top)  # simple mapping
                score += boost
                reasons.append(f"CVEBoost:{t}(+{boost})")

        # status & behavior heuristics
        if status == 403 and techs:
            score += 4
            reasons.append("AccessRestricted(403) -> potential admin/waf")
        if status == 200 and any(k in title for k in ('login', 'admin', 'panel', 'intranet')):
            score += 8
            reasons.append("Exposed login page")
            vectors.append('Exposed_Login_Panel')
        if size > 200000:
            score += 3
            reasons.append("Large application size")
        if entry.get('ssl_sans'):
            score += 1

        # Simple severity mapping
        severity = "INFO"
        if score >= 20: severity = "CRITICAL"
        elif score >= 12: severity = "HIGH"
        elif score >= 6: severity = "MEDIUM"
        elif score > 0: severity = "LOW"

        rp = RiskProfile(score=score, severity=severity, vectors=list(set(vectors)), reasons=reasons, suggested_commands=cmds)
        return rp

# -----------------------------
# PLUGIN FRAMEWORK (simple)
# -----------------------------
class BasePlugin:
    """Plugins should implement enrich_asset(self, asset: Asset) -> Asset"""
    def enrich_asset(self, asset: Asset) -> Asset:
        return asset

class PluginManager:
    def __init__(self, plugin_dir: str = None):
        self.plugins: List[BasePlugin] = []
        if plugin_dir and os.path.isdir(plugin_dir):
            sys.path.insert(0, plugin_dir)
            for fname in os.listdir(plugin_dir):
                if not fname.endswith('.py') or fname.startswith('_'): continue
                modname = fname[:-3]
                try:
                    mod = __import__(modname)
                    if hasattr(mod, 'init_plugin'):
                        p = mod.init_plugin()
                        if isinstance(p, BasePlugin):
                            self.plugins.append(p)
                except Exception as e:
                    print(f"[!] Failed to load plugin {modname}: {e}")

    def enrich(self, asset: Asset) -> Asset:
        for p in self.plugins:
            try:
                asset = p.enrich_asset(asset)
            except Exception:
                pass
        return asset

# -----------------------------
# CLUSTERING ENGINE (simple)
# -----------------------------
class ClusteringEngine:
    def cluster(self, assets: List[Asset]) -> Dict[str, List[Asset]]:
        """
        Creates simple clusters:
         - by ASN
         - by favicon hash (families)
         - by primary technology (first tech)
        Returns dict with cluster_name -> list
        """
        clusters = defaultdict(list)
        for a in assets:
            asn = a.asn or "ASN_UNKNOWN"
            clusters[f"ASN::{asn}"].append(a)
            if a.favicon_hash:
                clusters[f"FAVICON::{a.favicon_hash[:8]}"].append(a)
            if a.tech:
                clusters[f"TECH::{a.tech[0]}"].append(a)
        return clusters

# -----------------------------
# REPORTER (HTML)
# -----------------------------
class Reporter:
    def __init__(self, out_html: str = "report_v3.html"):
        self.out_html = out_html

    def render(self, assets: List[Asset]):
        rows_html = []
        severity_counts = Counter([a.risk.severity for a in assets])
        for a in assets:
            sev = a.risk.severity
            vectors = "; ".join(a.risk.vectors + a.risk.reasons)
            techs = ", ".join(a.tech)
            suggest = "<br>".join(a.risk.suggested_commands[:2]) if a.risk.suggested_commands else ""
            ip_asn = f"{a.ip or 'N/A'} / {a.asn or 'N/A'}"
            row = f"""
            <tr class="{sev}">
              <td><strong>{sev}</strong></td>
              <td>{a.risk.score}</td>
              <td>{a.domain} <div style="font-size:11px;color:#666">{ip_asn}</div></td>
              <td>{a.title or 'N/A'}</td>
              <td>{techs}</td>
              <td>{vectors}</td>
              <td>{suggest}</td>
            </tr>
            """
            rows_html.append(row)
        html = HTML_TEMPLATE.format(
            ts=time.strftime("%Y-%m-%d %H:%M:%S"),
            total=len(assets),
            severity_counts=dict(severity_counts),
            rows="\n".join(rows_html)
        )
        with open(self.out_html, 'w', encoding='utf-8') as f:
            f.write(html)
        print(f"[+] HTML report saved to {self.out_html}")

# -----------------------------
# MAIN CORE
# -----------------------------
class IntelligenceCoreV3:
    def __init__(self, input_path: str, cve_db_path: Optional[str] = None, plugin_dir: Optional[str] = None, max_workers=DEFAULT_MAX_WORKERS):
        """
        input_path: path to scanner JSON output (list of dicts) or 'pipe' if using pipeline with scanner.py output
        """
        self.input_path = input_path
        self.cve_db = self.load_cve_db(cve_db_path) if cve_db_path else {}
        self.plugin_mgr = PluginManager(plugin_dir)
        self.risk_engine = RiskEngineV3(cve_db=self.cve_db)
        self.clustering = ClusteringEngine()
        self.reporter = Reporter()
        self.max_workers = max_workers

    def load_cve_db(self, path: str) -> Dict:
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"[!] Failed to load CVE DB {path}: {e}")
            return {}

    def load_input(self):
        try:
            with open(self.input_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            print(f"[+] Loaded {len(data)} records from {self.input_path}")
            return data
        except Exception as e:
            print(f"[!] Failed to load input JSON: {e}")
            return []

    def enrich_and_score(self, raw_entry: Dict) -> Optional[Asset]:
        url = raw_entry.get('url') or raw_entry.get('original_url') or raw_entry.get('uri')
        if not url:
            return None
        domain = urlparse(url).netloc
        if ':' in domain:
            domain = domain.split(':')[0]

        # base fields
        status = raw_entry.get('status', 0)
        title = raw_entry.get('title', '')[:140]
        tech = raw_entry.get('tech', []) or []
        size = raw_entry.get('size', 0)

        # 1. resolve IP
        ip = safe_gethost(domain)

        # 2. ASN lookup (best-effort)
        asn = whois_asn_lookup(ip) if ip else None

        # 3. SSL info (non-blocking quick)
        ssl_info = get_ssl_cert_info(domain) if ip else {'issuer': None, 'sans': []}
        issuer = ssl_info.get('issuer')
        sans = ssl_info.get('sans', []) or []

        # 4. favicon hash (passive)
        favicon_hash = fetch_favicon_hash(domain)  # may be None

        # 5. Risk scoring
        risk = self.risk_engine.evaluate({
            'url': url, 'status': status, 'title': title, 'tech': tech, 'size': size, 'ssl_sans': sans
        })

        asset = Asset(
            url=url, domain=domain, ip=ip, asn=asn, status=status,
            title=title, tech=tech, size=size, ssl_issuer=issuer, ssl_sans=sans,
            favicon_hash=favicon_hash, risk=risk
        )

        # plugin enrichment (optional)
        asset = self.plugin_mgr.enrich(asset)

        return asset

    def process(self):
        raw = self.load_input()
        assets = []
        # concurrency on enrichment tasks for network ops
        with ThreadPoolExecutor(max_workers=self.max_workers) as ex:
            futures = {ex.submit(self.enrich_and_score, entry): entry for entry in raw}
            completed = 0
            for fut in as_completed(futures):
                completed += 1
                a = None
                try:
                    a = fut.result()
                except Exception as e:
                    print(f"[!] Enrichment error: {e}")
                if a:
                    assets.append(a)
                if completed % 20 == 0:
                    print(f"[+] Enriched {completed}/{len(raw)} entries")
        # sort assets by risk
        assets.sort(key=lambda x: x.risk.score, reverse=True)
        return assets

    def run_pipeline_with_scanner(self, input_list_file: str, scanner_cmd: Optional[List[str]] = None, scanner_output="scanner_tmp_output.json"):
        """
        Optional helper: invoke scanner.py (if present) to produce JSON and then run the analyzer.
        Example scanner_cmd: ['python3', 'scanner.py', '--output', 'scanner_tmp_output.json', 'urls.txt']
        """
        if not scanner_cmd:
            # default attempt to call scanner.py in same folder
            scanner_cmd = [sys.executable, 'scanner.py', '-o', scanner_output, input_list_file]
        print(f"[+] Running scanner pipeline: {' '.join(scanner_cmd)}")
        try:
            p = subprocess.run(scanner_cmd, check=True)
        except subprocess.CalledProcessError as e:
            print(f"[!] Scanner failed: {e}")
            return None
        # change input_path to scanner_output and proceed
        self.input_path = scanner_output
        return self.process()

    def save_final_targets(self, assets: List[Asset], filename="final_targets_v3.txt"):
        with open(filename, 'w', encoding='utf-8') as f:
            for a in assets:
                if a.ip and a.ip != "Unresolved":
                    f.write(f"{a.domain}\n")
        print(f"[+] Final target list saved to {filename}")

    def run(self, run_scanner_first: bool = False, scanner_input_file: Optional[str] = None):
        # if pipeline requested, run scanner first
        if run_scanner_first and scanner_input_file:
            assets = self.run_pipeline_with_scanner(scanner_input_file)
            if assets is None:
                print("[!] Pipeline aborted due to scanner error.")
                return
        else:
            assets = self.process()

        # clustering
        clusters = self.clustering.cluster(assets)
        # reporter
        self.reporter.render(assets)
        # final targets list
        self.save_final_targets(assets)
        # print small summary
        print("[*] Clusters found (sample):")
        for k, v in list(clusters.items())[:6]:
            print(f"  - {k}: {len(v)} assets")
        print("[*] Done. Inspect HTML report and final_targets_v3.txt. Confirm scope and permissions before any active tests.")

# -----------------------------
# CLI
# -----------------------------
def main():
    ap = argparse.ArgumentParser(prog="intelligence_core_v3", description="Intelligence Core v3.0 - Authorized Academic Use Only")
    ap.add_argument("-i", "--input", help="Input JSON (scanner output)", required=False)
    ap.add_argument("--pipeline", help="Run scanner pipeline: provide 'urls.txt' file path", required=False)
    ap.add_argument("--cvedb", help="Optional local CVE DB JSON file (tech->list of CVEs with cvss)", required=False)
    ap.add_argument("--plugins", help="Directory with plugin modules", required=False)
    ap.add_argument("--workers", help="Max concurrent workers (default 20)", type=int, default=DEFAULT_MAX_WORKERS)
    ap.add_argument("--out", help="Output HTML file", default="report_v3.html")
    args = ap.parse_args()

    if not args.input and not args.pipeline:
        print("Usage: intelligence_core_v3.py -i <scanner.json>  OR  --pipeline urls.txt")
        sys.exit(1)

    input_path = args.input
    core = IntelligenceCoreV3(input_path=input_path or "scanner_tmp_output.json", cve_db_path=args.cvedb, plugin_dir=args.plugins, max_workers=args.workers)
    core.reporter.out_html = args.out

    if args.pipeline:
        # run scanner then analyze
        core.run(run_scanner_first=True, scanner_input_file=args.pipeline)
    else:
        core.run(run_scanner_first=False)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user. Exiting.")
        sys.exit(0)
