#!/usr/bin/env python3
"""
scanner.py
Usage:
  # scan a docker image (if trivy is installed)
  python3 scanner.py nginx:latest

  # analyze existing JSON report
  python3 scanner.py path/to/report.json

  # same as above but specify minimum severity:
  python3 scanner.py nginx:latest --min-severity HIGH

Behavior:
  - If the first positional argument is a path to an existing .json file -> it will be parsed.
  - Otherwise it's treated as an image name. If trivy is available -> run trivy.
    If trivy is missing, the script falls back to sample_report.json (so demo works offline).
Exit codes:
  0 -> no HIGH/CRITICAL vulnerabilities
  1 -> found HIGH or CRITICAL
  2 -> runtime error (trivy missing when required etc.)
"""
import argparse
import json
import subprocess
import sys
from pathlib import Path
from datetime import datetime
import shutil

SEVERITY_ORDER = ["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

def run_trivy(image_name: str, timeout: int = 180):
    cmd = ["trivy", "image", "--quiet", "--format", "json", image_name]
    try:
        print(f"[+] Running: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if result.returncode not in (0, 2):  # 2 often means vulnerabilities found
            print(f"[!] Trivy returned code {result.returncode}. stderr:\n{result.stderr.strip()}", file=sys.stderr)
        return json.loads(result.stdout)
    except FileNotFoundError:
        print("[!] trivy not found (FileNotFoundError).", file=sys.stderr)
        raise
    except subprocess.TimeoutExpired:
        print("[!] Trivy timed out.", file=sys.stderr)
        raise
    except json.JSONDecodeError:
        print("[!] Failed to decode Trivy JSON output.", file=sys.stderr)
        print("stdout snippet:", (result.stdout or "")[:1000], file=sys.stderr)
        raise

def load_json(path: Path):
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)

def extract_vulnerabilities(report: dict):
    vulns = []
    if not isinstance(report, dict):
        return vulns

    if "Results" in report:
        for res in report.get("Results", []):
            target = res.get("Target")
            for v in res.get("Vulnerabilities") or []:
                vulns.append({
                    "id": v.get("VulnerabilityID") or v.get("id"),
                    "package": v.get("PkgName") or v.get("package"),
                    "severity": (v.get("Severity") or v.get("severity") or "UNKNOWN").upper(),
                    "installed_version": v.get("InstalledVersion") or v.get("installed_version"),
                    "fixed_version": v.get("FixedVersion") or v.get("fixed_version"),
                    "target": target
                })
    elif "vulnerabilities" in report:
        for v in report.get("vulnerabilities", []):
            vulns.append({
                "id": v.get("id"),
                "package": v.get("package"),
                "severity": (v.get("severity") or "UNKNOWN").upper(),
                "installed_version": v.get("installed_version"),
                "fixed_version": v.get("fixed_version"),
                "target": v.get("target")
            })
    else:
        # best-effort: search whole dict for any list that looks like vulnerabilities
        for key, val in report.items():
            if isinstance(val, list):
                for item in val:
                    if isinstance(item, dict) and ("VulnerabilityID" in item or "id" in item):
                        vulns.append({
                            "id": item.get("VulnerabilityID") or item.get("id"),
                            "package": item.get("PkgName") or item.get("package"),
                            "severity": (item.get("Severity") or item.get("severity") or "UNKNOWN").upper(),
                            "installed_version": item.get("InstalledVersion") or item.get("installed_version"),
                            "fixed_version": item.get("FixedVersion") or item.get("fixed_version"),
                            "target": item.get("Target") or None
                        })
    return vulns

def summarize(vulns: list, min_severity: str = "LOW"):
    min_index = SEVERITY_ORDER.index(min_severity) if min_severity in SEVERITY_ORDER else 0
    counts = {sev: 0 for sev in SEVERITY_ORDER}
    filtered = []

    for v in vulns:
        sev = v.get("severity", "UNKNOWN").upper()
        if sev not in counts:
            counts[sev] = 0
        counts[sev] += 1
        if SEVERITY_ORDER.index(sev) >= min_index:
            filtered.append(v)

    return counts, filtered

def print_report(vulns: list, filtered: list, counts: dict, subject: str = None):
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    title = f"Vulnerability Report for {subject}" if subject else "Vulnerability Report"
    print("="*70)
    print(f"{title} — generated: {now}")
    print("="*70)
    print("Counts by severity:")
    for sev in reversed(SEVERITY_ORDER):
        if counts.get(sev, 0):
            print(f"  {sev:8}: {counts[sev]}")
    print("-"*70)
    if not filtered:
        print("No vulnerabilities meeting the severity threshold found.")
        print("="*70)
        return

    print(f"Top {len(filtered)} vulnerabilities (severity >= threshold):\n")
    def sev_key(v): 
        # higher severity first
        try:
            return (-SEVERITY_ORDER.index(v.get("severity","UNKNOWN")), v.get("id",""))
        except ValueError:
            return (0, v.get("id",""))
    for v in sorted(filtered, key=sev_key):
        print(f"- {v.get('id')} | {v.get('package')} | {v.get('severity')}"
              + (f" | target: {v.get('target')}" if v.get('target') else ""))
        if v.get('installed_version') or v.get('fixed_version'):
            print(f"    installed: {v.get('installed_version')}  fixed: {v.get('fixed_version')}")
    print("="*70)

def parse_args():
    p = argparse.ArgumentParser(description="Trivy wrapper + JSON report analyzer (fallback to sample_report.json)")
    p.add_argument("subject", help="Docker image name (e.g. nginx:latest) or path to JSON report")
    p.add_argument("--min-severity", "-s", default="LOW", help="Minimum severity to show (UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL)")
    p.add_argument("--output", "-o", help="Save raw JSON to a file (only when scanning an image)")
    return p.parse_args()

def main():
    args = parse_args()
    subject = args.subject
    subject_path = Path(subject)
    report = None
    used_sample = False

    try:
        if subject_path.exists() and subject_path.suffix.lower() == ".json":
            report = load_json(subject_path)
            source = str(subject_path)
        else:
            # treat as image name
            trivy_path = shutil.which("trivy")
            if trivy_path:
                try:
                    report = run_trivy(subject)
                    source = f"trivy://{subject}"
                    if args.output:
                        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
                        with open(args.output, "w", encoding="utf-8") as f:
                            json.dump(report, f, indent=2, ensure_ascii=False)
                        print(f"[+] Saved raw JSON report to {args.output}")
                except Exception as e:
                    print(f"[!] Error running Trivy: {e}", file=sys.stderr)
                    print("[!] Falling back to sample_report.json for demo.", file=sys.stderr)
                    report = load_json(Path("sample_report.json"))
                    source = "sample_report.json (fallback)"
                    used_sample = True
            else:
                print("[!] trivy not found in PATH. Using sample_report.json (demo mode).", file=sys.stderr)
                report = load_json(Path("sample_report.json"))
                source = "sample_report.json (fallback)"
                used_sample = True

        vulns = extract_vulnerabilities(report)
        counts, filtered = summarize(vulns, min_severity=args.min_severity.upper())
        print_report(vulns, filtered, counts, subject if not used_sample else source)
        high_count = counts.get("HIGH", 0) + counts.get("CRITICAL", 0)
        if high_count > 0:
            sys.exit(1)
        sys.exit(0)

    except FileNotFoundError as e:
        print(f"[ERROR] File not found: {e}", file=sys.stderr)
        sys.exit(2)
    except Exception as e:
        print(f"[ERROR] Unexpected error: {e}", file=sys.stderr)
        sys.exit(2)

if __name__ == "__main__":
    main()
