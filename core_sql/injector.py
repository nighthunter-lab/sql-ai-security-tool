#!/usr/bin/env python3
# core_sql/run_injector_dry.py
"""
Dry-run injector helper:
  - Read scanner_output.json (scanner report)
  - For each vuln: pick payloads by technique+dbms, render a few, and print previews.
No network requests, safe to run locally.
Usage:
  python -m core_sql.run_injector_dry scanner_output.json --count 5
"""

import json
import sys
from pathlib import Path
from typing import Optional
from core_sql.payloads import load_payloads

TECH_TO_PTYPE = {
    "boolean": "boolean_blind",
    "error": "error_based",
    "time": "time_blind",
    "union": "union_query",
    "stacked": "stacked_queries",
    "inline": "inline_query"
}

def choose_candidates(pdb, vuln, limit=10):
    technique = vuln.get("technique") or vuln.get("type") or "boolean"
    ptype = TECH_TO_PTYPE.get(technique, "boolean_blind")
    dbms_hint = vuln.get("dbms")
    # try dbms+ptype first
    candidates = []
    if dbms_hint:
        candidates = pdb.by_dbms(dbms_hint, limit=limit)
        # filter those by ptype
        candidates = [c for c in candidates if c.get("type")==ptype or ptype in c.get("inferred",[])]
    if not candidates:
        candidates = pdb.by_technique(ptype, limit=limit)
    if not candidates:
        # fallback to any payloads
        candidates = pdb.all()[:limit]
    return candidates[:limit]

def render_preview(pdb, entry, ctx=None):
    vec = entry.get("vector") or entry.get("example") or ""
    ctx = ctx or {}
    return pdb.render(vec, ctx)

def main(scanner_file: str, count: int = 5):
    project_root = Path(__file__).resolve().parent.parent
    pdb = load_payloads(payload_dir=str(project_root / "core_sql" / "payloads"))

    # load scanner file
    with open(scanner_file, "r", encoding="utf-8") as fh:
        report = json.load(fh)

    vulns = report.get("vulnerabilities", [])
    if not vulns:
        print("No vulnerabilities found in scanner report.")
        return

    for i, v in enumerate(vulns, start=1):
        print("="*78)
        print(f"VULN {i}: id={v.get('id')} url={v.get('url')} param={v.get('param')} technique={v.get('technique')} dbms={v.get('dbms')}")
        candidates = choose_candidates(pdb, v, limit=count)
        if not candidates:
            print("  No candidates found.")
            continue
        for j, c in enumerate(candidates, start=1):
            # build a small context: prefer SLEEPTIME for time-based; add a RANDNUM
            ctx = {"QUERY": "SELECT database()", "RANDNUM": 4242, "RANDSTR": "rndstr", "SLEEPTIME": 2}
            preview = render_preview(pdb, c, ctx)
            title = c.get("title") or c.get("source") or c.get("id")
            print(f"\n  [{j}] {title}")
            print(f"      type: {c.get('type')} inferred: {c.get('inferred')}")
            print("      preview:", (preview or "")[:300].replace("\n"," "))
        print()
    print("="*78)
    print("Dry-run complete.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python -m core_sql.run_injector_dry scanner_output.json [--count N]")
        sys.exit(2)
    scanner_file = sys.argv[1]
    count = 5
    if "--count" in sys.argv:
        try:
            count = int(sys.argv[sys.argv.index("--count")+1])
        except Exception:
            pass
    main(scanner_file, count=count)