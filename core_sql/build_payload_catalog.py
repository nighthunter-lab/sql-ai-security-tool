#!/usr/bin/env python3
"""
Build a payload catalog JSON from SQLMap-style XML payload files found in:
  core_sql/payloads/

Writes:
  core_sql/payloads_catalog.json

Includes:
 - entries: list of payload dicts (id, title, type, dbms, dbms_version, vector, example, grep, level, risk, tags, inferred)
 - indexes: by_type, by_dbms, by_tag
 - metadata: generated_at, count
"""
import os, json, uuid, re
from pathlib import Path
from datetime import datetime
import xml.etree.ElementTree as ET

BASE = Path(__file__).resolve().parents[1]  # points to core_sql/
PAYLOAD_DIR = BASE / "payloads"
OUT_FILE = BASE / "payloads_catalog.json"

EXPECTED_XML = [
    "boolean_blind.xml",
    "error_based.xml",
    "inline_query.xml",
    "stacked_queries.xml",
    "time_blind.xml",
    "union_query.xml",
]

TECH_KEYWORDS = {
    "time_blind": [r"\bSLEEP\b", r"\bPG_SLEEP\b", r"\bWAITFOR\s+DELAY\b", r"\bBENCHMARK\b", r"\[SLEEPTIME\]"],
    "union_query": [r"\bUNION\b", r"\bCONCAT\b", r"\bGROUP_CONCAT\b", r"\[DELIMITER_START\]"],
    "boolean_blind": [r"\[INFERENCE\]", r"\bIF\(", r"\bELT\(", r"\bCASE\s+WHEN\b"],
    "error_based": [r"CAST\(|CONVERT\(|JSON_KEYS|ORA-|SQLSTATE|ERROR"],
    "stacked_queries": [r"^\s*;", r";SELECT\b", r";\s*SELECT"],
    "inline_query": [r"SELECT\s+\(", r"\bINLINE\b"]
}

def parse_xml_file(path: Path, ptype_hint: str):
    try:
        tree = ET.parse(str(path))
        root = tree.getroot()
    except Exception as e:
        print("skip", path, ":", e)
        return []

    out = []
    for test in root.findall("test"):
        entry = {
            "id": str(uuid.uuid4()),
            "title": (test.findtext("title") or "").strip(),
            "type": ptype_hint,
            "dbms": None,
            "dbms_version": None,
            "vector": None,
            "example": None,
            "grep": None,
            "level": None,
            "risk": None,
            "source": path.name,
            "tags": [],
            "inferred": []
        }
        # vector
        v = test.find("vector")
        if v is not None and v.text:
            entry["vector"] = v.text.strip()
        # request/payload
        req = test.find("request")
        if req is not None:
            p = req.find("payload")
            if p is not None and p.text:
                entry["example"] = p.text.strip()
            c = req.find("comment")
            if c is not None and c.text:
                entry["tags"].append("comment_token:" + c.text.strip())
        # response
        resp = test.find("response")
        if resp is not None:
            g = resp.find("grep")
            if g is not None and g.text:
                entry["grep"] = g.text.strip()
            t = resp.find("time")
            if t is not None and t.text:
                entry["tags"].append("response_time_marker")
        # details
        det = test.find("details")
        if det is not None:
            db = det.findtext("dbms")
            dv = det.findtext("dbms_version")
            if db:
                entry["dbms"] = db.strip()
                entry["tags"].append("dbms:" + db.strip())
            if dv:
                entry["dbms_version"] = dv.strip()
        # level/risk
        lvl = test.findtext("level")
        rsk = test.findtext("risk")
        entry["level"] = int(lvl) if lvl and lvl.isdigit() else None
        entry["risk"] = int(rsk) if rsk and rsk.isdigit() else None

        # infer techniques by scanning vector+example
        content = " ".join(filter(None, [entry["vector"] or "", entry["example"] or ""]))
        inferred = set()
        for t, patterns in TECH_KEYWORDS.items():
            for pat in patterns:
                if re.search(pat, content, re.I | re.M):
                    inferred.add(t)
                    break
        # prefer ptype_hint
        if ptype_hint:
            inferred.add(ptype_hint)
        # stacked special case
        if "stacked" in ptype_hint:
            inferred.add("stacked_queries")
        entry["inferred"] = sorted(list(inferred))

        # basic safety heuristic from risk
        if entry["risk"] is not None:
            if entry["risk"] <= 2:
                entry["safety"] = "non-destructive"
            elif entry["risk"] <= 4:
                entry["safety"] = "may-alter-db"
            else:
                entry["safety"] = "destructive"
        else:
            entry["safety"] = "non-destructive"

        # only keep entries with a vector or example
        if entry["vector"] or entry["example"]:
            out.append(entry)
    return out

def build_catalog():
    entries = []
    # parse expected xml files in payload dir
    for fname in EXPECTED_XML:
        p = PAYLOAD_DIR / fname
        if p.exists():
            entries.extend(parse_xml_file(p, fname.replace(".xml","")))
    # also parse any other xmls in dir
    for f in sorted(PAYLOAD_DIR.glob("*.xml")):
        if f.name in EXPECTED_XML:
            continue
        entries.extend(parse_xml_file(f, f.name.replace(".xml","")))
    # build indexes
    by_type = {}
    by_dbms = {}
    by_tag = {}
    for e in entries:
        t = e.get("type") or "unknown"
        by_type.setdefault(t, []).append(e["id"])
        db = e.get("dbms")
        if db:
            by_dbms.setdefault(db, []).append(e["id"])
        for tag in e.get("tags", []):
            by_tag.setdefault(tag, []).append(e["id"])
        # also index inferred techniques
        for it in e.get("inferred", []):
            by_type.setdefault(it, []).append(e["id"])
    catalog = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "count": len(entries),
        "entries": entries,
        "index": {
            "by_type": by_type,
            "by_dbms": by_dbms,
            "by_tag": by_tag
        }
    }
    return catalog

def main():
    if not PAYLOAD_DIR.exists():
        print("Payload dir not found:", PAYLOAD_DIR)
        return
    cat = build_catalog()
    OUT_FILE.write_text(json.dumps(cat, indent=2), encoding="utf-8")
    print("Wrote catalog:", OUT_FILE, "entries:", cat["count"])

if __name__ == "__main__":
    main()
