"""
core_sql/payloads.py

Loads SQLMap-style XML payload files from core_sql/payloads/ and exposes
convenience views by DBMS and by technique.

Usage:
    from core_sql.payloads import mysql, timebased, load_payloads

    # quick usage (default payload dir = core_sql/payloads)
    pdb = load_payloads()          # returns PayloadDB instance
    mysql_payloads = mysql()       # convenience - same as pdb.by_dbms("MySQL")
    tb = timebased()               # convenience - same as pdb.by_technique("time_blind")
    sample = mysql_payloads[0]
    rendered = pdb.render(sample["vector"], {"QUERY": "SELECT database()", "SLEEPTIME": 3})
"""

import os
import xml.etree.ElementTree as ET
import uuid
import random
import re
from typing import List, Dict, Optional, Any, Callable

DEFAULT_DIR = os.path.join(os.path.dirname(__file__), "payloads")
EXPECTED_XML = [
    "boolean_blind.xml",
    "error_based.xml",
    "inline_query.xml",
    "stacked_queries.xml",
    "time_blind.xml",
    "union_query.xml",
]

# ----------------- heuristic helpers -----------------
TECH_KEYWORDS = {
    "time_blind": [r"\bSLEEP\b", r"\bPG_SLEEP\b", r"\bWAITFOR\s+DELAY\b", r"\bBENCHMARK\b", r"\[SLEEPTIME\]"],
    "union_query": [r"\bUNION\b", r"\bCONCAT\b", r"\bGROUP_CONCAT\b", r"DELIMITER_START"],
    "boolean_blind": [r"\[INFERENCE\]", r"\bIF\(", r"\bELT\(", r"\bCASE\s+WHEN\b"],
    "error_based": [r"ERROR", r"CAST\(", r"CONVERT\(", r"JSON_KEYS", r"ORA-", r"SQLSTATE"],
    "stacked_queries": [r"^\s*;", r";SELECT\b", r";\s*SELECT"],
    "inline_query": [r"SELECT\s+\(", r"\bINLINE\b"]
}

DBMS_PATTERNS = {
    "MySQL": re.compile(r"mysql", re.I),
    "PostgreSQL": re.compile(r"postgres|pg_sleep|postgresql", re.I),
    "MSSQL": re.compile(r"microsoft sql server|sqlserver|mssql|@@version", re.I),
    "Oracle": re.compile(r"oracle|ora-\d+", re.I),
    "SQLite": re.compile(r"sqlite", re.I)
}

# ----------------- entry construction -----------------
def _new_entry():
    return {
        "id": str(uuid.uuid4()),
        "title": None,
        "type": None,            # file-based type e.g. boolean_blind, time_blind
        "dbms": None,            # e.g. MySQL
        "dbms_version": None,
        "vector": None,          # main template string
        "example": None,         # example payload if present
        "grep": None,            # response grep pattern
        "level": None,
        "risk": None,
        "source": None,          # filename
        "tags": [],              # small tags list
        "inferred": [],          # inferred techniques from vector content
    }

# ----------------- parser / catalog builder -----------------
class PayloadDB:
    def __init__(self, payload_dir: Optional[str] = None):
        self.payload_dir = os.path.abspath(payload_dir or DEFAULT_DIR)
        self.entries: List[Dict[str, Any]] = []
        self._loaded = False
        self.load()  # eager load by default

    def load(self):
        if self._loaded:
            return
        os.makedirs(self.payload_dir, exist_ok=True)
        # load expected xml files if they exist directly in payload_dir
        for fname in EXPECTED_XML:
            fpath = os.path.join(self.payload_dir, fname)
            if os.path.exists(fpath):
                ptype = fname.replace(".xml", "")
                self._parse_xml(fpath, ptype)
        # also support if user put the xmls in a subfolder (like sqlmap_xml)
        # scan directory for xml files and parse any found as best-effort
        for fname in sorted(os.listdir(self.payload_dir)):
            if fname.endswith(".xml") and fname not in EXPECTED_XML:
                fpath = os.path.join(self.payload_dir, fname)
                self._parse_xml(fpath, fname.replace(".xml", ""))
        self._loaded = True

    def _parse_xml(self, path: str, ptype: str):
        try:
            tree = ET.parse(path)
            root = tree.getroot()
        except Exception:
            return
        for test in root.findall("test"):
            e = _new_entry()
            e["source"] = os.path.basename(path)
            e["type"] = ptype
            e["title"] = (test.findtext("title") or "").strip()
            # vector
            v_el = test.find("vector")
            if v_el is not None and v_el.text:
                e["vector"] = v_el.text.strip()
            # request/payload example
            req = test.find("request")
            if req is not None:
                p = req.find("payload")
                if p is not None and p.text:
                    e["example"] = p.text.strip()
                # comment token (useful to render correctly)
                c = req.find("comment")
                if c is not None and c.text:
                    e["tags"].append("comment_token:" + c.text.strip())
            # response grep/time
            resp = test.find("response")
            if resp is not None:
                g = resp.find("grep")
                if g is not None and g.text:
                    e["grep"] = g.text.strip()
                t = resp.find("time")
                if t is not None and t.text:
                    e["tags"].append("response_time_marker")
            # details
            det = test.find("details")
            if det is not None:
                db = det.findtext("dbms")
                dv = det.findtext("dbms_version")
                if db:
                    e["dbms"] = db.strip()
                if dv:
                    e["dbms_version"] = dv.strip()
            # level / risk
            lvl = test.findtext("level")
            rsk = test.findtext("risk")
            e["level"] = int(lvl) if lvl and lvl.isdigit() else None
            e["risk"] = int(rsk) if rsk and rsk.isdigit() else None

            # infer techniques from vector / example / tags
            content = " ".join(filter(None, [e.get("vector") or "", e.get("example") or ""]))
            inferred = set()
            for tech, patterns in TECH_KEYWORDS.items():
                for pat in patterns:
                    if re.search(pat, content, re.I | re.M):
                        inferred.add(tech)
                        break
            # also prefer file-based type as technique if it's one of known categories
            if ptype in TECH_KEYWORDS.keys():
                inferred.add(ptype)
            # stacked queries often appear as leading semicolon or file name 'stacked'
            if ptype and "stacked" in ptype:
                inferred.add("stacked_queries")
            # add inferred list and some auto tags
            e["inferred"] = sorted(list(inferred))
            # add a simple tag if dbms specified
            if e["dbms"]:
                e["tags"].append("dbms:" + e["dbms"])
            # ensure vector or example exists
            if not e["vector"] and not e["example"]:
                continue
            self.entries.append(e)

    # ----------------- retrieval APIs -----------------
    def all(self) -> List[Dict[str, Any]]:
        return list(self.entries)

    def types(self) -> List[str]:
        return sorted(list({e["type"] for e in self.entries if e["type"]}))

    def dbms_list(self) -> List[str]:
        return sorted(list({(e.get("dbms") or "").strip() for e in self.entries if e.get("dbms")}))

    def by_dbms(self, dbms: str, limit: Optional[int] = None, safety: Optional[str] = None) -> List[Dict[str, Any]]:
        res = [e for e in self.entries if e.get("dbms") and dbms.lower() in e.get("dbms").lower()]
        if safety:
            # naive safety filter by risk: safety "non-destructive" -> risk <=2, "may-alter-db" -> <=4 else destructive
            if safety == "non-destructive":
                res = [r for r in res if (r.get("risk") or 0) <= 2]
            elif safety == "may-alter-db":
                res = [r for r in res if (r.get("risk") or 0) <= 4]
        return res[:limit] if limit else res

    def by_technique(self, technique: str, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        # technique should be one of the TECH_KEYWORDS keys or the xml filename base
        res = [e for e in self.entries if technique == e.get("type") or technique in e.get("inferred", [])]
        return res[:limit] if limit else res

    def by_tag(self, tag: str, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        res = [e for e in self.entries if any(t.startswith(tag) or t == tag for t in e.get("tags", []))]
        return res[:limit] if limit else res

    def get(self, entry_id: str) -> Optional[Dict[str, Any]]:
        for e in self.entries:
            if e["id"] == entry_id:
                return e
        return None

    def sample(self, technique: Optional[str] = None, dbms: Optional[str] = None) -> Optional[Dict[str, Any]]:
        if technique:
            lst = self.by_technique(technique, limit=1)
            if lst:
                return lst[0]
        if dbms:
            lst = self.by_dbms(dbms, limit=1)
            if lst:
                return lst[0]
        return self.entries[0] if self.entries else None

    # ----------------- rendering -----------------
    def render(self, template: str, context: Optional[Dict[str, Any]] = None) -> Optional[str]:
        """
        Replace common SQLMap placeholders:
          [QUERY], [RANDNUM], [RANDSTR], [SLEEPTIME], [INFERENCE]
        context is a dict: {"QUERY": "...", "RANDNUM": 1234, "RANDSTR": "abc", "SLEEPTIME": 3, "INFERENCE": "(1=1)"}
        """
        if not template:
            return template
        out = template
        ctx = context or {}
        # bracketed placeholders
        for k, v in ctx.items():
            out = out.replace(f"[{k}]", str(v))
        # supply RANDNUM/RANDSTR if missing
        if "[RANDNUM]" in out and "RANDNUM" not in ctx:
            out = out.replace("[RANDNUM]", str(random.randint(1000, 9999)))
        if "[RANDSTR]" in out and "RANDSTR" not in ctx:
            out = out.replace("[RANDSTR]", uuid.uuid4().hex[:8])
        # best-effort: remove newlines and collapse excessive whitespace for HTTP sending
        out = "\n".join(line.strip() for line in out.splitlines())
        out = re.sub(r"\s{2,}", " ", out)
        return out

# ----------------- module-level convenience -----------------
_global_db: Optional[PayloadDB] = None

def load_payloads(payload_dir: Optional[str] = None) -> PayloadDB:
    global _global_db
    if payload_dir:
        _global_db = PayloadDB(payload_dir=payload_dir)
    elif _global_db is None:
        _global_db = PayloadDB()
    return _global_db

# Convenience short functions so users can import like `from core_sql.payloads import mysql, timebased`
def _ensure_db():
    if _global_db is None:
        load_payloads()
    return _global_db

def mysql(limit: Optional[int] = None) -> List[Dict[str, Any]]:
    return _ensure_db().by_dbms("MySQL", limit=limit)

def postgres(limit: Optional[int] = None) -> List[Dict[str, Any]]:
    return _ensure_db().by_dbms("PostgreSQL", limit=limit)

def mssql(limit: Optional[int] = None) -> List[Dict[str, Any]]:
    return _ensure_db().by_dbms("MSSQL", limit=limit)

def oracle(limit: Optional[int] = None) -> List[Dict[str, Any]]:
    return _ensure_db().by_dbms("Oracle", limit=limit)

def sqlite(limit: Optional[int] = None) -> List[Dict[str, Any]]:
    return _ensure_db().by_dbms("SQLite", limit=limit)

def timebased(limit: Optional[int] = None) -> List[Dict[str, Any]]:
    return _ensure_db().by_technique("time_blind", limit=limit)

def boolean(limit: Optional[int] = None) -> List[Dict[str, Any]]:
    return _ensure_db().by_technique("boolean_blind", limit=limit)

def errorbased(limit: Optional[int] = None) -> List[Dict[str, Any]]:
    return _ensure_db().by_technique("error_based", limit=limit)

def union(limit: Optional[int] = None) -> List[Dict[str, Any]]:
    return _ensure_db().by_technique("union_query", limit=limit)

def stacked(limit: Optional[int] = None) -> List[Dict[str, Any]]:
    return _ensure_db().by_technique("stacked_queries", limit=limit)

def inline(limit: Optional[int] = None) -> List[Dict[str, Any]]:
    return _ensure_db().by_technique("inline_query", limit=limit)

def all(limit: Optional[int] = None) -> List[Dict[str, Any]]:
    return _ensure_db().all()[:limit] if limit else _ensure_db().all()

# ----------------- small test when run directly -----------------
if __name__ == "__main__":
    pdb = load_payloads()
    print("Loaded payload types:", pdb.types())
    print("DBMS found in payloads:", pdb.dbms_list())
    print("Sample time-based payload:", pdb.sample(technique="time_blind"))
    print("First 3 MySQL time-based vectors:")
    for i, e in enumerate(mysql()):
        if "time_blind" in e.get("inferred", []) or e.get("type") == "time_blind":
            print(i+1, e["title"][:80])
            if i >= 2:
                break
