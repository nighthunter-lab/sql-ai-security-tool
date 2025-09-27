"""
payload_catalog.py

Small loader and helper functions for core_sql/payloads_catalog.json

Usage:
  from core_sql.payload_catalog import CatalogLoader
  loader = CatalogLoader()   # auto-loads core_sql/payloads_catalog.json
  loader.get_by_dbms("MySQL")
  loader.get_by_type("time_blind")
  loader.sample(dbms="MySQL", technique="time_blind")
"""

import json, os
from pathlib import Path
from typing import List, Dict, Optional

BASE = Path(__file__).resolve().parent
CAT_FILE = BASE / "payloads_catalog.json"

class CatalogLoader:
    def __init__(self, path: Optional[str] = None):
        self.path = Path(path) if path else CAT_FILE
        if not self.path.exists():
            raise FileNotFoundError(f"Catalog not found: {self.path}")
        self._load()

    def _load(self):
        with open(self.path, "r", encoding="utf-8") as fh:
            self.catalog = json.load(fh)
        # convenience maps
        self.entries = {e["id"]: e for e in self.catalog.get("entries", [])}
        self.by_type = self.catalog.get("index", {}).get("by_type", {})
        self.by_dbms = self.catalog.get("index", {}).get("by_dbms", {})
        self.by_tag = self.catalog.get("index", {}).get("by_tag", {})

    def as_dict(self):
        return self.catalog

    def get_by_dbms(self, dbms: str, limit: Optional[int] = None) -> List[Dict]:
        ids = self.by_dbms.get(dbms, [])
        out = [self.entries[i] for i in ids if i in self.entries]
        return out[:limit] if limit else out

    def get_by_type(self, ptype: str, limit: Optional[int] = None) -> List[Dict]:
        ids = self.by_type.get(ptype, [])
        out = [self.entries[i] for i in ids if i in self.entries]
        return out[:limit] if limit else out

    def get_by_tag(self, tag: str, limit: Optional[int] = None) -> List[Dict]:
        ids = self.by_tag.get(tag, [])
        out = [self.entries[i] for i in ids if i in self.entries]
        return out[:limit] if limit else out

    def sample(self, dbms: Optional[str] = None, technique: Optional[str] = None) -> Optional[Dict]:
        if dbms:
            lst = self.get_by_dbms(dbms, limit=1)
            if lst:
                return lst[0]
        if technique:
            lst = self.get_by_type(technique, limit=1)
            if lst:
                return lst[0]
        # fallback: first entry
        entries = list(self.entries.values())
        return entries[0] if entries else None
