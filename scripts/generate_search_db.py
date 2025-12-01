#!/usr/bin/env python3
"""Generate an SQLite search DB from `mappings.json`.

Creates `static/search_index.sqlite` with two tables:
 - attacks(attack_id TEXT PRIMARY KEY, attack_name TEXT)
 - d3fend(id INTEGER PRIMARY KEY AUTOINCREMENT, attack_id TEXT, d3_id TEXT, name TEXT, type TEXT, tactic_id TEXT, url TEXT)

This DB lets the app load quickly without needing `mappings.json` at runtime.
"""
from __future__ import annotations

import json
import os
import sqlite3
from collections import defaultdict

ROOT = os.path.dirname(os.path.dirname(__file__))
MAPPINGS_FILE = os.path.join(ROOT, "mappings.json")
OUT_DB = os.path.join(ROOT, "static", "search_index.sqlite")


def extract_value(obj, field):
    if not obj:
        return ""
    if isinstance(obj.get(field), dict) and "value" in obj.get(field):
        return obj.get(field)["value"]
    v = obj.get(field)
    if isinstance(v, dict) and "value" in v:
        return v["value"]
    return v or ""


def main():
    if not os.path.exists(MAPPINGS_FILE):
        print(f"Error: {MAPPINGS_FILE} not found")
        return

    with open(MAPPINGS_FILE, "r", encoding="utf-8") as f:
        raw = json.load(f)

    if isinstance(raw, dict) and "results" in raw and isinstance(raw["results"], dict):
        bindings = raw["results"].get("bindings", [])
    else:
        bindings = [v for k, v in raw.items() if isinstance(v, dict)]

    mappings = []
    for entry in bindings:
        off_tech_id = extract_value(entry, "off_tech_id") or extract_value(entry, "off_tech")
        if isinstance(off_tech_id, str) and "#" in off_tech_id:
            off_tech_id = off_tech_id.split("#")[-1]
        if not off_tech_id:
            continue
        off_tech_id = str(off_tech_id).strip().upper()
        if not off_tech_id.startswith("T"):
            continue
        attack_name = extract_value(entry, "off_tech_label") or off_tech_id
        entry_data = {"attack_id": off_tech_id, "attack_name": str(attack_name).strip(), "d3fend": []}

        parent_tactic_raw = extract_value(entry, "def_tactic") or ""
        parent_tactic_id = ""
        if isinstance(parent_tactic_raw, str) and parent_tactic_raw:
            if "#" in parent_tactic_raw:
                parent_tactic_id = parent_tactic_raw.split("#")[-1].strip().upper()
            else:
                parent_tactic_id = parent_tactic_raw.strip().upper()

        seen = set()
        for field in ["def_tech", "def_artifact"]:
            uri = extract_value(entry, field)
            label = extract_value(entry, f"{field}_label") or uri
            if uri and isinstance(uri, str) and "#" in uri:
                d3_id = uri.split("#")[-1].strip()
            else:
                d3_id = None
                if isinstance(label, str) and label.startswith("D3"):
                    d3_id = label
            if not d3_id or d3_id in seen:
                continue
            seen.add(d3_id)
            name_str = (str(label).strip() if isinstance(label, str) else "") or d3_id
            tactic_names = {"harden", "detect", "isolate", "deceive", "evict", "restore"}
            path = "tactic" if name_str.lower() in tactic_names else "technique"
            d3_type = path
            tactic_id = parent_tactic_id if d3_type == "technique" and parent_tactic_id else ""
            entry_data["d3fend"].append({
                "id": d3_id,
                "name": name_str,
                "type": d3_type,
                "tactic_id": tactic_id,
                "url": f"https://d3fend.mitre.org/{path}/d3f:{d3_id}"
            })

        if entry_data["d3fend"]:
            mappings.append(entry_data)

    # Group duplicates by attack_id and dedupe
    grouped = defaultdict(lambda: {"attack_id": "", "attack_name": "", "d3fend": []})
    for e in mappings:
        key = e["attack_id"]
        if not grouped[key]["attack_id"]:
            grouped[key]["attack_id"] = key
            grouped[key]["attack_name"] = e["attack_name"]
        grouped[key]["d3fend"].extend(e["d3fend"])

    # Write to SQLite
    os.makedirs(os.path.join(ROOT, "static"), exist_ok=True)
    if os.path.exists(OUT_DB):
        os.remove(OUT_DB)
    conn = sqlite3.connect(OUT_DB)
    cur = conn.cursor()
    cur.execute("CREATE TABLE attacks(attack_id TEXT PRIMARY KEY, attack_name TEXT)")
    cur.execute(
        "CREATE TABLE d3fend(id INTEGER PRIMARY KEY AUTOINCREMENT, attack_id TEXT, d3_id TEXT, name TEXT, type TEXT, tactic_id TEXT, url TEXT)"
    )
    cur.execute("CREATE INDEX idx_d3f_attack ON d3fend(attack_id)")

    inserted_attacks = 0
    inserted_d3 = 0
    for k, g in grouped.items():
        # dedupe d3fend entries while preserving order
        seenids = set()
        uniq = []
        for d in g["d3fend"]:
            if d["id"] and d["id"] not in seenids:
                seenids.add(d["id"])
                uniq.append(d)
        cur.execute("INSERT INTO attacks(attack_id, attack_name) VALUES(?, ?)", (k, g["attack_name"]))
        inserted_attacks += 1
        for d in uniq:
            cur.execute(
                "INSERT INTO d3fend(attack_id, d3_id, name, type, tactic_id, url) VALUES(?, ?, ?, ?, ?, ?)",
                (k, d.get("id"), d.get("name"), d.get("type"), d.get("tactic_id"), d.get("url")),
            )
            inserted_d3 += 1

    conn.commit()
    conn.close()
    print(f"Wrote {inserted_attacks} attacks and {inserted_d3} d3fend rows to {OUT_DB}")


if __name__ == "__main__":
    main()
