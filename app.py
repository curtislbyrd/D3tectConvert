# app.py – FINAL VERSION: Correctly Parses MITRE's UUID-Key Object Structure
from flask import Flask, render_template, request, jsonify
from markupsafe import escape
from flask_talisman import Talisman
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import requests
import json
import os
import re
from collections import defaultdict

app = Flask(__name__)

# No secrets in source
# This project is intentionally shipped without any hard-coded secrets.
# If you want signed sessions or CSRF protection, set the `SECRET_KEY` environment
# variable in your deployment or development environment. We do not generate
# or store secrets in source control.
app.config.setdefault('SESSION_COOKIE_SECURE', True)
app.config.setdefault('SESSION_COOKIE_HTTPONLY', True)
app.config.setdefault('SESSION_COOKIE_SAMESITE', 'Lax')
app.config.setdefault('MAX_CONTENT_LENGTH', 10 * 1024)  # 10 KB max for incoming request bodies

# Security headers: stricter CSP allowing our static JS and Bootstrap CDN for styles
csp = {
    "default-src": ["'self'"],
    "script-src": ["'self'"],
    "style-src": ["'self'", "https://cdn.jsdelivr.net"],
    "img-src": ["'self'", "data:"],
    "connect-src": ["'self'"],
    "font-src": ["'self'", "https://cdn.jsdelivr.net"]
}

# In development (FLASK_DEBUG=1) skip initializing Talisman so the dev server
# does not send HSTS/redirect headers. This prevents browsers from learning
# HSTS for localhost and later attempting HTTPS handshakes against the plain
# HTTP dev server.
if os.environ.get("FLASK_DEBUG", "0") == "1":
    print("FLASK_DEBUG=1 -> skipping Talisman (no HSTS) for local development")
else:
    Talisman(app, content_security_policy=csp)

# Rate limiting (per IP)
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["120 per minute"]
)

MAPPINGS_URL = "https://d3fend.mitre.org/api/ontology/inference/d3fend-full-mappings.json"
MAPPINGS_FILE = "mappings.json"

def download_mappings():
    """Download the mappings file. This will overwrite the local file.

    Returns True if a download happened, False if nothing changed.
    """
    print("Downloading latest D3FEND ↔ ATT&CK mappings (~25MB)...")
    response = requests.get(MAPPINGS_URL, timeout=120)
    response.raise_for_status()
    with open(MAPPINGS_FILE, "w", encoding="utf-8") as f:
        f.write(response.text)
    print("Download complete.")
    return True

def load_mappings():
    # Only download if mappings file is missing or the environment variable
    # TD3_FORCE_DOWNLOAD=1 is set. This avoids unconditional downloads on each run.
    force = os.environ.get("TD3_FORCE_DOWNLOAD", "0") == "1"
    if not os.path.exists(MAPPINGS_FILE) or force:
        download_mappings()

    with open(MAPPINGS_FILE, "r", encoding="utf-8") as f:
        raw_data = json.load(f)
    mappings = []
    # Try to load local D3FEND ontology dump to enrich entries with canonical D3FEND IDs
    d3_meta = {}
    try:
        with open("stuff/d3fend.json", "r", encoding="utf-8") as df:
            d3_raw = json.load(df)
            graph = d3_raw.get("@graph", []) if isinstance(d3_raw, dict) else []
            for node in graph:
                nid = node.get("@id")
                if not nid or not isinstance(nid, str) or not nid.startswith("d3f:"):
                    continue
                key = nid.split(":", 1)[1]
                meta = {}
                # canonical d3fend id (e.g., D3A-...)
                if "d3f:d3fend-id" in node:
                    meta["d3fend_id"] = node.get("d3f:d3fend-id")
                # attack-id (e.g., T1556.009)
                if "d3f:attack-id" in node:
                    meta["attack_id"] = node.get("d3f:attack-id")
                if meta:
                    d3_meta[key] = meta
    except Exception:
        # non-fatal if ontology isn't present or parse fails
        d3_meta = {}

    # Helper to normalize and extract a value from a SPARQL-style binding or MITRE UUID-keyed entry
    def extract_value(obj, field):
        if not obj:
            return ""
        # If obj is a SPARQL binding (fields are dicts with 'value')
        if isinstance(obj.get(field), dict) and "value" in obj.get(field):
            return obj.get(field)["value"]
        # If obj is a MITRE-style entry where fields themselves are dicts
        v = obj.get(field)
        if isinstance(v, dict) and "value" in v:
            return v["value"]
        # Fall back to direct value
        return v or ""

    # Two possible input shapes:
    # 1) SPARQL JSON: { "results": { "bindings": [ { field: {"type":"literal","value":"..."}, ... }, ... ] } }
    # 2) MITRE UUID keyed: { "<uuid>": { field: {"type":"literal","value":"..."}, ... }, ... }

    bindings = None
    if isinstance(raw_data, dict) and "results" in raw_data and isinstance(raw_data["results"], dict):
        bindings = raw_data["results"].get("bindings", [])
    else:
        # Treat raw_data as a dict of uuid->entry; build a list of entries
        bindings = [v for k, v in raw_data.items() if isinstance(v, dict)]

    for entry in bindings:
        # Prefer explicit off_tech_id (literal), otherwise try off_tech URI and extract last fragment
        off_tech_id = extract_value(entry, "off_tech_id") or extract_value(entry, "off_tech")
        if isinstance(off_tech_id, str) and "#" in off_tech_id:
            off_tech_id = off_tech_id.split("#")[-1]
        if not off_tech_id:
            continue
        off_tech_id = str(off_tech_id).strip().upper()
        if not off_tech_id.startswith("T"):
            # some rows include non-ATT&CK subjects — skip
            continue

        attack_name = extract_value(entry, "off_tech_label") or off_tech_id
        entry_data = {
            "attack_id": off_tech_id,
            "attack_name": str(attack_name).strip(),
            "d3fend": []
        }

        # Extract a parent ATT&CK tactic id (TA000x) for this mapping row, if present.
        parent_tactic_raw = extract_value(entry, "def_tactic") or ""
        parent_tactic_id = ""
        if isinstance(parent_tactic_raw, str) and parent_tactic_raw:
            if "#" in parent_tactic_raw:
                parent_tactic_id = parent_tactic_raw.split("#")[-1].strip().upper()
            else:
                parent_tactic_id = parent_tactic_raw.strip().upper()

        seen_d3 = set()
        # Only iterate D3FEND resource fields (techniques/artifacts). def_tactic was handled above.
        for field in ["def_tech", "def_artifact"]:
            uri = extract_value(entry, field)
            label = extract_value(entry, f"{field}_label") or uri
            if uri and isinstance(uri, str) and "#" in uri:
                d3_id = uri.split("#")[-1].strip()
            else:
                # If label looks like a D3FEND id, use it
                d3_id = None
                if isinstance(label, str) and label.startswith("D3"):
                    d3_id = label
            if d3_id and d3_id not in seen_d3:
                seen_d3.add(d3_id)
                # Normalize name and decide whether to link to tactic vs technique
                name_str = (str(label).strip() if isinstance(label, str) else "") or d3_id
                tactic_names = {"harden", "detect", "isolate", "deceive", "evict", "restore"}
                path = "tactic" if name_str.lower() in tactic_names else "technique"

                # For techniques, attach the parent ATT&CK tactic id (if available).
                # For tactic entries, do not include a tactic_id.
                d3_type = path
                tactic_id = parent_tactic_id if d3_type == "technique" and parent_tactic_id else ""

                # Attach canonical D3FEND id (if available in the local ontology dump)
                d3fend_id = ""
                attack_ref = ""
                if d3_id in d3_meta:
                    if isinstance(d3_meta[d3_id].get("d3fend_id"), str):
                        d3fend_id = d3_meta[d3_id]["d3fend_id"]
                    if isinstance(d3_meta[d3_id].get("attack_id"), str):
                        attack_ref = d3_meta[d3_id]["attack_id"]

                entry_data["d3fend"].append({
                    "id": d3_id,
                    "d3fend_id": d3fend_id,
                    "attack_ref": attack_ref,
                    "name": name_str,
                    "type": d3_type,
                    "tactic_id": tactic_id,
                    "url": f"https://d3fend.mitre.org/{path}/d3f:{d3_id}"
                })

        if entry_data["d3fend"]:
            # Preferentially move known tactic names to the front so tactics show first in search results
            preferred = {"harden", "detect", "isolate", "deceive", "evict", "restore"}
            entry_data["d3fend"].sort(
                key=lambda d: 0 if d.get("type") == "tactic" and d.get("name", "").lower() in preferred else 1
            )
            mappings.append(entry_data)
    # Group duplicates by attack_id
    grouped = defaultdict(lambda: {"attack_id": "", "attack_name": "", "d3fend": []})
    for e in mappings:
        key = e["attack_id"]
        if not grouped[key]["attack_id"]:
            grouped[key]["attack_id"] = key
            grouped[key]["attack_name"] = e["attack_name"]
        grouped[key]["d3fend"].extend(e["d3fend"])

    final_mappings = []
    for key, g in grouped.items():
        # Dedupe D3FEND per technique (preserve order)
        seen = set()
        unique = []
        for d in g["d3fend"]:
            if d["id"] not in seen and d["id"]:
                seen.add(d["id"])
                unique.append(d)
        g["d3fend"] = unique
        final_mappings.append(g)

    print(f"SUCCESS: Loaded {len(final_mappings)} unique ATT&CK techniques with D3FEND countermeasures!")
    print(f"Example: {final_mappings[0]['attack_id']} - {len(final_mappings[0]['d3fend'])} defenses" if final_mappings else "No examples found.")
    return final_mappings

# Load at startup
mappings = load_mappings()

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/search")
def search():
    query = request.args.get("q", "").strip().upper()
    if not query:
        return jsonify({"error": "Enter a MITRE ATT&CK ID (e.g., T1566.001)"})

    # If the user pasted/selected an ID in the input, prefer that.
    # Try to extract an ATT&CK ID from the query (e.g., T1566 or T1566.001)
    id_match = re.search(r"T\d{4}(?:\.\d{3})?", query)
    if id_match:
        qid = id_match.group(0)
        # Support parent techniques (T1566 → T1566.001 etc.)
        if re.match(r"^T\d{4}$", qid):
            pattern = re.compile(rf"^{re.escape(qid)}(\.\d{{3}})?$")
        else:
            pattern = re.compile(rf"^{re.escape(qid)}$")
        results = [t for t in mappings if pattern.match(t["attack_id"])]
    else:
        # Treat query as a name search (case-insensitive substring match)
        qname = query.upper()
        results = [t for t in mappings if qname in (t.get("attack_name") or "").upper()]

    if not results:
        return jsonify({"error": f"No D3FEND correlations for '{query}'. Try an ATT&CK ID like T1566.001 or an attack name."})

    # Provide `attack_matches` in the shape the frontend expects (id/name/d3fend)
    # Build a sanitized response payload to reduce risk of reflected XSS when rendered client-side.
    attack_matches = []
    for t in results:
        safe_name = str(escape(t.get("attack_name") or t.get("attack_id")))
        safe_items = []
        for d in t.get("d3fend", []):
            safe_items.append({
                "id": str(escape(d.get("id", ""))),
                "name": str(escape(d.get("name", ""))),
                "type": str(escape(d.get("type", ""))),
                "tactic_id": str(escape(d.get("tactic_id", ""))) if d.get("tactic_id") else "",
                "d3fend_id": str(escape(d.get("d3fend_id", ""))) if d.get("d3fend_id") else "",
                "attack_ref": str(escape(d.get("attack_ref", ""))) if d.get("attack_ref") else "",
                "url": str(escape(d.get("url", "")))
            })
        attack_matches.append({
            "id": str(escape(t["attack_id"])),
            "name": safe_name,
            "d3fend": safe_items
        })

    return jsonify({
        "query": query,
        # keep `matches` for backward compatibility, but include `attack_matches` for UI
        "matches": results,
        "attack_matches": attack_matches,
        "total_d3fend": sum(len(t["d3fend"]) for t in results)
    })

# Debug route (remove after testing)
@app.route("/debug")
def debug():
    return jsonify({
        "total_loaded": len(mappings),
        "example_ids": [t["attack_id"] for t in mappings[:5]],
        "t1566_exists": any("T1566.001" in t["attack_id"] for t in mappings)
    })


@app.route("/api/attacks")
def api_attacks():
    """Return a list of available ATT&CK techniques (id + name).

    Query params:
      q (optional) - filter substring (case-insensitive)
      limit (optional) - max results (default 500)
    """
    q = request.args.get("q", "").strip().upper()
    try:
        limit = int(request.args.get("limit", 500))
    except ValueError:
        limit = 500

    out = []
    for t in mappings:
        tid = t.get("attack_id", "")
        name = (t.get("attack_name") or "").strip()
        if not tid:
            continue
        if not q or q in tid or q in name.upper():
            out.append({"id": tid, "name": name})
        if len(out) >= limit:
            break

    return jsonify(out)

if __name__ == "__main__":
    # Use env var to control debug in dev only. In production, run through gunicorn (Procfile).
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=debug)