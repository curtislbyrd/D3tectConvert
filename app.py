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
    "connect-src": ["'self'", "https://cdn.jsdelivr.net"],
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

SEARCH_INDEX_FILE = os.path.join(os.path.dirname(__file__), "static", "search_index.json")

# Only use the compact JSON index for all lookups

def load_mappings():
    if os.path.exists(SEARCH_INDEX_FILE):
        try:
            with open(SEARCH_INDEX_FILE, "r", encoding="utf-8") as sf:
                return json.load(sf)
        except Exception:
            pass
    return []

mappings = load_mappings()

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/search")
def search():
    query = request.args.get("q", "").strip()
    if not query:
        return jsonify({"error": "Enter a MITRE ATT&CK ID (e.g., T1566.001)"})

    q = query.strip().upper()
    id_match = re.search(r"T\d{4}(?:\.\d{3})?", q)
    if id_match:
        qid = id_match.group(0)
        if re.match(r"^T\d{4}$", qid):
            pattern = re.compile(rf"^{re.escape(qid)}(\.\d{{3}})?$")
        else:
            pattern = re.compile(rf"^{re.escape(qid)}$")
        results = [t for t in mappings if pattern.match(t["attack_id"])]
    else:
        qname = q.upper()
        results = [t for t in mappings if qname in (t.get("attack_name") or "").upper()]

    if not results:
        return jsonify({"error": f"No D3FEND correlations for '{query}'. Try an ATT&CK ID like T1566.001 or an attack name."})

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
        "matches": results,
        "attack_matches": attack_matches,
        "total_d3fend": sum(len(t["d3fend"]) for t in results)
    })

@app.route("/api/attacks")
def api_attacks():
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

@app.route("/debug")
def debug():
    return jsonify({
        "total_loaded": len(mappings),
        "example_ids": [t["attack_id"] for t in mappings[:5]],
        "t1566_exists": any("T1566.001" in t["attack_id"] for t in mappings)
    })

if __name__ == "__main__":
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=debug)