#!/usr/bin/env python3
"""
Simple build-time script to download the D3FEND ↔ ATT&CK mappings file.
Use this in your Render/CI build step to populate `mappings.json` before starting the app.
"""
import requests
import os

MAPPINGS_URL = "https://d3fend.mitre.org/api/ontology/inference/d3fend-full-mappings.json"
OUT = os.path.join(os.path.dirname(__file__), '..', 'mappings.json')

print('Downloading mappings...')
resp = requests.get(MAPPINGS_URL, timeout=120)
resp.raise_for_status()
with open(OUT, 'w', encoding='utf-8') as f:
    f.write(resp.text)
print('Wrote', OUT)
