#!/usr/bin/env python3
"""Test script to check OSV API responses."""

import json
import urllib.request

OSV_API = "https://api.osv.dev/v1/query"

# Test markdown-pdf vulnerability
payload = {
    "package": {"name": "markdown-pdf", "ecosystem": "npm"},
    "version": "11.0.0"
}

try:
    req = urllib.request.Request(
        OSV_API,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"}
    )
    
    with urllib.request.urlopen(req, timeout=10) as response:
        data = json.loads(response.read().decode())
    
    print("Full API Response:")
    print(json.dumps(data, indent=2))
    
    print("\n" + "="*80)
    print("Analyzing vulnerabilities:")
    print("="*80)
    
    for vuln in data.get("vulns", []):
        print(f"\nVulnerability ID: {vuln.get('id')}")
        print(f"Summary: {vuln.get('summary')}")
        print(f"Severity: {vuln.get('severity')}")
        print(f"Full vulnerability object:")
        print(json.dumps(vuln, indent=2, default=str))
        
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()
