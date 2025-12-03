#!/usr/bin/env python3
"""Test CVSS vector parsing."""

import sys
sys.path.insert(0, 'c:\\Users\\rautp\\Documents\\sca\\backend')

from sca_core import VulnerabilityDatabase, Severity

vuln_db = VulnerabilityDatabase()

# Test the CVSS vector from markdown-pdf
vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
score = vuln_db._estimate_cvss_from_vector(vector)
severity = vuln_db._severity_from_cvss(score) if score else None

print(f"Vector: {vector}")
print(f"Estimated Score: {score}")
print(f"Severity: {severity}")

# Verify this gives us HIGH
expected = Severity.HIGH
print(f"\nExpected: {expected}")
print(f"Match: {severity == expected}")

# Test the full inference with actual OSV response
print("\n" + "="*50)
print("Testing full severity inference:")
print("="*50)

test_vuln = {
    "id": "GHSA-qghr-877h-f9jh",
    "summary": "markdown-pdf vulnerable to local file read via server side cross-site scripting (XSS)",
    "database_specific": {
        "severity": "HIGH"
    },
    "severity": [
        {
            "type": "CVSS_V3",
            "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
        }
    ]
}

inferred_severity = vuln_db._infer_severity(test_vuln)
print(f"Inferred Severity: {inferred_severity}")
print(f"Expected: {Severity.HIGH}")
print(f"Match: {inferred_severity == Severity.HIGH}")
