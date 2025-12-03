#!/usr/bin/env python3
"""Test risk score calculation."""

import sys
sys.path.insert(0, 'c:\\Users\\rautp\\Documents\\sca\\backend')

from sca_core import Dependency, Vulnerability, Severity

# Create the markdown-pdf vulnerability
vuln = Vulnerability(
    cve_id="GHSA-qghr-877h-f9jh",
    severity=Severity.HIGH,
    description="markdown-pdf vulnerable to local file read via server side cross-site scripting (XSS)",
    cvss_score=7.5,
    fixed_version=None
)

# Create the dependency
dep = Dependency(
    name="markdown-pdf",
    version="11.0.0",
    package_manager="npm",
    vulnerabilities=[vuln]
)

print(f"Package: {dep.name} {dep.version}")
print(f"Vulnerability Severity: {vuln.severity.value}")
print(f"Risk Score: {dep.risk_score}")
print(f"\nExpected Risk Score: 1.5 (for single HIGH severity vulnerability)")
print(f"Match: {dep.risk_score == 1.5}")
