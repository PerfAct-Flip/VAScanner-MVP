"""PCI ASV-style scoring. Mirrors the PCI ASV Program Guide's severity/status
rule: CVSS >= 4.0 fails a component, below that passes (informational).
Not every engine reports a real CVSS score — the SSH audit's config/posture
checks have no CVE to score against — so those fall back to a fixed
per-severity-band estimate rather than leaving the report with a blank
score it can't compute a pass/fail from."""

from app.models import Finding

_SEVERITY_CVSS_FALLBACK = {
    "Critical": 10.0,
    "High": 7.5,
    "Medium": 5.5,
    "Low": 2.0,
    "Informational": 0.0,
}


def effective_cvss(finding: Finding) -> float:
    if finding.cvss_score is not None:
        return finding.cvss_score
    return _SEVERITY_CVSS_FALLBACK.get(finding.severity, 0.0)


def pci_severity_band(cvss: float) -> str:
    if cvss >= 7.0:
        return "High"
    if cvss >= 4.0:
        return "Medium"
    return "Low"


def pci_status(cvss: float) -> str:
    return "FAIL" if cvss >= 4.0 else "PASS"
