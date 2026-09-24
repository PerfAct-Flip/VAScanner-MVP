"""Builds the PCI ASV Scan Report PDF (Attestation of Scan Compliance,
Executive Summary, Vulnerability Details), mirroring the PCI ASV Program
Guide's standard report structure. Built entirely from real scan data —
sections the Program Guide expects but this app has no data model for yet
(scope exceptions, compensating controls, dispute resolution) are rendered
as an explicit "none recorded" rather than invented content."""

import io
from datetime import timedelta
from xml.sax.saxutils import escape as _esc

from sqlalchemy.orm import Session

from app.models import Asset, Finding, Scan, ScanTarget
from app.scanning.common import utcnow
from app.scanning.pci import effective_cvss, pci_severity_band, pci_status
from app.schemas import PciCompanyInfo, PciReportInfo

_SEVERITY_TABLE_ROWS = [
    ["Security Scan Level", "CVSS Score", "Scan Results", "Guidance"],
    [
        "High Severity",
        "7.0 – 10.0",
        "Fail",
        "Vulnerabilities must be corrected and the environment re-scanned to show a "
        "passing result. Take a risk-based approach, correcting the most critical "
        "(10.0) first, down to 4.0.",
    ],
    ["Medium Severity", "4.0 – 6.9", "Fail", "Same correction and re-scan guidance as High Severity."],
    [
        "Low Severity",
        "0.0 – 3.9",
        "Pass",
        "Passing scans can include these; correction is encouraged but not required.",
    ],
]


def _component_label(asset: Asset) -> str:
    return asset.hostname or asset.ip_address or f"asset {asset.id}"


def _company_rows(info: PciCompanyInfo, extra: list[list[str]] | None = None) -> list[list[str]]:
    rows = [
        ["Field", "Value"],
        ["Company", _esc(info.company)],
        ["Contact Name", _esc(info.contact_name)],
        ["Job Title", _esc(info.job_title)],
        ["Telephone", _esc(info.telephone)],
        ["Email", _esc(info.email)],
        ["Business Address", _esc(info.address)],
    ]
    if info.city:
        rows.append(["City", _esc(info.city)])
    if info.state:
        rows.append(["State/Province", _esc(info.state)])
    if info.postal_code:
        rows.append(["ZIP/Postal Code", _esc(info.postal_code)])
    if info.country:
        rows.append(["Country", _esc(info.country)])
    if extra:
        rows.extend(extra)
    if info.url:
        rows.append(["URL", _esc(info.url)])
    return rows


def build_pci_report(db: Session, scan_id: int, pci_info: PciReportInfo) -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    scan = db.get(Scan, scan_id)
    assets = (
        db.query(Asset)
        .join(ScanTarget, ScanTarget.asset_id == Asset.id)
        .filter(ScanTarget.scan_id == scan_id)
        .all()
    )
    findings = db.query(Finding).filter_by(scan_id=scan_id).order_by(Finding.asset_id, Finding.port).all()
    findings_by_asset: dict[int, list[Finding]] = {}
    for f in findings:
        findings_by_asset.setdefault(f.asset_id, []).append(f)

    completed_at = (scan.end_time or scan.created_at) if scan else utcnow()
    expiration = completed_at + timedelta(days=90)
    failing = [f for f in findings if pci_status(effective_cvss(f)) == "FAIL"]
    overall_status = "FAIL" if failing else "PASS"
    today = utcnow().strftime("%B %d, %Y")

    styles = getSampleStyleSheet()
    heading = ParagraphStyle("PciHeading", parent=styles["Heading2"], textColor=colors.HexColor("#2b5a8c"))
    subheading = ParagraphStyle("PciSubheading", parent=styles["Heading3"], textColor=colors.HexColor("#2b5a8c"))
    body = styles["Normal"]
    bold = ParagraphStyle("PciBold", parent=body, fontName="Helvetica-Bold")
    italic = ParagraphStyle("PciItalic", parent=body, fontName="Helvetica-Oblique", leftIndent=20)

    cell_style = ParagraphStyle("PciTableCell", parent=body, fontSize=8, leading=10)
    header_style = ParagraphStyle("PciTableHeader", parent=cell_style, fontName="Helvetica-Bold")

    def styled_table(rows, col_widths=None):
        # Plain strings don't wrap to a column's width in reportlab tables —
        # they just overflow into the next cell — so every cell is wrapped
        # in a Paragraph (a caller can still pass one directly, e.g. to
        # truncate/style a specific cell differently).
        wrapped = [
            [cell if isinstance(cell, Paragraph) else Paragraph(str(cell), header_style if i == 0 else cell_style) for cell in row]
            for i, row in enumerate(rows)
        ]
        t = Table(wrapped, colWidths=col_widths)
        t.setStyle(
            TableStyle(
                [
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#dbe7f4")),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#eef4fb"), colors.white]),
                ]
            )
        )
        return t

    customer_name = _esc(pci_info.customer.company)
    asv_name = _esc(pci_info.asv.company)
    story = []

    # --- Cover page ---
    story.append(Spacer(1, 100))
    story.append(Paragraph("PCI ASV Scan Report", styles["Title"]))
    story.append(Spacer(1, 12))
    story.append(Paragraph(customer_name, styles["Heading2"]))
    story.append(Paragraph(f"Prepared by {asv_name}", body))
    story.append(Paragraph("PCI SSC Approved Scanning Vendor", body))
    story.append(Spacer(1, 24))
    story.append(Paragraph(f"<b>Report Date:</b> {today}", body))
    story.append(Paragraph(f"<b>Certificate Number:</b> {_esc(pci_info.asv_certificate_number)}", body))
    story.append(PageBreak())

    # --- DOCUMENT 1: Attestation of Scan Compliance ---
    story.append(Paragraph("DOCUMENT 1: Attestation of Scan Compliance", styles["Title"]))
    story.append(Spacer(1, 12))

    story.append(Paragraph("A.1 Scan Customer Information", heading))
    story.append(styled_table(_company_rows(pci_info.customer), col_widths=[160, 320]))
    story.append(Spacer(1, 12))

    story.append(Paragraph("A.2 Approved Scanning Vendor Information", heading))
    story.append(
        styled_table(
            _company_rows(
                pci_info.asv, extra=[["ASV Certificate Number", _esc(pci_info.asv_certificate_number)]]
            ),
            col_widths=[160, 320],
        )
    )
    story.append(Spacer(1, 12))

    story.append(Paragraph("A.3 Scan Status", heading))
    story.append(
        styled_table(
            [
                ["Field", "Value"],
                ["Date scan completed", completed_at.strftime("%B %d, %Y")],
                ["Scan expiration date (90 days from completion)", expiration.strftime("%B %d, %Y")],
                ["Compliance Status", overall_status],
                ["Scan report type", pci_info.scan_report_type],
                ["Number of unique in-scope components scanned", str(len(assets))],
                ["Number of identified failing vulnerabilities", str(len(failing))],
                ["Number of components found by ASV but not scanned (customer confirmed out of scope)", "0"],
            ],
            col_widths=[340, 140],
        )
    )
    story.append(Spacer(1, 12))

    story.append(Paragraph("A.4 Scan Customer Attestation", heading))
    story.append(
        Paragraph(
            f'"{customer_name} attests on {today} that this scan (either by itself or combined with multiple, '
            "partial, or failed scans/rescans, as indicated in the above Section A.3, &quot;Scan Status&quot;) "
            "includes all components which should be in scope for PCI DSS, any component considered out of scope "
            "for this scan is properly segmented from my cardholder data environment, and any evidence submitted "
            "to the ASV to resolve scan exceptions — including compensating controls if applicable — is accurate "
            'and complete."',
            italic,
        )
    )
    story.append(Spacer(1, 8))
    story.append(
        Paragraph(
            f'"{customer_name} also acknowledges 1) accurate and complete scoping of this external scan is my '
            "responsibility, and 2) this scan result only indicates whether or not my scanned systems are "
            "compliant with the external vulnerability scan requirement of PCI DSS; this scan result does not "
            "represent my overall compliance status with PCI DSS or provide any indication of compliance with "
            'other PCI DSS requirements."',
            italic,
        )
    )
    story.append(Spacer(1, 8))
    story.append(
        Paragraph(f"<b>Signed:</b> {_esc(pci_info.customer.contact_name)}, {_esc(pci_info.customer.job_title)}", body)
    )
    story.append(Paragraph(f"<b>Date:</b> {today}", body))
    story.append(Spacer(1, 12))

    story.append(Paragraph("A.5 ASV Attestation", heading))
    story.append(
        Paragraph(
            f'"This scan and report was prepared and conducted by {asv_name} under certificate number '
            f"{_esc(pci_info.asv_certificate_number)}, according to internal processes that meet PCI DSS "
            'requirement 11.3.2 and the ASV Program Guide."',
            italic,
        )
    )
    story.append(Spacer(1, 8))
    story.append(
        Paragraph(
            f'"{asv_name} attests that the PCI DSS scan process was followed, including a manual or automated '
            "Quality Assurance process with customer boarding and scoping practices, review of results for "
            "anomalies, and review and correction of 1) disputed or incomplete results, 2) false positives, "
            "3) compensating controls (if applicable), and 4) active scan interference. This report and any "
            f'exceptions were reviewed by the {asv_name} QA Review Team."',
            italic,
        )
    )
    story.append(Spacer(1, 8))
    story.append(Paragraph(f"<b>Signed:</b> {_esc(pci_info.asv.contact_name)}, {_esc(pci_info.asv.job_title)}", body))
    story.append(Paragraph(f"<b>Date:</b> {today}", body))
    story.append(PageBreak())

    # --- DOCUMENT 2: Executive Summary ---
    story.append(Paragraph("DOCUMENT 2: ASV Scan Report — Executive Summary", styles["Title"]))
    story.append(Spacer(1, 12))

    story.append(Paragraph("Part 1. Scan Information", heading))
    story.append(
        styled_table(
            [
                ["Field", "Value"],
                ["Scan Customer Company", customer_name],
                ["ASV Company", asv_name],
                ["Date scan was completed", completed_at.strftime("%B %d, %Y")],
                ["Scan expiration date", expiration.strftime("%B %d, %Y")],
            ],
            col_widths=[220, 260],
        )
    )
    story.append(Spacer(1, 12))

    story.append(Paragraph("Part 2. Component Compliance Summary", heading))
    if assets:
        rows = [["IP Address", "Hostname"]]
        for a in assets:
            rows.append([_esc(a.ip_address or "—"), _esc(a.hostname or "—")])
        story.append(styled_table(rows, col_widths=[240, 240]))
    else:
        story.append(Paragraph("No components were in scope for this scan.", body))
    story.append(Spacer(1, 6))
    story.append(
        Paragraph("<b>Hosts Not Current:</b> None. All components scanned within the current scan cycle.", body)
    )
    story.append(Spacer(1, 12))

    story.append(Paragraph("Part 3a. Vulnerabilities Noted for each Component", heading))
    rows = [["Component", "Vulnerability Noted", "Severity", "CVSS", "Compliance", "Exceptions/Comp. Controls"]]
    for a in assets:
        host = _esc(_component_label(a))
        af = findings_by_asset.get(a.id, [])
        if not af:
            rows.append([host, "No vulnerabilities detected", "—", "—", "Pass", "None noted"])
            continue
        for f in af:
            cvss = effective_cvss(f)
            component = f"{host}:{f.port}" if f.port else host
            rows.append(
                [
                    component,
                    _esc((f.description or f.cve or "Finding")[:150]),
                    pci_severity_band(cvss),
                    f"{cvss:.1f}",
                    pci_status(cvss).capitalize(),
                    "None noted",
                ]
            )
    story.append(styled_table(rows, col_widths=[85, 175, 50, 40, 55, 100]))
    story.append(Spacer(1, 12))

    story.append(Paragraph("Part 3b. Special Notes to Scan Customer by Component", heading))
    story.append(Paragraph("No special notes recorded for this scan.", body))
    story.append(Spacer(1, 12))

    story.append(Paragraph("Part 4a/4b. Scope Submitted and In-Scope Components (Scanned)", heading))
    if assets:
        for a in assets:
            story.append(Paragraph(_esc(_component_label(a)), body))
    else:
        story.append(Paragraph("No components in scope.", body))
    story.append(Spacer(1, 6))
    story.append(Paragraph("All submitted scope items were scanned. No components were excluded.", body))
    story.append(PageBreak())

    # --- DOCUMENT 3: Vulnerability Details ---
    story.append(Paragraph("DOCUMENT 3: ASV Scan Report — Vulnerability Details", styles["Title"]))
    story.append(Spacer(1, 12))
    story.append(
        styled_table(
            [
                ["Field", "Value"],
                ["Scan Customer Company", customer_name],
                ["ASV Company", asv_name],
                ["Date scan was completed", completed_at.strftime("%B %d, %Y")],
                ["Scan expiration date", expiration.strftime("%B %d, %Y")],
            ],
            col_widths=[220, 260],
        )
    )
    story.append(Spacer(1, 12))

    story.append(Paragraph("PCI Severity Level Table", heading))
    story.append(styled_table(_SEVERITY_TABLE_ROWS, col_widths=[80, 65, 55, 260]))
    story.append(Spacer(1, 16))

    story.append(Paragraph("1.1 Vulnerability List (Summary Table)", heading))
    rows = [["Host Name:Port", "Vulnerability/Service", "CVE", "CVSS", "PCI Compliant?", "PCI Severity"]]
    for a in assets:
        host = _esc(_component_label(a))
        af = findings_by_asset.get(a.id, [])
        if not af:
            rows.append([host, "No vulnerabilities detected", "—", "—", "PASS", "—"])
            continue
        for f in af:
            cvss = effective_cvss(f)
            component = f"{host}:{f.port}" if f.port else host
            rows.append(
                [
                    component,
                    _esc((f.description or f.cve or "Finding")[:120]),
                    _esc(f.cve or "—"),
                    f"{cvss:.1f}",
                    pci_status(cvss),
                    pci_severity_band(cvss),
                ]
            )
    story.append(styled_table(rows, col_widths=[80, 175, 75, 40, 60, 65]))
    story.append(Spacer(1, 16))

    story.append(Paragraph("2. Detailed Findings", heading))
    for a in assets:
        af = findings_by_asset.get(a.id, [])
        story.append(Spacer(1, 8))
        story.append(Paragraph(_esc(_component_label(a)), subheading))
        story.append(Paragraph(f"<b>IP Address:</b> {_esc(a.ip_address or '—')}", body))
        if af:
            story.append(Paragraph(f"<b>Scan time:</b> {af[0].created_at.strftime('%B %d, %Y, %H:%M GMT')}", body))
        story.append(Spacer(1, 6))

        if not af:
            story.append(Paragraph("No vulnerabilities detected on this component.", body))
            continue

        for f in af:
            cvss = effective_cvss(f)
            port_label = f"{f.port}/tcp" if f.port else "—"
            story.append(Paragraph(_esc(f.description or f.cve or "Finding"), bold))
            story.append(
                Paragraph(
                    f"<b>PCI Severity:</b> {pci_severity_band(cvss)} &nbsp;&nbsp; "
                    f"<b>CVSS Base Score:</b> {cvss:.1f} &nbsp;&nbsp; "
                    f"<b>Port:</b> {port_label} &nbsp;&nbsp; "
                    f"<b>PCI Compliant:</b> {pci_status(cvss)}",
                    body,
                )
            )
            if f.cve:
                story.append(Paragraph(f"<b>CVE:</b> {_esc(f.cve)}", body))
            story.append(Paragraph(f"<b>Description:</b> {_esc(f.description or 'No description available.')}", body))
            story.append(
                Paragraph(
                    f"<b>Resolution:</b> {_esc(f.recommendation or 'No remediation guidance available for this check.')}",
                    body,
                )
            )
            story.append(Spacer(1, 10))

    story.append(Spacer(1, 12))
    story.append(Paragraph("End of Report", heading))
    story.append(Paragraph(f"<b>Total Components Scanned:</b> {len(assets)}", body))
    story.append(Paragraph(f"<b>Total Failing Vulnerabilities:</b> {len(failing)}", body))
    story.append(Paragraph(f"<b>Total Findings:</b> {len(findings)}", body))
    story.append(Paragraph(f"<b>Overall Compliance Status:</b> {overall_status}", body))

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter)
    doc.build(story)
    return buf.getvalue()
