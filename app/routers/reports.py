import csv
import io

from fastapi import APIRouter, Depends
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Asset, Finding

router = APIRouter(prefix="/api/v1/reports", tags=["reports"])


def _query_findings(db: Session, scan_id: int | None):
    query = db.query(Finding).order_by(Finding.engine, Finding.created_at.desc())
    if scan_id is not None:
        query = query.filter(Finding.scan_id == scan_id)
    return query.all()


def _asset_label(db: Session, asset_id: int) -> str:
    asset = db.get(Asset, asset_id)
    if not asset:
        return str(asset_id)
    return asset.hostname or asset.ip_address or str(asset_id)


@router.get("/csv")
def report_csv(scan_id: int | None = None, db: Session = Depends(get_db)):
    findings = _query_findings(db, scan_id)

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["ID", "Engine", "Asset", "Severity", "CVE", "Description", "Recommendation", "Created At"])
    for f in findings:
        writer.writerow(
            [f.id, f.engine, _asset_label(db, f.asset_id), f.severity, f.cve or "", f.description or "", f.recommendation or "", f.created_at]
        )

    filename = f"report_scan_{scan_id}.csv" if scan_id else "report_findings.csv"
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.get("/pdf")
def report_pdf(scan_id: int | None = None, db: Session = Depends(get_db)):
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    findings = _query_findings(db, scan_id)
    styles = getSampleStyleSheet()

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter)
    title = f"Vulnerability Findings — Scan {scan_id}" if scan_id else "Vulnerability Findings — All Scans"
    story = [Paragraph(title, styles["Title"]), Spacer(1, 12)]

    for engine_name, label in (("nuclei", "Nuclei Results"), ("openvas", "OpenVAS Results")):
        section = [f for f in findings if f.engine == engine_name]
        story.append(Paragraph(label, styles["Heading2"]))
        if not section:
            story.append(Paragraph("No findings.", styles["Normal"]))
            story.append(Spacer(1, 12))
            continue

        rows = [["Asset", "Severity", "CVE", "Description"]]
        for f in section:
            rows.append([
                _asset_label(db, f.asset_id),
                f.severity,
                f.cve or "-",
                Paragraph((f.description or "")[:300], styles["Normal"]),
            ])

        table = Table(rows, colWidths=[100, 60, 80, 240])
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2d3748")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                ]
            )
        )
        story.append(table)
        story.append(Spacer(1, 16))

    doc.build(story)
    buf.seek(0)

    filename = f"report_scan_{scan_id}.pdf" if scan_id else "report_findings.pdf"
    return StreamingResponse(
        buf,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )
