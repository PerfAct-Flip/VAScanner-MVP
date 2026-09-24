import csv
import io

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Asset, Finding, Report, Scan
from app.scanning.pci_report import build_pci_report
from app.schemas import ReportCreate, ReportOut

router = APIRouter(prefix="/api/v1/reports", tags=["reports"])

_MEDIA_TYPES = {"csv": "text/csv", "pdf": "application/pdf", "pci": "application/pdf"}


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


def _build_csv(db: Session, scan_id: int | None) -> bytes:
    findings = _query_findings(db, scan_id)

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["ID", "Engine", "Asset", "Severity", "CVE", "Description", "Recommendation", "Created At"])
    for f in findings:
        writer.writerow(
            [f.id, f.engine, _asset_label(db, f.asset_id), f.severity, f.cve or "", f.description or "", f.recommendation or "", f.created_at]
        )
    return buf.getvalue().encode("utf-8")


def _build_pdf(db: Session, scan_id: int | None) -> bytes:
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
    return buf.getvalue()


def _build_report(db: Session, scan_id: int | None, fmt: str, pci_info=None) -> bytes:
    if fmt == "csv":
        return _build_csv(db, scan_id)
    if fmt == "pci":
        return build_pci_report(db, scan_id, pci_info)
    return _build_pdf(db, scan_id)


@router.get("/csv")
def report_csv(scan_id: int | None = None, db: Session = Depends(get_db)):
    content = _build_csv(db, scan_id)
    filename = f"report_scan_{scan_id}.csv" if scan_id else "report_findings.csv"
    return StreamingResponse(
        iter([content]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.get("/pdf")
def report_pdf(scan_id: int | None = None, db: Session = Depends(get_db)):
    content = _build_pdf(db, scan_id)
    filename = f"report_scan_{scan_id}.pdf" if scan_id else "report_findings.pdf"
    return StreamingResponse(
        iter([content]),
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


# ---------------------------------------------------------------------------
# Generated (persisted) reports — a snapshot saved at generation time, kept
# around for later download, distinct from the always-live /csv and /pdf
# endpoints above.
# ---------------------------------------------------------------------------


@router.post("", response_model=ReportOut, status_code=201)
def generate_report(payload: ReportCreate, db: Session = Depends(get_db)):
    if payload.scan_id is not None and not db.get(Scan, payload.scan_id):
        raise HTTPException(status_code=404, detail=f"Unknown scan_id: {payload.scan_id}")

    findings = _query_findings(db, payload.scan_id)
    content = _build_report(db, payload.scan_id, payload.format, pci_info=payload.pci_info)

    report = Report(
        scan_id=payload.scan_id,
        format=payload.format,
        content=content,
        finding_count=len(findings),
    )
    db.add(report)
    db.commit()
    db.refresh(report)
    return report


@router.get("", response_model=list[ReportOut])
def list_reports(scan_id: int | None = None, db: Session = Depends(get_db)):
    query = db.query(Report).order_by(Report.generated_at.desc())
    if scan_id is not None:
        query = query.filter(Report.scan_id == scan_id)
    return query.all()


@router.get("/{report_id}/download")
def download_report(report_id: int, db: Session = Depends(get_db)):
    report = db.get(Report, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    ext = "pdf" if report.format == "pci" else report.format
    name_prefix = "pci_asv_report" if report.format == "pci" else "report"
    filename = (
        f"{name_prefix}_{report.id}_scan_{report.scan_id}.{ext}"
        if report.scan_id
        else f"{name_prefix}_{report.id}.{ext}"
    )
    return StreamingResponse(
        iter([report.content]),
        media_type=_MEDIA_TYPES[report.format],
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.delete("/{report_id}", status_code=204)
def delete_report(report_id: int, db: Session = Depends(get_db)):
    report = db.get(Report, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    db.delete(report)
    db.commit()
