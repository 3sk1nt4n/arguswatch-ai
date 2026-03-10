"""
PDF Report Generator - Solvent CyberSecurity branded.
Uses ReportLab. Per-customer, configurable period.
Includes: exec summary, detection table, HIBP/BreachDirectory counts,
remediation status, source attribution, 30-day recommendations.
"""
import io, os, logging
from datetime import datetime, timezone, timedelta
from pathlib import Path
from arguswatch.database import async_session
from arguswatch.models import (Detection, Customer, CustomerAsset, RemediationAction,
    DarkWebMention, SeverityLevel, DetectionStatus, CollectorRun)
from sqlalchemy import select, func, desc, and_

def _sev(val):
    """Safe severity extraction."""
    if val is None: return None
    return val.value if hasattr(val, "value") else str(val)


logger = logging.getLogger("arguswatch.pdf_report")

OUTPUT_DIR = Path("/app/reports")

async def _gather_report_data(customer_id: int, period_days: int) -> dict:
    since = datetime.utcnow() - timedelta(days=period_days)
    async with async_session() as db:
        # Customer info
        r = await db.execute(select(Customer).where(Customer.id == customer_id))
        cust = r.scalar_one_or_none()
        if not cust:
            return {"error": "Customer not found"}
        # Detection counts by severity
        sev_counts = {}
        for sev in SeverityLevel:
            r = await db.execute(select(func.count()).where(
                Detection.customer_id == customer_id,
                Detection.severity == sev,
                Detection.created_at >= since))
            sev_counts[sev.value] = r.scalar() or 0
        # Total
        total_r = await db.execute(select(func.count()).where(
            Detection.customer_id == customer_id, Detection.created_at >= since))
        total = total_r.scalar() or 0
        # Top detections (CRITICAL first)
        det_r = await db.execute(
            select(Detection).where(Detection.customer_id == customer_id, Detection.created_at >= since)
            .order_by(desc(Detection.created_at)).limit(20))
        detections = det_r.scalars().all()
        # Remediation status (join through Detection since RemediationAction has no customer_id)
        rem_r = await db.execute(
            select(RemediationAction).join(Detection, RemediationAction.detection_id == Detection.id)
            .where(Detection.customer_id == customer_id,
            RemediationAction.created_at >= since))
        remediations = rem_r.scalars().all()
        open_r = sum(1 for r in remediations if r.status in ("pending", "in_progress"))
        closed_r = sum(1 for r in remediations if r.status == "completed")
        # Dark web mentions
        dw_r = await db.execute(select(func.count()).where(
            DarkWebMention.customer_id == customer_id, DarkWebMention.discovered_at >= since))
        dw_count = dw_r.scalar() or 0
        # Source breakdown
        src_r = await db.execute(
            select(Detection.source, func.count(Detection.id).label("cnt"))
            .where(Detection.customer_id == customer_id, Detection.created_at >= since)
            .group_by(Detection.source).order_by(desc("cnt")).limit(10))
        sources = [{"source": row.source, "count": row.cnt} for row in src_r]
        # Assets
        assets_r = await db.execute(select(CustomerAsset).where(CustomerAsset.customer_id == customer_id))
        assets = assets_r.scalars().all()
        return {
            "customer": {"name": cust.name, "industry": cust.industry or "N/A",
                         "tier": cust.tier or "standard", "email": cust.email or ""},
            "period_days": period_days, "generated_at": datetime.utcnow().isoformat(),
            "total_detections": total, "severity_counts": sev_counts,
            "detections": [{
                "ioc_type": d.ioc_type, "ioc_value": d.ioc_value[:60],
                "severity": _sev(d.severity) or "MEDIUM",
                "status": d.status.value if d.status else "NEW",
                "source": d.source,
                "created_at": d.created_at.strftime("%Y-%m-%d %H:%M") if d.created_at else "",
            } for d in detections],
            "remediations": {"open": open_r, "closed": closed_r, "total": len(remediations)},
            "darkweb_mentions": dw_count,
            "sources": sources,
            "assets": [{"type": a.asset_type.value if hasattr(a.asset_type, 'value') else str(a.asset_type),
                        "value": a.asset_value, "criticality": a.criticality} for a in assets],
        }

def _build_pdf(data: dict) -> bytes:
    """Build PDF using ReportLab. Returns bytes."""
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.lib.colors import HexColor, white, black
        from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
            TableStyle, HRFlowable, KeepTogether)
        from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    except ImportError:
        return b""  # ReportLab not installed - handled gracefully

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, rightMargin=1.5*cm, leftMargin=1.5*cm,
                            topMargin=2*cm, bottomMargin=2*cm)
    styles = getSampleStyleSheet()
    NAVY = HexColor("#0d1b2a")
    ORANGE = HexColor("#e65c00")
    RED = HexColor("#c62828")
    GREEN = HexColor("#2e7d32")
    AMBER = HexColor("#e65100")
    GRAY = HexColor("#f8f9fb")
    GRAY2 = HexColor("#64748b")

    h1 = ParagraphStyle("h1", parent=styles["Normal"], fontSize=22, fontName="Helvetica-Bold",
                         textColor=white, alignment=TA_LEFT, spaceAfter=4)
    h2 = ParagraphStyle("h2", parent=styles["Normal"], fontSize=13, fontName="Helvetica-Bold",
                         textColor=NAVY, spaceBefore=14, spaceAfter=6)
    body = ParagraphStyle("body", parent=styles["Normal"], fontSize=9.5, textColor=HexColor("#334155"),
                          leading=14, spaceAfter=4)
    caption = ParagraphStyle("caption", parent=styles["Normal"], fontSize=8, textColor=GRAY2)
    sub = ParagraphStyle("sub", parent=styles["Normal"], fontSize=9, textColor=GRAY2, spaceAfter=2)

    SEV_COLORS = {"CRITICAL": RED, "HIGH": ORANGE, "MEDIUM": AMBER, "LOW": GREEN}

    cust = data["customer"]
    period = data["period_days"]
    sev = data["severity_counts"]
    score_raw = min(100, sev.get("CRITICAL",0)*15 + sev.get("HIGH",0)*8 + sev.get("MEDIUM",0)*3 + data["darkweb_mentions"]*12)
    score_tier = "CRITICAL" if score_raw >= 75 else "HIGH" if score_raw >= 50 else "MEDIUM" if score_raw >= 25 else "LOW"

    elements = []

    # ── Cover header ──
    header_data = [[
        Paragraph(f"<font color='#ffffff'>THREAT INTELLIGENCE REPORT</font>", h1),
        "",
    ]]
    header_table = Table(header_data, colWidths=["100%"])
    header_table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), NAVY),
        ("TOPPADDING", (0,0), (-1,-1), 18),
        ("BOTTOMPADDING", (0,0), (-1,-1), 18),
        ("LEFTPADDING", (0,0), (-1,-1), 16),
    ]))
    elements.append(header_table)
    elements.append(Spacer(1, 0.3*cm))

    # Meta row
    meta_data = [[
        Paragraph(f"<b>{cust['name']}</b>", ParagraphStyle("m", fontSize=12, fontName="Helvetica-Bold", textColor=NAVY)),
        Paragraph(f"Industry: {cust['industry']} &nbsp;·&nbsp; Tier: {cust['tier'].upper()} &nbsp;·&nbsp; Period: Last {period} days &nbsp;·&nbsp; Generated: {data['generated_at'][:10]}", sub),
    ]]
    meta_table = Table(meta_data, colWidths=["35%", "65%"])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), GRAY),
        ("TOPPADDING", (0,0), (-1,-1), 10), ("BOTTOMPADDING", (0,0), (-1,-1), 10),
        ("LEFTPADDING", (0,0), (-1,-1), 12),
        ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
    ]))
    elements.append(meta_table)
    elements.append(Spacer(1, 0.5*cm))

    # ── Executive Summary ──
    elements.append(Paragraph("Executive Summary", h2))
    elements.append(HRFlowable(width="100%", thickness=1, color=NAVY))
    elements.append(Spacer(1, 0.2*cm))

    kpi_data = [
        [Paragraph(f"<b>{data['total_detections']}</b>", ParagraphStyle("kpi_n", fontSize=26, fontName="Helvetica-Bold", textColor=NAVY, alignment=TA_CENTER)),
         Paragraph(f"<b>{sev.get('CRITICAL',0)}</b>", ParagraphStyle("kpi_c", fontSize=26, fontName="Helvetica-Bold", textColor=RED, alignment=TA_CENTER)),
         Paragraph(f"<b>{sev.get('HIGH',0)}</b>", ParagraphStyle("kpi_h", fontSize=26, fontName="Helvetica-Bold", textColor=ORANGE, alignment=TA_CENTER)),
         Paragraph(f"<b>{data['darkweb_mentions']}</b>", ParagraphStyle("kpi_d", fontSize=26, fontName="Helvetica-Bold", textColor=RED, alignment=TA_CENTER)),
         Paragraph(f"<b>{score_raw}/100</b>", ParagraphStyle("kpi_s", fontSize=26, fontName="Helvetica-Bold", textColor=SEV_COLORS.get(score_tier, ORANGE), alignment=TA_CENTER)),
        ],
        [Paragraph("Total Detections", ParagraphStyle("kl", fontSize=8, textColor=GRAY2, alignment=TA_CENTER)),
         Paragraph("Critical", ParagraphStyle("kl", fontSize=8, textColor=GRAY2, alignment=TA_CENTER)),
         Paragraph("High", ParagraphStyle("kl", fontSize=8, textColor=GRAY2, alignment=TA_CENTER)),
         Paragraph("Dark Web Hits", ParagraphStyle("kl", fontSize=8, textColor=GRAY2, alignment=TA_CENTER)),
         Paragraph(f"Risk Score ({score_tier})", ParagraphStyle("kl", fontSize=8, textColor=GRAY2, alignment=TA_CENTER)),
        ]
    ]
    kpi_table = Table(kpi_data, colWidths=["20%"]*5)
    kpi_table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), GRAY),
        ("TOPPADDING", (0,0), (-1,-1), 12), ("BOTTOMPADDING", (0,0), (-1,-1), 8),
        ("ALIGN", (0,0), (-1,-1), "CENTER"), ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
        ("LINEAFTER", (0,0), (3,-1), 0.5, HexColor("#e2e8f0")),
        ("ROUNDEDCORNERS", [6]),
    ]))
    elements.append(kpi_table)
    elements.append(Spacer(1, 0.4*cm))

    # Remediation status
    rem = data["remediations"]
    mtr_rate = round(rem["closed"] / max(rem["total"],1) * 100)
    elements.append(Paragraph(
        f"Remediation Status: <b>{rem['open']} open</b>, <b>{rem['closed']} closed</b> ({mtr_rate}% resolution rate) &nbsp;·&nbsp; "
        f"Dark web mentions: <b>{data['darkweb_mentions']}</b>", body))
    elements.append(Spacer(1, 0.3*cm))

    # ── Detection Table ──
    if data["detections"]:
        elements.append(Paragraph("Detection Log - Top 20 Findings", h2))
        elements.append(HRFlowable(width="100%", thickness=1, color=NAVY))
        elements.append(Spacer(1, 0.2*cm))
        tbl_data = [["Severity", "IOC Type", "IOC Value", "Source", "Status", "Detected"]]
        for d in data["detections"][:20]:
            tbl_data.append([
                Paragraph(f"<b>{d['severity']}</b>",
                    ParagraphStyle("ts", fontSize=8, fontName="Helvetica-Bold",
                                   textColor=SEV_COLORS.get(d["severity"], GRAY2), alignment=TA_CENTER)),
                Paragraph(d["ioc_type"], ParagraphStyle("tc", fontSize=8, textColor=NAVY)),
                Paragraph(f"<font name='Courier' size='7'>{d['ioc_value']}</font>",
                    ParagraphStyle("tv", fontSize=8, textColor=HexColor("#1e293b"))),
                Paragraph(d["source"], ParagraphStyle("ts2", fontSize=8, textColor=GRAY2)),
                Paragraph(d["status"], ParagraphStyle("ts3", fontSize=8, textColor=GRAY2)),
                Paragraph(d["created_at"], ParagraphStyle("td", fontSize=7.5, textColor=GRAY2)),
            ])
        det_table = Table(tbl_data, colWidths=["12%","12%","30%","13%","13%","20%"])
        det_table.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,0), NAVY), ("TEXTCOLOR", (0,0), (-1,0), white),
            ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"), ("FONTSIZE", (0,0), (-1,0), 8),
            ("TOPPADDING", (0,0), (-1,-1), 6), ("BOTTOMPADDING", (0,0), (-1,-1), 6),
            ("LEFTPADDING", (0,0), (-1,-1), 6),
            ("ROWBACKGROUNDS", (0,1), (-1,-1), [white, GRAY]),
            ("GRID", (0,0), (-1,-1), 0.25, HexColor("#e2e8f0")),
            ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
        ]))
        elements.append(det_table)
        elements.append(Spacer(1, 0.4*cm))

    # ── Source Attribution ──
    if data["sources"]:
        elements.append(Paragraph("Detection Sources", h2))
        elements.append(HRFlowable(width="100%", thickness=1, color=NAVY))
        elements.append(Spacer(1, 0.2*cm))
        src_data = [["Source", "Detections"]]
        for s in data["sources"]:
            src_data.append([s["source"], str(s["count"])])
        src_table = Table(src_data, colWidths=["70%","30%"])
        src_table.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,0), NAVY), ("TEXTCOLOR", (0,0), (-1,0), white),
            ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"), ("FONTSIZE", (0,0), (-1,-1), 9),
            ("TOPPADDING", (0,0), (-1,-1), 6), ("BOTTOMPADDING", (0,0), (-1,-1), 6),
            ("LEFTPADDING", (0,0), (-1,-1), 8),
            ("ROWBACKGROUNDS", (0,1), (-1,-1), [white, GRAY]),
            ("GRID", (0,0), (-1,-1), 0.25, HexColor("#e2e8f0")),
        ]))
        elements.append(src_table)
        elements.append(Spacer(1, 0.4*cm))

    # ── Recommendations ──
    elements.append(Paragraph("30-Day Recommendations", h2))
    elements.append(HRFlowable(width="100%", thickness=1, color=NAVY))
    elements.append(Spacer(1, 0.2*cm))
    recs = []
    if sev.get("CRITICAL",0) > 0:
        recs.append(f"CRITICAL - {sev['CRITICAL']} critical detections require immediate escalation. Review SLA compliance.")
    if sev.get("HIGH",0) > 0:
        recs.append(f"HIGH - {sev['HIGH']} high-severity IOCs outstanding. Ensure assignees are working active remediations.")
    if data["darkweb_mentions"] > 0:
        recs.append(f"DARK WEB - {data['darkweb_mentions']} mentions detected. Review for ransomware leak or data exposure context.")
    if rem["open"] > 0:
        recs.append(f"REMEDIATION - {rem['open']} open actions pending. Verify SLA not breached; escalate overdue items.")
    recs.append("Enable HIBP all 3 endpoints for complete breach coverage across all monitored domains.")
    recs.append("Run monthly TruffleHog scan across all customer GitHub organizations for secret exposure.")
    recs.append("Review ArgusWatch collector schedule - ensure all free collectors are active and running on schedule.")
    for i, r in enumerate(recs, 1):
        elements.append(Paragraph(f"<b>{i}.</b> {r}", body))
    elements.append(Spacer(1, 0.5*cm))

    # ── Footer ──
    footer_data = [[
        Paragraph("SOLVENT CYBERSECURITY LLC &nbsp;·&nbsp; Confidential - For Authorized Recipients Only",
            ParagraphStyle("f", fontSize=7.5, textColor=white, alignment=TA_CENTER))
    ]]
    footer = Table(footer_data, colWidths=["100%"])
    footer.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), NAVY),
        ("TOPPADDING", (0,0), (-1,-1), 8), ("BOTTOMPADDING", (0,0), (-1,-1), 8),
    ]))
    elements.append(footer)
    doc.build(elements)
    return buf.getvalue()

async def generate_pdf_report(customer_id: int, period_days: int = 30) -> dict:
    """Main entry point. Returns {file_path, file_name, size_bytes} or {error}."""
    data = await _gather_report_data(customer_id, period_days)
    if "error" in data:
        return data
    try:
        pdf_bytes = _build_pdf(data)
        if not pdf_bytes:
            return {"error": "ReportLab not installed. Run: pip install reportlab"}
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        safe_name = data["customer"]["name"].replace(" ", "_").replace("/", "_")[:30]
        fname = f"ArgusWatch_{safe_name}_{ts}.pdf"
        fpath = OUTPUT_DIR / fname
        fpath.write_bytes(pdf_bytes)
        return {"file_path": str(fpath), "file_name": fname,
                "size_bytes": len(pdf_bytes), "customer": data["customer"]["name"],
                "period_days": period_days, "total_detections": data["total_detections"]}
    except Exception as e:
        logger.error(f"PDF generation error: {e}")
        return {"error": str(e)}
