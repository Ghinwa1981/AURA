# ============================================================
#  AURA :: PDF Report Generator
#  ReportLab — professional security reports
# ============================================================

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.lib.colors import (
    HexColor, white, black
)
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table,
    TableStyle, HRFlowable
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from datetime import datetime
from io import BytesIO

# ── Colors ────────────────────────────────────────────────
COL_BG      = HexColor("#080B12")
COL_ACCENT  = HexColor("#3B82F6")
COL_SAFE    = HexColor("#10B981")
COL_WARN    = HexColor("#F59E0B")
COL_DANGER  = HexColor("#EF4444")
COL_CRIT    = HexColor("#8B5CF6")
COL_DARK    = HexColor("#1C1F2A")
COL_BORDER  = HexColor("#222535")
COL_TEXT    = HexColor("#F1F5FF")
COL_MUTED   = HexColor("#7C8BA8")

THREAT_COLORS = {
    "SAFE":     COL_SAFE,
    "CAUTION":  COL_WARN,
    "WARNING":  COL_WARN,
    "DANGER":   COL_DANGER,
    "CRITICAL": COL_CRIT,
    "CLEAR":    COL_ACCENT,
}

def get_threat_color(threat: str):
    return THREAT_COLORS.get(threat.upper(), COL_ACCENT)

# ── Generate PDF ──────────────────────────────────────────
def generate_report(report: dict, user: dict = None) -> bytes:
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=20*mm, rightMargin=20*mm,
        topMargin=20*mm, bottomMargin=20*mm
    )

    styles = getSampleStyleSheet()
    elements = []

    # ── Header ────────────────────────────────────────────
    title_style = ParagraphStyle(
        "Title",
        fontName="Helvetica-Bold",
        fontSize=24,
        textColor=white,
        backColor=COL_BG,
        spaceAfter=4,
        spaceBefore=0,
        leading=28,
    )
    sub_style = ParagraphStyle(
        "Sub",
        fontName="Helvetica",
        fontSize=10,
        textColor=COL_MUTED,
        spaceAfter=0,
    )

    # Header table (logo + info)
    threat = report.get("overallThreat", "CLEAR")
    threat_color = get_threat_color(threat)

    header_data = [[
        Paragraph("<b>AURA</b>", ParagraphStyle("Logo", fontName="Helvetica-Bold", fontSize=28, textColor=COL_ACCENT)),
        Paragraph(
            f"<b>Intelligence Report</b><br/>"
            f"<font color='#7C8BA8' size='9'>Strategic Neural Auditor · {datetime.now().strftime('%Y-%m-%d %H:%M')}</font>",
            ParagraphStyle("HeaderRight", fontName="Helvetica", fontSize=12, textColor=white, alignment=TA_RIGHT)
        )
    ]]
    header_table = Table(header_data, colWidths=[80*mm, 90*mm])
    header_table.setStyle(TableStyle([
        ("BACKGROUND",   (0,0), (-1,-1), COL_BG),
        ("TOPPADDING",   (0,0), (-1,-1), 12),
        ("BOTTOMPADDING",(0,0), (-1,-1), 12),
        ("LEFTPADDING",  (0,0), (-1,-1), 6),
        ("RIGHTPADDING", (0,0), (-1,-1), 6),
        ("VALIGN",       (0,0), (-1,-1), "MIDDLE"),
    ]))
    elements.append(header_table)
    elements.append(Spacer(1, 6*mm))

    # ── Threat Status Banner ───────────────────────────────
    banner_data = [[
        Paragraph(f"<b>{threat}</b>",
            ParagraphStyle("ThreatBig", fontName="Helvetica-Bold", fontSize=20, textColor=threat_color)),
        Paragraph(
            f"<b>{report.get('summary','')}</b><br/>"
            f"<font size='9' color='#7C8BA8'>{report.get('recommendation','')}</font>",
            ParagraphStyle("BannerInfo", fontName="Helvetica", fontSize=11, textColor=white, leading=16)
        )
    ]]
    banner = Table(banner_data, colWidths=[35*mm, 135*mm])
    banner.setStyle(TableStyle([
        ("BACKGROUND",   (0,0), (-1,-1), COL_DARK),
        ("TOPPADDING",   (0,0), (-1,-1), 10),
        ("BOTTOMPADDING",(0,0), (-1,-1), 10),
        ("LEFTPADDING",  (0,0), (-1,-1), 10),
        ("RIGHTPADDING", (0,0), (-1,-1), 10),
        ("VALIGN",       (0,0), (-1,-1), "MIDDLE"),
        ("LINEAFTER",    (0,0), (0,0), 2, threat_color),
        ("ROUNDEDCORNERS", [4]),
    ]))
    elements.append(banner)
    elements.append(Spacer(1, 6*mm))

    # ── Stats Row ──────────────────────────────────────────
    stats = [
        ["Objects", str(len(report.get("objects", [])))],
        ["Threats", str(report.get("dangerCount", 0))],
        ["Safe", str(report.get("safeCount", 0))],
        ["Confidence", f"{round(report.get('averageConfidence',0)*100)}%"],
        ["Scan Time", f"{report.get('processingTimeMs',0)}ms"],
    ]
    stats_data = [[
        Table([[Paragraph(s[0], ParagraphStyle("SL", fontName="Helvetica", fontSize=8, textColor=COL_MUTED, alignment=TA_CENTER)),
                Paragraph(f"<b>{s[1]}</b>", ParagraphStyle("SV", fontName="Helvetica-Bold", fontSize=18, textColor=COL_ACCENT, alignment=TA_CENTER))]],
               colWidths=[28*mm])
        for s in stats
    ]]
    stats_table = Table(stats_data, colWidths=[34*mm]*5)
    stats_table.setStyle(TableStyle([
        ("BACKGROUND",   (0,0), (-1,-1), COL_DARK),
        ("TOPPADDING",   (0,0), (-1,-1), 8),
        ("BOTTOMPADDING",(0,0), (-1,-1), 8),
        ("INNERGRID",    (0,0), (-1,-1), 0.5, COL_BORDER),
        ("BOX",          (0,0), (-1,-1), 0.5, COL_BORDER),
    ]))
    elements.append(stats_table)
    elements.append(Spacer(1, 6*mm))

    # ── Scan Info ──────────────────────────────────────────
    elements.append(Paragraph(
        "SCAN INFORMATION",
        ParagraphStyle("SecTitle", fontName="Helvetica-Bold", fontSize=9, textColor=COL_ACCENT, spaceBefore=4, spaceAfter=4, letterSpacing=2)
    ))
    elements.append(HRFlowable(width="100%", thickness=0.5, color=COL_BORDER))
    elements.append(Spacer(1, 4*mm))

    info_data = [
        ["Frame ID",   report.get("frameId", "—"),        "Timestamp", report.get("timestamp", "—")[:19]],
        ["Scan Type",  report.get("scanType", "IMAGE"),   "Session",   report.get("frameId","")[:15]],
        ["User",       user.get("username","Anonymous") if user else "Anonymous",
         "Role",       user.get("role","viewer") if user else "—"],
    ]
    info_table = Table(info_data, colWidths=[28*mm, 62*mm, 28*mm, 52*mm])
    info_table.setStyle(TableStyle([
        ("FONTNAME",     (0,0), (-1,-1), "Helvetica"),
        ("FONTSIZE",     (0,0), (-1,-1), 9),
        ("TEXTCOLOR",    (0,0), (-1,-1), white),
        ("TEXTCOLOR",    (0,0), (0,-1), COL_MUTED),
        ("TEXTCOLOR",    (2,0), (2,-1), COL_MUTED),
        ("FONTNAME",     (0,0), (0,-1), "Helvetica-Bold"),
        ("FONTNAME",     (2,0), (2,-1), "Helvetica-Bold"),
        ("BACKGROUND",   (0,0), (-1,-1), COL_DARK),
        ("TOPPADDING",   (0,0), (-1,-1), 5),
        ("BOTTOMPADDING",(0,0), (-1,-1), 5),
        ("LEFTPADDING",  (0,0), (-1,-1), 8),
        ("INNERGRID",    (0,0), (-1,-1), 0.5, COL_BORDER),
        ("BOX",          (0,0), (-1,-1), 0.5, COL_BORDER),
    ]))
    elements.append(info_table)
    elements.append(Spacer(1, 6*mm))

    # ── Detected Objects ───────────────────────────────────
    objects = report.get("objects", [])
    if objects:
        elements.append(Paragraph(
            "DETECTED OBJECTS",
            ParagraphStyle("SecTitle2", fontName="Helvetica-Bold", fontSize=9, textColor=COL_ACCENT, spaceBefore=4, spaceAfter=4, letterSpacing=2)
        ))
        elements.append(HRFlowable(width="100%", thickness=0.5, color=COL_BORDER))
        elements.append(Spacer(1, 4*mm))

        obj_header = [
            Paragraph("<b>Object</b>",     ParagraphStyle("OH", fontName="Helvetica-Bold", fontSize=9, textColor=COL_MUTED)),
            Paragraph("<b>Threat</b>",     ParagraphStyle("OH", fontName="Helvetica-Bold", fontSize=9, textColor=COL_MUTED)),
            Paragraph("<b>Confidence</b>", ParagraphStyle("OH", fontName="Helvetica-Bold", fontSize=9, textColor=COL_MUTED)),
            Paragraph("<b>Category</b>",   ParagraphStyle("OH", fontName="Helvetica-Bold", fontSize=9, textColor=COL_MUTED)),
            Paragraph("<b>Priority</b>",   ParagraphStyle("OH", fontName="Helvetica-Bold", fontSize=9, textColor=COL_MUTED)),
            Paragraph("<b>Rationale</b>",  ParagraphStyle("OH", fontName="Helvetica-Bold", fontSize=9, textColor=COL_MUTED)),
        ]

        obj_rows = [obj_header]
        for obj in objects:
            tc = get_threat_color(obj.get("threat","SAFE"))
            obj_rows.append([
                Paragraph(f"<b>{obj.get('label','')}</b>", ParagraphStyle("OL", fontName="Helvetica-Bold", fontSize=9, textColor=white)),
                Paragraph(f"<b>{obj.get('threat','')}</b>", ParagraphStyle("OT", fontName="Helvetica-Bold", fontSize=9, textColor=tc)),
                Paragraph(f"{round(obj.get('confidence',0)*100)}%", ParagraphStyle("OC", fontName="Helvetica", fontSize=9, textColor=white)),
                Paragraph(obj.get("category",""), ParagraphStyle("OCA", fontName="Helvetica", fontSize=9, textColor=COL_MUTED)),
                Paragraph(str(obj.get("priority",1)), ParagraphStyle("OP", fontName="Helvetica", fontSize=9, textColor=white, alignment=TA_CENTER)),
                Paragraph(obj.get("rationale","")[:60], ParagraphStyle("OR", fontName="Helvetica", fontSize=8, textColor=COL_MUTED)),
            ])

        obj_table = Table(obj_rows, colWidths=[25*mm, 20*mm, 20*mm, 20*mm, 15*mm, 70*mm])
        obj_table.setStyle(TableStyle([
            ("BACKGROUND",   (0,0), (-1,0),  COL_BG),
            ("BACKGROUND",   (0,1), (-1,-1), COL_DARK),
            ("ROWBACKGROUNDS",(0,1),(-1,-1), [COL_DARK, HexColor("#161820")]),
            ("TOPPADDING",   (0,0), (-1,-1), 5),
            ("BOTTOMPADDING",(0,0), (-1,-1), 5),
            ("LEFTPADDING",  (0,0), (-1,-1), 6),
            ("INNERGRID",    (0,0), (-1,-1), 0.5, COL_BORDER),
            ("BOX",          (0,0), (-1,-1), 0.5, COL_BORDER),
            ("VALIGN",       (0,0), (-1,-1), "MIDDLE"),
        ]))
        elements.append(obj_table)
        elements.append(Spacer(1, 6*mm))

    # ── Footer ─────────────────────────────────────────────
    elements.append(Spacer(1, 4*mm))
    elements.append(HRFlowable(width="100%", thickness=0.5, color=COL_BORDER))
    elements.append(Spacer(1, 3*mm))
    footer_data = [[
        Paragraph(
            "<b>AURA</b> · Strategic Neural Auditor · Confidential",
            ParagraphStyle("FL", fontName="Helvetica", fontSize=8, textColor=COL_MUTED)
        ),
        Paragraph(
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            ParagraphStyle("FR", fontName="Helvetica", fontSize=8, textColor=COL_MUTED, alignment=TA_RIGHT)
        )
    ]]
    footer = Table(footer_data, colWidths=[90*mm, 80*mm])
    footer.setStyle(TableStyle([("TOPPADDING",(0,0),(-1,-1),0),("BOTTOMPADDING",(0,0),(-1,-1),0)]))
    elements.append(footer)

    doc.build(elements)
    return buffer.getvalue()