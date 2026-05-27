from __future__ import annotations

import json
import os
from datetime import datetime

from fpdf import FPDF  # pyright: ignore[reportMissingModuleSource]


VULN_LABELS = {
    "xss":  "XSS",
    "sqli": "SQLi",
    "sql":  "SQLi",
    "bac":  "BAC",
    "misconfig": "Misconfig",
}


def _vuln_label(vuln_type: str) -> str:
    vt = (vuln_type or "").lower()
    for key, label in VULN_LABELS.items():
        if key in vt:
            return label
    return vuln_type.upper()


def generate(run_id: str, run_dir: str) -> bytes:
    findings_path = os.path.join(run_dir, "findings.json")
    findings: list[dict] = []
    if os.path.exists(findings_path):
        with open(findings_path, encoding="utf-8") as f:
            findings = json.load(f)

    try:
        ts = datetime.strptime(run_id, "run_%Y%m%d_%H%M%S").strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        ts = run_id

    xss_cnt  = sum(1 for f in findings if f.get("module") == "xss")
    sqli_cnt = sum(1 for f in findings if f.get("module") == "sqli")
    bac_cnt  = sum(1 for f in findings if f.get("module") == "bac")
    other_cnt = len(findings) - xss_cnt - sqli_cnt - bac_cnt

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    # 폰트 설정 (기본 내장 폰트 사용)
    pdf.set_font("Helvetica", "B", 20)
    pdf.set_text_color(9, 20, 38)
    pdf.cell(0, 10, "LADS Vulnerability Report", new_x="LMARGIN", new_y="NEXT")

    pdf.set_font("Helvetica", "", 11)
    pdf.set_text_color(100, 100, 100)
    pdf.cell(0, 6, f"Run: {run_id}    Scanned: {ts}", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)

    # 구분선
    pdf.set_draw_color(214, 219, 227)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(6)

    # 요약
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(9, 20, 38)
    pdf.cell(0, 8, "Summary", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)

    col_w = 45
    headers = ["Total", "XSS", "SQLi", "BAC", "Other"]
    values  = [str(len(findings)), str(xss_cnt), str(sqli_cnt), str(bac_cnt), str(other_cnt)]

    pdf.set_font("Helvetica", "B", 10)
    pdf.set_fill_color(242, 244, 246)
    pdf.set_text_color(50, 50, 50)
    for h in headers:
        pdf.cell(col_w, 8, h, border=1, fill=True, align="C")
    pdf.ln()

    pdf.set_font("Helvetica", "", 11)
    pdf.set_text_color(9, 20, 38)
    for v in values:
        pdf.cell(col_w, 8, v, border=1, align="C")
    pdf.ln(10)

    if not findings:
        pdf.set_font("Helvetica", "I", 11)
        pdf.set_text_color(100, 100, 100)
        pdf.cell(0, 8, "No vulnerabilities found.", new_x="LMARGIN", new_y="NEXT")
        return bytes(pdf.output())

    # 취약점 목록
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(9, 20, 38)
    pdf.cell(0, 8, "Findings", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)

    for i, f in enumerate(findings, 1):
        if pdf.get_y() > 255:
            pdf.add_page()

        vtype = _vuln_label(f.get("vuln_type", ""))

        # 번호 + 타입
        pdf.set_font("Helvetica", "B", 11)
        pdf.set_text_color(9, 20, 38)
        pdf.set_fill_color(238, 242, 247)
        pdf.cell(0, 8, f"  [{i}] {vtype}  -  {f.get('point', '')}", fill=True, new_x="LMARGIN", new_y="NEXT")

        # 세부 정보
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(60, 60, 60)
        rows = [
            ("URL",     f.get("url", "")),
            ("Method",  f.get("method", "")),
            ("Param",   f.get("param", "")),
            ("Payload", f.get("payload", "")),
            ("Evidence",f.get("evidence", "")),
        ]
        for label, val in rows:
            display = str(val)[:85] + ("..." if len(str(val)) > 85 else "")
            pdf.set_font("Helvetica", "B", 10)
            pdf.cell(22, 6, f"  {label}")
            pdf.set_font("Helvetica", "", 10)
            pdf.cell(0, 6, display, new_x="LMARGIN", new_y="NEXT")

        pdf.ln(3)

    return bytes(pdf.output())
