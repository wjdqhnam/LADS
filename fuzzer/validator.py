"""
Validator
executor 결과(execution_results.json) -> 취약 판정 -> findings 저장
xss_analyzer / sqli_analyzer 로직 통합
"""
from __future__ import annotations

import json

from baseline.sqli import ERROR_PATTERNS as _MYSQL_ERRORS

_XSS_MARKERS = [
    "onerror=alert",
    "onerror=eval",
    "onerror=prompt",
    "onload=alert",
    "onmouseover=alert",
    "onfocus=alert",
    "ontoggle=alert",
    "onstart=alert",
    "onanimationstart=alert",
    "src=x onerror",
    "<script>alert",
    "javascript:alert",
    "href=javascript:",
    "<svg/onload",
    "<svg onload",
    "<details open ontoggle",
    # backtick 변형 (xss_analyzer 추가분)
    "onerror=eval(",
    "alert`",
    "prompt`",
]

_HTML_ENCODED = ("&lt;", "&gt;", "&quot;", "&#x3c;", "&#60;")


def _check_xss(body: str, payload: str = "") -> tuple[bool, str]:
    tl = body.lower()

    # 1. 전체 페이로드 반영 확인 (xss_analyzer 방식)
    if payload:
        pl = payload.lower()
        idx = tl.find(pl)
        if idx != -1:
            surrounding = body[max(0, idx - 5): idx + len(payload) + 5]
            if not any(enc in surrounding for enc in _HTML_ENCODED):
                return True, "xss_reflected: full payload"

    # 2. 마커 기반 확인
    for marker in _XSS_MARKERS:
        ml = marker.lower()
        idx = tl.find(ml)
        if idx == -1:
            continue
        surrounding = body[max(0, idx - 10): idx + len(marker) + 10]
        if not any(enc in surrounding for enc in _HTML_ENCODED):
            return True, f"xss_reflected: '{marker}'"

    return False, ""


def _check_sqli(body: str) -> tuple[bool, str]:
    tl = body.lower()
    for pattern in _MYSQL_ERRORS:
        if pattern in tl:
            return True, f"mysql_error: '{pattern}'"
    return False, ""


def _check_time(elapsed: float, threshold: float = 4.5) -> tuple[bool, str]:
    if elapsed >= threshold:
        return True, f"time_delay={elapsed:.2f}s (>= {threshold}s)"
    return False, ""


def validate(results: list[dict], progress_callback=None) -> list[dict]:
    findings = []
    total = len(results)

    for idx, r in enumerate(results):
        if progress_callback:
            progress_callback(idx + 1, total)

        if r.get("error") or not r.get("response_body"):
            continue

        body = r["response_body"]
        payload = r.get("payload") or ""
        meta = r.get("meta") or {}
        vuln_type = (meta.get("vuln_type") or "").lower()
        elapsed = r.get("elapsed") or 0.0

        found = False
        evidence = ""

        if "xss" in vuln_type:
            found, evidence = _check_xss(body, payload)
        elif "sqli" in vuln_type or "sql" in vuln_type:
            found, evidence = _check_sqli(body)
            if not found:
                # time-based: vuln_type 무관하게 항상 시도
                found, evidence = _check_time(elapsed)
        else:
            found, evidence = _check_xss(body, payload)
            if not found:
                found, evidence = _check_sqli(body)
            if not found:
                found, evidence = _check_time(elapsed)

        if found:
            findings.append({
                "id":          r.get("id"),
                "point":       r.get("point"),
                "url":         r.get("url"),
                "method":      r.get("method"),
                "param":       r.get("inject_param"),
                "payload":     payload,
                "inject_mode": r.get("inject_mode"),
                "vuln_type":   meta.get("vuln_type"),
                "status":      r.get("status"),
                "elapsed":     elapsed,
                "evidence":    evidence,
            })

    return findings


def run(
    input_file: str = "results/execution_results.json",
    output_file: str = "results/findings.json",
    progress_callback=None,
) -> list[dict]:
    with open(input_file, encoding="utf-8") as f:
        results = json.load(f)

    findings = validate(results, progress_callback=progress_callback)

    import os
    os.makedirs(os.path.dirname(output_file) or ".", exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(findings, f, ensure_ascii=False, indent=2)

    return findings
