"""
Validator
executor 결과(execution_results.json) -> 취약 판정 -> findings 저장
xss_analyzer / sqli_analyzer 로직 통합
"""
from __future__ import annotations

import json
import re
from collections import defaultdict

from payload.baseline.sqli import ERROR_PATTERNS as _MYSQL_ERRORS

# Boolean 판정: TRUE 조건 페이로드 패턴
_BOOL_TRUE = re.compile(
    r"1=1|'1'\s*=\s*'1'|OR\s+1\b|OR\(1=1\)|AND\(1=1\)|or_true|and_true|paren_true",
    re.IGNORECASE,
)
# Boolean 판정: FALSE 조건 페이로드 패턴
_BOOL_FALSE = re.compile(
    r"1=2|'1'\s*=\s*'2'|AND\s+1=2|AND\(1=2\)|paren_false|and_false",
    re.IGNORECASE,
)
# Boolean 판정: 응답 길이 차이 임계값 (5%)
_BOOL_DIFF_THRESHOLD = 0.05

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


def _make_finding(r: dict, evidence: str) -> dict:
    meta = r.get("meta") or {}
    return {
        "id":          r.get("id"),
        "point":       r.get("point"),
        "url":         r.get("url"),
        "method":      r.get("method"),
        "param":       r.get("inject_param"),
        "payload":     r.get("payload") or "",
        "inject_mode": r.get("inject_mode"),
        "vuln_type":   meta.get("vuln_type"),
        "status":      r.get("status"),
        "elapsed":     r.get("elapsed") or 0.0,
        "evidence":    evidence,
    }


def _detect_boolean(results: list[dict]) -> list[dict]:
    """
    같은 (point, inject_param, url) 그룹 내에서
    TRUE/FALSE 조건 응답 길이 비교 → Boolean SQLi 판정.
    """
    # SQLi 결과만 추출
    sqli_results = [
        r for r in results
        if not r.get("error")
        and r.get("response_body")
        and ("sqli" in (((r.get("meta") or {}).get("vuln_type")) or "").lower()
             or "sql" in (((r.get("meta") or {}).get("vuln_type")) or "").lower())
    ]

    # (point, inject_param, url) 기준 그룹핑
    groups: dict[tuple, list[dict]] = defaultdict(list)
    for r in sqli_results:
        key = (r.get("point"), r.get("inject_param"), r.get("url"))
        groups[key].append(r)

    findings = []

    for key, group in groups.items():
        true_items, false_items = [], []

        for r in group:
            payload = r.get("payload") or ""
            if _BOOL_TRUE.search(payload):
                true_items.append(r)
            elif _BOOL_FALSE.search(payload):
                false_items.append(r)

        if not true_items or not false_items:
            continue

        avg_true  = sum(len(r["response_body"]) for r in true_items)  / len(true_items)
        avg_false = sum(len(r["response_body"]) for r in false_items) / len(false_items)
        max_len   = max(avg_true, avg_false, 1)
        diff      = abs(avg_true - avg_false) / max_len

        if diff < _BOOL_DIFF_THRESHOLD:
            continue

        # TRUE 조건 응답이 더 길어야 정상적인 boolean 패턴
        direction = "true>false" if avg_true > avg_false else "true<false"
        evidence = (
            f"boolean_sqli: true_len={avg_true:.0f}, false_len={avg_false:.0f}, "
            f"diff={diff:.1%} ({direction})"
        )

        # TRUE 조건 페이로드 중 대표 1개만 finding으로 등록
        best = max(true_items, key=lambda r: len(r["response_body"]))
        findings.append(_make_finding(best, evidence))

    return findings


def validate(results: list[dict], progress_callback=None) -> list[dict]:
    findings = []
    found_ids: set = set()
    total = len(results)

    # ── Phase 1: 결과 단건 검사 (error-based, time-based, XSS) ──────────────
    for idx, r in enumerate(results):
        if progress_callback:
            progress_callback(idx + 1, total)

        if r.get("error") or not r.get("response_body"):
            continue

        body    = r["response_body"]
        payload = r.get("payload") or ""
        meta    = r.get("meta") or {}
        vuln_type = (meta.get("vuln_type") or "").lower()
        elapsed = r.get("elapsed") or 0.0

        found    = False
        evidence = ""

        if "xss" in vuln_type:
            found, evidence = _check_xss(body, payload)
        elif "sqli" in vuln_type or "sql" in vuln_type:
            found, evidence = _check_sqli(body)
            if not found:
                found, evidence = _check_time(elapsed)
        else:
            found, evidence = _check_xss(body, payload)
            if not found:
                found, evidence = _check_sqli(body)
            if not found:
                found, evidence = _check_time(elapsed)

        if found:
            f = _make_finding(r, evidence)
            findings.append(f)
            found_ids.add(r.get("id"))

    # ── Phase 2: 그룹 단위 boolean 탐지 ────────────────────────────────────
    for bf in _detect_boolean(results):
        if bf["id"] not in found_ids:
            findings.append(bf)
            found_ids.add(bf["id"])

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
